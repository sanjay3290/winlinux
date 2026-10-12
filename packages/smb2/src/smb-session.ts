// Public SMB2 session API. One SmbSession per server connection.
// Paths are share-relative with forward slashes; the protocol layer converts
// them to SMB backslash form. Credentials pass through to the AuthProvider
// untouched — this module never reads passwords.
import { pipeline } from "node:stream/promises";
import { createWriteStream, type ReadStream } from "node:fs";
import { open, rm } from "node:fs/promises";
import Client from "./client/Client.js";
import Session from "./client/Session.js";
import Tree from "./client/Tree.js";
import File from "./client/File.js";
import PacketType from "./protocol/smb2/PacketType.js";
import * as structureUtil from "./protocol/structureUtil.js";
import { CreateOptions } from "./protocol/smb2/packets/Create.js";
import { FileInfoClass, InfoType } from "./protocol/smb2/packets/SetInfo.js";
import CreateDispositionType from "./protocol/smb2/CreateDispositionType.js";
import FilePipePrinterAccess from "./protocol/smb2/FilePipePrinterAccess.js";
import type { AuthProvider, Credentials } from "./auth-contract.js";
import * as util from "./protocol/util.js";
import {
  SmbAccessDeniedError,
  SmbConnectionError,
  SmbEncryptionRequiredError,
  SmbError,
  SmbFileTooLargeError,
  SmbIsADirectoryError,
  SmbNotADirectoryError,
  throwIfAborted,
  toSmbError,
} from "./errors.js";
import type DirectoryEntry from "./protocol/models/DirectoryEntry.js";
import { SHI1005_FLAGS_ENCRYPT_DATA, SrvsvcClient } from "./rpc/srvsvc.js";

export interface SMBConnectOptions {
  host: string;
  port?: number; // default 445
  authProvider: AuthProvider;
  credentials: Credentials;
  signing?: 'auto' | 'required'; // default 'auto': sign when server asks
  requestTimeoutMs?: number; // default 30_000 per SMB round trip
  connectTimeoutMs?: number; // default 5_000 for the TCP connect
  // Highest dialect to offer. Default "3.1.1": SMB 3.x with AES
  // signing and encryption when the server negotiates it, SMB 2.x otherwise.
  maxDialect?: '2.1' | '3.1.1';
}

// What the connection negotiated, for diagnostics.
export interface SmbSecurityInfo {
  dialect: string; // "2.0.2", "2.1", "3.0", "3.0.2" or "3.1.1"
  signingAlgorithm: string; // "HMAC-SHA256", "AES-CMAC" or "AES-GMAC"
  cipher: string; // "AES-128-GCM", "AES-128-CCM" or "none"
  encryptData: boolean; // the server encrypts the whole session
  signing: boolean; // requests are signed (or encrypted): signing is in effect
}

export interface ShareInfo {
  name: string; // e.g. 'C$', 'Shared'
  type: string; // e.g. 'disk', 'printer', 'ipc'
  comment: string;
}

export interface DirEntry {
  name: string;
  isDirectory: boolean;
  sizeBytes: bigint;
  mtime: Date;
  // FILE_ATTRIBUTE_REPARSE_POINT: a symbolic link, junction or other
  // reparse point on the server. Recursive copies skip these.
  isReparsePoint: boolean;
}

export interface FileStat {
  sizeBytes: bigint;
  mtime: Date;
  atime: Date;
  isDirectory: boolean;
  readonly: boolean;
}

// Cancellation. On abort the call sends no further request, the
// request in flight rejects at once and its response is discarded, the
// file or directory handle closes, and the call rejects with SmbAbortError
// (`err.name === 'AbortError'`, `err.cause` the signal's reason). A signal
// that is already aborted rejects before any request goes out. The session
// stays usable for the next call.
export interface AbortOptions {
  signal?: AbortSignal;
}

export interface SMBSession {
  listShares(): Promise<ShareInfo[]>;
  list(share: string, dirPath?: string, opts?: AbortOptions): Promise<DirEntry[]>;
  // The directory entry by entry, one QUERY_DIRECTORY response at a time:
  // a caller can stop early with `break`, which closes the handle.
  listIter(share: string, dirPath?: string, opts?: AbortOptions): AsyncIterable<DirEntry>;
  stat(share: string, filePath: string, opts?: AbortOptions): Promise<FileStat>;
  readFile(share: string, filePath: string, opts?: AbortOptions): Promise<Buffer>;
  // The bytes [offset, offset + length) of a file of any size: the
  // file opens read-only with share access read, write and delete, so a
  // file another process holds open for append reads too. Fewer bytes
  // come back at end of file, an empty Buffer past it. `length` above
  // MAX_BUFFERED_FILE_BYTES is refused.
  readRange(share: string, filePath: string, offset: number | bigint, length: number, opts?: AbortOptions): Promise<Buffer>;
  writeFile(share: string, filePath: string, data: Buffer | string): Promise<void>;
  upload(localPath: string, share: string, remotePath: string): Promise<void>;
  download(share: string, remotePath: string, localPath: string, opts?: AbortOptions): Promise<void>;
  readonly security: SmbSecurityInfo; // what the connection negotiated
  delete(share: string, filePath: string): Promise<void>; // file or empty directory
  deleteFile(share: string, filePath: string): Promise<void>; // refuses a directory
  deleteDirectory(share: string, dirPath: string): Promise<void>; // empty directories only
  rename(share: string, fromPath: string, toPath: string): Promise<void>; // within one share
  mkdir(share: string, dirPath: string): Promise<void>;
  close(): Promise<void>; // tree disconnect, logoff, socket close
}

export const DEFAULT_PORT = 445;
export const DEFAULT_REQUEST_TIMEOUT_MS = 30_000;
// readFile/writeFile buffer whole files; bigger transfers must stream.
export const MAX_BUFFERED_FILE_BYTES = 64 * 1024 * 1024;

export async function connect(opts: SMBConnectOptions): Promise<SMBSession> {
  const client = new Client(opts.host, {
    port: opts.port ?? DEFAULT_PORT,
    requestTimeout: opts.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS,
    ...(opts.connectTimeoutMs !== undefined ? { connectTimeout: opts.connectTimeoutMs } : {}),
  });
  try {
    const session = await client.authenticate({
      authProvider: opts.authProvider,
      credentials: opts.credentials,
      signing: opts.signing,
      ...(opts.maxDialect ? { maxDialect: opts.maxDialect } : {}),
    });
    return new SmbSession(client, session);
  } catch (error) {
    await client.close().catch(() => undefined);
    const typed = toSmbError(error, `connect to ${opts.host}`);
    if (typed instanceof SmbError) throw typed;
    if (error instanceof Error) {
      const wrapped = new SmbConnectionError(`cannot connect to ${opts.host}:${opts.port ?? DEFAULT_PORT}: ${error.message}`);
      (wrapped as { cause?: unknown }).cause = error;
      throw wrapped;
    }
    throw typed;
  }
}

function toDirEntry(entry: DirectoryEntry): DirEntry {
  return {
    name: entry.filename.replace(/^\.\//, ""),
    isDirectory: entry.type === "Directory",
    sizeBytes: entry.fileSize,
    mtime: entry.lastWriteTime,
    isReparsePoint: entry.fileAttributes.includes("ReparsePoint"),
  };
}

export class SmbSession implements SMBSession {
  private trees = new Map<string, Tree>();

  constructor(
    private readonly client: Client,
    private readonly session: Session,
  ) {}

  get security(): SmbSecurityInfo {
    return { ...this.session.security };
  }

  private async treeFor(share: string): Promise<Tree> {
    let tree = this.trees.get(share);
    if (!tree) {
      try {
        tree = await this.session.connectTree(share);
      } catch (error) {
        const typed = toSmbError(error, `tree connect to ${share}`);
        if (typed instanceof SmbAccessDeniedError && !(typed instanceof SmbEncryptionRequiredError)) {
          throw await this.refineTreeConnectDenied(share, typed);
        }
        throw typed;
      }
      this.trees.set(share, tree);
    }
    return tree;
  }

  // Windows answers a TREE_CONNECT to a share that requires encryption, on a
  // dialect below 3.0 with RejectUnencryptedAccess on (the default), with a
  // bare STATUS_ACCESS_DENIED (MS-SMB2 3.3.5.7). The error response carries
  // no ShareFlags, so the SMB exchange alone cannot tell it from a share ACL
  // that excludes the account. SRVSVC NetrShareGetInfo level 1005 can: its
  // shi1005_flags carry SHI1005_FLAGS_ENCRYPT_DATA (MS-SRVS 2.2.4.29). The
  // probe runs over IPC$ on this session. When it fails for any reason, or
  // the flag is clear, the original access-denied error stands, so a real
  // ACL deny is never reported as an encryption problem.
  private async refineTreeConnectDenied(share: string, denied: SmbAccessDeniedError): Promise<SmbError> {
    let flags: number;
    try {
      flags = await new SrvsvcClient(this.session).getShareFlags(share);
    } catch {
      return denied;
    }
    if ((flags & SHI1005_FLAGS_ENCRYPT_DATA) === 0) return denied;
    return new SmbEncryptionRequiredError(
      `share ${share} requires SMB encryption, which this connection did not negotiate (dialect ${this.session.security.dialect || "unknown"}, cipher ${this.session.security.cipher})`,
      denied.status,
    );
  }

  async listShares(): Promise<ShareInfo[]> {
    try {
      return await new SrvsvcClient(this.session).enumShares();
    } catch (error) {
      throw toSmbError(error, "list shares");
    }
  }

  async list(share: string, dirPath?: string, opts: AbortOptions = {}): Promise<DirEntry[]> {
    const context = `list ${share}/${dirPath ?? ""}`;
    throwIfAborted(opts.signal, context);
    try {
      const tree = await this.treeFor(share);
      const entries = await tree.readDirectory(dirPath ?? "", { signal: opts.signal });
      return entries.map(toDirEntry);
    } catch (error) {
      throw toSmbError(error, context);
    }
  }

  async *listIter(share: string, dirPath?: string, opts: AbortOptions = {}): AsyncGenerator<DirEntry, void, undefined> {
    const context = `list ${share}/${dirPath ?? ""}`;
    throwIfAborted(opts.signal, context);
    let tree: Tree;
    try {
      tree = await this.treeFor(share);
    } catch (error) {
      throw toSmbError(error, context);
    }
    // The handle closes when the pages end, when the consumer stops early
    // (return() on this iterator closes the inner one) or on an error.
    const pages = tree.readDirectoryPages(dirPath ?? "", { signal: opts.signal });
    try {
      for await (const page of pages) {
        for (const entry of page) yield toDirEntry(entry);
      }
    } catch (error) {
      throw toSmbError(error, context);
    }
  }

  async stat(share: string, filePath: string, opts: AbortOptions = {}): Promise<FileStat> {
    const context = `stat ${share}/${filePath}`;
    throwIfAborted(opts.signal, context);
    const tree = await this.treeFor(share);
    const file = new File(tree);
    try {
      await this.openForStat(file, filePath, opts.signal);
      const basic = await this.queryInfo(tree, file, FileInfoClass.BasicInformation, opts.signal);
      const standard = await this.queryInfo(tree, file, FileInfoClass.StandardInformation, opts.signal);
      const attributes = basic.readUInt32LE(32);
      return {
        sizeBytes: standard.readBigUInt64LE(8),
        mtime: structureUtil.parseDate(basic.subarray(16, 24)),
        atime: structureUtil.parseDate(basic.subarray(8, 16)),
        isDirectory: standard[21] !== 0 || (attributes & 0x10) !== 0,
        readonly: (attributes & 0x1) !== 0,
      };
    } catch (error) {
      throw toSmbError(error, context);
    } finally {
      await file.close();
    }
  }

  // Some servers require FILE_DIRECTORY_FILE to open a directory; opening a
  // file with that flag fails. Try plain first, retry flagged, keep the
  // first error when both fail. A CREATE never takes the signal: an abort
  // during it is seen once it has answered, so the handle it opened is
  // known and closes.
  private async openForStat(file: File, filePath: string, signal?: AbortSignal): Promise<void> {
    try {
      await file.open(filePath, { desiredAccess: FilePipePrinterAccess.ReadAttributes });
    } catch (first) {
      throwIfAborted(signal, "stat");
      try {
        await file.open(filePath, {
          desiredAccess: FilePipePrinterAccess.ReadAttributes,
          createOptions: CreateOptions.Directory,
        });
      } catch {
        throw first;
      }
    }
  }

  private async queryInfo(tree: Tree, file: File, infoClass: number, signal?: AbortSignal): Promise<Buffer> {
    throwIfAborted(signal, "stat");
    const response = await tree.request({ type: PacketType.QueryInfo }, {
      infoType: InfoType.File,
      fileInfoClass: infoClass,
      fileId: file._id,
      buffer: Buffer.alloc(0),
    }, { signal });
    return response.body.buffer as Buffer;
  }

  async readFile(share: string, filePath: string, opts: AbortOptions = {}): Promise<Buffer> {
    const context = `read ${share}/${filePath}`;
    throwIfAborted(opts.signal, context);
    const tree = await this.treeFor(share);
    const file = new File(tree);
    try {
      await file.open(filePath);
      if (file.fileSize > BigInt(MAX_BUFFERED_FILE_BYTES)) {
        throw new SmbFileTooLargeError(
          `file ${share}/${filePath} is ${file.fileSize} bytes, above the ${MAX_BUFFERED_FILE_BYTES} byte buffer cap; use download() to stream it`
        );
      }
      return await file.read({ signal: opts.signal });
    } catch (error) {
      throw toSmbError(error, context);
    } finally {
      await file.close();
    }
  }

  async readRange(share: string, filePath: string, offset: number | bigint, length: number, opts: AbortOptions = {}): Promise<Buffer> {
    const context = `read ${share}/${filePath} at ${offset}`;
    if (typeof offset === "bigint" ? offset < 0n : !Number.isInteger(offset) || offset < 0) {
      throw new RangeError(`readRange offset must be a non-negative integer, got ${String(offset)}`);
    }
    if (!Number.isInteger(length) || length < 0) throw new RangeError(`readRange length must be a non-negative integer, got ${String(length)}`);
    if (length > MAX_BUFFERED_FILE_BYTES) {
      throw new SmbFileTooLargeError(
        `range of ${length} bytes is above the ${MAX_BUFFERED_FILE_BYTES} byte buffer cap; read smaller ranges, or use download() to stream the file`
      );
    }
    throwIfAborted(opts.signal, context);
    const tree = await this.treeFor(share);
    const file = new File(tree);
    try {
      await file.open(filePath); // read-only, share read | write | delete
      return await file.readRange(typeof offset === "bigint" ? offset : BigInt(offset), length, { signal: opts.signal });
    } catch (error) {
      throw toSmbError(error, context);
    } finally {
      await file.close();
    }
  }

  async writeFile(share: string, filePath: string, data: Buffer | string): Promise<void> {
    const buffer = Buffer.isBuffer(data) ? data : Buffer.from(data, "utf8");
    if (buffer.length > MAX_BUFFERED_FILE_BYTES) {
      throw new SmbFileTooLargeError(
        `data is ${buffer.length} bytes, above the ${MAX_BUFFERED_FILE_BYTES} byte buffer cap; use upload() to stream it`
      );
    }
    const tree = await this.treeFor(share);
    const file = new File(tree);
    try {
      await file.open(filePath, {
        desiredAccess: FilePipePrinterAccess.WriteData,
        createDisposition: CreateDispositionType.OverwriteIf,
      });
      await file.setSize(BigInt(buffer.length));
      if (buffer.length > 0) await file.write(buffer);
    } catch (error) {
      throw toSmbError(error, `write ${share}/${filePath}`);
    } finally {
      await file.close();
    }
  }

  async upload(localPath: string, share: string, remotePath: string): Promise<void> {
    // Open the local file before the OverwriteIf CREATE, so a missing or
    // unreadable source never truncates the remote file.
    const source = await open(localPath, "r");
    let reader: ReadStream | undefined;
    try {
      if (!(await source.stat()).isFile()) {
        throw Object.assign(new Error(`EISDIR: ${localPath} is not a regular file`), {
          code: "EISDIR",
          path: localPath,
        });
      }
      const tree = await this.treeFor(share);
      const file = new File(tree);
      try {
        await file.open(remotePath, {
          desiredAccess: FilePipePrinterAccess.WriteData,
          createDisposition: CreateDispositionType.OverwriteIf,
        });
        const writer = file.createWriteStream();
        reader = source.createReadStream();
        await pipeline(reader, writer);
        await file.setSize(BigInt(writer.bytesWritten));
      } catch (error) {
        throw toSmbError(error, `upload ${localPath} to ${share}/${remotePath}`);
      } finally {
        await file.close();
      }
    } finally {
      if (!reader) await source.close();
    }
  }

  // A download that fails or aborts leaves no partial file at localPath
  //: the write stream is closed by pipeline(), then the file is
  // removed (a missing one is fine), and the original error is thrown.
  // Only a file this call opened for writing is removed: a failure before
  // that (the remote CREATE, or a local open that fails) leaves an existing
  // file at localPath untouched.
  async download(share: string, remotePath: string, localPath: string, opts: AbortOptions = {}): Promise<void> {
    const context = `download ${share}/${remotePath} to ${localPath}`;
    throwIfAborted(opts.signal, context);
    const tree = await this.treeFor(share);
    const file = new File(tree);
    let written = false;
    try {
      await file.open(remotePath);
      const writer = createWriteStream(localPath);
      writer.once("open", () => {
        written = true;
      });
      await pipeline(file.createReadStream({ signal: opts.signal }), writer);
    } catch (error) {
      if (written) await rm(localPath, { force: true }).catch(() => undefined);
      throw toSmbError(error, context);
    } finally {
      await file.close();
    }
  }

  async delete(share: string, filePath: string): Promise<void> {
    try {
      const tree = await this.treeFor(share);
      const info = await this.stat(share, filePath);
      if (info.isDirectory) {
        await tree.removeDirectory(filePath);
      } else {
        await tree.removeFile(filePath);
      }
    } catch (error) {
      throw toSmbError(error, `delete ${share}/${filePath}`);
    }
  }

  // rm: a directory is refused before any delete, so `rm` can never take a
  // tree away.
  async deleteFile(share: string, filePath: string): Promise<void> {
    try {
      const tree = await this.treeFor(share);
      const info = await this.stat(share, filePath);
      if (info.isDirectory) {
        throw new SmbIsADirectoryError(`is a directory: ${share}/${filePath}; use rmdir`);
      }
      await tree.removeFile(filePath);
    } catch (error) {
      throw toSmbError(error, `delete ${share}/${filePath}`);
    }
  }

  // rmdir: the server refuses a directory that still has entries with
  // STATUS_DIRECTORY_NOT_EMPTY (SmbDirectoryNotEmptyError); nothing here
  // recurses.
  async deleteDirectory(share: string, dirPath: string): Promise<void> {
    try {
      const tree = await this.treeFor(share);
      const info = await this.stat(share, dirPath);
      if (!info.isDirectory) {
        throw new SmbNotADirectoryError(`not a directory: ${share}/${dirPath}; use delete`);
      }
      await tree.removeDirectory(dirPath);
    } catch (error) {
      throw toSmbError(error, `rmdir ${share}/${dirPath}`);
    }
  }

  // mv within one share: SMB2 RenameInformation. An existing target is not
  // replaced (STATUS_OBJECT_NAME_COLLISION, SmbAlreadyExistsError).
  async rename(share: string, fromPath: string, toPath: string): Promise<void> {
    try {
      const tree = await this.treeFor(share);
      const info = await this.stat(share, fromPath);
      if (info.isDirectory) {
        await tree.renameDirectory(fromPath, util.toWindowsFilePath(toPath));
      } else {
        await tree.renameFile(fromPath, toPath);
      }
    } catch (error) {
      throw toSmbError(error, `rename ${share}/${fromPath} to ${share}/${toPath}`);
    }
  }

  async mkdir(share: string, dirPath: string): Promise<void> {
    try {
      const tree = await this.treeFor(share);
      await tree.createDirectory(dirPath);
    } catch (error) {
      throw toSmbError(error, `mkdir ${share}/${dirPath}`);
    }
  }

  async close(): Promise<void> {
    this.trees.clear();
    try {
      await this.session.logoff();
    } finally {
      await this.client.close();
    }
  }
}
