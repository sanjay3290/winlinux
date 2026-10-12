import File from "./File.js";
import type Session from "./Session.js";
import type { SendOptions } from "./Client.js";
import Directory, { type ReadOptions } from "./Directory.js";
import { EventEmitter } from "events";
import type Header from "../protocol/smb2/Header.js";
import * as util from "../protocol/util.js";
import type Response from "../protocol/smb2/Response.js";
import PacketType from "../protocol/smb2/PacketType.js";
import DirectoryAccess from "../protocol/smb2/DirectoryAccess.js";
import FilePipePrinterAccess from "../protocol/smb2/FilePipePrinterAccess.js";
import { SMB2_SHAREFLAG_ENCRYPT_DATA } from "../smb3.js";

interface Tree {
  on(event: "connect" | "disconnect", callback: (tree: Tree) => void): this;

  once(event: "connect" | "disconnect", callback: (tree: Tree) => void): this;
}

class Tree extends EventEmitter {
  _id: number;
  connected = false;
  connecting = false;
  openFiles: File[] = [];
  openDirectories: Directory[] = [];

  constructor(
    public session: Session
  ) {
    super();
  }

  async connect(path: string) {
    if (this.connected || this.connecting) return;
    this.connecting = true;

    const buffer = Buffer.from(
      util.toWindowsPath(`//${this.session.client.host}/${path}`),
      "ucs2"
    );
    const response = await this.request({ type: PacketType.TreeConnect }, { buffer });
    this._id = response.header.treeId;
    // SMB 3.x share-level encryption.
    if (((response.body.shareFlags as number | undefined) ?? 0) & SMB2_SHAREFLAG_ENCRYPT_DATA) {
      try {
        this.session.client.markTreeEncrypted(this.session._id, this._id);
      } catch (error) {
        this.connecting = false;
        await this.request({ type: PacketType.TreeDisconnect }).catch(() => undefined);
        throw error;
      }
    }

    // Below SMB 3.1.1, the first tree checks the NEGOTIATE; a
    // failure has already ended the connection.
    try {
      await this.session.validateNegotiate(this);
    } catch (error) {
      this.connecting = false;
      throw error;
    }

    this.connecting = false;
    this.connected = true;

    this.emit("connect", this);
  }

  async disconnect() {
    if (!this.connected) return;
    this.connected = false;

    await Promise.all([
      ...this.openFiles.map(x => x.close()),
      ...this.openDirectories.map(x => x.close())
    ]);

    await this.request({ type: PacketType.TreeDisconnect });
    this.session.client.unmarkTree(this.session._id, this._id);

    this.emit("disconnect", this);
  }

  // Every open handle closes even when the operation fails: a
  // handle left open after STATUS_DIRECTORY_NOT_EMPTY, for example, kept
  // its directory alive until logoff, so a later delete-on-close did not
  // delete. close() on a handle that never opened is a no-op.
  async createDirectory(path: string) {
    const directory = new Directory(this);
    this.registerDirectory(directory);

    try {
      await directory.create(path);
    } finally {
      await directory.close();
    }
  }

  async removeDirectory(path: string) {
    const directory = new Directory(this);
    this.registerDirectory(directory);

    try {
      await directory.open(path, { desiredAccess: DirectoryAccess.Delete });
      await directory.remove();
    } finally {
      await directory.close();
    }
  }

  async renameDirectory(path: string, newPath: string) {
    const directory = new Directory(this);
    this.registerDirectory(directory);

    try {
      await directory.open(path, { desiredAccess: DirectoryAccess.MaximumAllowed });
      await directory.rename(newPath);
    } finally {
      await directory.close();
    }
  }

  async watch(onChange?: (response: Response) => void, recursive?: boolean) {
    return await this.watchDirectory("", onChange, recursive);
  }

  async watchDirectory(path: string = "/", onChange: (response: Response) => void, recursive?: boolean) {
    const directory = new Directory(this);
    this.registerDirectory(directory);

    await directory.open(path);
    await directory.watch(recursive);
    directory.addListener("change", onChange);

    return async () => {
      directory.removeListener("change", onChange);
      await directory.unwatch();
    };
  }

  async readDirectory(path: string = "/", options: ReadOptions = {}) {
    const directory = new Directory(this);
    this.registerDirectory(directory);

    try {
      await directory.open(path);
      return await directory.read(options);
    } finally {
      await directory.close();
    }
  }

  // The directory one QUERY_DIRECTORY response at a time. The handle
  // closes when the pages run out, when the consumer stops early (return()
  // on the iterator, which `break` in a for-await loop does), or on an
  // error, an abort included.
  async *readDirectoryPages(path: string = "/", options: ReadOptions = {}) {
    const directory = new Directory(this);
    this.registerDirectory(directory);

    try {
      await directory.open(path);
      yield* directory.pages(options);
    } finally {
      await directory.close();
    }
  }

  async exists(path: string) {
    const file = new File(this);
    this.registerFile(file);
    const exists = await file.exists(path);
    await file.close();
    return exists;
  }

  async createFile(path: string, content?: Buffer | string) {
    const file = new File(this);
    this.registerFile(file);
    await file.create(path);
    if (typeof content !== "undefined") {
      await file.setSize(BigInt(content.length));
      await file.write(content);
    }
    await file.close();
  }

  async createFileWriteStream(path: string) {
    const file = new File(this);
    this.registerFile(file);
    await file.create(path);
    const stream = file.createWriteStream();
    stream.once("close", async () => {
      await file.setSize(BigInt(stream.bytesWritten));
      file.close();
    });
    return stream;
  }

  async removeFile(path: string) {
    const file = new File(this);
    this.registerFile(file);
    try {
      await file.open(path, { desiredAccess: FilePipePrinterAccess.Delete });
      await file.remove();
    } finally {
      await file.close();
    }
  }

  async renameFile(path: string, newPath: string) {
    const desiredAccess =  FilePipePrinterAccess.Delete |
      FilePipePrinterAccess.WriteAttributes |
      FilePipePrinterAccess.ReadAttributes |
      FilePipePrinterAccess.ReadControl;
    const file = new File(this);
    this.registerFile(file);
    try {
      await file.open(path, { desiredAccess });
      await file.rename(newPath);
    } finally {
      await file.close();
    }
  }

  async readFile(path: string) {
    const file = new File(this);
    this.registerFile(file);

    try {
      await file.open(path);
      return await file.read();
    } finally {
      await file.close();
    }
  }

  async createFileReadStream(path: string) {
    const file = new File(this);
    this.registerFile(file);

    await file.open(path);
    const stream = file.createReadStream();
    stream.once("close", async () => {
      await file.close();
    });
    return stream;
  }

  private registerFile(file: File) {
    file
      .once("open", () => this.openFiles.push(file))
      .once("close", () => this.openFiles.splice(this.openFiles.indexOf(file), 1));
  }

  private registerDirectory(directory: Directory) {
    directory
      .once("open", () => this.openDirectories.push(directory))
      .once("close", () => this.openDirectories.splice(this.openDirectories.indexOf(directory), 1));
  }

  createRequest(header: Header = {}, body: any = {}) {
    return this.session.createRequest(
      {
        treeId: this._id,
        ...header
      },
      body
    );
  }

  request(header: Header = {}, body: any = {}, options?: SendOptions) {
    return this.session.request(
      {
        treeId: this._id,
        ...header
      },
      body,
      options
    );
  }
}

export default Tree;