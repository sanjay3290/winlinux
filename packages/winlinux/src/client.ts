// The facade. connect() validates and opens nothing; each
// protocol slot opens on its first call. Dependencies are injected so unit
// tests can count opens; src/index.ts binds the real modules.
import { constants as fsConstants, rmSync } from 'node:fs';
import { access, mkdir, open, readFile, rename, rm, stat } from 'node:fs/promises';
import { X509Certificate, createHash, createPrivateKey, randomBytes } from 'node:crypto';
import path from 'node:path';
import { checkKeytabFile, type AuthProvider, type AuthTarget, type Credentials, type Mechanism } from '@winlinux/auth';
import { KERBEROS_INSECURE_REASON, type WinRMConnectOptions, type WinRMSession, type OutputChunk, type EventLogQuery, type InputCommandChunk } from '@winlinux/winrm';
import {
  SmbAccessDeniedError,
  SmbAlreadyExistsError,
  SmbIsADirectoryError,
  SmbNotADirectoryError,
  SmbNotFoundError,
  SmbSharingViolationError,
  type SMBConnectOptions,
  type SMBSession,
} from '@winlinux/smb2';
import {
  WinLinuxTransferError,
  WinLinuxUsageError,
  isTcpUnreachable,
  mapSmbOpError,
  mapSmbOpenError,
  mapWinrmOpError,
  mapWinrmOpenError,
  type ErrorContext,
} from './errors.js';
import { planAuth, winrmEncrypted } from './plan-auth.js';
import { redact } from './redact.js';
import { SESSION_CLOSE_TIMEOUT_MS, Slot } from './slot.js';
import type { ConnectOptions, Protocol, TransferOptions, TransferVia, WinLinuxClient } from './types.js';
import { checkPath, checkShare, checkVia, validateConnect, validatePassword } from './validate.js';
import {
  Base64LineDecoder,
  TextCap,
  buildGetScript,
  buildPutScript,
  checkTransferShare,
  remoteSegments,
  scriptFailure,
  scriptMessage,
  sha256File,
  uploadLines,
} from './winrm-transfer.js';
import {
  WinLinuxAbortError,
  checkLocalName,
  checkParallel,
  checkRemoteName,
  joinRemote,
  runPool,
  safeJoin,
  trimRemote,
  walkLocal,
  walkRemote,
  type TreeFileEvent,
  type TreeTransferOptions,
  type TreeTransferSummary,
} from './tree.js';

// Creates one directory; an existing directory is fine, a file in the way
// keeps the module's collision error.
async function ensureDirectory(session: SMBSession, share: string, dirPath: string): Promise<void> {
  try {
    await session.mkdir(share, dirPath);
  } catch (err) {
    if (!(err instanceof SmbAlreadyExistsError)) throw err;
    if (!(await session.stat(share, dirPath)).isDirectory) throw err;
  }
}

// get -r: where the tree lands. Like scp -r: an existing directory receives
// <localDir>/<base>; a missing localDir becomes the copy (its parent must
// exist); a file is a usage error. Local stat only, before any SMB open.
async function resolveTreeDestination(localDir: string, base: string): Promise<string> {
  let info;
  try {
    info = await stat(localDir);
  } catch (err) {
    if (codeOf(err) !== 'ENOENT') throw err;
    const parent = path.dirname(path.resolve(localDir));
    const parentInfo = await stat(parent).catch(() => undefined);
    if (!parentInfo?.isDirectory()) throw new WinLinuxUsageError(`get -r: no such directory: ${path.dirname(localDir)}`);
    return localDir;
  }
  if (!info.isDirectory()) throw new WinLinuxUsageError(`get -r: not a directory: ${localDir}`);
  return path.join(localDir, base);
}

// mkdir -p: create each prefix in turn. A prefix that already exists
// is fine when it is a directory; a file in the way keeps the collision
// error from the module (exit 5), never a silent success.
async function mkdirParents(session: SMBSession, share: string, dirPath: string): Promise<void> {
  const parts = dirPath.split(/[\\/]/).filter(Boolean);
  for (let depth = 1; depth <= parts.length; depth++) {
    await ensureDirectory(session, share, parts.slice(0, depth).join('/'));
  }
}

export interface ClientDeps {
  winrmConnect: (opts: WinRMConnectOptions) => Promise<WinRMSession>;
  smbConnect: (opts: SMBConnectOptions) => Promise<SMBSession>;
  createAuthProvider: (mechanism: Mechanism) => AuthProvider;
  // True when Kerberos contexts expose a session key (@winlinux/krb-session-key).
  // Absent: false.
  kerberosSessionKey?: () => Promise<boolean>;
  // Diagnostics for the CLI --verbose flag. Never receives secrets.
  log?: (line: string) => void;
  closeTimeoutMs?: number; // per session; default 5000
}

// The SMB TCP connect bound: a filtered port 445 costs at most this
// long before `auto` falls back to WinRM.
export const SMB_CONNECT_TIMEOUT_MS = 5000;

function codeOf(err: unknown): string | undefined {
  const code = (err as { code?: unknown })?.code;
  return typeof code === 'string' ? code : undefined;
}

// The temp file is an implementation detail: an error from smb2's download or
// from the local fs that names it is reworded to name the user's destination.
// Class, status, code and cause stay as they are.
function nameDestination(err: unknown, temp: string, localPath: string): unknown {
  if (!(err instanceof Error)) return err;
  if (err.message.includes(temp)) err.message = err.message.split(temp).join(localPath);
  if ((err as { path?: unknown }).path === temp) (err as { path?: string }).path = localPath;
  return err;
}

// get: where the file lands. Like scp
// and cp, an existing directory, or a localPath that ends in a separator,
// receives <dir>/<remote base name>; a missing directory is a usage error.
// Decided by local stat() alone, before any SMB open, so a refused
// destination wastes no transfer. Idempotent: the result is a
// file path, so resolving it again returns it unchanged.
export async function resolveGetDestination(remotePath: string, localPath: string): Promise<string> {
  const wantsDir = localPath.endsWith('/') || localPath.endsWith(path.sep);
  let info;
  try {
    info = await stat(localPath);
  } catch (err) {
    const code = codeOf(err);
    // stat('file/') is ENOTDIR on Linux and macOS.
    if (wantsDir && code === 'ENOTDIR') throw new WinLinuxUsageError(`not a directory: ${localPath}`);
    if (code !== 'ENOENT') throw err;
    if (wantsDir) throw new WinLinuxUsageError(`no such directory: ${localPath}`);
    return localPath; // a new file
  }
  if (!info.isDirectory()) {
    if (wantsDir) throw new WinLinuxUsageError(`not a directory: ${localPath}`);
    return localPath; // overwrites, like scp
  }
  const base = remotePath.split(/[\\/]/).filter(Boolean).pop();
  if (!base) throw new WinLinuxUsageError(`cannot take a file name from ${remotePath}`);
  const target = path.join(localPath, base);
  const existing = await stat(target).catch((err: unknown) => {
    if (codeOf(err) !== 'ENOENT') throw err;
    return undefined;
  });
  if (existing?.isDirectory()) throw new WinLinuxUsageError(`cannot overwrite directory ${target} with ${remotePath}`);
  return target;
}

// kerberosHostname: the modules build the AuthTarget from `host`
// (HTTP for WinRM, cifs for SMB). This wrapper fills the contract's `spn`
// field with the caller's name instead, so the connection still goes to
// `host` while the ticket is for <service>/<kerberosHostname>. NTLM uses
// it as MsvAvTargetName; Basic ignores it.
//
// It sets `spn` on the module's own target, not on a copy: the WinRM
// transport sets channelBindings on that object once TLS is up, after the
// context exists, and the provider reads the binding from it.
function withSpnHost(provider: AuthProvider, hostname: string): AuthProvider {
  return {
    mechanism: provider.mechanism,
    createContext: (target: AuthTarget, credentials: Credentials) => {
      target.spn = `${target.service}/${hostname}`;
      return provider.createContext(target, credentials);
    },
  };
}

// The get script reads no stdin: one Send with End and no data.
async function* noInput(): AsyncGenerator<Buffer> {}

// Certificate sign-in: reads the PEM files at each open. The key
// file is equal to the account password, so a key that group or others can
// read or write is refused (usage error), not warned about. Paths may appear
// in --verbose; file contents never do.
async function readClientCertificate(
  options: ConnectOptions,
  log: (line: string) => void,
): Promise<{ cert: Buffer; key: Buffer; passphrase?: string }> {
  const certFile = options.clientCert as string;
  const keyFile = options.clientKey as string;
  const read = async (what: string, file: string): Promise<Buffer> => {
    try {
      return await readFile(file);
    } catch (err) {
      const code = codeOf(err);
      throw new WinLinuxUsageError(`${what} ${file}: ${code === 'ENOENT' ? 'no such file' : (err as Error).message}`, { cause: err });
    }
  };
  let info;
  try {
    info = await stat(keyFile);
  } catch (err) {
    throw new WinLinuxUsageError(`client key ${keyFile}: ${codeOf(err) === 'ENOENT' ? 'no such file' : (err as Error).message}`, { cause: err });
  }
  if (!info.isFile()) throw new WinLinuxUsageError(`client key ${keyFile}: not a regular file`);
  // eslint-disable-next-line no-bitwise
  if ((info.mode & 0o077) !== 0) {
    throw new WinLinuxUsageError(`client key ${keyFile} is accessible by group or others; run chmod 600 ${keyFile}`);
  }
  const cert = await read('client certificate', certFile);
  const key = await read('client key', keyFile);
  // Check both locally, so a wrong passphrase or a bad file is a usage
  // error that names the file, not a failed TLS connection.
  try {
    createPrivateKey(options.clientKeyPassphrase === undefined ? { key } : { key, passphrase: options.clientKeyPassphrase });
  } catch (err) {
    throw new WinLinuxUsageError(`client key ${keyFile}: cannot read it (wrong passphrase, or not a PEM private key)`, { cause: err });
  }
  try {
    new X509Certificate(cert);
  } catch (err) {
    throw new WinLinuxUsageError(`client certificate ${certFile}: not a PEM certificate`, { cause: err });
  }
  log(`certificate ${certFile}, key ${keyFile}`);
  return options.clientKeyPassphrase === undefined ? { cert, key } : { cert, key, passphrase: options.clientKeyPassphrase };
}

// A failed WinRM copy script: the same error class and message as
// the SMB path for the common cases, naming <share>/<path> as the user
// typed it. The script's raw .NET text stays in the cause (printed with -v).
function transferFailure(
  direction: 'get' | 'put',
  context: string,
  where: string,
  stderr: string,
  exitCode: number,
  scrub: (text: string) => string,
): Error {
  const failure = scriptFailure(stderr, exitCode);
  const raw = new WinLinuxTransferError(`${direction} ${where} over WinRM failed: ${scrub(failure.raw ?? failure.message)}`, direction, 'remote');
  let err: Error;
  switch (failure.kind) {
    case 'notfound':
      err = new SmbNotFoundError(`no such file or directory: ${context}`);
      break;
    case 'noshare':
      err = new SmbNotFoundError(`share not found: ${context}`);
      break;
    case 'denied':
      err = new SmbAccessDeniedError(`access denied: ${context}`);
      break;
    case 'inuse':
      err = new SmbSharingViolationError(`sharing violation (file in use): ${context}`);
      break;
    case 'isdir':
      err = new SmbIsADirectoryError(`is a directory: ${context}`);
      break;
    default:
      return new WinLinuxTransferError(`${direction} ${where} over WinRM failed: ${scrub(failure.message)}`, direction, 'remote', { cause: raw });
  }
  (err as Error & { cause?: unknown }).cause = raw;
  return err;
}

export function createClient(host: string, options: ConnectOptions, deps: ClientDeps): WinLinuxClient {
  const validated = validateConnect(host, options);
  const auth = validated.auth;
  let credentials = validated.credentials;
  const spnHost = validated.kerberosHostname;
  const authProvider = (mechanism: Mechanism): AuthProvider => {
    const provider = deps.createAuthProvider(mechanism);
    return spnHost === undefined ? provider : withSpnHost(provider, spnHost);
  };
  const winrmOpts = options.winrm ?? {};
  const smbOpts = options.smb ?? {};
  const encrypted = winrmEncrypted(winrmOpts);
  const winrmPort = winrmOpts.port ?? (winrmOpts.tls ? 5986 : 5985);
  const smbPort = smbOpts.port ?? 445;
  const log = deps.log ?? (() => undefined);
  // Redact every password this client has held, not only the current one.
  const passwords: string[] = credentials.password ? [credentials.password] : [];
  // The key passphrase is redacted like a password.
  if (options.clientKeyPassphrase) passwords.push(options.clientKeyPassphrase);
  const scrub = (text: string) =>
    passwords.reduce((out, password) => redact(out, { username: credentials.username, password }), text);

  // planAuth runs at each open, so setPassword() can change the plan.
  // keyed is refreshed at each open (the addon check is async): SMB needs it
  // for Kerberos signing, WinRM for Kerberos over plain HTTP.
  let keyed = false;
  const plan = () => planAuth(auth, credentials, encrypted, keyed);
  // Keytab: check the file before any socket opens, so a bad mode is
  // a usage error (exit 1), not an auth failure. Each open checks again:
  // the file can change while the client lives.
  const checkKeytab = async (): Promise<void> => {
    if (credentials.keytab === undefined) return;
    try {
      await checkKeytabFile(credentials.keytab);
    } catch (err) {
      throw new WinLinuxUsageError((err as Error).message, { cause: err });
    }
    // The path only; the key bytes never leave kinit.
    log(`kerberos keytab ${credentials.keytab}`);
  };
  const winrmCtx = (): ErrorContext => ({ protocol: 'winrm', host, port: winrmPort, mechanism: plan().winrm.mechanism, redact: scrub });
  const smbCtx = (): ErrorContext => ({ protocol: 'smb', host, port: smbPort, mechanism: plan().smb.mechanism, redact: scrub });
  const closeError = (protocol: string) => (err: unknown) =>
    log(`${protocol} close error: ${scrub(err instanceof Error ? err.message : String(err))}`);

  const winrm = new Slot<WinRMSession>({
    open: async () => {
      keyed = (await deps.kerberosSessionKey?.()) ?? false;
      const { winrm: p } = plan();
      if (p.refused) throw new WinLinuxUsageError(p.reason);
      // Kerberos sends no channel binding yet, so over HTTPS only a
      // verified certificate ties the ticket to the server. Negotiate
      // that picks Kerberos is refused by the transport, before its token.
      if (p.mechanism === 'kerberos' && winrmOpts.tls === true && winrmOpts.tlsVerify === false) {
        throw new WinLinuxUsageError(KERBEROS_INSECURE_REASON);
      }
      await checkKeytab();
      log(`winrm open ${host}:${winrmPort} (${winrmOpts.tls ? 'https' : 'http'}, mechanism ${p.mechanism})`);
      if (p.mechanism === 'certificate') {
        // No AuthProvider: the TLS client certificate is the credential.
        return deps.winrmConnect({
          host,
          port: winrmPort,
          path: winrmOpts.path,
          tls: true,
          tlsVerify: winrmOpts.tlsVerify ?? true,
          encryption: winrmOpts.encryption,
          operationTimeoutMs: winrmOpts.operationTimeoutMs,
          ...(winrmOpts.connectTimeoutMs !== undefined ? { connectTimeoutMs: winrmOpts.connectTimeoutMs } : {}),
          clientCertificate: await readClientCertificate(options, log),
        });
      }
      return deps.winrmConnect({
        host,
        port: winrmPort,
        path: winrmOpts.path,
        tls: winrmOpts.tls ?? false,
        tlsVerify: winrmOpts.tlsVerify ?? true,
        encryption: winrmOpts.encryption,
        operationTimeoutMs: winrmOpts.operationTimeoutMs,
          ...(winrmOpts.connectTimeoutMs !== undefined ? { connectTimeoutMs: winrmOpts.connectTimeoutMs } : {}),
        // CredSSP: the transport checks these again.
        ...(winrmOpts.credsspAllowHttp !== undefined ? { credsspAllowHttp: winrmOpts.credsspAllowHttp } : {}),
        ...(p.mechanism === 'credssp' && winrmOpts.onCredSSPDelegation ? { onCredSSPDelegation: winrmOpts.onCredSSPDelegation } : {}),
        authProvider: authProvider(p.mechanism as Mechanism),
        credentials: credentials as Credentials,
      });
    },
    // A planAuth refusal is already a usage error; keep it as is.
    mapOpenError: (err) => (err instanceof WinLinuxUsageError ? err : mapWinrmOpenError(err, winrmCtx())),
    mapOpError: (err) => mapWinrmOpError(err, winrmCtx()),
    onCloseError: closeError('winrm'),
    closeTimeoutMs: deps.closeTimeoutMs,
  });

  const smb = new Slot<SMBSession>({
    open: async () => {
      keyed = (await deps.kerberosSessionKey?.()) ?? false;
      const { smb: p } = plan();
      if (p.refused) throw new WinLinuxUsageError(p.reason);
      await checkKeytab();
      log(`smb open ${host}:${smbPort} (mechanism ${p.mechanism})`);
      const session = await deps.smbConnect({
        host,
        port: smbPort,
        signing: smbOpts.signing,
        requestTimeoutMs: smbOpts.requestTimeoutMs,
        connectTimeoutMs: SMB_CONNECT_TIMEOUT_MS,
        ...(smbOpts.maxDialect ? { maxDialect: smbOpts.maxDialect } : {}),
        authProvider: authProvider(p.mechanism as Mechanism),
        credentials: credentials as Credentials,
      });
      // What the connection negotiated, for --verbose, and whether
      // signing is in effect, not only the algorithm the dialect would use.
      const sec = session.security;
      if (sec) {
        log(`smb dialect ${sec.dialect}, signing ${sec.signing ? sec.signingAlgorithm : 'off'}, encryption ${sec.cipher}${sec.encryptData ? ' (whole session)' : ''}`);
      }
      return session;
    },
    // A planAuth refusal is already a usage error; keep it as is.
    mapOpenError: (err) => (err instanceof WinLinuxUsageError ? err : mapSmbOpenError(err, smbCtx())),
    mapOpError: (err) => mapSmbOpError(err, smbCtx()),
    onCloseError: closeError('smb'),
    closeTimeoutMs: deps.closeTimeoutMs,
  });

  let closing: Promise<void> | undefined;
  // Temp files of downloads in flight; close() removes any that are left.
  const partials = new Set<string>();

  // How get and put travel. `route` caches the auto decision for
  // the client's life; `routing` makes concurrent first calls share one
  // SMB probe. A probe that fails without a fallback is not cached.
  const defaultVia: TransferVia = options.transfer?.via ?? 'smb';
  let route: 'smb' | 'winrm' | undefined;
  let routing: Promise<'smb' | 'winrm'> | undefined;
  const pickRoute = (via: TransferVia | undefined): Promise<'smb' | 'winrm'> => {
    checkVia('via', via);
    const wanted = via ?? defaultVia;
    // Certificate sign-in has no SMB path: auto copies over WinRM
    // at once, with no SMB probe and no notice.
    if (wanted === 'auto' && auth === 'certificate') return Promise.resolve('winrm');
    if (wanted !== 'auto') return Promise.resolve(wanted);
    if (route) return Promise.resolve(route);
    const probe = async (): Promise<'smb' | 'winrm'> => {
      try {
        await smb.use(async () => undefined);
        route = 'smb';
      } catch (err) {
        if (!isTcpUnreachable(err)) throw err;
        route = 'winrm';
        log(`smb ${host}:${smbPort} unreachable; transfers use WinRM`);
        options.transfer?.onFallback?.({ host, smbPort, cause: err as Error });
      } finally {
        routing = undefined;
      }
      return route;
    };
    routing ??= probe();
    return routing;
  };

  // WinRM copies in flight. close() aborts them and waits (bounded) for
  // their cleanup: stdin closed, Signal and Delete sent.
  const copies = new Set<{ abort: AbortController; done: Promise<unknown> }>();
  const trackCopy = async <T>(signal: AbortSignal | undefined, run: (signal: AbortSignal) => Promise<T>): Promise<T> => {
    const abort = new AbortController();
    const onAbort = () => abort.abort(signal?.reason);
    if (signal?.aborted) abort.abort(signal.reason);
    signal?.addEventListener('abort', onAbort, { once: true });
    const done = run(abort.signal);
    const entry = { abort, done: done.catch(() => undefined) };
    copies.add(entry);
    try {
      return await done;
    } finally {
      copies.delete(entry);
      signal?.removeEventListener('abort', onAbort);
    }
  };

  // Runs one transfer script and hands each chunk to `onChunk`. Errors of
  // the WinRM call go through the slot's mapping; errors of `onChunk`
  // (local file writes) do not.
  const runTransferScript = async (
    script: string,
    input: AsyncIterable<Buffer>,
    signal: AbortSignal,
    onChunk: (chunk: InputCommandChunk) => Promise<void> | void,
  ): Promise<void> => {
    for await (const chunk of winrm.stream((s) => s.runPowerShellWithInput(script, input, { signal }))) {
      await onChunk(chunk);
    }
  };

  // get over WinRM into `temp`: decode, hash and write each line as it
  // arrives; compare with the server's hash at the end.
  const winrmDownload = async (share: string, remotePath: string, temp: string, signal: AbortSignal): Promise<void> => {
    checkTransferShare(share);
    const script = buildGetScript(share, remoteSegments(remotePath));
    const decoder = new Base64LineDecoder();
    const hash = createHash('sha256');
    const stderr = new TextCap();
    let exit: { exitCode: number } | undefined;
    const file = await open(temp, 'wx', 0o600);
    try {
      await runTransferScript(script, noInput(), signal, async (chunk) => {
        if (chunk.stream === 'stdout') {
          for (const bytes of decoder.push(chunk.data)) {
            hash.update(bytes);
            await file.write(bytes);
          }
        } else if (chunk.stream === 'stderr') {
          stderr.add(chunk.data);
        } else if (chunk.stream === 'exit') {
          exit = chunk;
        }
      });
    } finally {
      await file.close();
    }
    const where = `${share}/${remotePath}`;
    if (!exit) throw new WinLinuxTransferError(`get ${where} over WinRM: the command ended without an exit code`, 'get', 'protocol');
    if (exit.exitCode !== 0) {
      throw transferFailure('get', `download ${where} to ${temp}`, where, stderr.text, exit.exitCode, scrub);
    }
    const remote = decoder.end();
    const local = hash.digest('hex');
    if (remote !== local) {
      throw new WinLinuxTransferError(`get ${where} over WinRM: sha256 mismatch: the server read ${remote}, the client wrote ${local}`, 'get', 'mismatch');
    }
    log(`winrm get ${where} sha256 ${local}`);
  };

  // put over WinRM: hash the local file, then stream it as base64 lines
  // to the put script, which checks the hash before it replaces the file.
  const winrmUpload = async (localPath: string, share: string, remotePath: string, signal: AbortSignal): Promise<void> => {
    checkTransferShare(share);
    const segments = remoteSegments(remotePath);
    const { sha256 } = await sha256File(localPath);
    const script = buildPutScript(share, segments, sha256, `.winlinux-${randomBytes(6).toString('hex')}.part`);
    const stdout = new TextCap();
    const stderr = new TextCap();
    let exit: { exitCode: number; inputComplete: boolean } | undefined;
    await runTransferScript(script, uploadLines(localPath), signal, (chunk) => {
      if (chunk.stream === 'stdout') stdout.add(chunk.data);
      else if (chunk.stream === 'stderr') stderr.add(chunk.data);
      else if (chunk.stream === 'exit') exit = chunk;
    });
    const where = `${share}/${remotePath}`;
    if (!exit) throw new WinLinuxTransferError(`put ${where} over WinRM: the command ended without an exit code`, 'put', 'protocol');
    if (exit.exitCode === 3) {
      throw new WinLinuxTransferError(`put ${where} over WinRM: ${scrub(scriptMessage(stderr.text, 3))}`, 'put', 'mismatch');
    }
    if (exit.exitCode !== 0) {
      throw transferFailure('put', `upload ${localPath} to ${where}`, where, stderr.text, exit.exitCode, scrub);
    }
    if (!exit.inputComplete || !stdout.text.split(/\r?\n/).includes(`sha256:${sha256}`)) {
      throw new WinLinuxTransferError(`put ${where} over WinRM: the server did not confirm sha256 ${sha256}`, 'put', 'protocol');
    }
    log(`winrm put ${where} sha256 ${sha256}`);
  };

  // put: check the local file before any SMB open. smb2 upload opens the
  // remote file with OverwriteIf before it reads the local file, so a missing
  // local file would otherwise truncate the remote one.
  // A refusal is a WinLinuxUsageError that names the local path.
  const checkLocalSource = async (localPath: string): Promise<void> => {
    const refuse = (why: string, cause?: unknown) =>
      new WinLinuxUsageError(`put: local file ${localPath}: ${why}`, cause === undefined ? undefined : { cause });
    let info;
    try {
      info = await stat(localPath);
    } catch (err) {
      throw refuse(codeOf(err) === 'ENOENT' ? 'no such file' : err instanceof Error ? err.message : String(err), err);
    }
    if (info.isDirectory()) throw refuse('is a directory');
    if (!info.isFile()) throw refuse('not a regular file');
    try {
      await access(localPath, fsConstants.R_OK);
    } catch (err) {
      throw refuse('not readable', err);
    }
  };

  // get: download into `.<name>.winlinux-<rand>.part` next to the destination,
  // then rename over it. A failed or interrupted transfer leaves the old file.
  // Errors name localPath, never the temp file.
  const download = async (share: string, remotePath: string, localPath: string, opts?: TransferOptions): Promise<void> => {
    const via = await pickRoute(opts?.via);
    const dir = path.dirname(localPath);
    const temp = path.join(dir, `.${path.basename(localPath)}.winlinux-${randomBytes(6).toString('hex')}.part`);
    const named = (err: unknown) => {
      throw nameDestination(err, temp, localPath);
    };
    partials.add(temp);
    try {
      if (via === 'winrm') {
        await trackCopy(opts?.signal, (signal) => winrmDownload(share, remotePath, temp, signal)).catch(named);
      } else {
        // Renamed inside use(), so a wrapped WinLinuxConnectionError names it too.
        await smb.use((s) => s.download(share, remotePath, temp).catch(named));
      }
      await rename(temp, localPath).catch(named);
    } finally {
      partials.delete(temp);
      await rm(temp, { force: true });
    }
  };

  // The file phase of getDir/putDir: the pool, the events, the counters and
  // the abort rule (no new file after an abort; files in flight finish).
  const copyFiles = async (
    files: Array<{ rel: string; size: number }>,
    parallel: number,
    opts: TreeTransferOptions,
    base: Omit<TreeTransferSummary, 'files' | 'bytes'>,
    copyOne: (rel: string, size: number) => Promise<number>,
  ): Promise<TreeTransferSummary> => {
    let done = 0;
    let bytes = 0;
    let started = 0;
    await runPool(files, parallel, opts.signal, async (file) => {
      const event: TreeFileEvent = { path: file.rel, index: ++started, total: files.length, sizeBytes: file.size };
      opts.onFile?.(event);
      // Await first: `bytes += await x` would read `bytes` before the await
      // and lose the counts of files that finish in parallel.
      const copied = await copyOne(file.rel, file.size);
      bytes += copied;
      done++;
      opts.onFileDone?.(event);
    });
    if (opts.signal?.aborted && done < files.length) throw new WinLinuxAbortError(done, files.length);
    return { ...base, files: done, bytes };
  };

  return {
    host,
    username: credentials.username,
    run: (cmd, args, opts) => winrm.use((s) => s.runCommand(cmd, args, opts)),
    runPowerShell: (script) => winrm.use((s) => s.runPowerShell(script)),
    runStream: (cmd, args, opts): AsyncIterable<OutputChunk> => winrm.stream((s) => s.runCommandStream(cmd, args, opts)),
    runPowerShellStream: (script): AsyncIterable<OutputChunk> => winrm.stream((s) => s.runPowerShellStream(script)),
    readEventLog: (query: EventLogQuery) => winrm.use((s) => s.readEventLog(query)),
    listServices: () => winrm.use((s) => s.listServices()),
    listProcesses: () => winrm.use((s) => s.listProcesses()),
    listShares: () => smb.use((s) => s.listShares()),
    ls: async (share, dirPath) => {
      checkShare(share);
      return smb.use((s) => s.list(share, dirPath));
    },
    get: async (share, remotePath, localPath, opts?: TransferOptions) => {
      checkShare(share);
      return download(share, remotePath, await resolveGetDestination(remotePath, localPath), opts);
    },
    put: async (localPath, share, remotePath, opts?: TransferOptions) => {
      checkShare(share);
      await checkLocalSource(localPath);
      if ((await pickRoute(opts?.via)) === 'winrm') {
        return trackCopy(opts?.signal, (signal) => winrmUpload(localPath, share, remotePath, signal));
      }
      return smb.use((s) => s.upload(localPath, share, remotePath));
    },
    stat: async (share, remotePath) => {
      checkShare(share);
      checkPath('path', remotePath);
      return smb.use((s) => s.stat(share, remotePath));
    },
    mkdir: async (share, dirPath, opts) => {
      checkShare(share);
      checkPath('path', dirPath);
      return smb.use((s) => (opts?.parents ? mkdirParents(s, share, dirPath) : s.mkdir(share, dirPath)));
    },
    rm: async (share, remotePath) => {
      checkShare(share);
      checkPath('path', remotePath);
      return smb.use((s) => s.deleteFile(share, remotePath));
    },
    rmdir: async (share, dirPath) => {
      checkShare(share);
      checkPath('path', dirPath);
      return smb.use((s) => s.deleteDirectory(share, dirPath));
    },
    mv: async (share, fromPath, toPath) => {
      checkShare(share);
      checkPath('source path', fromPath);
      checkPath('destination path', toPath);
      return smb.use((s) => s.rename(share, fromPath, toPath));
    },
    readFile: async (share, remotePath) => {
      checkShare(share);
      checkPath('path', remotePath);
      return smb.use((s) => s.readFile(share, remotePath));
    },
    writeFile: async (share, remotePath, data) => {
      checkShare(share);
      checkPath('path', remotePath);
      return smb.use((s) => s.writeFile(share, remotePath, data));
    },
    getDir: async (share, remoteDir, localDir, opts: TreeTransferOptions = {}): Promise<TreeTransferSummary> => {
      checkShare(share);
      const parallel = checkParallel(opts.parallel);
      const remoteRoot = trimRemote(remoteDir);
      const base = remoteRoot ? (remoteRoot.split('/').pop() as string) : share;
      checkRemoteName(base);
      const target = await resolveTreeDestination(localDir, base);
      if (remoteRoot) {
        const info = await smb.use((s) => s.stat(share, remoteRoot));
        if (!info.isDirectory) throw new SmbNotADirectoryError(`not a directory: ${share}/${remoteRoot}; use get without -r`);
      }
      const plan = await walkRemote((dir) => smb.use((s) => s.list(share, dir || undefined)), remoteRoot);
      for (const skip of plan.skipped) opts.onSkip?.(skip);
      for (const dir of plan.dirs) await mkdir(safeJoin(target, dir.split('/').filter(Boolean)), { recursive: true });
      return copyFiles(plan.files, parallel, opts, { share, remotePath: remoteRoot, localPath: target, directories: plan.dirs.length, skipped: plan.skipped.length }, async (rel) => {
        const local = safeJoin(target, rel.split('/'));
        await download(share, joinRemote(remoteRoot, rel), local);
        return (await stat(local)).size;
      });
    },
    putDir: async (localDir, share, remoteDir, opts: TreeTransferOptions = {}): Promise<TreeTransferSummary> => {
      checkShare(share);
      const parallel = checkParallel(opts.parallel);
      // The local side first, so a bad source wastes no SMB open.
      let info;
      try {
        info = await stat(localDir);
      } catch (err) {
        throw new WinLinuxUsageError(`put -r: local directory ${localDir}: ${codeOf(err) === 'ENOENT' ? 'no such directory' : (err as Error).message}`, { cause: err });
      }
      if (!info.isDirectory()) throw new WinLinuxUsageError(`put -r: local directory ${localDir}: not a directory`);
      const base = path.basename(path.resolve(localDir));
      checkLocalName(base);
      const plan = await walkLocal(localDir);
      const remoteRoot = trimRemote(remoteDir);
      let target = base;
      if (remoteRoot) {
        target = remoteRoot;
        try {
          const existing = await smb.use((s) => s.stat(share, remoteRoot));
          if (!existing.isDirectory) throw new SmbNotADirectoryError(`not a directory: ${share}/${remoteRoot}`);
          target = `${remoteRoot}/${base}`;
        } catch (err) {
          if (!(err instanceof SmbNotFoundError)) throw err;
        }
      }
      for (const skip of plan.skipped) opts.onSkip?.(skip);
      for (const dir of plan.dirs) await smb.use((s) => ensureDirectory(s, share, joinRemote(target, dir)));
      return copyFiles(plan.files, parallel, opts, { share, remotePath: target, localPath: localDir, directories: plan.dirs.length, skipped: plan.skipped.length }, async (rel, size) => {
        await smb.use((s) => s.upload(path.join(localDir, ...rel.split('/')), share, joinRemote(target, rel)));
        return size;
      });
    },
    setPassword: (password: string) => {
      validatePassword(password);
      if (credentials.keytab !== undefined) throw new WinLinuxUsageError('a keytab and a password cannot be used together');
      credentials = Object.freeze({ ...credentials, password });
      passwords.push(password);
      winrm.reset();
      smb.reset();
    },
    reset: (protocol?: Protocol) => {
      if (protocol === undefined || protocol === 'winrm') winrm.reset();
      if (protocol === undefined || protocol === 'smb') smb.reset();
    },
    close: () => {
      if (!closing) {
        for (const temp of partials) rmSync(temp, { force: true });
        const opened = [winrm.state, smb.state];
        // WinRM copies first: abort them, then let them close stdin, Signal
        // and Delete (bounded) before the sessions go away.
        const inFlight = [...copies];
        for (const copy of inFlight) copy.abort.abort(new Error('client closed'));
        let timer: NodeJS.Timeout | undefined;
        const bound = new Promise<void>((resolve) => {
          timer = setTimeout(resolve, deps.closeTimeoutMs ?? SESSION_CLOSE_TIMEOUT_MS);
        });
        const copiesDone = inFlight.length === 0 ? Promise.resolve() : Promise.race([Promise.allSettled(inFlight.map((c) => c.done)), bound]);
        closing = copiesDone
          .finally(() => clearTimeout(timer))
          .then(() => Promise.allSettled([winrm.close(), smb.close()]))
          .then(() => {
          if (opened[0] !== 'idle') log('winrm closed');
          if (opened[1] !== 'idle') log('smb closed');
        });
      }
      return closing;
    },
  };
}
