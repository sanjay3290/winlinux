// Public option and client types.
import type { Mechanism } from '@winlinux/auth';

// Facade sign-in methods: the auth contract's mechanisms, plus WinRM
// certificate sign-in, which is not a token handshake and stays
// outside the contract.
export type AuthMechanism = Mechanism | 'certificate';
import type { CommandResult, OutputChunk, EventLogQuery, EventRecord, ServiceInfo, ProcessInfo, InvokeOptions, PSInvocationResult, PSPipeline } from '@winlinux/winrm';
import type { ShareInfo, DirEntry, FileStat } from '@winlinux/smb2';
import type { TreeTransferOptions, TreeTransferSummary } from './tree.js';

export type Protocol = 'winrm' | 'smb';

export interface WinRMOptions {
  port?: number; // default 5985, or 5986 when tls
  tls?: boolean; // default false
  tlsVerify?: boolean; // default true
  path?: string; // default '/wsman'
  encryption?: 'auto' | 'always' | 'never'; // default 'auto'
  operationTimeoutMs?: number; // default 60_000
  connectTimeoutMs?: number; // TCP connect + TLS handshake, default 10_000
  // CredSSP only: allow it over plain HTTP. The outer HTTP channel
  // then has no certificate check, and CredSSP delegates the password.
  credsspAllowHttp?: boolean; // default false
  // CredSSP only: called with the host on every CredSSP sign-in, just
  // before the encrypted password goes to the server. The library never
  // prints; the CLI writes `winlinux: CredSSP: your password is delegated to <host>`.
  onCredSSPDelegation?: (host: string) => void;
}

export interface SMBOptions {
  port?: number; // default 445
  signing?: 'auto' | 'required'; // default 'auto'
  requestTimeoutMs?: number; // default 30_000
  maxDialect?: '2.1' | '3.1.1'; // default '3.1.1': SMB 3.x signing and encryption when the server offers them
}

// How get and put move a file. 'smb': SMB2/3 on port 445.
// 'winrm': PowerShell over WinRM (5985/5986), for networks that block 445.
// 'auto': SMB, unless its TCP connect is refused, unreachable or times
// out; then WinRM, for the rest of the client's life.
export type TransferVia = 'smb' | 'winrm' | 'auto';

export interface TransferFallbackEvent {
  host: string;
  smbPort: number;
  cause: Error; // the WinLinuxConnectionError of the SMB open
}

export interface TransferSettings {
  via?: TransferVia; // default 'smb'
  // 'auto' only: called once, when the client switches to WinRM.
  onFallback?: (event: TransferFallbackEvent) => void;
}

// Per call: overrides the client's `transfer.via` and can stop a WinRM copy.
export interface TransferOptions {
  via?: TransferVia;
  // Aborts the copy. Over WinRM the client closes the remote command's
  // stdin (the put script removes its temp file), sends Signal terminate,
  // removes the local .part file and rejects with WinRMAbortError. An SMB
  // get stops at the request in flight, removes the local .part file and
  // rejects with SmbAbortError; an SMB put does not read it yet.
  // Both abort errors have `name === 'AbortError'`.
  signal?: AbortSignal;
}

export interface ConnectOptions {
  username: string;
  password?: string;
  domain?: string;
  realm?: string;
  useTicketCache?: boolean;
  // Kerberos keytab sign-in: the path to a keytab file. No password
  // and no ticket cache with it; needs a realm (or a domain). The file must
  // not be readable or writable by group or others.
  keytab?: string;
  // 'credssp' is explicit opt-in: it delegates the password to the
  // server for the double hop. WinRM only; needs a password, a verified
  // HTTPS certificate (or winrm.credsspAllowHttp), and never runs under
  // 'negotiate'.
  auth?: AuthMechanism;
  // Certificate sign-in (auth 'certificate'): PEM file paths, WinRM
  // over HTTPS only. The key file must not be readable or writable by group
  // or others. clientKeyPassphrase decrypts an encrypted key; it is
  // redacted like a password.
  clientCert?: string;
  clientKey?: string;
  clientKeyPassphrase?: string;
  // Kerberos only: the DNS name to build the service principal from
  // (HTTP/<name>, cifs/<name>) while the connection goes to `host`. Needed
  // when `host` is an IP address, which has no principal in the KDC. Opt-in;
  // winlinux never resolves it by reverse DNS.
  kerberosHostname?: string;
  winrm?: WinRMOptions;
  smb?: SMBOptions;
  transfer?: TransferSettings; // how get and put travel
}

// A PSRP runspace pool on the server: one runspace whose
// state (variables, modules, the current directory) persists across
// invoke() calls, until close(). The client offers the server no host, so a
// script that prompts fails on the server instead of waiting.
export interface PowerShellSession {
  readonly host: string;
  readonly serverProtocolVersion: string;
  invoke(script: string, opts?: InvokeOptions): PSPipeline;
  close(): Promise<void>;
}

export interface PowerShellOptions {
  // The session configuration; default Microsoft.PowerShell. It names a
  // server-side endpoint and adds no sign-in risk.
  configurationName?: string;
  // Aborts the open.
  signal?: AbortSignal;
}

export interface InvokePowerShellOptions extends PowerShellOptions {
  // Appends `Out-String -Stream -Width n`: the server formats the output
  // and every output value is a string line.
  outString?: { width: number };
}

export interface WinLinuxClient {
  readonly host: string;
  readonly username: string;
  // Argv semantics: each element of `args` reaches the program as one
  // argument (quoted for cmd.exe and the program). For cmd.exe
  // syntax, run `cmd` with `['/c', '<line>']`.
  run(cmd: string, args?: string[], opts?: { cwd?: string; signal?: AbortSignal }): Promise<CommandResult>;
  // The script goes out as -EncodedCommand, so `|`, `&` and quotes are safe.
  runPowerShell(script: string): Promise<CommandResult>;
  runStream(cmd: string, args?: string[], opts?: { cwd?: string; signal?: AbortSignal }): AsyncIterable<OutputChunk>;
  runPowerShellStream(script: string): AsyncIterable<OutputChunk>;
  // PSRP: a persistent session, or one pipeline in a pool that is
  // opened and closed for it. Each uses the WinRM sign-in of this client
  // on its own connection; the WinRS methods above are unchanged.
  openPowerShell(opts?: PowerShellOptions): Promise<PowerShellSession>;
  invokePowerShell(script: string, opts?: InvokePowerShellOptions): Promise<PSInvocationResult>;
  readEventLog(query: EventLogQuery): Promise<EventRecord[]>;
  // Service and process state: Get-Service and Get-Process over WinRM.
  listServices(): Promise<ServiceInfo[]>;
  listProcesses(): Promise<ProcessInfo[]>;
  listShares(): Promise<ShareInfo[]>;
  ls(share: string, dirPath?: string): Promise<DirEntry[]>;
  get(share: string, remotePath: string, localPath: string, opts?: TransferOptions): Promise<void>;
  put(localPath: string, share: string, remotePath: string, opts?: TransferOptions): Promise<void>;
  // File operations. Paths are share-relative with `/`.
  stat(share: string, remotePath: string): Promise<FileStat>;
  mkdir(share: string, dirPath: string, opts?: { parents?: boolean }): Promise<void>; // parents: like mkdir -p
  rm(share: string, remotePath: string): Promise<void>; // files only: a directory is SmbIsADirectoryError
  rmdir(share: string, dirPath: string): Promise<void>; // empty directories only: SmbDirectoryNotEmptyError otherwise
  mv(share: string, fromPath: string, toPath: string): Promise<void>; // within one share; an existing target is SmbAlreadyExistsError
  // Small files, buffered in memory (64 MiB cap in @winlinux/smb2); use get/put to stream.
  readFile(share: string, remotePath: string): Promise<Buffer>;
  writeFile(share: string, remotePath: string, data: Buffer | string): Promise<void>;
  // Recursive copies, like scp -r. An existing destination directory
  // receives <dest>/<source base name>; a missing one becomes the copy.
  getDir(share: string, remoteDir: string, localDir: string, opts?: TreeTransferOptions): Promise<TreeTransferSummary>;
  putDir(localDir: string, share: string, remoteDir: string, opts?: TreeTransferOptions): Promise<TreeTransferSummary>;
  // Credentials (account-lockout guard)
  setPassword(password: string): void; // new password for later opens; clears the auth-failure latch on both slots
  reset(protocol?: Protocol): void; // clears the auth-failure latch on one slot, or both
  close(): Promise<void>;
}
