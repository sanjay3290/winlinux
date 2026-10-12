import type { AuthProvider, Credentials } from '../auth-provider.js';
import { WinRMSessionImpl } from './session.js';

export type { AuthProvider, Credentials, AuthTarget, Mechanism, SecurityContext, StepResult } from '../auth-provider.js';
export { MAX_ENVELOPE_SIZE, SEND_CHUNK_BYTES } from './envelopes.js';
export { WinRMError, WinRMAuthError, WinRMTransportError, WinRMFaultError, WinRMProtocolError, WinRMAbortError, PSRemotingError } from './errors.js';
// PSRP message and fragment codec (MS-PSRP 2.2.1 and 2.2.4).
export {
  Defragmenter,
  Destination,
  EMPTY_GUID,
  MAX_FRAGMENT_BLOB_BYTES,
  MAX_MESSAGE_BYTES,
  MAX_PARTIAL_MESSAGES,
  MessageType,
  decodeFragments,
  decodeMessage,
  encodeFragments,
  encodeMessage,
  messageTypeName,
} from './psrp/index.js';
export type { Fragment, PsrpMessage } from './psrp/index.js';
// CLIXML serializer and deserializer subset (MS-PSRP 2.2.5).
export {
  deserializeClixml,
  isPSObject,
  psDateTime,
  psEnum,
  psGuid,
  psObject,
  psScriptBlock,
  psUri,
  psVersion,
  psXml,
  serializeClixml,
  toErrorRecord,
  toInformationRecord,
  toInformationalMessage,
  toJson,
  toProgressRecord,
} from './psrp/index.js';
export type { PSDateTime, PSDictionary, PSDuration, PSErrorRecord, PSInformationRecord, PSObject, PSObjectKind, PSProgressRecord, PSSecureString, PSValue } from './psrp/index.js';
// PSRP runspace pool and pipeline (MS-PSRP 3.1.4).
export { MIN_SERVER_PROTOCOL_VERSION, openRunspacePool } from './psrp/index.js';
export type { InvokeOptions, PSCommand, PSConnectOptions, PSInvocationResult, PSInvocationState, PSPipeline, PSStreamEvent, PsrpTraceEvent, RunspacePool, RunspacePoolState } from './psrp/index.js';
export { CREDSSP_HTTP_REASON, CREDSSP_INSECURE_REASON, KERBEROS_INSECURE_REASON } from './transport.js';
export { psQuote } from './powershell.js';

export interface WinRMConnectOptions {
  host: string;
  port?: number;
  path?: string;
  tls?: boolean;
  tlsVerify?: boolean;
  // Required unless clientCertificate is set.
  authProvider?: AuthProvider;
  credentials?: Credentials;
  // Certificate sign-in over HTTPS: PEM cert and key. The auth
  // contract is unchanged: no AuthProvider takes part.
  clientCertificate?: { cert: Buffer; key: Buffer; passphrase?: string };
  encryption?: 'auto' | 'always' | 'never';
  operationTimeoutMs?: number;
  // TCP connect plus the TLS handshake; default 10_000.
  connectTimeoutMs?: number;
  // CredSSP over plain HTTP is refused unless this is true. The
  // outer HTTP channel has no certificate check; CredSSP delegates the
  // password. HTTPS with a verified certificate needs no flag.
  credsspAllowHttp?: boolean;
  // Called with the host on every CredSSP sign-in, before the encrypted
  // password goes out. The library never prints; the caller tells the user.
  onCredSSPDelegation?: (host: string) => void;
}

export interface CommandResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}

export interface OutputChunk {
  stream: 'stdout' | 'stderr';
  data: string;
}

// The output of a command that reads stdin. The last chunk is
// `exit`; inputComplete is false when a Send failed before all of the
// input went out (the command had exited, for example).
export type InputCommandChunk = OutputChunk | { stream: 'exit'; exitCode: number; inputComplete: boolean };

export interface InputCommandOptions {
  cwd?: string;
  signal?: AbortSignal;
  // After an abort, how long the command may take to exit by itself once
  // its stdin is closed, before Signal terminate. Default 2000 ms.
  abortGraceMs?: number;
}

export interface EventLogQuery {
  logName: string;
  maxEvents?: number;
  level?: 1 | 2 | 3 | 4 | 5;
  provider?: string;
  oldest?: boolean;
  startTime?: Date;
}

export interface EventRecord {
  timeCreated: string;
  id: number;
  level: string;
  provider: string;
  message: string;
}

export interface ServiceInfo {
  name: string;
  displayName: string;
  status: string;
  startType: string;
}

export interface ProcessInfo {
  id: number;
  name: string;
  cpuSeconds: number | null;
  workingSetBytes: number;
  startTime: string | null;
}

export interface WinRMSession {
  /**
   * Runs one program with argv semantics: `cmd` is the program and each
   * element of `args` reaches it as exactly one argument, however it is
   * spelled. The line still passes through cmd.exe on the server, so the
   * client quotes every word for cmd.exe and for the program's own
   * CommandLineToArgvW split. A caller that wants cmd.exe to
   * interpret pipes, redirection or `%VAR%` runs `cmd` with
   * `['/c', '<line>']`; the line is then one argument, which the inner
   * cmd.exe parses as usual.
   */
  runCommand(cmd: string, args?: string[], opts?: { cwd?: string; signal?: AbortSignal }): Promise<CommandResult>;
  /**
   * Runs a PowerShell script as `powershell.exe -NoProfile -NonInteractive
   * -EncodedCommand <base64 UTF-16LE>`, so the script's own syntax never
   * meets cmd.exe. stderr comes back with its CLIXML stripped.
   */
  runPowerShell(script: string): Promise<CommandResult>;
  /** Streaming form of runCommand; the same argv contract applies. */
  runCommandStream(cmd: string, args?: string[], opts?: { cwd?: string; signal?: AbortSignal }): AsyncIterable<OutputChunk>;
  /** Streaming form of runPowerShell; the same -EncodedCommand encoding applies. */
  runPowerShellStream(script: string): AsyncIterable<OutputChunk>;
  /**
   * Runs one program (argv contract of runCommand) with `input` as its
   * stdin. Each input chunk goes out in rsp:Send requests of at most
   * SEND_CHUNK_BYTES, base64 encoded; the last Send has End="true". The
   * next chunk is read only after the server acknowledged the last Send.
   * Output follows once stdin is closed; the last chunk is `exit`. On an
   * abort the session closes stdin, waits up to `abortGraceMs` for the
   * command to exit, then sends Signal terminate and throws
   * WinRMAbortError. An error thrown by `input` takes the same path and is
   * rethrown.
   */
  runCommandWithInput(cmd: string, args: string[], input: AsyncIterable<Buffer>, opts?: InputCommandOptions): AsyncIterable<InputCommandChunk>;
  /** runCommandWithInput for a PowerShell script (-EncodedCommand); stderr comes once, CLIXML stripped. */
  runPowerShellWithInput(script: string, input: AsyncIterable<Buffer>, opts?: InputCommandOptions): AsyncIterable<InputCommandChunk>;
  readEventLog(q: EventLogQuery): Promise<EventRecord[]>;
  listServices(): Promise<ServiceInfo[]>;
  listProcesses(): Promise<ProcessInfo[]>;
  close(): Promise<void>;
}

export async function connect(opts: WinRMConnectOptions): Promise<WinRMSession> {
  return new WinRMSessionImpl(opts);
}
