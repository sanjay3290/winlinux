// Facade errors and the module-error mapping.
import type { AuthMechanism } from './types.js';
import { WinRMAuthError, WinRMError, WinRMProtocolError, WinRMTransportError } from '@winlinux/winrm';
import {
  SmbAccessDeniedError,
  SmbAuthError,
  SmbConnectionError,
  SmbError,
  SmbSigningError,
  SmbTimeoutError,
} from '@winlinux/smb2';

import type { Protocol } from './types.js';
export type { Protocol };

export class WinLinuxError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = new.target.name;
  }
}

export class WinLinuxUsageError extends WinLinuxError {}

export class WinLinuxAuthError extends WinLinuxError {
  readonly protocol: Protocol;
  readonly mechanism: AuthMechanism;

  constructor(message: string, protocol: Protocol, mechanism: AuthMechanism, options?: { cause?: unknown }) {
    super(message, options);
    this.protocol = protocol;
    this.mechanism = mechanism;
  }
}

export class WinLinuxConnectionError extends WinLinuxError {
  readonly protocol: Protocol;
  readonly host: string;
  readonly port: number;

  constructor(message: string, protocol: Protocol, host: string, port: number, options?: { cause?: unknown }) {
    super(message, options);
    this.protocol = protocol;
    this.host = host;
    this.port = port;
  }
}

// A file copy over WinRM failed: the SHA-256 of the two sides
// differ ('mismatch'), the remote script refused or failed ('remote', for
// example no such file or access denied), or the server's output broke
// the line protocol ('protocol'). Exit code 5, like other file errors.
export type TransferFailure = 'mismatch' | 'remote' | 'protocol';

export class WinLinuxTransferError extends WinLinuxError {
  readonly direction: 'get' | 'put';
  readonly reason: TransferFailure;

  constructor(message: string, direction: 'get' | 'put', reason: TransferFailure, options?: { cause?: unknown }) {
    super(message, options);
    this.direction = direction;
    this.reason = reason;
  }
}

// TCP-level failures of a connect: nothing answered on the port. Only
// these let `transfer.via: 'auto'` fall back from SMB to WinRM.
const UNREACHABLE_CODES = new Set(['ECONNREFUSED', 'ETIMEDOUT', 'EHOSTUNREACH', 'ENETUNREACH', 'EHOSTDOWN', 'ENETDOWN']);

// True for a WinLinuxConnectionError from the SMB open whose root cause is
// a refused, unreachable or timed-out TCP connect. Auth errors, file
// errors and protocol failures after the connect (a reset, a dialect
// error, a request timeout) are false.
export function isTcpUnreachable(err: unknown): boolean {
  if (!(err instanceof WinLinuxConnectionError) || err.protocol !== 'smb') return false;
  let cause: unknown = (err as { cause?: unknown }).cause;
  if (!(cause instanceof SmbConnectionError)) return false;
  cause = (cause as { cause?: unknown }).cause;
  if (cause instanceof Error && cause.message === 'connect_timeout') return true;
  return isSystemError(cause) && UNREACHABLE_CODES.has(cause.code);
}

// What a mapper needs to build a wrapped error.
export interface ErrorContext {
  protocol: Protocol;
  host: string;
  port: number;
  mechanism: AuthMechanism;
  redact: (text: string) => string;
}

// A system error is an Error with a string `code` (ECONNREFUSED, ENOENT, TLS codes).
export function isSystemError(err: unknown): err is Error & { code: string } {
  return err instanceof Error && typeof (err as { code?: unknown }).code === 'string';
}

function hasPath(err: unknown): boolean {
  return typeof (err as { path?: unknown })?.path === 'string';
}

function messageOf(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function wrapMessage(ctx: ErrorContext, what: string, cause: unknown): string {
  return ctx.redact(`${ctx.protocol} ${what} failed for ${ctx.host}:${ctx.port}: ${messageOf(cause)}`);
}

export function usage(ctx: ErrorContext, cause: unknown): WinLinuxUsageError {
  return new WinLinuxUsageError(wrapMessage(ctx, 'setup', cause), { cause });
}

export function auth(ctx: ErrorContext, cause: unknown): WinLinuxAuthError {
  return new WinLinuxAuthError(wrapMessage(ctx, 'authentication', cause), ctx.protocol, ctx.mechanism, { cause });
}

export function connection(ctx: ErrorContext, cause: unknown): WinLinuxConnectionError {
  return new WinLinuxConnectionError(wrapMessage(ctx, 'connection', cause), ctx.protocol, ctx.host, ctx.port, { cause });
}

// WinRM open = inside winrm.connect(). Every failure there is a configuration refusal.
export function mapWinrmOpenError(err: unknown, ctx: ErrorContext): unknown {
  return usage(ctx, err);
}

// A plain Error is not a module error and has no `code`. winrm's own code throws
// only WinRMError subclasses, so on the WinRM side it comes from the security
// context: step, wrap, unwrap, or createContext on re-auth.
function isPlainError(err: unknown): err is Error {
  return err instanceof Error && !(err instanceof WinRMError) && !(err instanceof SmbError) && !isSystemError(err);
}

// winrm refuses Kerberos message encryption (transport.ts:23-26).
function isKerberosEncryptionRefusal(err: unknown): boolean {
  return err instanceof WinRMProtocolError && err.message.startsWith('WinRM message encryption');
}

function isMissingAuthToken(err: unknown): boolean {
  return err instanceof WinRMProtocolError && /^Auth provider returned no .*token/.test(err.message);
}

// WinRM op = inside a session method (the first op runs the HTTP handshake).
export function mapWinrmOpError(err: unknown, ctx: ErrorContext): unknown {
  // Thrown by the facade's own code inside a WinRM call: a typed
  // facade error, or a local file error (it names a path), as it is.
  if (err instanceof WinLinuxError) return err;
  if (isSystemError(err) && hasPath(err)) return err;
  if (err instanceof WinRMAuthError) return auth(ctx, err);
  if (isKerberosEncryptionRefusal(err)) return usage(ctx, err);
  if (isMissingAuthToken(err)) return auth(ctx, err);
  if (err instanceof WinRMTransportError) return connection(ctx, err);
  if (isSystemError(err)) return connection(ctx, err);
  if (err instanceof WinRMError) return err; // fault, protocol, query failed: pass-through
  if (isPlainError(err)) return auth(ctx, err); // thrown by ctx.step, also during a re-auth
  return err;
}

// STATUS_ACCOUNT_LOCKED_OUT: not mapped to SmbAuthError by smb2's throwForStatus.
export const STATUS_ACCOUNT_LOCKED_OUT = 0xc0000234;

// SMB open = inside smb2.connect(): TCP, NEGOTIATE and SESSION_SETUP.
export function mapSmbOpenError(err: unknown, ctx: ErrorContext): unknown {
  if (err instanceof SmbAuthError || err instanceof SmbSigningError || err instanceof SmbAccessDeniedError) {
    return auth(ctx, err);
  }
  if (err instanceof SmbConnectionError) {
    const cause = (err as { cause?: unknown }).cause;
    if (isSystemError(cause) || (cause instanceof Error && cause.message === 'connect_timeout')) return connection(ctx, err);
    return auth(ctx, err); // the auth provider threw (for example "NTLM needs a password")
  }
  if (err instanceof SmbError && err.status === STATUS_ACCOUNT_LOCKED_OUT) return auth(ctx, err);
  return connection(ctx, err); // SmbTimeoutError, SmbDialectError, other SmbError, anything else
}

// SMB op. A failed signature check or a dropped socket means the session is
// no longer usable: connection class, so the slot resets.
export function mapSmbOpError(err: unknown, ctx: ErrorContext): unknown {
  if (err instanceof SmbTimeoutError || err instanceof SmbSigningError) return connection(ctx, err);
  if (isPlainError(err) && err.message === 'not_connected') return connection(ctx, err); // Client.ts:145
  if (isSystemError(err) && !hasPath(err)) return connection(ctx, err);
  return err; // SmbError subclasses and local fs errors: pass-through
}

// CLI exit codes.
export const EXIT = {
  ok: 0,
  usage: 1,
  auth: 2,
  connection: 3,
  remote: 4,
  file: 5,
  internal: 6,
  interrupted: 130,
} as const;

export function exitCodeFor(err: unknown): number {
  // WinLinuxAbortError (tree.ts): a recursive copy stopped by Ctrl+C.
  if (err instanceof WinLinuxError && err.name === 'WinLinuxAbortError') return EXIT.interrupted;
  if (err instanceof WinLinuxUsageError) return EXIT.usage;
  if (err instanceof WinLinuxAuthError) return EXIT.auth;
  if (err instanceof WinLinuxConnectionError) return EXIT.connection;
  if (err instanceof WinLinuxTransferError) return EXIT.file;
  if (err instanceof WinRMError) return EXIT.remote;
  if (err instanceof SmbError) return EXIT.file;
  if (isSystemError(err) && hasPath(err)) return EXIT.file;
  const code = (err as { code?: unknown })?.code;
  if (typeof code === 'string' && code.startsWith('ERR_PARSE_ARGS_')) return EXIT.usage;
  return EXIT.internal;
}
