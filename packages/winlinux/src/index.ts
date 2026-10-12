// Public entry point of the `winlinux` package.
import { createClient } from './client.js';
import { realDeps } from './real-deps.js';
import type { ConnectOptions, WinLinuxClient } from './types.js';

export type { Mechanism } from '@winlinux/auth';
export type { AuthMechanism } from './types.js';
export type { CommandResult, OutputChunk, EventLogQuery, EventRecord, ServiceInfo, ProcessInfo } from '@winlinux/winrm';
export type { ShareInfo, DirEntry, FileStat } from '@winlinux/smb2';
export type {
  WinRMOptions,
  SMBOptions,
  ConnectOptions,
  Protocol,
  WinLinuxClient,
  TransferVia,
  TransferSettings,
  TransferOptions,
  TransferFallbackEvent,
  PowerShellSession,
  PowerShellOptions,
  InvokePowerShellOptions,
} from './types.js';

export { WinLinuxError, WinLinuxUsageError, WinLinuxAuthError, WinLinuxConnectionError, WinLinuxTransferError } from './errors.js';
export type { TransferFailure } from './errors.js';
export { WinLinuxAbortError } from './tree.js';
export type { TreeTransferOptions, TreeTransferSummary, TreeFileEvent, TreeSkipEvent } from './tree.js';

// Pass-through error classes, re-exported unchanged so callers can use instanceof.
export { WinRMError, WinRMAuthError, WinRMTransportError, WinRMFaultError, WinRMProtocolError, WinRMAbortError, PSRemotingError } from '@winlinux/winrm';
// PSRP: the pipeline and value types a PowerShellSession hands out.
export type { InvokeOptions, PSCommand, PSErrorRecord, PSInformationRecord, PSInvocationResult, PSInvocationState, PSObject, PSPipeline, PSProgressRecord, PSStreamEvent, PSValue } from '@winlinux/winrm';
export { isPSObject, toJson as psValueToJson } from '@winlinux/winrm';
export {
  SmbError,
  SmbAbortError,
  SmbAccessDeniedError,
  SmbNotFoundError,
  SmbAlreadyExistsError,
  SmbSharingViolationError,
  SmbAuthError,
  SmbSigningError,
  SmbDialectError,
  SmbTimeoutError,
  SmbConnectionError,
  SmbFileTooLargeError,
  SmbEncryptionRequiredError,
  SmbNotADirectoryError,
  SmbIsADirectoryError,
  SmbDirectoryNotEmptyError,
} from '@winlinux/smb2';

/**
 * Validates the options and returns a client. Opens no socket: the first
 * command opens WinRM (5985, or 5986 with `winrm.tls`), and the first file
 * call opens SMB (445). With `transfer.via` 'winrm' or 'auto', get and put
 * can copy over WinRM instead. One frozen credential set serves both
 * protocols.
 *
 * After a `WinLinuxAuthError` a protocol does not retry by itself, so a bad
 * password cannot lock the account. Call `setPassword()` or `reset()` first.
 *
 * Kerberos with a password: each protocol runs its own `kinit` into its own
 * temp ccache; concurrent first calls are safe. SMB signing with Kerberos
 * needs the optional `@winlinux/krb-session-key` addon. With it, `negotiate`
 * plus a password and a `realm` also tries Kerberos for SMB.
 *
 * @throws WinLinuxUsageError when the options are invalid.
 */
export async function connect(host: string, options: ConnectOptions): Promise<WinLinuxClient> {
  return createClient(host, options, realDeps());
}
