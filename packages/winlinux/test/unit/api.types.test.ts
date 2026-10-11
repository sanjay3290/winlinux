import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import * as api from '../../dist/index.js';
import type {
  Mechanism,
  CommandResult,
  OutputChunk,
  EventLogQuery,
  EventRecord,
  ShareInfo,
  DirEntry,
  FileStat,
  WinRMOptions,
  SMBOptions,
  ConnectOptions,
  Protocol,
  WinLinuxClient,
} from '../../dist/index.js';
import type * as Auth from '@winlinux/auth';
import type * as Winrm from '@winlinux/winrm';
import type * as Smb from '@winlinux/smb2';

// Compile-time helpers: a false here fails `npm run build:test` (and so `npm test`).
type Equal<A, B> = [A] extends [B] ? ([B] extends [A] ? true : false) : false;
function assertType<T extends true>(_value?: T): void {}

describe('public API', () => {
  it('exports every public name', () => {
    const runtimeNames = [
      'connect',
      'WinLinuxError',
      'WinLinuxUsageError',
      'WinLinuxAuthError',
      'WinLinuxConnectionError',
      'WinLinuxTransferError',
      'WinLinuxAbortError',
      'WinRMError',
      'WinRMAuthError',
      'WinRMTransportError',
      'WinRMFaultError',
      'WinRMProtocolError',
      'WinRMAbortError',
      'SmbError',
      'SmbAccessDeniedError',
      'SmbNotFoundError',
      'SmbAlreadyExistsError',
      'SmbSharingViolationError',
      'SmbAuthError',
      'SmbSigningError',
      'SmbDialectError',
      'SmbTimeoutError',
      'SmbConnectionError',
      'SmbFileTooLargeError',
      'SmbEncryptionRequiredError',
      'SmbNotADirectoryError',
      'SmbIsADirectoryError',
      'SmbDirectoryNotEmptyError',
    ];
    for (const name of runtimeNames) {
      assert.equal(typeof (api as Record<string, unknown>)[name], 'function', `missing export ${name}`);
    }
    // The internal factory stays private.
    assert.equal((api as Record<string, unknown>).createClient, undefined);
    assert.deepEqual(Object.keys(api).sort(), [...runtimeNames].sort());

    // Type-only exports: each must resolve and have the design shape.
    const mechanism: Mechanism = 'negotiate';
    const result: CommandResult = { stdout: '', stderr: '', exitCode: 0 };
    const chunk: OutputChunk = { stream: 'stdout', data: '' };
    const query: EventLogQuery = { logName: 'System' };
    const record: EventRecord = { timeCreated: '', id: 1, level: '', provider: '', message: '' };
    const share: ShareInfo = { name: 'C$', type: 'disk', comment: '' };
    const entry: DirEntry = { name: 'a', isDirectory: false, sizeBytes: 1n, mtime: new Date(0), isReparsePoint: false };
    const info: FileStat = { sizeBytes: 1n, mtime: new Date(0), atime: new Date(0), isDirectory: false, readonly: false };
    assert.ok(info);
    const winrm: WinRMOptions = { port: 5986, tls: true, tlsVerify: false, path: '/wsman', encryption: 'auto', operationTimeoutMs: 1 };
    const smb: SMBOptions = { port: 445, signing: 'required', requestTimeoutMs: 1 };
    const options: ConnectOptions = { username: 'u', password: 'p', domain: 'D', realm: 'R', useTicketCache: false, auth: mechanism, winrm, smb };
    const protocol: Protocol = 'smb';
    assert.ok(result && chunk && query && record && share && entry && options && protocol);

    // Every client method from the design, with its signature.
    type C = WinLinuxClient;
    assertType<Equal<C['run'], (cmd: string, args?: string[], opts?: { cwd?: string }) => Promise<CommandResult>>>();
    assertType<Equal<C['runPowerShell'], (script: string) => Promise<CommandResult>>>();
    assertType<Equal<C['runStream'], (cmd: string, args?: string[], opts?: { cwd?: string }) => AsyncIterable<OutputChunk>>>();
    assertType<Equal<C['runPowerShellStream'], (script: string) => AsyncIterable<OutputChunk>>>();
    assertType<Equal<C['readEventLog'], (query: EventLogQuery) => Promise<EventRecord[]>>>();
    assertType<Equal<C['listServices'], () => Promise<api.ServiceInfo[]>>>();
    assertType<Equal<C['listProcesses'], () => Promise<api.ProcessInfo[]>>>();
    assertType<Equal<C['listShares'], () => Promise<ShareInfo[]>>>();
    assertType<Equal<C['ls'], (share: string, dirPath?: string) => Promise<DirEntry[]>>>();
    assertType<Equal<C['get'], (share: string, remotePath: string, localPath: string) => Promise<void>>>();
    assertType<Equal<C['put'], (localPath: string, share: string, remotePath: string) => Promise<void>>>();
    // The per-call transfer options, as the fourth argument.
    assertType<Equal<Parameters<C['get']>, [share: string, remotePath: string, localPath: string, opts?: api.TransferOptions]>>();
    assertType<Equal<Parameters<C['put']>, [localPath: string, share: string, remotePath: string, opts?: api.TransferOptions]>>();
    assertType<Equal<api.TransferVia, 'smb' | 'winrm' | 'auto'>>();
    assertType<Equal<api.TransferOptions, { via?: api.TransferVia; signal?: AbortSignal }>>();
    assertType<Equal<NonNullable<ConnectOptions['transfer']>, api.TransferSettings>>();
    assertType<Equal<C['stat'], (share: string, remotePath: string) => Promise<FileStat>>>();
    assertType<Equal<C['mkdir'], (share: string, dirPath: string, opts?: { parents?: boolean }) => Promise<void>>>();
    assertType<Equal<C['rm'], (share: string, remotePath: string) => Promise<void>>>();
    assertType<Equal<C['rmdir'], (share: string, dirPath: string) => Promise<void>>>();
    assertType<Equal<C['mv'], (share: string, fromPath: string, toPath: string) => Promise<void>>>();
    assertType<Equal<C['readFile'], (share: string, remotePath: string) => Promise<Buffer>>>();
    assertType<Equal<C['writeFile'], (share: string, remotePath: string, data: Buffer | string) => Promise<void>>>();
    assertType<Equal<C['getDir'], (share: string, remoteDir: string, localDir: string, opts?: api.TreeTransferOptions) => Promise<api.TreeTransferSummary>>>();
    assertType<Equal<C['putDir'], (localDir: string, share: string, remoteDir: string, opts?: api.TreeTransferOptions) => Promise<api.TreeTransferSummary>>>();
    assertType<Equal<C['close'], () => Promise<void>>>();
    assertType<Equal<C['host'], string>>();
    assertType<Equal<C['username'], string>>();
    assertType<Equal<typeof api.connect, (host: string, options: ConnectOptions) => Promise<WinLinuxClient>>>();

    const authErr = new api.WinLinuxAuthError('m', 'smb', 'ntlm', { cause: 1 });
    assert.equal(authErr.name, 'WinLinuxAuthError');
    assert.equal(authErr.protocol, 'smb');
    assert.equal(authErr.mechanism, 'ntlm');
    assert.equal(authErr.cause, 1);
    assert.ok(authErr instanceof api.WinLinuxError);
    const connErr = new api.WinLinuxConnectionError('m', 'winrm', 'h', 5985);
    assert.deepEqual([connErr.name, connErr.protocol, connErr.host, connErr.port], ['WinLinuxConnectionError', 'winrm', 'h', 5985]);
    assert.equal(new api.WinLinuxUsageError('m').name, 'WinLinuxUsageError');
    const transferErr = new api.WinLinuxTransferError('m', 'put', 'mismatch');
    assert.deepEqual([transferErr.name, transferErr.direction, transferErr.reason], ['WinLinuxTransferError', 'put', 'mismatch']);
    assert.ok(transferErr instanceof api.WinLinuxError);
    assert.equal(new api.WinLinuxError('m').name, 'WinLinuxError');
  });

  it('contract copies stay mutually assignable', () => {
    // The winrm and smb2 contract copies match @winlinux/auth.
    assertType<Equal<Auth.AuthProvider, Winrm.AuthProvider>>();
    assertType<Equal<Auth.AuthProvider, Smb.AuthProvider>>();
    assertType<Equal<Auth.Credentials, Winrm.Credentials>>();
    assertType<Equal<Auth.Credentials, Smb.Credentials>>();
    assertType<Equal<Auth.SecurityContext, Winrm.SecurityContext>>();
    assertType<Equal<Auth.SecurityContext, Smb.SecurityContext>>();
    assertType<Equal<Auth.Mechanism, Winrm.Mechanism>>();
    assertType<Equal<Auth.Mechanism, Smb.Mechanism>>();
    assert.ok(true);
  });
});
