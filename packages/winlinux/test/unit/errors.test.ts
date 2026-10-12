import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  WinRMAbortError,
  WinRMAuthError,
  WinRMError,
  WinRMFaultError,
  WinRMProtocolError,
  WinRMTransportError,
} from '@winlinux/winrm';
import {
  SmbAbortError,
  SmbAccessDeniedError,
  SmbAuthError,
  SmbConnectionError,
  SmbDialectError,
  SmbEncryptionRequiredError,
  SmbError,
  SmbFileTooLargeError,
  SmbNotFoundError,
  SmbSigningError,
  SmbTimeoutError,
} from '@winlinux/smb2';
import {
  EXIT,
  WinLinuxAuthError,
  WinLinuxConnectionError,
  WinLinuxUsageError,
  exitCodeFor,
  mapSmbOpError,
  mapSmbOpenError,
  mapWinrmOpError,
  mapWinrmOpenError,
  type ErrorContext,
} from '../../dist/errors.js';

const SECRET = 'err-test-secret';
const winrm: ErrorContext = {
  protocol: 'winrm',
  host: 'srv',
  port: 5985,
  mechanism: 'ntlm',
  redact: (t) => t.split(SECRET).join('***'),
};
const smb: ErrorContext = { ...winrm, protocol: 'smb', port: 445 };

function sysError(code: string, extra: Record<string, unknown> = {}): Error {
  return Object.assign(new Error(`${code} happened`), { code, ...extra });
}

function withCause<T extends Error>(err: T, cause: unknown): T {
  (err as { cause?: unknown }).cause = cause;
  return err;
}

function isWrapped(mapped: unknown, cls: Function, cause: unknown): void {
  assert.ok(mapped instanceof cls, `expected ${cls.name}, got ${String(mapped)}`);
  assert.equal((mapped as Error).cause, cause);
}

describe('error mapping', () => {
  it('maps winrm open errors to usage', () => {
    const errs = [
      new WinRMTransportError("WinRM refuses plain HTTP with encryption 'never'"),
      new WinRMProtocolError('WinRM message encryption over plain HTTP is not supported for Kerberos yet'),
      new WinRMError('WinRM connect needs a host'),
      new Error('Basic auth needs a username'),
    ];
    for (const err of errs) isWrapped(mapWinrmOpenError(err, winrm), WinLinuxUsageError, err);
    const mapped = mapWinrmOpenError(new Error(`bad ${SECRET}`), winrm) as Error;
    assert.equal(mapped.message, 'winrm setup failed for srv:5985: bad ***');
  });

  it('maps WinRMAuthError to auth', () => {
    const err = new WinRMAuthError('WinRM authentication failed');
    const mapped = mapWinrmOpError(err, winrm);
    isWrapped(mapped, WinLinuxAuthError, err);
    assert.equal((mapped as WinLinuxAuthError).protocol, 'winrm');
    assert.equal((mapped as WinLinuxAuthError).mechanism, 'ntlm');
    assert.equal((mapped as Error).message, 'winrm authentication failed for srv:5985: WinRM authentication failed');
  });

  it('maps winrm system and transport errors to connection', () => {
    for (const err of [
      sysError('ECONNREFUSED'),
      sysError('ENOTFOUND'),
      sysError('ECONNRESET'),
      sysError('DEPTH_ZERO_SELF_SIGNED_CERT'),
      new WinRMTransportError('WinRM request failed with HTTP 503'),
      new WinRMTransportError('WinRM refuses an unencrypted HTTP 200 response on an encrypted session'),
    ]) {
      const mapped = mapWinrmOpError(err, winrm);
      isWrapped(mapped, WinLinuxConnectionError, err);
      assert.deepEqual([(mapped as WinLinuxConnectionError).host, (mapped as WinLinuxConnectionError).port], ['srv', 5985]);
    }
  });

  it('maps a plain Error from the security context to auth, including re-auth', () => {
    for (const message of ['NTLM needs a password', 'kinit failed: bad password', 'Kerberos step failed', 'NTLM wrap: context is not established']) {
      const err = new Error(message);
      isWrapped(mapWinrmOpError(err, winrm), WinLinuxAuthError, err);
    }
  });

  it('maps no-token protocol errors to auth and kerberos encryption refusals to usage', () => {
    for (const message of ['Auth provider returned no initial token', 'Auth provider returned no token for the server challenge']) {
      const err = new WinRMProtocolError(message);
      isWrapped(mapWinrmOpError(err, winrm), WinLinuxAuthError, err);
    }
    for (const message of [
      'WinRM message encryption over plain HTTP is not supported for Kerberos yet: use HTTPS (tls:true, port 5986).',
      "WinRM message encryption is not supported for Kerberos yet: on HTTPS, use encryption 'auto' or 'never'.",
    ]) {
      const err = new WinRMProtocolError(message);
      isWrapped(mapWinrmOpError(err, winrm), WinLinuxUsageError, err);
    }
  });

  it('passes through faults and other protocol errors', () => {
    const errs = [
      new WinRMFaultError('fault', 's:Receiver', null, 'r', 5, 'm', '<xml/>'),
      new WinRMProtocolError('WinRM response has no ShellId'),
      new WinRMError('WinRM event log query failed with exit code 1: boom'),
    ];
    for (const err of errs) assert.equal(mapWinrmOpError(err, winrm), err);
  });

  it('maps smb open errors by class, status and cause, including ACCOUNT_LOCKED_OUT', () => {
    const authErrs = [
      new SmbAuthError('authentication failed during session setup', 0xc000006d),
      new SmbAccessDeniedError('access denied: session setup', 0xc0000022),
      new SmbError('SMB request failed during session setup', 0xc0000234),
      new SmbSigningError('packet signing is required but the auth provider supplied no session key'),
      withCause(new SmbConnectionError('cannot connect to srv:445: NTLM needs a password'), new Error('NTLM needs a password')),
    ];
    for (const err of authErrs) {
      const mapped = mapSmbOpenError(err, smb);
      isWrapped(mapped, WinLinuxAuthError, err);
      assert.equal((mapped as WinLinuxAuthError).protocol, 'smb');
    }
    const connErrs = [
      withCause(new SmbConnectionError('cannot connect'), sysError('ECONNREFUSED')),
      withCause(new SmbConnectionError('cannot connect'), new Error('connect_timeout')),
      new SmbTimeoutError('request timed out during connect'),
      new SmbDialectError('server requires SMB3'),
      new SmbError('SMB request failed during negotiate', 0xc00000bb),
    ];
    for (const err of connErrs) isWrapped(mapSmbOpenError(err, smb), WinLinuxConnectionError, err);
  });

  it('maps smb op timeouts, signature failures, not_connected and socket errors to connection', () => {
    for (const err of [
      new SmbTimeoutError('request timed out during list'),
      new SmbSigningError('response signature verification failed'),
      new Error('not_connected'),
      sysError('ECONNRESET'),
      sysError('EPIPE'),
    ]) {
      isWrapped(mapSmbOpError(err, smb), WinLinuxConnectionError, err);
    }
  });

  it('passes through smb file errors and local fs errors', () => {
    for (const err of [
      new SmbNotFoundError('no such file or directory: x', 0xc0000034),
      new SmbAccessDeniedError('access denied: x', 0xc0000022),
      new SmbFileTooLargeError('too big'),
      sysError('ENOENT', { path: '/tmp/missing' }),
      sysError('EACCES', { path: '/root/x' }),
    ]) {
      assert.equal(mapSmbOpError(err, smb), err);
    }
  });

  it('exit code for each error class matches the CLI exit code table', () => {
    assert.equal(exitCodeFor(new WinLinuxUsageError('u')), EXIT.usage);
    assert.equal(exitCodeFor(new WinLinuxAuthError('a', 'smb', 'ntlm')), EXIT.auth);
    assert.equal(exitCodeFor(new WinLinuxConnectionError('c', 'winrm', 'h', 1)), EXIT.connection);
    assert.equal(exitCodeFor(new WinRMFaultError('f', null, null, 'r', null, null, '')), EXIT.remote);
    assert.equal(exitCodeFor(new WinRMProtocolError('p')), EXIT.remote);
    assert.equal(exitCodeFor(new WinRMAbortError()), EXIT.interrupted);
    assert.equal(exitCodeFor(new SmbAbortError('download s/f to x was aborted')), EXIT.interrupted);
    assert.equal(exitCodeFor(new WinRMError('e')), EXIT.remote);
    assert.equal(exitCodeFor(new SmbNotFoundError('n')), EXIT.file);
    assert.equal(exitCodeFor(new SmbFileTooLargeError('t')), EXIT.file);
    assert.equal(exitCodeFor(new SmbEncryptionRequiredError('e', 0xc0000022)), EXIT.file);
    assert.equal(exitCodeFor(sysError('ENOENT', { path: '/x' })), EXIT.file);
    assert.equal(exitCodeFor(Object.assign(new TypeError('bad'), { code: 'ERR_PARSE_ARGS_UNKNOWN_OPTION' })), EXIT.usage);
    assert.equal(exitCodeFor(new TypeError('bug')), EXIT.internal);
    assert.equal(exitCodeFor('string'), EXIT.internal);
    assert.deepEqual(
      [EXIT.ok, EXIT.usage, EXIT.auth, EXIT.connection, EXIT.remote, EXIT.file, EXIT.internal, EXIT.interrupted],
      [0, 1, 2, 3, 4, 5, 6, 130],
    );
  });
});
