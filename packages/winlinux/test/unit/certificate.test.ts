// Certificate sign-in in the facade and the CLI: planAuth, validation,
// the key file check, the passphrase, redaction and the CLI flags. The
// HTTPS mock asks for a client certificate signed by a test CA.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { chmod, copyFile, mkdtemp } from 'node:fs/promises';
import { readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { connect, WinLinuxUsageError, type ConnectOptions } from '../../dist/index.js';
import { createClient } from '../../dist/client.js';
import { planAuth } from '../../dist/plan-auth.js';
import { HELP } from '../../dist/cli/app.js';
import { pemKeyIsEncrypted, resolvePassphrase, takeEnvPassphrase } from '../../dist/cli/password.js';
import { parseConfig } from '../../dist/cli/config.js';
import { fakeDeps } from '../helpers/fakes.js';
import { runCli } from '../helpers/cli.js';
import { doneReceive } from '../helpers/winrm-mock.js';
import { actionOf, startMockServer, type MockHandler } from '../../../winrm/dist/test/helpers/mock-server.js';

const FIXTURES = fileURLToPath(new URL('../../../winrm/dist/test/fixtures/', import.meta.url));
const fx = (name: string) => join(FIXTURES, name);
const PASSPHRASE = 'Test-Key-Passphrase-Sentinel';
const MUTUAL = 'http://schemas.dmtf.org/wbem/wsman/1/wsman/secprofile/https/mutual';

// Copies of the fixture key with a chosen mode (git does not keep modes).
async function keyCopy(name: string, mode: number): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'winlinux-key-'));
  const file = join(dir, name);
  await copyFile(fx(`client-cert/${name}`), file);
  await chmod(file, mode);
  return file;
}

const SIGNAL = '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><rsp:SignalResponse xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell"/></s:Body></s:Envelope>';
const DELETE = '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><x:DeleteResponse xmlns:x="http://schemas.xmlsoap.org/ws/2004/09/transfer"/></s:Body></s:Envelope>';
const handler: MockHandler = (req) => {
  if (req.headers.authorization !== MUTUAL) return { status: 401 };
  const action = actionOf(req.body);
  const read = (n: string) => readFileSync(fx(n), 'utf8');
  const body =
    action === 'Create' ? read('create-response.xml') : action === 'Command' ? read('command-response.xml') : action === 'Receive' ? doneReceive('cert-user\n', 0) : action === 'Signal' ? SIGNAL : DELETE;
  return { status: 200, headers: { 'Content-Type': 'application/soap+xml;charset=UTF-8' }, body };
};
const certMock = () =>
  startMockServer(handler, {
    tls: { cert: readFileSync(fx('tls-test-cert.pem')), key: readFileSync(fx('tls-test-key.pem')), requestCert: true, rejectUnauthorized: true, ca: readFileSync(fx('client-cert/ca-cert.pem')) },
  });

describe('planAuth: certificate', () => {
  it('WinRM uses the certificate; SMB is refused before any socket', () => {
    for (const e of [true, false]) {
      const plan = planAuth('certificate', {}, e);
      assert.deepEqual(plan.winrm, { refused: false, mechanism: 'certificate' });
      assert.deepEqual(plan.smb, { refused: true, mechanism: 'certificate', reason: 'certificate sign-in is WinRM-only; use --via winrm for files' });
    }
  });
});

describe('connect() with a certificate', () => {
  const base: ConnectOptions = { username: 'admin', auth: 'certificate', clientCert: '/c.pem', clientKey: '/k.pem', winrm: { tls: true } };
  const usage = async (opts: ConnectOptions, re: RegExp) =>
    assert.rejects(connect('server.example.test', opts), (e: Error) => e instanceof WinLinuxUsageError && re.test(e.message));

  it('refuses it without TLS, without files, with a password, a ticket cache or a keytab, and with encryption always', async () => {
    await usage({ ...base, winrm: {} }, /certificate sign-in needs HTTPS: use --tls/);
    await usage({ ...base, clientKey: undefined }, /needs clientCert and clientKey/);
    await usage({ ...base, password: 'pw' }, /takes no password, ticket cache or keytab/);
    await usage({ ...base, useTicketCache: true }, /takes no password/);
    await usage({ ...base, keytab: '/k' }, /takes no password/);
    await usage({ ...base, winrm: { tls: true, encryption: 'always' } }, /no message encryption/);
  });

  it('refuses certificate files with another mechanism', async () => {
    await usage({ username: 'u', password: 'p', clientCert: '/c.pem' }, /need auth 'certificate'/);
    await usage({ username: 'u', password: 'p', clientKeyPassphrase: 'x' }, /need auth 'certificate'/);
  });

  it('a group- or world-accessible key is a usage error before any socket', async () => {
    const key = await keyCopy('client-key.pem', 0o644);
    const deps = fakeDeps({});
    const client = createClient('server.example.test', { ...base, clientCert: fx('client-cert/client-cert.pem'), clientKey: key }, deps);
    await assert.rejects(client.run('whoami'), (e: Error) => {
      assert.ok(e instanceof WinLinuxUsageError);
      assert.equal(e.message, `client key ${key} is accessible by group or others; run chmod 600 ${key}`);
      return true;
    });
    assert.equal(deps.winrmOpens.length, 0);
    await client.close();
  });

  it('a certificate file that is not PEM is a usage error', async () => {
    const key = await keyCopy('client-key.pem', 0o600);
    const client = createClient('server.example.test', { ...base, clientCert: key, clientKey: key }, fakeDeps({}));
    await assert.rejects(client.run('whoami'), /client certificate .*: not a PEM certificate/);
    await client.close();
  });

  it('passes the PEM bytes and the passphrase to winrm, with no AuthProvider; SMB is refused', async () => {
    const key = await keyCopy('client-key-encrypted.pem', 0o600);
    const lines: string[] = [];
    const deps = { ...fakeDeps({}), log: (l: string) => lines.push(l) };
    const client = createClient('server.example.test', { ...base, clientCert: fx('client-cert/client-cert.pem'), clientKey: key, clientKeyPassphrase: PASSPHRASE }, deps);
    await client.run('whoami');
    const open = deps.winrmOpens[0];
    assert.equal(open?.authProvider, undefined);
    assert.equal(open?.credentials, undefined);
    assert.equal(open?.tls, true);
    assert.equal(open?.clientCertificate?.passphrase, PASSPHRASE);
    assert.ok(open?.clientCertificate?.cert.toString().includes('BEGIN CERTIFICATE'));
    assert.ok(open?.clientCertificate?.key.toString().includes('BEGIN ENCRYPTED PRIVATE KEY'));
    assert.deepEqual(deps.mechanisms, [], 'no auth provider was created');
    await assert.rejects(client.ls('C$'), /certificate sign-in is WinRM-only/);
    assert.equal(deps.smbOpens.length, 0);
    assert.ok(!lines.join('\n').includes(PASSPHRASE) && !lines.join('\n').includes('PRIVATE KEY'));
    await client.close();
  });

  it('with via auto, files go over WinRM at once: no SMB open, no notice; --via smb is refused', async () => {
    const key = await keyCopy('client-key.pem', 0o600);
    const deps = fakeDeps({});
    const notices: unknown[] = [];
    const client = createClient(
      'server.example.test',
      { ...base, clientCert: fx('client-cert/client-cert.pem'), clientKey: key, transfer: { via: 'auto', onFallback: (e) => notices.push(e) } },
      deps,
    );
    const dir = await mkdtemp(join(tmpdir(), 'winlinux-cert-get-'));
    // The fake WinRM session has no copy script, so the get fails; what
    // matters is the route: WinRM opened, SMB never.
    await assert.rejects(client.get('C$', 'x.txt', join(dir, 'x.txt')));
    assert.equal(deps.winrmOpens.length, 1);
    assert.equal(deps.smbOpens.length, 0);
    assert.deepEqual(notices, []);
    await assert.rejects(client.get('C$', 'x.txt', join(dir, 'x.txt'), { via: 'smb' }), /certificate sign-in is WinRM-only; use --via winrm for files/);
    await client.close();
  });

  it('runs a command against an HTTPS mock that requires a client certificate', async () => {
    const server = await certMock();
    try {
      const key = await keyCopy('client-key.pem', 0o600);
      const client = await connect('127.0.0.1', {
        ...base,
        clientCert: fx('client-cert/client-cert.pem'),
        clientKey: key,
        winrm: { tls: true, tlsVerify: false, port: server.port },
      });
      try {
        const r = await client.run('whoami');
        assert.equal(r.stdout, 'cert-user\n');
      } finally {
        await client.close();
      }
      assert.ok(server.requests.every((q) => q.headers.authorization === MUTUAL && q.clientCertCN === 'test-user'));
      assert.ok(!server.requests.some((q) => /negotiate/i.test(String(q.headers.authorization))));
    } finally {
      await server.close();
    }
  });
});

describe('the key passphrase', () => {
  it('detects encrypted PEM keys', () => {
    assert.equal(pemKeyIsEncrypted(readFileSync(fx('client-cert/client-key-encrypted.pem'), 'utf8')), true);
    assert.equal(pemKeyIsEncrypted(readFileSync(fx('client-cert/client-key.pem'), 'utf8')), false);
    assert.equal(pemKeyIsEncrypted('-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n'), true);
  });

  it('WINLINUX_KEY_PASSPHRASE is read once and removed from the environment', () => {
    const env: NodeJS.ProcessEnv = { WINLINUX_KEY_PASSPHRASE: PASSPHRASE };
    assert.equal(takeEnvPassphrase(env), PASSPHRASE);
    assert.equal('WINLINUX_KEY_PASSPHRASE' in env, false);
    assert.equal(takeEnvPassphrase(env), undefined);
  });

  it('prompts with no echo on a terminal, and is a usage error without one', async () => {
    const written: string[] = [];
    const stdin = Object.assign(new EventEmitter(), {
      isTTY: true,
      isRaw: false,
      setRawMode(on: boolean) {
        this.isRaw = on;
        return this;
      },
      setEncoding: () => undefined,
      resume: () => undefined,
      pause: () => undefined,
    });
    const stderr = { write: (t: string) => written.push(t) } as unknown as NodeJS.WritableStream;
    const answer = resolvePassphrase(undefined, { env: {}, stdin: stdin as unknown as NodeJS.ReadStream, stderr });
    stdin.emit('data', `${PASSPHRASE}\r`);
    assert.equal(await answer, PASSPHRASE);
    assert.equal(written[0], 'Key passphrase: ');
    assert.ok(!written.join('').includes(PASSPHRASE), 'no echo');
    await assert.rejects(
      resolvePassphrase(undefined, { env: {}, stdin: { isTTY: false } as unknown as NodeJS.ReadStream, stderr }),
      /the client key is encrypted: set WINLINUX_KEY_PASSPHRASE or run in a terminal/,
    );
  });
});

describe('CLI -a certificate', () => {
  it('--help and profiles know the method and the keys', () => {
    assert.match(HELP, /certificate/);
    assert.match(HELP, /--cert <file> --key <file>/);
    const c = parseConfig('Host w\n  Auth certificate\n  CertFile ~/c.pem\n  KeyFile ~/k.pem\n', '/c');
    assert.deepEqual(c.blocks[0]?.settings, { auth: 'certificate', certFile: '~/c.pem', keyFile: '~/k.pem' });
  });

  it('without --tls, and with a 0644 key, exits 1 with no password prompt', async () => {
    const key = await keyCopy('client-key.pem', 0o644);
    let r = await runCli(['run', '-a', 'certificate', '--cert', fx('client-cert/client-cert.pem'), '--key', key, 'admin@server.example.test', 'whoami']);
    assert.equal(r.code, 1);
    assert.match(r.stderr, /certificate sign-in needs HTTPS: use --tls/);
    r = await runCli(['run', '-a', 'certificate', '--tls', '--cert', fx('client-cert/client-cert.pem'), '--key', key, 'admin@server.example.test', 'whoami']);
    assert.equal(r.code, 1);
    assert.match(r.stderr, /is accessible by group or others; run chmod 600/);
    assert.ok(!r.stderr.includes('Password'));
  });

  it('runs against the mock with an encrypted key and WINLINUX_KEY_PASSPHRASE; --insecure warns; the passphrase never prints', async () => {
    const server = await certMock();
    try {
      const key = await keyCopy('client-key-encrypted.pem', 0o600);
      const r = await runCli(
        ['run', '-v', '-a', 'certificate', '--tls', '--insecure', '--winrm-port', String(server.port), '--cert', fx('client-cert/client-cert.pem'), '--key', key, 'admin@127.0.0.1', 'whoami'],
        { WINLINUX_KEY_PASSPHRASE: PASSPHRASE },
      );
      assert.equal(r.code, 0, r.stderr);
      assert.equal(r.stdout, 'cert-user\n');
      assert.match(r.stderr, /warning: --insecure with a client certificate/);
      assert.match(r.stderr, /mechanism certificate/);
      assert.ok(!r.stderr.includes(PASSPHRASE) && !r.stdout.includes(PASSPHRASE));
    } finally {
      await server.close();
    }
  });

  it('an encrypted key with no passphrase source exits 1', async () => {
    const key = await keyCopy('client-key-encrypted.pem', 0o600);
    const r = await runCli(['run', '-a', 'certificate', '--tls', '--cert', fx('client-cert/client-cert.pem'), '--key', key, 'admin@server.example.test', 'whoami']);
    assert.equal(r.code, 1);
    assert.match(r.stderr, /the client key is encrypted/);
  });

  it('a wrong passphrase fails without printing it', async () => {
    const server = await certMock();
    try {
      const key = await keyCopy('client-key-encrypted.pem', 0o600);
      const r = await runCli(
        ['run', '-a', 'certificate', '--tls', '--insecure', '--winrm-port', String(server.port), '--cert', fx('client-cert/client-cert.pem'), '--key', key, 'admin@127.0.0.1', 'whoami'],
        { WINLINUX_KEY_PASSPHRASE: 'Wrong-Passphrase-Sentinel' },
      );
      assert.equal(r.code, 1, r.stderr);
      assert.match(r.stderr, /client key .*: cannot read it \(wrong passphrase, or not a PEM private key\)/);
      assert.ok(!r.stderr.includes('Wrong-Passphrase-Sentinel'), r.stderr);
      assert.equal(server.requests.length, 0, 'no request with a key that cannot be read');
    } finally {
      await server.close();
    }
  });
});
