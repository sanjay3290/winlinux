// Kerberos keytab sign-in in the facade and the CLI. Fake deps and a
// fake kinit on PATH: no KDC, no network.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { chmod, mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { connect, WinLinuxUsageError, type ConnectOptions } from '../../dist/index.js';
import { createClient } from '../../dist/client.js';
import { planAuth } from '../../dist/plan-auth.js';
import { HELP } from '../../dist/cli/app.js';
import { fakeDeps } from '../helpers/fakes.js';
import { runCli } from '../helpers/cli.js';

const KEY_BYTES = 'KEYTAB-SENTINEL-BYTES-0123456789';
const HTTP = true;
const HTTPS = false;

async function keytabFile(mode: number): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'winlinux-keytab-'));
  const file = join(dir, 'svc.keytab');
  await writeFile(file, KEY_BYTES);
  await chmod(file, mode);
  return file;
}

async function rejectsUsage(options: ConnectOptions, pattern: RegExp, host = 'server.example.test'): Promise<void> {
  await assert.rejects(connect(host, options), (err: unknown) => {
    assert.ok(err instanceof WinLinuxUsageError, `expected WinLinuxUsageError, got ${String(err)}`);
    assert.match((err as Error).message, pattern);
    return true;
  });
}

describe('planAuth with a keytab', () => {
  const KT = { keytab: '/k/svc.keytab', realm: 'EXAMPLE.TEST' };
  it('negotiate plans Kerberos for both protocols: no NTLM fallback without a password', () => {
    for (const keyed of [false, true]) {
      assert.deepEqual(planAuth('negotiate', KT, HTTPS, keyed), {
        winrm: { refused: false, mechanism: 'kerberos' },
        smb: { refused: false, mechanism: 'kerberos' },
      });
    }
    assert.deepEqual(planAuth('negotiate', KT, HTTP, true).winrm, { refused: false, mechanism: 'kerberos' });
  });

  it('kerberos plans Kerberos; plain HTTP without the addon is refused as for any Kerberos', () => {
    assert.deepEqual(planAuth('kerberos', KT, HTTPS).winrm, { refused: false, mechanism: 'kerberos' });
    assert.deepEqual(planAuth('kerberos', KT, HTTPS).smb, { refused: false, mechanism: 'kerberos' });
    assert.equal(planAuth('kerberos', KT, HTTP, false).winrm.refused, true);
    assert.equal(planAuth('negotiate', KT, HTTP, false).winrm.refused, true);
  });

  it('a keytab beside a password still plans Kerberos only (validation refuses that pair earlier)', () => {
    assert.deepEqual(planAuth('negotiate', { ...KT, password: 'pw' }, HTTPS).smb, { refused: false, mechanism: 'kerberos' });
  });
});

describe('connect() with a keytab', () => {
  const base = { username: 'svc', realm: 'EXAMPLE.TEST', keytab: '/k/svc.keytab' };
  it('refuses a keytab with a password, the ticket cache, ntlm, basic, or no realm', async () => {
    await rejectsUsage({ ...base, password: 'pw' }, /keytab and a password/);
    await rejectsUsage({ ...base, useTicketCache: true }, /keytab and the ticket cache/);
    await rejectsUsage({ ...base, auth: 'ntlm' }, /auth 'ntlm' cannot use a keytab/);
    await rejectsUsage({ ...base, auth: 'basic' }, /auth 'basic' cannot use a keytab/);
    await rejectsUsage({ username: 'svc', keytab: '/k/svc.keytab' }, /keytab needs a realm/);
    await rejectsUsage({ ...base, keytab: '' }, /file path/);
  });

  it('accepts a realm, a domain, or user@REALM, with kerberos or negotiate and no password', async () => {
    for (const opts of [
      base,
      { ...base, auth: 'kerberos' as const },
      { username: 'svc', domain: 'EXAMPLE', keytab: '/k/f' },
      { username: 'svc@EXAMPLE.TEST', keytab: '/k/f' },
    ]) {
      const client = await connect('server.example.test', opts);
      await client.close();
    }
  });

  it('refuses an IP address host, as for any Kerberos-only sign-in', async () => {
    await rejectsUsage(base, /not an IP address/, '192.0.2.10');
  });

  it('a group- or world-accessible keytab is a usage error before any socket opens', async () => {
    const file = await keytabFile(0o644);
    const deps = fakeDeps({});
    const client = createClient('server.example.test', { ...base, keytab: file, winrm: { tls: true } }, deps);
    await assert.rejects(client.run('hostname'), (err: unknown) => {
      assert.ok(err instanceof WinLinuxUsageError);
      assert.equal((err as Error).message, `keytab ${file} is accessible by group or others; run chmod 600 ${file}`);
      return true;
    });
    await assert.rejects(client.ls('C$'), WinLinuxUsageError);
    assert.equal(deps.winrmOpens.length, 0);
    assert.equal(deps.smbOpens.length, 0);
    await client.close();
  });

  it('a 0600 keytab reaches the module as credentials.keytab, with no password, and --verbose names the path only', async () => {
    const file = await keytabFile(0o600);
    const lines: string[] = [];
    const deps = { ...fakeDeps({}), log: (line: string) => lines.push(line) };
    const client = createClient('server.example.test', { ...base, keytab: file, winrm: { tls: true } }, deps);
    await client.run('hostname');
    assert.equal(deps.winrmOpens.length, 1);
    assert.deepEqual(deps.winrmOpens[0]?.credentials, { username: 'svc', realm: 'EXAMPLE.TEST', keytab: file });
    assert.ok(lines.includes(`kerberos keytab ${file}`), lines.join('\n'));
    assert.ok(!lines.join('\n').includes(KEY_BYTES));
    await client.close();
  });

  it('setPassword() is refused with a keytab', async () => {
    const client = createClient('server.example.test', base, fakeDeps({}));
    assert.throws(() => client.setPassword('pw'), /keytab and a password/);
    await client.close();
  });
});

describe('CLI --keytab', () => {
  it('--help documents --keytab', () => {
    assert.match(HELP, /--keytab <file>/);
  });

  it('no prompt and no WINLINUX_PASSWORD: a 0644 keytab exits 1 with the chmod hint', async () => {
    const file = await keytabFile(0o644);
    const r = await runCli(['run', '--keytab', file, '--realm', 'EXAMPLE.TEST', '--tls', 'svc@server.example.test', '--', 'hostname']);
    assert.equal(r.code, 1, r.stderr);
    assert.equal(r.stderr, `winlinux: WinLinuxUsageError: keytab ${file} is accessible by group or others; run chmod 600 ${file}\n`);
    assert.ok(!r.stderr.includes('Password'), 'no prompt');
  });

  it('refuses --keytab with -K, with -a ntlm, and without a realm (exit 1)', async () => {
    const file = await keytabFile(0o600);
    const cases: Array<[string[], RegExp]> = [
      [['-K', '--realm', 'EXAMPLE.TEST'], /--keytab and -K cannot be used together/],
      [['-a', 'ntlm', '--realm', 'EXAMPLE.TEST'], /auth 'ntlm' cannot use a keytab/],
      [[], /keytab needs a realm/],
    ];
    for (const [flags, message] of cases) {
      const r = await runCli(['run', '--keytab', file, ...flags, 'svc@server.example.test', '--', 'hostname']);
      assert.equal(r.code, 1, r.stderr);
      assert.match(r.stderr, message);
    }
  });

  it('runs kinit with the keytab and nothing on stdin; the key bytes appear nowhere', async () => {
    const file = await keytabFile(0o600);
    const bin = await mkdtemp(join(tmpdir(), 'fakebin-'));
    const out = await mkdtemp(join(tmpdir(), 'kinitout-'));
    // A fake MIT kinit that records its argv and stdin, then fails, so the
    // run stops before GSS or any socket.
    await writeFile(
      join(bin, 'kinit'),
      `#!/bin/sh\necho "$@" > "${out}/args"\ncat > "${out}/stdin"\necho "kinit: Key table entry not found" >&2\nexit 1\n`,
    );
    await chmod(join(bin, 'kinit'), 0o755);
    const r = await runCli(
      ['run', '-v', '--keytab', file, '--realm', 'EXAMPLE.TEST', '--tls', 'svc@server.example.test', '--', 'hostname'],
      { PATH: `${bin}:${process.env.PATH ?? ''}`, WINLINUX_PASSWORD: 'ignored-env-password' },
    );
    assert.equal((await readFile(join(out, 'args'), 'utf8')).trim(), `-k -t ${file} svc@EXAMPLE.TEST`);
    assert.equal(await readFile(join(out, 'stdin'), 'utf8'), '', 'nothing on kinit stdin');
    assert.equal(r.code, 2, r.stderr);
    assert.match(r.stderr, /kinit failed/);
    assert.match(r.stderr, new RegExp(`kerberos keytab ${file.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`));
    assert.ok(!r.stderr.includes(KEY_BYTES) && !r.stdout.includes(KEY_BYTES));
    assert.ok(!r.stderr.includes('ignored-env-password'));
  });
});
