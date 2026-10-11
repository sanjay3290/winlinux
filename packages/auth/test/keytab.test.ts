// Kerberos keytab sign-in. Fake kinit (on PATH or injected) and a
// fake GSS layer: no KDC, no network.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { chmod, mkdir, mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  KerberosAuthProvider,
  checkKeytabFile,
  defaultKinitRunner,
  keytabCredentialsError,
  kinitArgv,
  type GssClient,
  type KinitRunner,
} from '../src/auth/kerberos.js';
import { NegotiateAuthProvider } from '../src/auth/negotiate.js';
import { NtlmAuthProvider } from '../src/auth/ntlm/provider.js';
import { BasicAuthProvider } from '../src/auth/basic.js';
import { frameNegTokenResp, OID_NTLMSSP } from '../src/auth/spnego.js';
import type { AuthTarget, Credentials } from '../src/auth/types.js';

const TARGET: AuthTarget = { host: 'server.example.test', service: 'HTTP' };
// Sentinel key bytes: must never appear in an error, argv or stdin.
const KEY_BYTES = 'KEYTAB-SENTINEL-BYTES-0123456789';

const fakeGss = async (): Promise<GssClient> => ({
  contextComplete: true,
  step: async () => 'eA==',
  wrap: async () => 'eA==',
  unwrap: async () => 'eA==',
});

async function keytabFile(mode: number): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'winlinux-keytab-'));
  const file = join(dir, 'svc.keytab');
  await writeFile(file, KEY_BYTES);
  await chmod(file, mode);
  return file;
}

interface KinitCall {
  args: string[];
  password: string | undefined;
  keytab: string | undefined;
  ccache: string | undefined;
}

function recordingKinit(): { calls: KinitCall[]; kinit: KinitRunner } {
  const calls: KinitCall[] = [];
  return {
    calls,
    kinit: async (args, password, env, keytab) => {
      calls.push({ args, password, keytab, ccache: env.KRB5CCNAME });
    },
  };
}

async function withFakeKinitOnPath<T>(versionBanner: string | undefined, fn: (out: string) => Promise<T>): Promise<T> {
  const dir = await mkdtemp(join(tmpdir(), 'fakebin-'));
  const out = await mkdtemp(join(tmpdir(), 'kinitout-'));
  const script =
    '#!/bin/sh\n' +
    (versionBanner ? `if [ "$1" = "--version" ]; then echo "${versionBanner}"; exit 0; fi\n` : '') +
    `echo "$@" > "${out}/args"\n` +
    `cat > "${out}/stdin"\n` +
    'exit 0\n';
  await writeFile(join(dir, 'kinit'), script);
  await chmod(join(dir, 'kinit'), 0o755);
  const savedPath = process.env.PATH;
  process.env.PATH = `${dir}${savedPath ? `:${savedPath}` : ''}`;
  try {
    return await fn(out);
  } finally {
    if (savedPath === undefined) delete process.env.PATH;
    else process.env.PATH = savedPath;
  }
}

describe('kinit argv for a keytab', () => {
  it('MIT: -k -t <file> <principal>; Heimdal: --keytab=<file> --use-keytab <principal>', () => {
    assert.deepEqual(kinitArgv(['svc@EXAMPLE.TEST'], false, '/k/svc.keytab'), ['-k', '-t', '/k/svc.keytab', 'svc@EXAMPLE.TEST']);
    assert.deepEqual(kinitArgv(['svc@EXAMPLE.TEST'], true, '/k/svc.keytab'), [
      '--keytab=/k/svc.keytab',
      '--use-keytab',
      'svc@EXAMPLE.TEST',
    ]);
  });

  it('the password argv is unchanged', () => {
    assert.deepEqual(kinitArgv(['a@EXAMPLE.TEST'], false), ['a@EXAMPLE.TEST']);
    assert.deepEqual(kinitArgv(['a@EXAMPLE.TEST'], true), ['--password-file=STDIN', 'a@EXAMPLE.TEST']);
  });

  it('defaultKinitRunner needs exactly one of a password or a keytab', async () => {
    await assert.rejects(defaultKinitRunner(['a@EXAMPLE.TEST'], 'pw', {}, '/k/f'), /exactly one/);
    await assert.rejects(defaultKinitRunner(['a@EXAMPLE.TEST'], undefined, {}), /exactly one/);
  });
});

describe('Kerberos context with a keytab', () => {
  it('MIT kinit on PATH: keytab argv, nothing on stdin', async () => {
    const file = await keytabFile(0o600);
    await withFakeKinitOnPath(undefined, async (out) => {
      const ctx = new KerberosAuthProvider({ gss: fakeGss }).createContext(TARGET, {
        username: 'svc',
        keytab: file,
        realm: 'EXAMPLE.TEST',
      });
      await ctx.step();
      assert.equal((await readFile(join(out, 'args'), 'utf8')).trim(), `-k -t ${file} svc@EXAMPLE.TEST`);
      assert.equal(await readFile(join(out, 'stdin'), 'utf8'), '');
      await ctx.dispose!();
    });
  });

  it('Heimdal kinit on PATH: --keytab= --use-keytab, nothing on stdin', async () => {
    const file = await keytabFile(0o600);
    await withFakeKinitOnPath('kinit (Heimdal 1.5.1apple1)', async (out) => {
      const ctx = new KerberosAuthProvider({ gss: fakeGss }).createContext(TARGET, {
        username: 'svc',
        keytab: file,
        domain: 'example.test',
      });
      await ctx.step();
      assert.equal(
        (await readFile(join(out, 'args'), 'utf8')).trim(),
        `--keytab=${file} --use-keytab svc@EXAMPLE.TEST`,
      );
      assert.equal(await readFile(join(out, 'stdin'), 'utf8'), '');
      await ctx.dispose!();
    });
  });

  it('runs kinit with the keytab into the private temp ccache that GSS uses', async () => {
    const file = await keytabFile(0o600);
    const rec = recordingKinit();
    let gssCcache: string | undefined;
    const ctx = new KerberosAuthProvider({
      kinit: rec.kinit,
      gss: async (_service, init) => {
        gssCcache = init.ccache;
        return fakeGss();
      },
    }).createContext(TARGET, { username: 'svc@EXAMPLE.TEST', keytab: file });
    await ctx.step();
    assert.equal(rec.calls.length, 1);
    assert.deepEqual(rec.calls[0], { args: ['svc@EXAMPLE.TEST'], password: undefined, keytab: file, ccache: gssCcache });
    assert.match(gssCcache ?? '', /^FILE:/);
    await ctx.dispose!();
  });

  const refusals: Array<[string, Credentials, RegExp]> = [
    ['a password', { username: 'svc', realm: 'EXAMPLE.TEST', keytab: '/k/f', password: 'pw' }, /keytab and a password/],
    ['the ticket cache', { username: 'svc', realm: 'EXAMPLE.TEST', keytab: '/k/f', useTicketCache: true }, /keytab and the ticket cache/],
    ['no realm', { username: 'svc', keytab: '/k/f' }, /needs a realm/],
    ['an empty path', { username: 'svc', realm: 'EXAMPLE.TEST', keytab: '' }, /file path/],
  ];
  for (const [what, creds, message] of refusals) {
    it(`refuses a keytab with ${what}, before kinit`, async () => {
      assert.match(keytabCredentialsError(creds)?.message ?? '', message);
      const rec = recordingKinit();
      const ctx = new KerberosAuthProvider({ kinit: rec.kinit, gss: fakeGss }).createContext(TARGET, creds);
      await assert.rejects(ctx.step(), message);
      assert.equal(rec.calls.length, 0);
    });
  }

  it('refuses a keytab readable by group or others (0644, 0640, 0604), with a chmod 600 hint', async () => {
    for (const mode of [0o644, 0o640, 0o604, 0o620]) {
      const file = await keytabFile(mode);
      const rec = recordingKinit();
      const ctx = new KerberosAuthProvider({ kinit: rec.kinit, gss: fakeGss }).createContext(TARGET, {
        username: 'svc',
        realm: 'EXAMPLE.TEST',
        keytab: file,
      });
      await assert.rejects(ctx.step(), (err: Error) => {
        assert.equal(err.message, `keytab ${file} is accessible by group or others; run chmod 600 ${file}`);
        assert.ok(!err.message.includes(KEY_BYTES));
        return true;
      });
      assert.equal(rec.calls.length, 0, `mode ${mode.toString(8)}: no kinit`);
    }
  });

  it('accepts 0600 and 0400', async () => {
    for (const mode of [0o600, 0o400]) await checkKeytabFile(await keytabFile(mode));
  });

  it('refuses a missing file and a directory', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'winlinux-keytab-'));
    await assert.rejects(checkKeytabFile(join(dir, 'none.keytab')), /no such file/);
    const sub = join(dir, 'sub');
    await mkdir(sub, { mode: 0o700 });
    await assert.rejects(checkKeytabFile(sub), /not a regular file/);
  });

  it('a kinit failure names kinit, never the key bytes', async () => {
    const file = await keytabFile(0o600);
    const ctx = new KerberosAuthProvider({
      gss: fakeGss,
      kinit: async () => {
        throw new Error("kinit failed: kinit: Key table entry not found while getting initial credentials");
      },
    }).createContext(TARGET, { username: 'svc', realm: 'EXAMPLE.TEST', keytab: file });
    await assert.rejects(ctx.step(), (err: Error) => {
      assert.match(err.message, /^kinit failed/);
      assert.ok(!err.message.includes(KEY_BYTES));
      return true;
    });
  });
});

describe('other mechanisms with a keytab', () => {
  it('NTLM and Basic refuse a keytab', async () => {
    const creds = { username: 'svc', realm: 'EXAMPLE.TEST', keytab: '/k/f' };
    await assert.rejects(new NtlmAuthProvider().createContext(TARGET, creds).step(), /NTLM cannot use a keytab/);
    assert.throws(() => new BasicAuthProvider().createContext(TARGET, creds), /Basic auth cannot use a keytab/);
  });

  it('Negotiate with a keytab runs Kerberos and never falls back to NTLM', async () => {
    const file = await keytabFile(0o600);
    const creds = { username: 'svc', realm: 'EXAMPLE.TEST', keytab: file };
    const rec = recordingKinit();
    const ok = new NegotiateAuthProvider({ kinit: rec.kinit, gss: fakeGss }).createContext(TARGET, creds);
    await ok.step();
    assert.equal(ok.negotiatedMechanism, 'kerberos');
    assert.equal(rec.calls[0]?.keytab, file);
    await ok.dispose!();

    // A client-side Kerberos failure is final: the Kerberos error, not an NTLM token.
    const failing = new NegotiateAuthProvider({
      kinit: rec.kinit,
      gss: async () => {
        throw new Error('Cannot find KDC for realm "EXAMPLE.TEST"');
      },
    }).createContext(TARGET, creds);
    await assert.rejects(failing.step(), /Kerberos init failed: Cannot find KDC/);
  });

  it('Negotiate with a keytab refuses a server that picks NTLM', async () => {
    const file = await keytabFile(0o600);
    const gss = async (): Promise<GssClient> => ({
      contextComplete: false,
      step: async () => 'eA==',
      wrap: async () => 'eA==',
      unwrap: async () => 'eA==',
    });
    const ctx = new NegotiateAuthProvider({ kinit: recordingKinit().kinit, gss }).createContext(TARGET, {
      username: 'svc',
      realm: 'EXAMPLE.TEST',
      keytab: file,
    });
    await ctx.step();
    const pickNtlm = frameNegTokenResp({ supportedMech: OID_NTLMSSP, responseToken: Buffer.from('x') });
    await assert.rejects(ctx.step(pickNtlm), /server picked NTLM, which was not offered/);
  });
});
