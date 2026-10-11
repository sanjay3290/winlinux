// Fake-`kinit` on PATH: argv + stdin asserted, no real KDC. No network.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile, chmod } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { KerberosAuthProvider, type GssClient } from '../src/auth/kerberos.js';
import type { AuthTarget } from '../src/auth/types.js';

const TARGET: AuthTarget = { host: 'server.domain', service: 'HTTP' };

const fakeGss = async (): Promise<GssClient> => ({
  contextComplete: true,
  step: async () => 'eA==',
  wrap: async () => 'eA==',
  unwrap: async () => 'eA==',
});

async function makeFakeKinit(
  exitCode: number,
  versionBanner?: string,
): Promise<{ dir: string; out: string }> {
  const dir = await mkdtemp(join(tmpdir(), 'fakebin-'));
  const out = await mkdtemp(join(tmpdir(), 'kinitout-'));
  const script =
    '#!/bin/sh\n' +
    (versionBanner
      ? `if [ "$1" = "--version" ]; then echo "${versionBanner}"; exit 0; fi\n`
      : '') +
    `echo "$@" > "${out}/args"\n` +
    `cat > "${out}/stdin"\n` +
    `echo "$KRB5CCNAME" > "${out}/env"\n` +
    `exit ${exitCode}\n`;
  await writeFile(join(dir, 'kinit'), script);
  await chmod(join(dir, 'kinit'), 0o755);
  return { dir, out };
}

describe('kinit invocation', () => {
  it('passes principal on argv and password on stdin, with a temp KRB5CCNAME', async () => {
    const { dir, out } = await makeFakeKinit(0);
    const savedPath = process.env.PATH;
    const savedCcache = process.env.KRB5CCNAME;
    process.env.PATH = `${dir}${savedPath ? `:${savedPath}` : ''}`;
    try {
      const ctx = new KerberosAuthProvider({ gss: fakeGss }).createContext(TARGET, {
        username: 'alice',
        password: 's3cret-pw',
        domain: 'example.com',
      });
      await ctx.step();
      assert.equal((await readFile(join(out, 'args'), 'utf8')).trim(), 'alice@EXAMPLE.COM');
      assert.equal(await readFile(join(out, 'stdin'), 'utf8'), 's3cret-pw');
      const ccache = (await readFile(join(out, 'env'), 'utf8')).trim();
      assert.match(ccache, /^FILE:/);
      await ctx.dispose!();
      assert.equal(process.env.KRB5CCNAME, savedCcache);
    } finally {
      if (savedPath === undefined) delete process.env.PATH;
      else process.env.PATH = savedPath;
      if (process.env.KRB5CCNAME !== savedCcache) {
        if (savedCcache === undefined) delete process.env.KRB5CCNAME;
        else process.env.KRB5CCNAME = savedCcache;
      }
    }
  });

  it('adds --password-file=STDIN for Heimdal kinit, which ignores a piped stdin otherwise', async () => {
    const { dir, out } = await makeFakeKinit(0, 'kinit (Heimdal 1.5.1apple1)');
    const savedPath = process.env.PATH;
    process.env.PATH = `${dir}${savedPath ? `:${savedPath}` : ''}`;
    try {
      const ctx = new KerberosAuthProvider({ gss: fakeGss }).createContext(TARGET, {
        username: 'alice',
        password: 's3cret-pw',
        realm: 'EXAMPLE.COM',
      });
      await ctx.step();
      assert.equal(
        (await readFile(join(out, 'args'), 'utf8')).trim(),
        '--password-file=STDIN alice@EXAMPLE.COM',
      );
      assert.equal(await readFile(join(out, 'stdin'), 'utf8'), 's3cret-pw');
      await ctx.dispose!();
    } finally {
      if (savedPath === undefined) delete process.env.PATH;
      else process.env.PATH = savedPath;
    }
  });

  it('surfaces kinit failure instead of hanging or faking success', async () => {
    const { dir } = await makeFakeKinit(3);
    const savedPath = process.env.PATH;
    process.env.PATH = `${dir}${savedPath ? `:${savedPath}` : ''}`;
    try {
      const ctx = new KerberosAuthProvider({ gss: fakeGss }).createContext(TARGET, {
        username: 'alice',
        password: 'pw',
        realm: 'EXAMPLE.COM',
      });
      await assert.rejects(() => ctx.step(), /kinit failed/);
    } finally {
      if (savedPath === undefined) delete process.env.PATH;
      else process.env.PATH = savedPath;
    }
  });

});
