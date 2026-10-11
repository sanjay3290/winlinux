// Unit tests for the addon that need no KDC. The live handshake, the
// session key and the event-loop proof are in
// packages/auth/test/integration/live.test.ts.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { existsSync, readdirSync } from 'node:fs';
import { copyFile, mkdir, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { KrbClient, gssFactory, iovSupported, load } from '../src/index.js';

const execFileAsync = promisify(execFile);
const indexJs = join(dirname(fileURLToPath(import.meta.url)), '../src/index.js');

// Runs a small ESM script in a fresh process (the library loads once per
// process) and returns its JSON output.
async function probe(script: string, env: NodeJS.ProcessEnv = {}): Promise<Record<string, unknown>> {
  const { stdout } = await execFileAsync(process.execPath, ['--input-type=module', '-e', script], {
    env: { ...process.env, ...env },
    encoding: 'utf8',
  });
  return JSON.parse(stdout) as Record<string, unknown>;
}

const loaderScript = `
import { readFileSync } from 'node:fs';
const mapped = () => process.platform === 'linux'
  ? readFileSync('/proc/self/maps', 'utf8').includes('libgssapi_krb5')
  : null;
const out = { platform: process.platform };
const mod = await import(${JSON.stringify(indexJs)});
out.mappedBeforeLoad = mapped();
try { mod.load(); out.loaded = true; } catch (e) { out.loaded = false; out.error = e.message; }
out.mappedAfterLoad = mapped();
console.log(JSON.stringify(out));
`;

describe('krb-session-key: native library loading', () => {
  it('loads on this host', () => {
    assert.doesNotThrow(() => load());
  });

  it('Linux opens libgssapi_krb5 only at first use (dlopen); macOS links GSS.framework', async () => {
    const out = await probe(loaderScript);
    assert.equal(out.loaded, true, String(out.error));
    if (process.platform === 'linux') {
      assert.equal(out.mappedBeforeLoad, false, 'importing the package must not load libgssapi_krb5');
      assert.equal(out.mappedAfterLoad, true, 'load() maps libgssapi_krb5');
    } else {
      assert.equal(out.platform, 'darwin');
    }
  });

  it('a missing GSSAPI library gives a clear error that names the package to install (Linux)', async () => {
    const out = await probe(loaderScript, { WINLINUX_GSSAPI_LIBRARY: '/nonexistent/libgssapi_krb5.so.2' });
    if (process.platform === 'linux') {
      assert.equal(out.loaded, false);
      assert.match(String(out.error), /cannot load the MIT Kerberos GSSAPI library \/nonexistent\/libgssapi_krb5\.so\.2/);
      assert.match(String(out.error), /libgssapi-krb5-2 \(Debian\/Ubuntu\)/);
      assert.match(String(out.error), /krb5-libs/);
    } else {
      // macOS links GSS.framework at build time; the override does not apply.
      assert.equal(out.loaded, true, String(out.error));
    }
  });
});

describe('krb-session-key: context lifecycle without a KDC', () => {
  it('create() rejects a non-string service name with a TypeError', async () => {
    await assert.rejects(
      () => (KrbClient as unknown as { create: (s: unknown) => Promise<unknown> }).create(42),
      TypeError,
    );
  });

  it('create() with a missing ccache rejects asynchronously with the GSS reason', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'krbsk-'));
    try {
      const pending = gssFactory('cifs@host.example.com', { ccache: `FILE:${join(dir, 'no-such-ccache')}` });
      assert.ok(pending instanceof Promise, 'create() returns a promise');
      await assert.rejects(pending, (err: Error) => {
        assert.match(err.message, /^gss_acquire_cred: /);
        return true;
      });
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('an incomplete context has no session key and cannot verify, wrap or unwrap', async () => {
    const client = await KrbClient.create('cifs@host.example.com');
    try {
      assert.equal(client.contextComplete, false);
      assert.throws(() => client.sessionKey(), /sessionKey: the context is not complete/);
      assert.throws(() => client.verifyMic(Buffer.from('m'), Buffer.from('x')), /verifyMic: the context is not complete/);
      await assert.rejects(() => client.wrap('AA=='), /wrap: the context is not complete/);
      await assert.rejects(() => client.unwrap('AA=='), /unwrap: the context is not complete/);
    } finally {
      client.dispose();
    }
  });

  it('wrapIov/unwrapIov exist when the library has gss_wrap_iov and refuse an incomplete context', async () => {
    const client = await KrbClient.create('HTTP@host.example.com');
    try {
      // MIT krb5 (Linux) and Apple GSS.framework both export gss_wrap_iov.
      assert.equal(iovSupported(), true);
      assert.equal(typeof client.wrapIov, 'function');
      assert.equal(typeof client.unwrapIov, 'function');
      await assert.rejects(() => client.wrapIov!(Buffer.from('soap')), /wrapIov: the context is not complete/);
      await assert.rejects(() => client.unwrapIov!(Buffer.alloc(60), Buffer.from('x')), /unwrapIov: the context is not complete/);
    } finally {
      client.dispose();
    }
  });

  it('wrapIov/unwrapIov are refused after dispose()', async () => {
    const client = await KrbClient.create('HTTP@host.example.com');
    const asAny = client as unknown as { wrapIov: (d: unknown) => Promise<unknown>; unwrapIov: (h: unknown, d: unknown) => Promise<unknown> };
    client.dispose();
    await assert.rejects(() => asAny.wrapIov('soap'), /wrapIov: the context is disposed/);
    await assert.rejects(() => asAny.unwrapIov('h', 'd'), /unwrapIov: the context is disposed/);
  });

  it('a rejected operation does not leave an unhandled rejection behind (track)', async () => {
    const unhandled: unknown[] = [];
    const onUnhandled = (reason: unknown) => unhandled.push(reason);
    process.on('unhandledRejection', onUnhandled);
    const client = await KrbClient.create('HTTP@host.example.com');
    try {
      await assert.rejects(() => client.wrap('AA=='), /wrap: the context is not complete/);
      await new Promise((r) => setImmediate(r));
      assert.deepEqual(unhandled, []);
    } finally {
      process.off('unhandledRejection', onUnhandled);
      client.dispose();
    }
  });

  it('dispose() is idempotent and blocks later calls', async () => {
    const client = await KrbClient.create('cifs@host.example.com');
    client.dispose();
    client.dispose();
    await assert.rejects(() => client.step(''), /step: the context is disposed/);
    assert.throws(() => client.sessionKey(), /sessionKey: the context is disposed/);
  });

  it('dispose() during an in-flight step does not throw and releases after the step settles', async () => {
    const client = await KrbClient.create('cifs@host.invalid');
    const stepping = client.step(''); // no credentials/KDC: it rejects asynchronously
    assert.doesNotThrow(() => client.dispose(), 'cleanup must not see the busy error');
    await assert.rejects(stepping);
    await new Promise((r) => setImmediate(r));
    await assert.rejects(() => client.step(''), /the context is disposed/);
  });
});

// The loader (node-gyp-build) tries <package>/build/Release first, then
// <package>/prebuilds/<platform>-<arch>/. PREBUILDS_ONLY=1 makes it skip the
// local build, which is how an installed package with no compiler behaves.
describe('krb-session-key: prebuilt binary loading', () => {
  const pkgDir = join(dirname(fileURLToPath(import.meta.url)), '../..');
  const builtAddon = join(pkgDir, 'build/Release/krb_session_key.node');
  const prebuildDir = join(pkgDir, 'prebuilds', `${process.platform}-${process.arch}`);
  // The file name prebuildify gives a Node-API build of this package.
  const prebuildFile = join(prebuildDir, '@winlinux+krb-session-key.node');

  it('loads from prebuilds/<platform>-<arch>/ when no local build is used', async () => {
    // Use the locally built addon as the prebuild, unless a real prebuild
    // for this platform is already there (never overwrite it).
    const haveRealPrebuild = existsSync(prebuildDir) && readdirSync(prebuildDir).some((f) => f.endsWith('.node'));
    if (!haveRealPrebuild) {
      await mkdir(prebuildDir, { recursive: true });
      await copyFile(builtAddon, prebuildFile);
    }
    try {
      const out = await probe(loaderScript, { PREBUILDS_ONLY: '1' });
      assert.equal(out.loaded, true, String(out.error));
    } finally {
      if (!haveRealPrebuild) await rm(prebuildFile, { force: true });
    }
  });

  it('keeps the "not built" error when neither a build nor a prebuild loads', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'krbsk-noprebuild-'));
    try {
      // node-gyp-build honours <NAME>_PREBUILD as the directory to search.
      const out = await probe(loaderScript, { PREBUILDS_ONLY: '1', '@WINLINUX/KRB_SESSION_KEY_PREBUILD': dir });
      assert.equal(out.loaded, false);
      assert.match(String(out.error), /^@winlinux\/krb-session-key: the native addon is not built \(No native build was found for platform=/);
      assert.match(String(out.error), /Run `npm rebuild @winlinux\/krb-session-key`/);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
