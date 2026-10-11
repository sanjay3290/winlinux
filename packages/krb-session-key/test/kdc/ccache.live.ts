// A context with its own credential cache sets and then clears the
// library's default ccache name (exec_create in krb_session_key.c). The
// clear used to pass NULL, which Heimdal dereferences: every
// password-Kerberos context crashed the process on Heimdal and, by the
// same code, on Apple's GSS.framework. MIT accepts NULL. Linux only; run
// with   npm run test:kdc -w @winlinux/krb-session-key
//
// The MIT leg runs in this process. The Heimdal leg runs in a child under
// WINLINUX_GSSAPI_LIBRARY when that library is installed
// (libgssapi3-heimdal on Debian/Ubuntu, which CI installs); without it the
// Heimdal leg cannot run and the test says so.
import { after, before, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { KrbClient } from '../../src/index.js';
import { SERVICES, startLocalKdc, type LocalKdc } from './kdc.js';

const indexJs = join(dirname(fileURLToPath(import.meta.url)), '../../src/index.js');

// Creates two ccache-scoped contexts in turn and disposes them, the way
// the auth provider does for password Kerberos. Returns the service
// names the contexts targeted.
const CHILD_SCRIPT = `
  const { KrbClient } = await import(process.argv[1]);
  for (const spn of ['HTTP@one.example.test', 'cifs@two.example.test']) {
    const client = await KrbClient.create(spn, { ccache: process.env.CCACHE });
    client.dispose();
  }
  console.log('created and disposed');
`;

function heimdalLibrary(): string | undefined {
  const env = process.env['WINLINUX_HEIMDAL_LIBRARY'];
  if (env) return env;
  for (const candidate of ['/usr/lib/x86_64-linux-gnu/libgssapi.so.3', '/usr/lib/aarch64-linux-gnu/libgssapi.so.3', '/usr/lib/libgssapi.so.3']) {
    if (existsSync(candidate)) return candidate;
  }
  return undefined;
}

function runChild(library: string | undefined, ccache: string): Promise<{ code: number | null; signal: string | null; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    const env: NodeJS.ProcessEnv = { ...process.env, CCACHE: ccache };
    if (library) env['WINLINUX_GSSAPI_LIBRARY'] = library;
    else delete env['WINLINUX_GSSAPI_LIBRARY'];
    execFile(
      process.execPath,
      ['--input-type=module', '-e', CHILD_SCRIPT, indexJs],
      { env },
      (err, stdout, stderr) => {
        const e = err as (Error & { code?: number | string; signal?: string }) | null;
        resolve({
          code: e ? (typeof e.code === 'number' ? e.code : null) : 0,
          signal: e?.signal ?? null,
          stdout: String(stdout),
          stderr: String(stderr),
        });
      },
    );
  });
}

describe('per-context ccache set and clear', () => {
  let kdc: LocalKdc;

  before(async () => {
    kdc = await startLocalKdc();
  });

  after(async () => {
    await kdc?.stop();
  });

  it('MIT: a ccache-scoped context works, and the override is cleared after it', async () => {
    const service = SERVICES.aes256.replace('/', '@');
    const scoped = await KrbClient.create(service, { ccache: kdc.ccache });
    const token = await scoped.step('');
    assert.ok(token.length > 0, 'the scoped ccache yields an AP-REQ');
    scoped.dispose();
    // The override is cleared: a default-credential context reads the
    // process default ccache, which has no ticket here, so it must NOT
    // find alice's. A leaked override would make this step succeed.
    const plain = await KrbClient.create(service);
    await assert.rejects(plain.step(''), /credentials were unavailable|No Kerberos credentials|no credentials/i);
    plain.dispose();
  });

  it('MIT, in a child process: two scoped contexts in turn exit 0', async () => {
    const r = await runChild(undefined, kdc.ccache);
    assert.equal(r.signal, null, r.stderr);
    assert.equal(r.code, 0, r.stderr);
    assert.match(r.stdout, /created and disposed/);
  });

  it('Heimdal, in a child process: two scoped contexts in turn exit 0 instead of crashing', async (t) => {
    const library = heimdalLibrary();
    if (!library) {
      // Not a pass: the leg did not run. Say so loudly without failing a
      // machine that has no Heimdal; CI installs libgssapi3-heimdal.
      t.diagnostic('Heimdal leg not run: no libgssapi.so.3 found (install libgssapi3-heimdal, or set WINLINUX_HEIMDAL_LIBRARY)');
      return;
    }
    const r = await runChild(library, kdc.ccache);
    assert.equal(r.signal, null, `the child died with ${r.signal}: ${r.stderr}`);
    assert.equal(r.code, 0, r.stderr);
    assert.match(r.stdout, /created and disposed/);
  });
});
