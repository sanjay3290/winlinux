// The `kerberos` package is an optional dependency. Without it, NTLM
// and Basic work, Kerberos fails with an error that names the package to
// install, and Negotiate falls back to NTLM when a password exists. The
// unit tests stand in for the package through the importer seam; the child
// process test hides the real package from Node's resolver, so the error
// is the one Node raises for a consumer who installed with --omit=optional.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import {
  GSSAPI_LIBRARY_HINT,
  KERBEROS_PACKAGE_NOT_INSTALLED,
  KerberosAuthProvider,
  createKerberosPackageGssFactory,
  isKerberosPackageMissing,
  kerberosPackageLoadError,
  type KerberosImporter,
} from '../src/auth/kerberos.js';
import { NegotiateAuthProvider } from '../src/auth/negotiate.js';
import { OID_NTLMSSP, unframeSpnego } from '../src/auth/spnego.js';
import type { AuthTarget } from '../src/auth/types.js';

const TARGET: AuthTarget = { host: 'server.domain', service: 'HTTP' };

// What Node raises for `import('kerberos')` when the package is not installed.
const notInstalled = (): Error =>
  Object.assign(new Error("Cannot find package 'kerberos' imported from /app/node_modules/@winlinux/auth/dist/src/auth/kerberos.js"), {
    code: 'ERR_MODULE_NOT_FOUND',
  });
// ... and what the package raises when its own binding cannot load.
const bindingMissing = (): Error =>
  Object.assign(new Error("Cannot find module '/app/node_modules/kerberos/build/Release/kerberos.node'\nRequire stack:\n- /app/node_modules/kerberos/lib/util.js"), {
    code: 'MODULE_NOT_FOUND',
  });
const libraryMissing = (): Error =>
  Object.assign(new Error('libgssapi_krb5.so.2: cannot open shared object file: No such file or directory'), {
    code: 'ERR_DLOPEN_FAILED',
  });

const failingImporter = (make: () => Error): KerberosImporter => async () => {
  throw make();
};

describe('the kerberos package is optional', () => {
  it('tells a missing package apart from a package that cannot load', () => {
    assert.equal(isKerberosPackageMissing(notInstalled()), true);
    assert.equal(isKerberosPackageMissing(Object.assign(new Error("Cannot find module 'kerberos'"), { code: 'MODULE_NOT_FOUND' })), true);
    assert.equal(isKerberosPackageMissing(bindingMissing()), false);
    assert.equal(isKerberosPackageMissing(libraryMissing()), false);
    assert.equal(isKerberosPackageMissing(new Error("Cannot find package 'kerberos'")), false, 'no code: not the resolver');
    assert.equal(isKerberosPackageMissing(null), false);
  });

  it('a missing package becomes the install hint; other load errors keep their message', () => {
    assert.equal(kerberosPackageLoadError(notInstalled()).message, KERBEROS_PACKAGE_NOT_INSTALLED);
    assert.match(KERBEROS_PACKAGE_NOT_INSTALLED, /npm install kerberos/);
    const binding = kerberosPackageLoadError(bindingMissing());
    assert.equal(binding.message, bindingMissing().message);
    const library = kerberosPackageLoadError(libraryMissing());
    assert.equal(library.message, `${libraryMissing().message}; ${GSSAPI_LIBRARY_HINT}`);
    assert.equal((library.cause as Error).message, libraryMissing().message);
    assert.equal(kerberosPackageLoadError('boom').message, 'boom');
  });

  it('a Kerberos context fails at its first step with the install hint', async () => {
    const factory = createKerberosPackageGssFactory(failingImporter(notInstalled));
    const ctx = new KerberosAuthProvider({ gss: factory }).createContext(TARGET, { username: 'alice', useTicketCache: true });
    await assert.rejects(ctx.step(), (err: Error) => {
      assert.equal(err.message, `Kerberos init failed: ${KERBEROS_PACKAGE_NOT_INSTALLED}`);
      return true;
    });
    assert.equal(ctx.complete, false);
  });

  it('Negotiate with a password falls back to NTLM when the package is missing', async () => {
    const factory = createKerberosPackageGssFactory(failingImporter(notInstalled));
    const ctx = new NegotiateAuthProvider({ gss: factory }).createContext(TARGET, {
      username: 'alice',
      password: 'pw',
      domain: 'CORP',
      useTicketCache: true, // no kinit
    });
    const first = await ctx.step();
    assert.equal(ctx.negotiatedMechanism, 'ntlm');
    const init = unframeSpnego(first.output as Buffer);
    assert.equal(init.kind, 'init');
    if (init.kind !== 'init') throw new Error('unreachable');
    assert.deepEqual(init.mechTypes, [OID_NTLMSSP]);
  });

  it('Negotiate with the ticket cache alone reports the missing package, not a missing NTLM password', async () => {
    const factory = createKerberosPackageGssFactory(failingImporter(notInstalled));
    const ctx = new NegotiateAuthProvider({ gss: factory }).createContext(TARGET, { username: 'alice', useTicketCache: true });
    await assert.rejects(ctx.step(), (err: Error) => {
      assert.equal(err.message, `Kerberos init failed: ${KERBEROS_PACKAGE_NOT_INSTALLED}`);
      return true;
    });
    assert.equal(ctx.negotiatedMechanism, undefined);
  });

  it('Negotiate with the ticket cache alone keeps any other Kerberos failure too', async () => {
    const ctx = new NegotiateAuthProvider({
      gss: async () => {
        throw new Error('gss_acquire_cred: No credentials were supplied');
      },
    }).createContext(TARGET, { username: 'alice', useTicketCache: true });
    await assert.rejects(ctx.step(), /No credentials were supplied/);
  });

  // The real import('kerberos') in the compiled module, with the package
  // and the addon hidden from Node's resolver for one child process.
  it('without the package: Basic and NTLM work, Kerberos names the package, Negotiate uses NTLM', async () => {
    const helpers = (name: string) => fileURLToPath(new URL(`./helpers/${name}.js`, import.meta.url));
    const { stdout, stderr } = await promisify(execFile)(
      process.execPath,
      ['--import', helpers('no-kerberos-register'), helpers('no-kerberos-child')],
      { timeout: 30_000 },
    );
    assert.equal(stderr.trim(), '', 'the child prints no warnings');
    const result = JSON.parse(stdout) as Record<string, unknown>;
    assert.equal(result.basicComplete, true);
    assert.equal(result.ntlmOffersNtlm, true);
    assert.equal(result.kerberos, `Kerberos init failed: ${KERBEROS_PACKAGE_NOT_INSTALLED}`);
    assert.match(result.kerberos as string, /npm install kerberos/);
    assert.equal(result.negotiateWon, 'ntlm');
    assert.equal(result.negotiateOffersNtlm, true);
    assert.equal(result.negotiateTicketCacheOnly, `Kerberos init failed: ${KERBEROS_PACKAGE_NOT_INSTALLED}`);
  });
});
