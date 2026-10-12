import { execFile } from 'node:child_process';
import { constants } from 'node:fs';
import { access, mkdtemp, rm, stat } from 'node:fs/promises';
import { isIP } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { AuthProvider, AuthTarget, Credentials, SecurityContext, StepResult } from './types.js';
import type { ChannelBoundTarget } from './channel-bindings.js';
import type { WinRMMessageProtection, WinRMSealed } from './winrm-extension.js';
import {
  NegState,
  OID_KRB5,
  encodeMechTypeList,
  frameNegTokenInit,
  frameNegTokenResp,
  unframeSpnego,
} from './spnego.js';

// Narrow GSS seam (base64 in/out). Tests inject fakes. Production uses
// @winlinux/krb-session-key when it is installed and built, else the
// `kerberos` package. The optional members exist only on the addon.
export interface GssClient {
  readonly contextComplete: boolean;
  // True when the GSS layer holds the channel bindings of GssInit and puts
  // them into every token. Undefined with the `kerberos` package,
  // which takes no bindings and sends none.
  readonly channelBound?: boolean;
  step(challenge: string): Promise<string>;
  wrap(data: string, options?: { protect?: boolean }): Promise<string>;
  unwrap(challenge: string): Promise<string>;
  // Full GSS session key (GSS_C_INQ_SSPI_SESSION_KEY) of a complete context.
  sessionKey?(): Buffer;
  // gss_verify_mic; false when the MIC does not verify.
  verifyMic?(message: Buffer, mic: Buffer): boolean;
  // gss_wrap_iov / gss_unwrap_iov with HEADER | DATA | PADDING: the
  // MS-WSMV split for WinRM message encryption. Present only when the
  // GSS library has gss_wrap_iov (the addon tests for it at load).
  wrapIov?(data: Buffer): Promise<WinRMSealed>;
  unwrapIov?(header: Buffer, data: Buffer): Promise<Buffer>;
  dispose?(): void;
}

export interface GssInit {
  principal?: string;
  // Credential cache for this context only (for example FILE:/tmp/x/ccache).
  // Absent: the GSS library default (KRB5CCNAME or the system default).
  ccache?: string;
  // Channel bindings: the application_data of a GSS channel-binding
  // structure with no addresses, the target's `channelBindings`
  // (channel-bindings.ts), for example the RFC 5929 tls-server-end-point
  // binding of the TLS server certificate. The AP-REQ then carries the MD5
  // of the packed structure in its authenticator checksum (RFC 4121
  // 4.1.1.2), which a server that enforces channel binding compares with
  // its own certificate.
  channelBindings?: Buffer;
}

export type GssFactory = (service: string, init: GssInit) => Promise<GssClient>;

// The part of @winlinux/krb-session-key this module uses. Declared here so
// auth builds without the addon.
interface KrbSessionKeyModule {
  load(): void;
  gssFactory(service: string, init: GssInit): Promise<GssClient>;
}

// Serializes the fallback path's KRB5CCNAME window (see withCcacheEnv).
let ccacheEnvLock: Promise<void> = Promise.resolve();

// The `kerberos` package takes no ccache argument and reads KRB5CCNAME when
// it acquires credentials (initializeClient with a principal, or the first
// step). Only for that fallback: set KRB5CCNAME for one call, under a
// process-wide lock, and restore it before the lock is released.
// Known window: while that call runs (initializeClient, or the first step's
// TGS round trip), process.env.KRB5CCNAME holds this context's temp ccache.
// Other code in the process that reads the env in that window (a child
// process, another Kerberos library) sees it. Auth contexts do not: they
// wait on the lock. With @winlinux/krb-session-key there is no window.
export async function withCcacheEnv<T>(ccache: string, fn: () => Promise<T>): Promise<T> {
  const previous = ccacheEnvLock;
  let release!: () => void;
  ccacheEnvLock = new Promise<void>((r) => {
    release = r;
  });
  await previous;
  const saved = process.env.KRB5CCNAME;
  process.env.KRB5CCNAME = ccache;
  try {
    return await fn();
  } finally {
    if (saved === undefined) delete process.env.KRB5CCNAME;
    else process.env.KRB5CCNAME = saved;
    release();
  }
}

// The `kerberos` package is an optional dependency of @winlinux/auth
//: only this import loads it, so an NTLM-only or Basic-only consumer
// can install with `npm install --omit=optional` and skip its native build.
// A missing package raises Node's ERR_MODULE_NOT_FOUND (MODULE_NOT_FOUND
// from a CommonJS require), which becomes the install hint below. A package
// that is installed but cannot load its binding (the build failed, or the
// GSSAPI run-time library is missing) raises its own error, which passes
// through with a hint for the library case.
export const KERBEROS_PACKAGE_NOT_INSTALLED =
  'the kerberos package is not installed: run `npm install kerberos` ' +
  '(an optional dependency of @winlinux/auth; NTLM and Basic work without it), ' +
  'or install @winlinux/krb-session-key';
export const GSSAPI_LIBRARY_HINT =
  'install the MIT Kerberos run-time library: libgssapi-krb5-2 (Debian/Ubuntu), krb5-libs (Fedora/RHEL/Alpine)';

// The part of the `kerberos` package this module uses. Declared here, like
// KrbSessionKeyModule, so the emitted declarations never name the optional
// package: a consumer without it still type-checks against @winlinux/auth.
export interface KerberosPackageClient {
  contextComplete: boolean;
  step(challenge: string): Promise<string>;
  wrap(challenge: string, options?: { protect?: boolean }): Promise<string>;
  unwrap(challenge: string): Promise<string>;
}
export interface KerberosPackage {
  GSS_C_MUTUAL_FLAG: number;
  GSS_C_REPLAY_FLAG: number;
  GSS_C_SEQUENCE_FLAG: number;
  GSS_C_CONF_FLAG: number;
  GSS_C_INTEG_FLAG: number;
  GSS_MECH_OID_KRB5: number;
  initializeClient(service: string, options?: { principal?: string; gssFlag?: number; mechOID?: number }): Promise<KerberosPackageClient>;
}
export type KerberosImporter = () => Promise<KerberosPackage>;

export function isKerberosPackageMissing(err: unknown): boolean {
  const code = (err as { code?: unknown } | null)?.code;
  if (code !== 'ERR_MODULE_NOT_FOUND' && code !== 'MODULE_NOT_FOUND') return false;
  return /Cannot find (?:package|module) 'kerberos'/.test((err as Error).message ?? '');
}

export function kerberosPackageLoadError(err: unknown): Error {
  if (isKerberosPackageMissing(err)) return new Error(KERBEROS_PACKAGE_NOT_INSTALLED);
  if (err instanceof Error && /libgssapi_krb5/.test(err.message)) {
    return new Error(`${err.message}; ${GSSAPI_LIBRARY_HINT}`, { cause: err });
  }
  return err instanceof Error ? err : new Error(String(err));
}

// Builds the `kerberos` package factory on an importer, so tests can stand
// in for the package without uninstalling it. The package has no channel
// binding parameter, so a context on it sends none: over TLS, only
// the verified server certificate ties its AP-REQ to the server. The
// context reports this as channelBound false.
export function createKerberosPackageGssFactory(importKerberos: KerberosImporter = () => import('kerberos')): GssFactory {
  return async (service, init) => {
    let krb: KerberosPackage;
    try {
      krb = await importKerberos();
    } catch (err) {
      throw kerberosPackageLoadError(err);
    }
    const create = () =>
      krb.initializeClient(service, {
        principal: init.principal,
        // eslint-disable-next-line no-bitwise
        gssFlag:
          krb.GSS_C_MUTUAL_FLAG |
          krb.GSS_C_REPLAY_FLAG |
          krb.GSS_C_SEQUENCE_FLAG |
          krb.GSS_C_CONF_FLAG |
          krb.GSS_C_INTEG_FLAG,
        // Raw KRB5 tokens; SPNEGO framing stays in this module (design risk R1).
        mechOID: krb.GSS_MECH_OID_KRB5,
      });
    const { ccache } = init;
    if (!ccache) return create();
    const client = await withCcacheEnv(ccache, create);
    let first = true;
    return {
      get contextComplete() {
        return client.contextComplete;
      },
      step(challenge: string) {
        if (!first) return client.step(challenge);
        first = false;
        return withCcacheEnv(ccache, () => client.step(challenge));
      },
      wrap: (data, options) => client.wrap(data, options),
      unwrap: (challenge) => client.unwrap(challenge),
    };
  };
}

export const kerberosPackageGssFactory: GssFactory = createKerberosPackageGssFactory();

let addonModule: Promise<KrbSessionKeyModule | null> | null = null;
let addonError: string | undefined;

// Resolves the addon once. null when it is not installed, not built, or
// cannot load the system GSSAPI library (the reason is kept for errors).
export function loadKrbSessionKey(): Promise<KrbSessionKeyModule | null> {
  addonModule ??= (async () => {
    const specifier = '@winlinux/krb-session-key';
    let mod: KrbSessionKeyModule;
    try {
      mod = (await import(specifier)) as KrbSessionKeyModule;
    } catch {
      return null; // not installed: the normal fallback case
    }
    try {
      mod.load();
      return mod;
    } catch (err) {
      addonError = (err as Error).message;
      return null;
    }
  })();
  return addonModule;
}

// True when @winlinux/krb-session-key is installed and loads, so Kerberos
// contexts expose a session key (SMB2 signing).
export async function kerberosSessionKeyAvailable(): Promise<boolean> {
  return (await loadKrbSessionKey()) !== null;
}

export const defaultGssFactory: GssFactory = async (service, init) => {
  const addon = await loadKrbSessionKey();
  if (addon) return addon.gssFactory(service, init);
  try {
    return await kerberosPackageGssFactory(service, init);
  } catch (err) {
    if (!addonError) throw err;
    throw new Error(`${(err as Error).message} (${addonError})`);
  }
};

// args: the client principal. With a password, the runner writes it to
// kinit's stdin. With a keytab, kinit reads the key from the file
// and the runner writes nothing to stdin. Never both.
export type KinitRunner = (
  args: string[],
  password: string | undefined,
  env: NodeJS.ProcessEnv,
  keytab?: string,
) => Promise<void>;

// Heimdal kinit (macOS) reads the password from the tty unless told to use
// stdin; MIT kinit reads stdin when it is not a tty and has no such flag.
function kinitIsHeimdal(env: NodeJS.ProcessEnv): Promise<boolean> {
  return new Promise<boolean>((resolve) => {
    const child = execFile('kinit', ['--version'], { env }, (_err, stdout, stderr) =>
      resolve(/heimdal/i.test(`${stdout}${stderr}`)),
    );
    child.stdin?.on('error', () => undefined);
    child.stdin?.end();
  });
}

// The kinit argv for one flavour. Password: MIT reads stdin as is; Heimdal
// needs --password-file=STDIN. Keytab: MIT `-k -t <file>`, Heimdal
// `--keytab=<file> --use-keytab`.
export function kinitArgv(args: string[], heimdal: boolean, keytab?: string): string[] {
  if (keytab !== undefined) {
    return heimdal ? [`--keytab=${keytab}`, '--use-keytab', ...args] : ['-k', '-t', keytab, ...args];
  }
  return heimdal ? ['--password-file=STDIN', ...args] : args;
}

export const defaultKinitRunner: KinitRunner = async (args, password, env, keytab) => {
  if ((password === undefined) === (keytab === undefined)) {
    throw new Error('kinit needs exactly one of a password or a keytab');
  }
  const argv = kinitArgv(args, await kinitIsHeimdal(env), keytab);
  return new Promise<void>((resolve, reject) => {
    const child = execFile('kinit', argv, { env }, (err, _stdout, stderr) => {
      if (err) reject(new Error(`kinit failed: ${(stderr || err.message).trim()}`));
      else resolve();
    });
    child.stdin?.on('error', () => undefined);
    if (password !== undefined) child.stdin?.write(password);
    child.stdin?.end();
  });
};

export interface KerberosProviderDeps {
  gss?: GssFactory;
  kinit?: KinitRunner;
}

// Kerberos needs a name the KDC has a principal for. An IP address builds
// `HTTP@<ip>`, which no AD registers, so the KDC answers "Server not found in
// Kerberos database" after a kinit and a TGS round trip. Refuse it up
// front, before any network, unless the caller names the SPN host. No reverse
// DNS: it is spoofable (MIT `rdns = false` is the safe default).
export function kerberosHostError(target: AuthTarget): Error | undefined {
  if (target.spn || !isIP(target.host)) return undefined;
  return new Error(
    `Kerberos needs the server's DNS name, not an IP address (${target.host}); ` +
      "use the FQDN, name the SPN host explicitly, or use NTLM",
  );
}

function servicePrincipal(target: AuthTarget): string {
  if (target.spn) return target.spn.replace('/', '@');
  return `${target.service}@${target.host}`;
}

function clientPrincipal(creds: Credentials): string | undefined {
  if (creds.username.includes('@')) return creds.username;
  const realm = creds.realm ?? creds.domain?.toUpperCase();
  if (realm) return `${creds.username}@${realm}`;
  return undefined;
}

function kinitPrincipal(creds: Credentials): string {
  const p = clientPrincipal(creds);
  if (!p) {
    const what = creds.keytab !== undefined ? 'keytab' : 'password';
    throw new Error(`Kerberos ${what} auth needs a realm: set realm or domain`);
  }
  return p;
}

// Keytab sign-in: kinit reads the key from the file. The file is
// equal to the account password, so it is refused, not warned about, when
// group or others can read or write it.
export function keytabCredentialsError(creds: Credentials): Error | undefined {
  if (creds.keytab === undefined) return undefined;
  if (typeof creds.keytab !== 'string' || creds.keytab.length === 0) return new Error('keytab must be a file path');
  if (creds.password !== undefined) return new Error('a keytab and a password cannot be used together');
  if (creds.useTicketCache) return new Error('a keytab and the ticket cache cannot be used together');
  if (!clientPrincipal(creds)) return new Error('Kerberos keytab auth needs a realm: set realm or domain');
  return undefined;
}

export async function checkKeytabFile(file: string): Promise<void> {
  let info;
  try {
    info = await stat(file);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    throw new Error(`keytab ${file}: ${code === 'ENOENT' ? 'no such file' : (err as Error).message}`);
  }
  if (!info.isFile()) throw new Error(`keytab ${file}: not a regular file`);
  // eslint-disable-next-line no-bitwise
  if ((info.mode & 0o077) !== 0) {
    throw new Error(`keytab ${file} is accessible by group or others; run chmod 600 ${file}`);
  }
  try {
    await access(file, constants.R_OK);
  } catch {
    throw new Error(`keytab ${file}: not readable`);
  }
}

// The DER MechTypeList this context sends: the bytes a mechListMIC covers.
const KRB5_MECH_LIST = encodeMechTypeList([OID_KRB5]);

export class KerberosSecurityContext implements SecurityContext, WinRMMessageProtection {
  private gss: GssClient | null = null;
  private firstStep = true;
  private done = false;
  private finalTokenSeen = false;
  private key: Buffer | null = null;
  private ccacheDir: string | null = null;
  private disposed = false;

  constructor(
    private readonly target: AuthTarget,
    private readonly credentials: Credentials,
    private readonly deps: KerberosProviderDeps,
  ) {}

  get complete(): boolean {
    return this.done;
  }

  readonly negotiatedMechanism = 'kerberos' as const;

  // A copy of the full GSS session key once the context is complete, when
  // the GSS layer can export it (@winlinux/krb-session-key). Undefined with
  // the `kerberos` package. dispose() zeroes the internal copy only.
  get sessionKey(): Buffer | undefined {
    return this.key ? Buffer.from(this.key) : undefined;
  }

  // True once the GSS layer holds the target's channel binding, so the
  // tokens are bound to the TLS server certificate: the addon with
  // target.channelBindings set before the first step. False without a
  // binding, before the first step, and with the `kerberos` package.
  get channelBound(): boolean {
    return this.gss?.channelBound === true;
  }

  private async ensureGss(): Promise<GssClient> {
    if (this.gss) return this.gss;
    const hostError = kerberosHostError(this.target);
    if (hostError) throw hostError;
    const { password, useTicketCache, keytab } = this.credentials;
    const keytabError = keytabCredentialsError(this.credentials);
    if (keytabError) throw keytabError;
    let ccache: string | undefined;
    if ((password !== undefined && !useTicketCache) || keytab !== undefined) {
      const principal = kinitPrincipal(this.credentials);
      if (keytab !== undefined) await checkKeytabFile(keytab);
      const dir = await mkdtemp(join(tmpdir(), 'winlinux-krb5cc-'));
      this.ccacheDir = dir;
      ccache = `FILE:${join(dir, 'ccache')}`;
      const run = this.deps.kinit ?? defaultKinitRunner;
      // kinit gets its own env; process.env is never changed.
      const env = { ...process.env, KRB5CCNAME: ccache };
      if (keytab !== undefined) await run([principal], undefined, env, keytab);
      else await run([principal], password, env);
    }
    const factory = this.deps.gss ?? defaultGssFactory;
    // The binding the consumer set on the target before this first step
    // (channel-bindings.ts): the WinRM transport learns its TLS server
    // certificate before it asks for the first token.
    const bindings = (this.target as ChannelBoundTarget).channelBindings;
    try {
      this.gss = await factory(servicePrincipal(this.target), {
        principal: clientPrincipal(this.credentials),
        ...(ccache ? { ccache } : {}),
        ...(bindings && bindings.length > 0 ? { channelBindings: Buffer.from(bindings) } : {}),
      });
    } catch (err) {
      throw new Error(`Kerberos init failed: ${(err as Error).message}`);
    }
    return this.gss;
  }

  // Called once GSS reports the context complete.
  private onComplete(gss: GssClient): void {
    this.done = true;
    if (gss.sessionKey) {
      try {
        const raw = gss.sessionKey();
        this.key = Buffer.from(raw);
        raw.fill(0); // keep one live copy only
      } catch (err) {
        throw new Error(`Kerberos session key: ${(err as Error).message}`);
      }
    }
  }

  // RFC 4178 mechListMIC from the server, over the MechTypeList we sent.
  // A MIC that does not verify fails the handshake. A MIC that this GSS
  // layer cannot check (the `kerberos` package has no verify_mic) is
  // accepted: the Kerberos AP-REP already gave mutual authentication, and
  // our list holds one mechanism, so there is no downgrade to detect.
  private checkMechListMic(gss: GssClient, mic: Buffer | undefined): void {
    if (!mic || mic.length === 0) return;
    if (!gss.verifyMic) return;
    let ok: boolean;
    try {
      ok = gss.verifyMic(KRB5_MECH_LIST, mic);
    } catch (err) {
      throw new Error(`Kerberos: cannot verify the server mechListMIC: ${(err as Error).message}`);
    }
    if (!ok) throw new Error('Kerberos: the server mechListMIC does not verify');
  }

  // One final NegTokenResp after completion: accept-completed, no mechanism
  // token, and an optional mechListMIC that must verify.
  private acceptFinalToken(gss: GssClient, inputToken: Buffer): StepResult {
    const framed = unframeSpnego(inputToken);
    if (framed.kind !== 'resp') throw new Error('Kerberos: expected a final SPNEGO NegTokenResp');
    if (framed.responseToken && framed.responseToken.length > 0) {
      throw new Error('Kerberos: handshake is already complete; unexpected mechanism token');
    }
    if (framed.negState !== undefined && framed.negState !== NegState.acceptCompleted) {
      throw new Error(`Kerberos: final SPNEGO negState is ${framed.negState}, not accept-completed`);
    }
    this.checkMechListMic(gss, framed.mechListMIC);
    this.finalTokenSeen = true;
    return { output: null, complete: true };
  }

  async step(inputToken?: Buffer): Promise<StepResult> {
    if (this.disposed) throw new Error('Kerberos context is disposed');
    if (this.done) {
      if (this.finalTokenSeen || !inputToken || inputToken.length === 0 || !this.gss) {
        throw new Error('Kerberos: handshake is already complete');
      }
      return this.acceptFinalToken(this.gss, inputToken);
    }
    const gss = await this.ensureGss();

    if (this.firstStep) {
      if (inputToken !== undefined) throw new Error('Kerberos: first step takes no input token');
      this.firstStep = false;
      let out: string;
      try {
        out = await gss.step('');
      } catch (err) {
        throw new Error(`Kerberos step failed: ${(err as Error).message}`);
      }
      const output = out ? frameNegTokenInit([OID_KRB5], Buffer.from(out, 'base64')) : null;
      if (gss.contextComplete) this.onComplete(gss);
      return { output, complete: this.done };
    }

    if (!inputToken || inputToken.length === 0) throw new Error('Kerberos: missing server token');
    const framed = unframeSpnego(inputToken);
    if (framed.kind !== 'resp' || !framed.responseToken) {
      throw new Error('Kerberos: expected a SPNEGO NegTokenResp with a token');
    }
    if (framed.negState === NegState.reject) throw new Error('Kerberos: the server rejected the SPNEGO negotiation');
    let out: string;
    try {
      out = await gss.step(framed.responseToken.toString('base64'));
    } catch (err) {
      throw new Error(`Kerberos step failed: ${(err as Error).message}`);
    }
    // A mutual-auth AP-REP is consumed here, not sent on.
    const output = out ? frameNegTokenResp({ responseToken: Buffer.from(out, 'base64') }) : null;
    if (gss.contextComplete) {
      this.onComplete(gss);
      // The AP-REP and the server's mechListMIC can share this token.
      this.checkMechListMic(gss, framed.mechListMIC);
      if (framed.mechListMIC) this.finalTokenSeen = true;
    }
    return { output, complete: this.done };
  }

  async wrap(plaintext: Buffer): Promise<Buffer> {
    if (this.disposed) throw new Error('Kerberos context is disposed');
    if (!this.gss || !this.done) throw new Error('Kerberos wrap: context is not established');
    const out = await this.gss.wrap(plaintext.toString('base64'), { protect: true });
    return Buffer.from(out, 'base64');
  }

  // The WinRM extension (./winrm-extension.ts). Both members exist only
  // once the GSS layer is created (the first step) and offers the IOV
  // split; with the `kerberos` package they stay undefined, so the WinRM
  // transport can tell the two cases apart after the first step.
  get wrapWinRM(): ((plaintext: Buffer) => Promise<WinRMSealed>) | undefined {
    if (!this.gss?.wrapIov || !this.gss.unwrapIov) return undefined;
    return async (plaintext: Buffer) => {
      if (this.disposed) throw new Error('Kerberos context is disposed');
      if (!this.gss?.wrapIov || !this.done) throw new Error('Kerberos wrapWinRM: context is not established');
      const sealed = await this.gss.wrapIov(plaintext);
      if (sealed.data.length !== plaintext.length) {
        // MS-WSMV 2.2.9.1.2.2.2: no padding; the data length is the
        // OriginalContent Length. AES-CTS never pads, so this is a guard
        // against an enctype this split was not proven for.
        throw new Error(
          `Kerberos wrapWinRM: sealed data is ${sealed.data.length} bytes for ${plaintext.length} bytes of plaintext (padding is not allowed by MS-WSMV)`,
        );
      }
      return sealed;
    };
  }

  get unwrapWinRM(): ((header: Buffer, data: Buffer) => Promise<Buffer>) | undefined {
    if (!this.gss?.wrapIov || !this.gss.unwrapIov) return undefined;
    return async (header: Buffer, data: Buffer) => {
      if (this.disposed) throw new Error('Kerberos context is disposed');
      if (!this.gss?.unwrapIov || !this.done) throw new Error('Kerberos unwrapWinRM: context is not established');
      return this.gss.unwrapIov(header, data);
    };
  }

  async unwrap(ciphertext: Buffer): Promise<Buffer> {
    if (this.disposed) throw new Error('Kerberos context is disposed');
    if (!this.gss || !this.done) throw new Error('Kerberos unwrap: context is not established');
    const out = await this.gss.unwrap(ciphertext.toString('base64'));
    return Buffer.from(out, 'base64');
  }

  async dispose(): Promise<void> {
    this.disposed = true;
    this.key?.fill(0);
    this.key = null;
    try {
      this.gss?.dispose?.();
    } finally {
      this.gss = null;
      if (this.ccacheDir) {
        await rm(this.ccacheDir, { recursive: true, force: true });
        this.ccacheDir = null;
      }
    }
  }
}

export class KerberosAuthProvider implements AuthProvider {
  readonly mechanism = 'kerberos' as const;

  constructor(private readonly deps: KerberosProviderDeps = {}) {}

  createContext(target: AuthTarget, credentials: Credentials): SecurityContext {
    return new KerberosSecurityContext(target, credentials, this.deps);
  }
}
