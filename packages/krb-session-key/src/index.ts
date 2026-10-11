// Public API of @winlinux/krb-session-key: a GSSAPI Kerberos initiator
// (raw KRB5 mechanism tokens, base64 in and out) that also returns the
// context session key. Its shape matches the `GssClient` / `GssFactory`
// seam in @winlinux/auth, so auth can use it in place of the `kerberos`
// package. SPNEGO framing stays in @winlinux/auth.
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

interface NativeBinding {
  load(): void;
  create(spn: string, ccache?: string | null, principal?: string | null): Promise<NativeHandle>;
  step(handle: NativeHandle, token?: Buffer | null): Promise<{ output: Buffer | null; complete: boolean }>;
  wrap(handle: NativeHandle, data: Buffer, protect: boolean): Promise<Buffer>;
  unwrap(handle: NativeHandle, data: Buffer): Promise<Buffer>;
  hasIov(): boolean;
  wrapIov(handle: NativeHandle, data: Buffer): Promise<WinRMSealed>;
  unwrapIov(handle: NativeHandle, header: Buffer, data: Buffer): Promise<Buffer>;
  sessionKey(handle: NativeHandle): Buffer;
  verifyMic(handle: NativeHandle, message: Buffer, mic: Buffer): boolean;
  release(handle: NativeHandle): void;
}

// Opaque native context handle (a napi external).
type NativeHandle = { readonly __brand: 'krb-session-key-handle' };

let binding: NativeBinding | null = null;

function native(): NativeBinding {
  if (binding) return binding;
  // node-gyp-build looks in <package>/build/Release first (a local source
  // build), then in <package>/prebuilds/<platform>-<arch>/ (the binaries
  // shipped in the package). dist/src/index.js -> <package>.
  const require = createRequire(import.meta.url);
  try {
    const load = require('node-gyp-build') as (dir: string) => NativeBinding;
    binding = load(fileURLToPath(new URL('../..', import.meta.url)));
  } catch (err) {
    throw new Error(
      '@winlinux/krb-session-key: the native addon is not built ' +
        `(${(err as Error).message}). Run \`npm rebuild @winlinux/krb-session-key\`; ` +
        'see the package README for the build prerequisites.',
    );
  }
  return binding;
}

// Loads the addon and the system GSSAPI library. Throws a clear error when
// either is missing. On Linux this is the first dlopen of libgssapi_krb5.
export function load(): void {
  native().load();
}

// One gss_wrap_iov result: the RFC 4121 per-message token with the trailer
// rotated into it (`header`, the MS-WSMV encryption header), and the sealed
// `data` of exactly the plaintext length. unwrapIov takes the same two
// pieces back from any sender: header || data is one wrap token, and the
// addon hands it to gss_unwrap, which accepts every RRC and EC a peer may
// use; the header length is whatever the peer's Length-Field said.
export interface WinRMSealed {
  header: Buffer;
  data: Buffer;
}

// True when the system GSSAPI library exports gss_wrap_iov (MIT krb5 1.8+,
// Heimdal 1.5+, Apple GSS.framework). Loads the library.
export function iovSupported(): boolean {
  return native().hasIov();
}

export interface KrbInit {
  // Client principal, for example user@REALM. Optional.
  principal?: string;
  // Credential cache for this context only, for example FILE:/tmp/x/ccache.
  // When absent, the GSS library default (KRB5CCNAME or the system default).
  ccache?: string;
}

export class KrbClient {
  private done = false;
  private released = false;
  // The native op in flight, if any. dispose() waits for it before release.
  private inFlight: Promise<unknown> | null = null;

  // Present only when the GSSAPI library has gss_wrap_iov, so a caller
  // can test for the capability (the GssClient seam in @winlinux/auth).
  wrapIov?: (data: Buffer) => Promise<WinRMSealed>;
  unwrapIov?: (header: Buffer, data: Buffer) => Promise<Buffer>;

  private constructor(private readonly handle: NativeHandle) {
    if (native().hasIov()) {
      this.wrapIov = async (data) => {
        this.assertLive('wrapIov');
        return this.track(native().wrapIov(this.handle, data));
      };
      this.unwrapIov = async (header, data) => {
        this.assertLive('unwrapIov');
        return this.track(native().unwrapIov(this.handle, header, data));
      };
    }
  }

  // service is a host-based name: "cifs@dc1.example.com".
  static async create(service: string, init: KrbInit = {}): Promise<KrbClient> {
    const handle = await native().create(service, init.ccache ?? null, init.principal ?? null);
    return new KrbClient(handle);
  }

  get contextComplete(): boolean {
    return this.done;
  }

  // One gss_init_sec_context call. Input and output are base64; the first
  // call takes ''. Returns '' when GSS produces no token.
  async step(challenge: string): Promise<string> {
    this.assertLive('step');
    const input = challenge ? Buffer.from(challenge, 'base64') : null;
    const r = await this.track(native().step(this.handle, input));
    this.done = r.complete;
    return r.output ? r.output.toString('base64') : '';
  }

  async wrap(data: string, options: { protect?: boolean } = {}): Promise<string> {
    this.assertLive('wrap');
    const out = await this.track(native().wrap(this.handle, Buffer.from(data, 'base64'), options.protect ?? false));
    return out.toString('base64');
  }

  async unwrap(challenge: string): Promise<string> {
    this.assertLive('unwrap');
    const out = await this.track(native().unwrap(this.handle, Buffer.from(challenge, 'base64')));
    return out.toString('base64');
  }

  // The full GSS session key (GSS_C_INQ_SSPI_SESSION_KEY), for example 32
  // bytes for aes256-cts. A fresh Buffer on each call. Protocols apply their
  // own rules (SMB2 uses the first 16 bytes).
  sessionKey(): Buffer {
    this.assertLive('sessionKey');
    return native().sessionKey(this.handle);
  }

  // gss_verify_mic over `message`. False when the MIC does not verify.
  verifyMic(message: Buffer, mic: Buffer): boolean {
    this.assertLive('verifyMic');
    return native().verifyMic(this.handle, message, mic);
  }

  // Never throws. With an op in flight, the native release waits until the
  // op completes (the native side refuses to release a busy context).
  dispose(): void {
    if (this.released) return;
    this.released = true;
    this.done = false;
    const release = () => {
      try {
        native().release(this.handle);
      } catch {
        // Nothing to report to a caller that is cleaning up.
      }
    };
    if (this.inFlight) void this.inFlight.then(release, release);
    else release();
  }

  private track<T>(op: Promise<T>): Promise<T> {
    // inFlight never rejects: the caller handles op's rejection, and a
    // second rejecting promise would be an unhandled rejection.
    const settled: Promise<void> = op.then(
      () => undefined,
      () => undefined,
    ).finally(() => {
      if (this.inFlight === settled) this.inFlight = null;
    });
    this.inFlight = settled;
    return op;
  }

  private assertLive(what: string): void {
    if (this.released) throw new Error(`krb-session-key ${what}: the context is disposed`);
  }
}

// Matches the GssFactory seam of @winlinux/auth.
export function gssFactory(service: string, init: KrbInit): Promise<KrbClient> {
  return KrbClient.create(service, init);
}
