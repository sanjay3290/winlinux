import type {
  AuthProvider,
  AuthTarget,
  Credentials,
  Mechanism,
  SecurityContext,
  StepResult,
} from './types.js';
import { OID_KRB5, OID_NTLMSSP, unframeSpnego } from './spnego.js';
import type { WinRMMessageProtection, WinRMSealed } from './winrm-extension.js';
import { KerberosSecurityContext, type KerberosProviderDeps } from './kerberos.js';
import { NtlmSecurityContext } from './ntlm/provider.js';

// Kerberos failures that mean "wrong or unusable credentials": the KDC
// already counted a bad password (or the account is locked). Falling back to
// NTLM with the same password would count a second failure against the
// account-lockout threshold, so these fail the handshake instead.
const CREDENTIAL_FAILURE =
  /preauthentication failed|password incorrect|PREAUTH_FAILED|credentials have been revoked|CLIENT_REVOKED|account locked|locked out|password has expired|KEY_EXPIRED/i;

export class KerberosCredentialError extends Error {
  override readonly name = 'KerberosCredentialError';
  readonly code = 'KRB_CREDENTIALS';
  constructor(cause: Error) {
    super(`Kerberos rejected the credentials (no NTLM fallback, to avoid a second bad-password count): ${cause.message}`, { cause });
  }
}

// The Kerberos leg offers the IETF Kerberos OID only. Windows may name it
// with the Microsoft Kerberos OID in supportedMech; both are Kerberos.
const OID_MS_KRB5 = '1.2.840.48018.1.2.2';
const KERBEROS_OIDS = new Set([OID_KRB5, OID_MS_KRB5]);

function credentialFailure(err: unknown): KerberosCredentialError | null {
  if (err instanceof KerberosCredentialError) return err;
  if (err instanceof Error && CREDENTIAL_FAILURE.test(err.message)) return new KerberosCredentialError(err);
  return null;
}

export class NegotiateSecurityContext implements SecurityContext, WinRMMessageProtection {
  private inner: SecurityContext | null = null;
  private won: Mechanism | null = null;

  constructor(
    private readonly target: AuthTarget,
    private readonly credentials: Credentials,
    private readonly kerberosDeps: KerberosProviderDeps,
  ) {}

  get complete(): boolean {
    return this.inner?.complete ?? false;
  }

  get negotiatedMechanism(): Mechanism | undefined {
    return this.won ?? undefined;
  }

  get sessionKey(): Buffer | undefined {
    return this.inner?.sessionKey;
  }

  // The Kerberos leg's channel binding state; NTLM binds through
  // its own AV pair and reports nothing here.
  get channelBound(): boolean {
    return (this.inner as { channelBound?: boolean } | null)?.channelBound === true;
  }

  // The WinRM extension of the mechanism that won (Kerberos offers it with
  // the addon; NTLM never does, WinRM uses its wrap() instead).
  get wrapWinRM(): ((plaintext: Buffer) => Promise<WinRMSealed>) | undefined {
    return (this.inner as WinRMMessageProtection | null)?.wrapWinRM;
  }

  get unwrapWinRM(): ((header: Buffer, data: Buffer) => Promise<Buffer>) | undefined {
    return (this.inner as WinRMMessageProtection | null)?.unwrapWinRM;
  }

  private startKerberos(): KerberosSecurityContext {
    const ctx = new KerberosSecurityContext(this.target, this.credentials, this.kerberosDeps);
    this.inner = ctx;
    return ctx;
  }

  // A keytab has no password, and neither has the ticket cache on
  // its own, so NTLM cannot run: the Kerberos failure is final, and the
  // caller sees it rather than "NTLM needs a password". With a password,
  // NTLM takes over; that includes a missing `kerberos` package, which is
  // an optional dependency.
  private fallBackToNtlm(kerberosError?: unknown): NtlmSecurityContext {
    if (this.credentials.keytab !== undefined || this.credentials.password === undefined) {
      if (kerberosError instanceof Error) throw kerberosError;
      throw new Error(this.credentials.keytab !== undefined ? 'a keytab works with Kerberos only' : 'Negotiate needs a password for NTLM');
    }
    const prev = this.inner;
    const ctx = new NtlmSecurityContext(this.target, this.credentials);
    this.inner = ctx;
    this.won = 'ntlm';
    void prev?.dispose?.().catch(() => undefined);
    return ctx;
  }

  async step(inputToken?: Buffer): Promise<StepResult> {
    if (!this.inner) {
      const kerberos = this.startKerberos();
      try {
        const res = await kerberos.step(inputToken);
        this.won = 'kerberos';
        return res;
      } catch (err) {
        // A client-side failure before any Kerberos token went out (no
        // realm, no ticket, no KDC, unknown SPN): NTLM takes over, unless
        // the KDC rejected the password (lockout guard).
        const denied = credentialFailure(err);
        if (denied) throw denied;
        return await this.fallBackToNtlm(err).step();
      }
    }

    if (this.won !== 'kerberos') return await this.inner.step(inputToken);

    // The Kerberos token has gone to the server, which must not be able to
    // move the exchange to the weaker NTLM. A supportedMech the
    // client did not offer is refused (RFC 4178 4.2.2); a reject, a
    // malformed token or a failed AP-REP or mechListMIC is fatal.
    if (inputToken && inputToken.length > 0) {
      let supportedMech: string | undefined;
      try {
        const framed = unframeSpnego(inputToken);
        if (framed.kind === 'resp') supportedMech = framed.supportedMech;
      } catch {
        // Not a SPNEGO token; the Kerberos context reports the error.
      }
      if (supportedMech !== undefined && !KERBEROS_OIDS.has(supportedMech)) {
        const name = supportedMech === OID_NTLMSSP ? 'NTLM' : supportedMech;
        throw new Error(`Negotiate: the server picked ${name}, which was not offered (only Kerberos was); no fallback after the Kerberos token`);
      }
    }
    try {
      return await this.inner.step(inputToken);
    } catch (err) {
      throw credentialFailure(err) ?? err;
    }
  }

  async wrap(plaintext: Buffer): Promise<Buffer> {
    if (!this.inner?.wrap) throw new Error('Negotiate wrap: context is not established');
    return this.inner.wrap(plaintext);
  }

  async unwrap(ciphertext: Buffer): Promise<Buffer> {
    if (!this.inner?.unwrap) throw new Error('Negotiate unwrap: context is not established');
    return this.inner.unwrap(ciphertext);
  }

  async dispose(): Promise<void> {
    await this.inner?.dispose?.();
  }
}

export class NegotiateAuthProvider implements AuthProvider {
  readonly mechanism = 'negotiate' as const;

  constructor(private readonly kerberosDeps: KerberosProviderDeps = {}) {}

  createContext(target: AuthTarget, credentials: Credentials): SecurityContext {
    return new NegotiateSecurityContext(target, credentials, this.kerberosDeps);
  }
}
