import { hostname } from 'node:os';
import type { AuthProvider, AuthTarget, Credentials, SecurityContext, StepResult } from '../types.js';
import {
  NegState,
  OID_NTLMSSP,
  encodeMechTypeList,
  frameNegTokenInit,
  frameNegTokenResp,
  unframeSpnego,
} from '../spnego.js';
import {
  F_KEY_EXCH,
  F_SEAL,
  F_SIGN,
  TYPE1_FLAGS,
  buildType1,
  buildType3,
  negotiateResponseFlags,
  parseType2,
} from './messages.js';
import { NtlmSealSession, type SealSessionOptions } from './seal.js';
import { channelBindingsHash, type ChannelBoundTarget } from '../channel-bindings.js';

function defaultWorkstation(): string {
  const short = hostname().split('.')[0] || 'CLIENT';
  return short.toUpperCase().slice(0, 15);
}

export interface NtlmContextOptions {
  // How wrap()/unwrap() continue after the SPNEGO mechListMIC.
  //   'separate' (default): the mechListMIC uses its own seal state, and
  //     wrap()/unwrap() start at seq 0 with a fresh RC4 state. This is the
  //     state of bare NTLMSSP, which the WinRM HTTP transport sends:
  //     there the mechListMIC never reaches the server.
  //   'spnego': the mechListMIC goes on the wire inside SPNEGO
  //     (CredSSP). MS-SPNG 3.3.5.1: the MIC is the first signed message of the
  //     NTLM session (seq 0); then the RC4 state of that direction resets
  //     and the sequence number goes on, so the first wrap() is seq 1 with
  //     the initial key stream. The server mechListMIC does the same in the
  //     server direction. Windows and pyspnego do this.
  mechListMICSealState?: 'separate' | 'spnego';
}

export class NtlmSecurityContext implements SecurityContext {
  private state: 'start' | 'sent-type1' | 'complete' = 'start';
  private type1Raw: Buffer | null = null;
  private session: NtlmSealSession | null = null;
  private key: Buffer | null = null;
  private sealNegotiated = false;
  private disposed = false;
  private micOptions: SealSessionOptions | null = null;
  private finalTokenSeen = false;

  constructor(
    private readonly target: AuthTarget,
    private readonly credentials: Credentials,
    private readonly options: NtlmContextOptions = {},
  ) {}

  private get spnegoSealState(): boolean {
    return this.options.mechListMICSealState === 'spnego';
  }

  get complete(): boolean {
    return this.state === 'complete';
  }

  readonly negotiatedMechanism = 'ntlm' as const;

  // A copy: dispose() zeroes the internal key, and consumers such as SMB2
  // signing keep using the key after the context is disposed.
  get sessionKey(): Buffer | undefined {
    return this.key ? Buffer.from(this.key) : undefined;
  }

  async step(inputToken?: Buffer): Promise<StepResult> {
    if (this.disposed) throw new Error('NTLM context is disposed');
    if (this.state === 'start') {
      if (inputToken !== undefined) throw new Error('NTLM: first step takes no input token');
      const { username, password, domain } = this.credentials;
      if (!username) throw new Error('NTLM needs a username');
      if (this.credentials.keytab !== undefined) throw new Error('NTLM cannot use a keytab; a keytab works with Kerberos only');
      if (password === undefined) throw new Error('NTLM needs a password');
      this.type1Raw = buildType1({ domain: domain ?? '', workstation: defaultWorkstation() });
      this.state = 'sent-type1';
      return {
        output: frameNegTokenInit([OID_NTLMSSP], this.type1Raw),
        complete: false,
      };
    }
    if (this.state === 'complete') {
      if (this.finalTokenSeen || !inputToken || inputToken.length === 0) {
        throw new Error('NTLM: handshake is already complete');
      }
      return this.acceptFinalToken(inputToken);
    }
    if (!inputToken || inputToken.length === 0) throw new Error('NTLM: missing server challenge');

    const framed = unframeSpnego(inputToken);
    let type2Raw: Buffer;
    if (framed.kind === 'resp') {
      if (!framed.responseToken) throw new Error('NTLM: server response holds no token');
      type2Raw = framed.responseToken;
    } else if (framed.kind === 'raw') {
      type2Raw = framed.token; // tolerate stacks that send raw NTLM
    } else {
      throw new Error('NTLM: expected a challenge, got NegTokenInit');
    }

    const challenge = parseType2(type2Raw);
    const responseFlags = negotiateResponseFlags(TYPE1_FLAGS, challenge.flags);
    const spn = this.target.spn ?? `${this.target.service}/${this.target.host}`;
    // Read now, not at construction: a consumer may set the binding on the
    // target once its TLS connection is up (channel-bindings.ts).
    const binding = (this.target as ChannelBoundTarget).channelBindings;
    const built = await buildType3({
      username: this.credentials.username,
      password: this.credentials.password ?? '',
      domain: this.credentials.domain ?? '',
      workstation: defaultWorkstation(),
      challenge,
      responseFlags,
      targetName: spn,
      negotiateMessage: this.type1Raw ?? undefined,
      channelBindings: binding ? channelBindingsHash(binding) : undefined,
    });
    // eslint-disable-next-line no-bitwise
    this.sealNegotiated = (responseFlags & F_SEAL) !== 0;
    const sealOptions = {
      exportedSessionKey: built.exportedSessionKey,
      negotiatedFlags: responseFlags,
      // eslint-disable-next-line no-bitwise
      keyExchange: (responseFlags & F_KEY_EXCH) !== 0 && (responseFlags & (F_SIGN | F_SEAL)) !== 0,
    };
    this.session = new NtlmSealSession(sealOptions);
    // SPNEGO mechListMIC (RFC 4178 5, MS-SPNG 3.1.5.1): sent with type3 when
    // type3 carries a MIC, whatever the SIGN flag, and when NTLM gives
    // integrity. AD DCs (Samba, Windows) demand it once type3 has a MIC.
    // The seal state that follows it depends on mechListMICSealState.
    // eslint-disable-next-line no-bitwise
    const wantMic = built.micIncluded || (responseFlags & F_SIGN) !== 0;
    let mechListMIC: Buffer | undefined;
    if (wantMic && this.spnegoSealState) {
      mechListMIC = this.session.sign(encodeMechTypeList([OID_NTLMSSP]));
      this.session.resetRc4('client');
    } else if (wantMic) {
      mechListMIC = new NtlmSealSession(sealOptions).sign(encodeMechTypeList([OID_NTLMSSP]));
    }
    this.key = built.exportedSessionKey;
    this.micOptions = sealOptions;
    this.state = 'complete';
    return {
      output: frameNegTokenResp({ responseToken: built.message, mechListMIC }),
      complete: true,
    };
  }

  // One final NegTokenResp from the server after type3: accept-completed
  // and an optional mechListMIC (MS-SPNG 3.1.5.1). The MIC is at server
  // seq 0 and must verify ('spnego': on the session itself, which then
  // resets its server RC4 state; 'separate': on a fresh state).
  private acceptFinalToken(inputToken: Buffer): StepResult {
    const framed = unframeSpnego(inputToken);
    if (framed.kind !== 'resp' || (framed.responseToken && framed.responseToken.length > 0)) {
      throw new Error('NTLM: handshake is already complete');
    }
    if (framed.negState !== undefined && framed.negState !== NegState.acceptCompleted) {
      throw new Error(`NTLM: final SPNEGO negState is ${framed.negState}, not accept-completed`);
    }
    const mic = framed.mechListMIC;
    if (mic && mic.length > 0) {
      let ok: boolean;
      if (this.spnegoSealState && this.session) {
        ok = this.session.verify(encodeMechTypeList([OID_NTLMSSP]), mic);
        this.session.resetRc4('server');
      } else {
        ok = this.micOptions !== null &&
          new NtlmSealSession(this.micOptions).verify(encodeMechTypeList([OID_NTLMSSP]), mic);
      }
      if (!ok) throw new Error('NTLM: the server mechListMIC does not verify');
    }
    this.finalTokenSeen = true;
    return { output: null, complete: true };
  }

  async wrap(plaintext: Buffer): Promise<Buffer> {
    if (this.disposed) throw new Error('NTLM context is disposed');
    if (!this.session) throw new Error('NTLM wrap: context is not established');
    if (!this.sealNegotiated) throw new Error('NTLM wrap: the server did not negotiate SEAL');
    return this.session.seal(plaintext);
  }

  async unwrap(ciphertext: Buffer): Promise<Buffer> {
    if (this.disposed) throw new Error('NTLM context is disposed');
    if (!this.session) throw new Error('NTLM unwrap: context is not established');
    if (!this.sealNegotiated) throw new Error('NTLM unwrap: the server did not negotiate SEAL');
    return this.session.unseal(ciphertext);
  }

  async dispose(): Promise<void> {
    this.disposed = true;
    this.key?.fill(0);
    this.key = null;
    this.session = null;
    this.micOptions = null;
  }
}

export class NtlmAuthProvider implements AuthProvider {
  readonly mechanism = 'ntlm' as const;

  createContext(target: AuthTarget, credentials: Credentials): SecurityContext {
    return new NtlmSecurityContext(target, credentials);
  }
}
