import { createHash } from 'node:crypto';
import { NTLM_STUB, spnegoInit, spnegoResp } from './ntlm-wire.js';
import type {
  AuthProvider,
  AuthTarget,
  Credentials,
  Mechanism,
  SecurityContext,
  StepResult,
} from '../../src/auth-provider.js';

// Fake NTLM-layout sealing for wrap/unwrap tests. Like the real NTLM
// provider (MS-NLMP 3.4.4.2), wrap() returns a 16-byte signature followed
// by sealed data of the same length as the plaintext, and unwrap() takes
// that same blob. The signature is version 1 + an 8-byte MD5 checksum of
// the plaintext + sequence 0, so a flipped byte fails unwrap(). The
// "cipher" is a XOR with 0x5a. It proves the layout, not the crypto.
export const FAKE_NTLM_SIGNATURE_LENGTH = 16;

function fakeChecksum(plaintext: Buffer): Buffer {
  return createHash('md5').update(plaintext).digest().subarray(0, 8);
}

function xor5a(data: Buffer): Buffer {
  return Buffer.from(data.map((b) => b ^ 0x5a));
}

export function fakeNtlmWrap(plaintext: Buffer): Buffer {
  const sig = Buffer.concat([Buffer.from([1, 0, 0, 0]), fakeChecksum(plaintext), Buffer.alloc(4)]);
  return Buffer.concat([sig, xor5a(plaintext)]);
}

export function fakeNtlmUnwrap(blob: Buffer): Buffer {
  if (blob.length < FAKE_NTLM_SIGNATURE_LENGTH) throw new Error('fake NTLM unwrap: blob shorter than a signature');
  const sig = blob.subarray(0, FAKE_NTLM_SIGNATURE_LENGTH);
  if (sig.readUInt32LE(0) !== 1) throw new Error('fake NTLM unwrap: bad signature version');
  const plaintext = xor5a(blob.subarray(FAKE_NTLM_SIGNATURE_LENGTH));
  if (!sig.subarray(4, 12).equals(fakeChecksum(plaintext))) throw new Error('fake NTLM unwrap: checksum mismatch');
  return plaintext;
}

export interface SealPair {
  wrap: (plaintext: Buffer) => Buffer;
  unwrap: (blob: Buffer) => Buffer;
}

export const FAKE_NTLM: SealPair = { wrap: fakeNtlmWrap, unwrap: fakeNtlmUnwrap };

// Fake Kerberos IOV split, shaped like a real gss_wrap_iov result for
// aes-cts-hmac-sha1-96: a 60-byte header (RFC 4121 wrap token: TOK_ID 0504,
// Flags, Filler ff, EC 0, RRC 28, SND_SEQ, then 44 bytes that stand in for
// the confounder, the encrypted header copy and the checksum; here an MD5 of
// the plaintext, repeated) and sealed data of exactly the plaintext length
// (XOR with 0xa5). unwrap checks the TOK_ID and the checksum, so a flipped
// byte in either part fails. It proves the framing, not the crypto.
export const FAKE_KRB_HEADER_LENGTH = 60;

function fakeKrbChecksum(plaintext: Buffer): Buffer {
  const md5 = createHash('md5').update(plaintext).digest();
  return Buffer.concat([md5, md5, md5]).subarray(0, 44);
}

function xorA5(data: Buffer): Buffer {
  return Buffer.from(data.map((b) => b ^ 0xa5));
}

export function fakeKrbWrapIov(plaintext: Buffer, seq = 0): { header: Buffer; data: Buffer } {
  // seq is informational (SND_SEQ); the fake has no replay window.
  const header = Buffer.alloc(16);
  header.writeUInt16BE(0x0504, 0);
  header[2] = 0x06; // Sealed | AcceptorSubkey
  header[3] = 0xff;
  header.writeUInt16BE(0, 4); // EC
  header.writeUInt16BE(28, 6); // RRC
  header.writeBigUInt64BE(BigInt(seq), 8);
  return { header: Buffer.concat([header, fakeKrbChecksum(plaintext)]), data: xorA5(plaintext) };
}

export function fakeKrbUnwrapIov(header: Buffer, data: Buffer): Buffer {
  if (header.length !== FAKE_KRB_HEADER_LENGTH) throw new Error(`fake Kerberos unwrap: header is ${header.length} bytes, not 60`);
  if (header.readUInt16BE(0) !== 0x0504) throw new Error('fake Kerberos unwrap: bad TOK_ID');
  const plaintext = xorA5(data);
  if (!header.subarray(16).equals(fakeKrbChecksum(plaintext))) throw new Error('fake Kerberos unwrap: checksum mismatch');
  return plaintext;
}

export interface IovPair {
  wrapIov: (plaintext: Buffer, seq?: number) => { header: Buffer; data: Buffer };
  unwrapIov: (header: Buffer, data: Buffer) => Buffer;
}

export const FAKE_KRB_IOV: IovPair = { wrapIov: fakeKrbWrapIov, unwrapIov: fakeKrbUnwrapIov };

export interface SealCall {
  input: Buffer;
  output: Buffer;
}

export interface ScriptedStep {
  // Expected server challenge fed to step(). Null for the first call.
  expectInput: Buffer | null;
  output: Buffer | null;
  complete: boolean;
}

export class StubSecurityContext implements SecurityContext {
  complete = false;
  readonly stepsTaken: Array<Buffer | undefined> = [];
  wrap?: (plaintext: Buffer) => Promise<Buffer>;
  unwrap?: (ciphertext: Buffer) => Promise<Buffer>;
  // Every wrap()/unwrap() input and output, copied, in call order.
  readonly wrapCalls: SealCall[] = [];
  readonly unwrapCalls: SealCall[] = [];

  private taken = 0;

  constructor(
    private readonly script: ScriptedStep[],
    seal?: SealPair,
  ) {
    if (seal) {
      this.wrap = async (plaintext: Buffer) => {
        const output = seal.wrap(plaintext);
        this.wrapCalls.push({ input: Buffer.from(plaintext), output: Buffer.from(output) });
        return output;
      };
      this.unwrap = async (ciphertext: Buffer) => {
        const input = Buffer.from(ciphertext);
        const output = seal.unwrap(ciphertext);
        this.unwrapCalls.push({ input, output: Buffer.from(output) });
        return output;
      };
    }
  }

  async step(inputToken?: Buffer): Promise<StepResult> {
    const s = this.script[this.taken];
    if (!s) throw new Error(`stub context: unexpected step() call #${this.taken + 1}`);
    this.taken += 1;
    this.stepsTaken.push(inputToken);
    const expected = s.expectInput;
    if (expected === null) {
      if (inputToken !== undefined) throw new Error('stub context: expected first step() with no input');
    } else {
      if (!inputToken || !inputToken.equals(expected)) throw new Error('stub context: challenge mismatch');
    }
    this.complete = s.complete;
    return { output: s.output, complete: s.complete };
  }

  get calls(): number {
    return this.taken;
  }
}

export interface IovCall {
  input: Buffer;
  header: Buffer;
  data: Buffer;
}

// A Kerberos-shaped stub: it declares the optional WinRM extension
// (wrapWinRM / unwrapWinRM accessors, like KerberosSecurityContext in
// @winlinux/auth) and offers it once `complete` when it has an IovPair.
// With `iov` absent the accessors always read undefined: the shape of a
// context on the `kerberos` package fallback. It also carries the
// contract wrap()/unwrap() (an RFC 4121-style single blob is not needed
// here; the fake NTLM layout stands in).
export class KerberosStubSecurityContext extends StubSecurityContext {
  readonly wrapWinRMCalls: IovCall[] = [];
  readonly unwrapWinRMCalls: IovCall[] = [];
  private seq = 0;

  constructor(
    script: ScriptedStep[],
    private readonly iov?: IovPair,
    readonly negotiatedMechanism: Mechanism | undefined = 'kerberos',
  ) {
    super(script, FAKE_NTLM);
  }

  get wrapWinRM(): ((plaintext: Buffer) => Promise<{ header: Buffer; data: Buffer }>) | undefined {
    if (!this.iov || this.calls === 0) return undefined;
    return async (plaintext: Buffer) => {
      if (!this.complete) throw new Error('stub context: wrapWinRM before completion');
      const out = this.iov!.wrapIov(plaintext, this.seq++);
      this.wrapWinRMCalls.push({ input: Buffer.from(plaintext), header: Buffer.from(out.header), data: Buffer.from(out.data) });
      return out;
    };
  }

  get unwrapWinRM(): ((header: Buffer, data: Buffer) => Promise<Buffer>) | undefined {
    if (!this.iov || this.calls === 0) return undefined;
    return async (header: Buffer, data: Buffer) => {
      if (!this.complete) throw new Error('stub context: unwrapWinRM before completion');
      const out = this.iov!.unwrapIov(header, data);
      this.unwrapWinRMCalls.push({ input: Buffer.from(out), header: Buffer.from(header), data: Buffer.from(data) });
      return out;
    };
  }
}

export class StubAuthProvider implements AuthProvider {
  readonly contexts: StubSecurityContext[] = [];

  constructor(
    readonly mechanism: Mechanism,
    private readonly factory: () => StubSecurityContext,
  ) {}

  createContext(_target: AuthTarget, _credentials: Credentials): SecurityContext {
    const ctx = this.factory();
    this.contexts.push(ctx);
    return ctx;
  }
}

// Basic-style: one step, complete at once, never offers wrap.
export function basicStub(token = 'basic-token'): StubAuthProvider {
  return new StubAuthProvider('basic', () => new StubSecurityContext([{ expectInput: null, output: Buffer.from(token), complete: true }]));
}

// NTLM-style: initial token, then a challenge/response round.
export function challengeStub(opts?: {
  seal?: boolean | SealPair;
  mechanism?: Mechanism;
  initial?: string;
  challenge?: string;
  response?: string;
}): StubAuthProvider {
  const initial = Buffer.from(opts?.initial ?? 'initial-token');
  const challenge = Buffer.from(opts?.challenge ?? 'server-challenge');
  const response = Buffer.from(opts?.response ?? 'response-token');
  const seal = opts?.seal === true ? FAKE_NTLM : opts?.seal || undefined;
  return new StubAuthProvider(
    opts?.mechanism ?? 'ntlm',
    () =>
      new StubSecurityContext(
        [
          { expectInput: null, output: initial, complete: false },
          { expectInput: challenge, output: response, complete: true },
        ],
        seal,
      ),
  );
}

// NTLM-shaped, framed like the real provider: a SPNEGO NegTokenInit
// around an NTLMSSP NEGOTIATE, then, for the bare CHALLENGE the server
// sends back, a NegTokenResp around an AUTHENTICATE with a mechListMIC.
// The transport must send the NTLMSSP messages bare; the gate in
// mock-server.ts tells the two framings apart.
export function ntlmStub(opts?: { seal?: boolean | SealPair }): StubAuthProvider {
  const seal = opts?.seal === true ? FAKE_NTLM : opts?.seal || undefined;
  return new StubAuthProvider(
    'ntlm',
    () =>
      new StubSecurityContext(
        [
          { expectInput: null, output: spnegoInit(NTLM_STUB.initial), complete: false },
          { expectInput: NTLM_STUB.challenge, output: spnegoResp(NTLM_STUB.response, { mechListMIC: Buffer.from('mic-16-bytes-xxx') }), complete: true },
        ],
        seal,
      ),
  );
}

// Kerberos-style: the same challenge/response round as challengeStub, on
// a KerberosStubSecurityContext. iov: the split it offers once complete
// (default: the fake one); false: declared but never offered (the
// `kerberos` package fallback shape). mechanism 'negotiate' makes a
// Negotiate provider whose context reports Kerberos as the winner.
export function kerberosStub(opts?: { iov?: IovPair | false; mechanism?: 'kerberos' | 'negotiate' }): StubAuthProvider {
  const iov = opts?.iov === false ? undefined : (opts?.iov ?? FAKE_KRB_IOV);
  return new StubAuthProvider(
    opts?.mechanism ?? 'kerberos',
    () =>
      new KerberosStubSecurityContext(
        [
          { expectInput: null, output: Buffer.from('initial-token'), complete: false },
          { expectInput: Buffer.from('server-challenge'), output: Buffer.from('response-token'), complete: true },
        ],
        iov,
      ),
  );
}

export const CREDENTIALS: Credentials = { username: 'user', password: 'pass', domain: 'WORKGROUP' };
