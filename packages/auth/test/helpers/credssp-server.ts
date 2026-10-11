// An in-process CredSSP acceptor for tests (MS-CSSP 3.2.5, server side):
// TLS over an in-memory duplex with a test certificate, an inner acceptor
// (a fake one, or real NTLM below), the pubKeyAuth check and reply, and the
// TSCredentials decrypt. No network. Test values are sentinels only.
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { Duplex } from 'node:stream';
import tls from 'node:tls';
import { RC4, hmacMd5, ntowfv2 } from '../../src/auth/ntlm/crypto.js';
import { signKey, sealKey } from '../../src/auth/ntlm/seal.js';
import { NegState, OID_NTLMSSP, encodeMechTypeList, frameNegTokenResp, unframeSpnego } from '../../src/auth/spnego.js';
import { decodeTSCredentials, decodeTSRequest, encodeTSRequest, type TSRequest } from '../../src/auth/credssp/tsrequest.js';

// EC P-256 test certificate, CN=credssp.example.test, valid 2026-2046.
// Test-only key material; it protects nothing.
export const TEST_CERT = `-----BEGIN CERTIFICATE-----
MIIBlDCCATmgAwIBAgIUUOUE/pzqp3nktzjpvKTqvqDMO1cwCgYIKoZIzj0EAwIw
HzEdMBsGA1UEAwwUY3JlZHNzcC5leGFtcGxlLnRlc3QwHhcNMjYxMDEwMDIzMjIy
WhcNNDYxMDA1MDIzMjIyWjAfMR0wGwYDVQQDDBRjcmVkc3NwLmV4YW1wbGUudGVz
dDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABO1sbQrKiYJCC2VsPEX8snF+mwUO
Y9RITMBiyEmkSuhOUsx7nOHPOOXu6yDrDQk7n7gKWyIpP00MRLg5vIghTK2jUzBR
MB0GA1UdDgQWBBQ0XqDe/bRoLt7ucD0vhJYBkYYjazAfBgNVHSMEGDAWgBQ0XqDe
/bRoLt7ucD0vhJYBkYYjazAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0kA
MEYCIQDexs21XEgfAOBslZMJI2cUdRbOerSNg/T1yzmbBW87XgIhANmhwy4FT/5I
eJ97o8Me/x70KUz4HFrWpQaKnMOmF8Fv
-----END CERTIFICATE-----
`;
export const TEST_KEY = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg36hDWMfCCoVKCibN
1z5f37nyDXZ9fk9P3D52U+CRb22hRANCAATtbG0KyomCQgtlbDxF/LJxfpsFDmPU
SEzAYshJpEroTlLMe5zhzzjl7usg6w0JO5+4ClsiKT9NDES4ObyIIUyt
-----END PRIVATE KEY-----
`;
// The certificate's SubjectPublicKey (the uncompressed EC point), from
// `openssl x509 -pubkey | openssl pkey -pubin -outform DER | tail -c 65`.
export const TEST_SUBJECT_PUBLIC_KEY_HEX =
  '04ed6c6d0aca8982420b656c3c45fcb2717e9b050e63d4484cc062c849a44ae84e52cc7b9ce1cf38e5eeeb20eb0d093b9fb80a5b22293f4d0c44b839bc88214cad';

const turn = (): Promise<void> => new Promise((resolve) => setImmediate(resolve));

export class MemoryTlsServer {
  private readonly wire: Duplex;
  readonly socket: tls.TLSSocket;
  private out: Buffer[] = [];
  private plain: Buffer[] = [];
  private failure: Error | null = null;
  secure = false;

  constructor(cert: string | Buffer, key: string | Buffer, opts: { maxVersion?: tls.SecureVersion; ciphers?: string } = {}) {
    const out = this.out;
    this.wire = new Duplex({
      read() {},
      write(chunk: Buffer, _enc, cb) {
        out.push(Buffer.from(chunk));
        cb();
      },
    });
    const secureContext = tls.createSecureContext({ cert, key, ...(opts.maxVersion ? { maxVersion: opts.maxVersion } : {}), ...(opts.ciphers ? { ciphers: opts.ciphers } : {}) });
    this.socket = new tls.TLSSocket(this.wire, { isServer: true, secureContext });
    this.socket.on('secure', () => {
      this.secure = true;
    });
    this.socket.on('data', (d: Buffer) => this.plain.push(d));
    this.socket.on('error', (e: Error) => {
      this.failure ??= e;
    });
  }

  private async settle(): Promise<void> {
    let quiet = 0;
    let last = -1;
    for (let i = 0; i < 5000 && quiet < 3; i++) {
      await turn();
      if (this.failure) throw this.failure;
      const now = this.out.reduce((n, b) => n + b.length, 0) + this.plain.reduce((n, b) => n + b.length, 0);
      quiet = now === last ? quiet + 1 : 0;
      last = now;
    }
  }

  async feed(input: Buffer): Promise<{ out: Buffer; plain: Buffer }> {
    this.wire.push(input);
    await this.settle();
    return { out: Buffer.concat(this.out.splice(0)), plain: Buffer.concat(this.plain.splice(0)) };
  }

  async write(data: Buffer): Promise<Buffer> {
    this.socket.write(data);
    await this.settle();
    return Buffer.concat(this.out.splice(0));
  }

  cipherName(): string {
    return this.socket.getCipher()?.name ?? '';
  }

  close(): void {
    this.socket.destroy();
    this.wire.destroy();
  }
}

export interface InnerAcceptor {
  accept(token: Buffer): Promise<{ output: Buffer | null; complete: boolean }>;
  // A final SPNEGO token to send along with the server pubKeyAuth.
  finalToken?(): Buffer | undefined;
  wrap(data: Buffer): Buffer;
  unwrap(data: Buffer): Buffer;
}

// A fake inner mechanism: two tokens each way and a XOR "seal" with a
// 4-byte marker. It proves the CredSSP layer, not the inner crypto.
export const FAKE_INNER = {
  clientFirst: Buffer.from('FAKE-NEGOTIATE'),
  serverChallenge: Buffer.from('FAKE-CHALLENGE'),
  clientResponse: Buffer.from('FAKE-AUTHENTICATE'),
};

export function fakeSeal(data: Buffer): Buffer {
  return Buffer.concat([Buffer.from('SEAL'), Buffer.from(data.map((b) => b ^ 0x5a))]);
}

export function fakeUnseal(data: Buffer): Buffer {
  if (!data.subarray(0, 4).equals(Buffer.from('SEAL'))) throw new Error('fake unseal: no marker');
  return Buffer.from(data.subarray(4).map((b) => b ^ 0x5a));
}

export function fakeAcceptor(): InnerAcceptor {
  let round = 0;
  return {
    async accept(token) {
      round += 1;
      if (round === 1 && token.equals(FAKE_INNER.clientFirst)) return { output: FAKE_INNER.serverChallenge, complete: false };
      if (round === 2 && token.equals(FAKE_INNER.clientResponse)) return { output: null, complete: true };
      throw new Error(`fake acceptor: unexpected token in round ${round}`);
    },
    wrap: fakeSeal,
    unwrap: fakeUnseal,
  };
}

// --- Real NTLMv2 acceptor (MS-NLMP 3.2.5), for the end-to-end tests. ---

const MECH_LIST = encodeMechTypeList([OID_NTLMSSP]);
// Challenge flags: UNICODE, REQUEST_TARGET, SIGN, SEAL, NTLM, ALWAYS_SIGN,
// TARGET_TYPE_SERVER, ESS, TARGET_INFO, VERSION, 128, KEY_EXCH, 56.
const CHALLENGE_FLAGS = 0xe28a8235;

function av(id: number, value: Buffer): Buffer {
  const h = Buffer.alloc(4);
  h.writeUInt16LE(id, 0);
  h.writeUInt16LE(value.length, 2);
  return Buffer.concat([h, value]);
}

function buildChallenge(serverChallenge: Buffer): Buffer {
  const target = Buffer.from('EXAMPLE', 'utf16le');
  const ts = Buffer.alloc(8);
  ts.writeBigUInt64LE(BigInt(Date.now()) * 10000n + 116444736000000000n, 0);
  const info = Buffer.concat([
    av(2, Buffer.from('EXAMPLE', 'utf16le')),
    av(1, Buffer.from('SERVER', 'utf16le')),
    av(4, Buffer.from('example.test', 'utf16le')),
    av(3, Buffer.from('server.example.test', 'utf16le')),
    av(7, ts),
    av(0, Buffer.alloc(0)),
  ]);
  const h = Buffer.alloc(56);
  h.write('NTLMSSP\0', 0, 'ascii');
  h.writeUInt32LE(2, 8);
  h.writeUInt16LE(target.length, 12);
  h.writeUInt16LE(target.length, 14);
  h.writeUInt32LE(56, 16);
  h.writeUInt32LE(CHALLENGE_FLAGS, 20);
  serverChallenge.copy(h, 24);
  h.writeUInt16LE(info.length, 40);
  h.writeUInt16LE(info.length, 42);
  h.writeUInt32LE(56 + target.length, 44);
  Buffer.from([10, 0, 0x7c, 0x4f, 0, 0, 0, 0x0f]).copy(h, 48);
  return Buffer.concat([h, target, info]);
}

function field(msg: Buffer, at: number): Buffer {
  const len = msg.readUInt16LE(at);
  const off = msg.readUInt32LE(at + 4);
  return msg.subarray(off, off + len);
}

// Server half of NTLM session security: seals with the server keys,
// unseals with the client keys (MS-NLMP 3.4.4.2, 3.4.3). One state per
// direction for the whole session, as Windows keeps it: the SPNEGO
// mechListMIC is the first signed message of its direction (seq 0); then
// that direction's RC4 state resets and the sequence number goes on
// (MS-SPNG 3.3.5.1), so the pubKeyAuth that follows is seq 1. A client
// that restarts at seq 0, or keeps the RC4 stream running, fails here as
// it fails on Windows.
class ServerSeal {
  private readonly clientSign: Buffer;
  private readonly serverSign: Buffer;
  private readonly clientSealKey: Buffer;
  private readonly serverSealKey: Buffer;
  private clientRc4: RC4;
  private serverRc4: RC4;
  private clientSeq = 0;
  private serverSeq = 0;
  constructor(key: Buffer, flags: number) {
    this.clientSign = signKey(key, 'Client');
    this.serverSign = signKey(key, 'Server');
    this.clientSealKey = sealKey(key, flags, 'Client');
    this.serverSealKey = sealKey(key, flags, 'Server');
    this.clientRc4 = new RC4(this.clientSealKey);
    this.serverRc4 = new RC4(this.serverSealKey);
  }
  private seqBuf(n: number): Buffer {
    const seq = Buffer.alloc(4);
    seq.writeUInt32LE(n, 0);
    return seq;
  }
  seal(data: Buffer): Buffer {
    const seq = this.seqBuf(this.serverSeq++);
    const sealed = this.serverRc4.update(data);
    const checksum = this.serverRc4.update(hmacMd5(this.serverSign, seq, data).subarray(0, 8));
    return Buffer.concat([Buffer.from([1, 0, 0, 0]), checksum, seq, sealed]);
  }
  unseal(blob: Buffer): Buffer {
    const seq = this.seqBuf(this.clientSeq++);
    if (!blob.subarray(12, 16).equals(seq)) {
      throw new Error(`ntlm acceptor: bad sequence number ${blob.readUInt32LE(12)}, expected ${seq.readUInt32LE(0)}`);
    }
    const plain = this.clientRc4.update(blob.subarray(16));
    const checksum = this.clientRc4.update(Buffer.from(blob.subarray(4, 12)));
    if (!checksum.equals(hmacMd5(this.clientSign, seq, plain).subarray(0, 8))) throw new Error('ntlm acceptor: bad checksum');
    return plain;
  }
  // The client's SPNEGO mechListMIC: client seq 0, then the client RC4
  // state resets.
  verifyClientMic(message: Buffer, mic: Buffer): boolean {
    const seq = this.seqBuf(this.clientSeq++);
    const expected = Buffer.concat([
      Buffer.from([1, 0, 0, 0]),
      this.clientRc4.update(hmacMd5(this.clientSign, seq, message).subarray(0, 8)),
      seq,
    ]);
    this.clientRc4 = new RC4(this.clientSealKey);
    return mic.length === 16 && timingSafeEqual(mic, expected);
  }
  // The server's SPNEGO mechListMIC: server seq 0, then the server RC4
  // state resets.
  serverMic(message: Buffer): Buffer {
    const seq = this.seqBuf(this.serverSeq++);
    const checksum = this.serverRc4.update(hmacMd5(this.serverSign, seq, message).subarray(0, 8));
    this.serverRc4 = new RC4(this.serverSealKey);
    return Buffer.concat([Buffer.from([1, 0, 0, 0]), checksum, seq]);
  }
}

export interface NtlmAcceptorResult {
  user?: string;
  domain?: string;
  verified: boolean;
}

export function ntlmAcceptor(password: string, result: NtlmAcceptorResult = { verified: false }): InnerAcceptor {
  const serverChallenge = randomBytes(8);
  let session: ServerSeal | null = null;
  let final: Buffer | undefined;
  let round = 0;
  return {
    async accept(token) {
      round += 1;
      const framed = unframeSpnego(token);
      if (round === 1) {
        if (framed.kind !== 'init' || !framed.mechTypes.includes(OID_NTLMSSP) || !framed.mechToken) throw new Error('ntlm acceptor: expected NegTokenInit');
        return {
          output: frameNegTokenResp({ negState: NegState.acceptIncomplete, supportedMech: OID_NTLMSSP, responseToken: buildChallenge(serverChallenge) }),
          complete: false,
        };
      }
      if (framed.kind !== 'resp' || !framed.responseToken) throw new Error('ntlm acceptor: expected NegTokenResp');
      const msg = framed.responseToken;
      const flags = msg.readUInt32LE(60);
      const user = field(msg, 36).toString('utf16le');
      const domain = field(msg, 28).toString('utf16le');
      const nt = field(msg, 20);
      const responseKey = await ntowfv2(password, user, domain);
      const proof = hmacMd5(responseKey, serverChallenge, nt.subarray(16));
      if (!timingSafeEqual(proof, nt.subarray(0, 16))) throw new Error('ntlm acceptor: wrong password');
      const base = hmacMd5(responseKey, proof);
      const key = new RC4(base).update(field(msg, 52));
      session = new ServerSeal(key, flags);
      if (!framed.mechListMIC || !session.verifyClientMic(MECH_LIST, framed.mechListMIC)) throw new Error('ntlm acceptor: bad client mechListMIC');
      final = frameNegTokenResp({ negState: NegState.acceptCompleted, mechListMIC: session.serverMic(MECH_LIST) });
      Object.assign(result, { user, domain, verified: true });
      return { output: null, complete: true };
    },
    finalToken: () => final,
    wrap(data) {
      if (!session) throw new Error('ntlm acceptor: not established');
      return session.seal(data);
    },
    unwrap(data) {
      if (!session) throw new Error('ntlm acceptor: not established');
      return session.unseal(data);
    },
  };
}

export const CLIENT_MAGIC = 'CredSSP Client-To-Server Binding Hash\0';
export const SERVER_MAGIC = 'CredSSP Server-To-Client Binding Hash\0';

// SHA-256 over the spec formula, computed here without the module under test.
export function specHash(magic: string, nonce: Buffer, key: Buffer): Buffer {
  return createHash('sha256').update(Buffer.from(magic, 'ascii')).update(nonce).update(key).digest();
}

export interface ServerFaults {
  version?: number; // the version in every server TSRequest (default 6)
  errorCode?: number; // sent instead of the challenge
  wrongPubKey?: boolean; // reply with a hash over another key
  noPubKeyAuth?: boolean;
  echoNonce?: Buffer; // a clientNonce in the reply
}

export interface DelegatedCreds {
  domain: string;
  username: string;
  password: string;
}

// Drives the server side. respond() takes one client token and returns the
// server token, or null once the TSCredentials arrived. It is strict where
// Windows is: the TSRequest that finishes the inner exchange must
// also carry pubKeyAuth and the clientNonce, pubKeyAuth must verify under
// the server's NTLM state (sequence numbers included), and authInfo comes
// only after the server's pubKeyAuth. Windows drops CredSSP on any of
// these; this server throws.
export class CredSSPTestServer {
  readonly tls: MemoryTlsServer;
  readonly subjectPublicKey: Buffer;
  clientNonce: Buffer | undefined;
  clientHashOk = false;
  versions: number[] = [];
  credentials: DelegatedCreds | undefined;
  private phase: 'nego' | 'credentials' | 'done' = 'nego';
  private innerRounds = 0;

  constructor(
    private readonly inner: InnerAcceptor,
    private readonly faults: ServerFaults = {},
    cert: string | Buffer = TEST_CERT,
    key: string | Buffer = TEST_KEY,
    tlsOpts: { maxVersion?: tls.SecureVersion; ciphers?: string } = {},
    // The certificate's SubjectPublicKey, computed outside the module
    // under test (for TEST_CERT: openssl, see TEST_SUBJECT_PUBLIC_KEY_HEX).
    subjectPublicKeyHex: string = TEST_SUBJECT_PUBLIC_KEY_HEX,
  ) {
    this.tls = new MemoryTlsServer(cert, key, tlsOpts);
    this.subjectPublicKey = Buffer.from(subjectPublicKeyHex, 'hex');
  }

  private version(): number {
    return this.faults.version ?? 6;
  }

  async respond(token: Buffer): Promise<Buffer | null> {
    const { out, plain } = await this.tls.feed(token);
    if (plain.length === 0) return out;
    const req = decodeTSRequest(plain);
    this.versions.push(req.version);
    const reply: TSRequest = { version: this.version() };
    if (this.faults.errorCode !== undefined) {
      reply.errorCode = this.faults.errorCode;
      return Buffer.concat([out, await this.tls.write(encodeTSRequest(reply))]);
    }
    if (this.phase === 'credentials') {
      if (!req.authInfo || req.negoTokens || req.pubKeyAuth || req.clientNonce) {
        throw new Error('test server: expected a TSRequest with authInfo only after the server pubKeyAuth');
      }
      const creds = decodeTSCredentials(this.inner.unwrap(req.authInfo));
      this.credentials = {
        domain: creds.domain.toString('utf16le'),
        username: creds.username.toString('utf16le'),
        password: creds.password.toString('utf16le'),
      };
      this.phase = 'done';
      return null;
    }
    if (this.phase !== 'nego') throw new Error('test server: the exchange is over');
    if (req.authInfo) throw new Error('test server: authInfo before the server pubKeyAuth');
    if (req.negoTokens) {
      const res = await this.inner.accept(req.negoTokens[0] as Buffer);
      this.innerRounds += 1;
      if (!res.complete) {
        if (req.pubKeyAuth || req.clientNonce) throw new Error('test server: pubKeyAuth before the inner exchange finished');
        reply.negoTokens = [res.output as Buffer];
        return Buffer.concat([out, await this.tls.write(encodeTSRequest(reply))]);
      }
    } else if (this.innerRounds === 0) {
      throw new Error('test server: expected a negoToken');
    }
    // Here the inner exchange is over: the client's last token (NTLM
    // AUTHENTICATE) is in this TSRequest, or the client had none left to
    // send (Kerberos after the AP-REP). pubKeyAuth and clientNonce must be
    // in this same TSRequest.
    if (!req.pubKeyAuth || !req.clientNonce) {
      throw new Error('test server: the last inner token came without pubKeyAuth and clientNonce in the same TSRequest');
    }
    this.clientNonce = Buffer.from(req.clientNonce);
    const got = this.inner.unwrap(req.pubKeyAuth);
    this.clientHashOk = got.equals(specHash(CLIENT_MAGIC, req.clientNonce, this.subjectPublicKey));
    if (!this.clientHashOk) throw new Error('test server: client pubKeyAuth does not match');
    const final = this.inner.finalToken?.();
    if (final) reply.negoTokens = [final];
    if (!this.faults.noPubKeyAuth) {
      const key = this.faults.wrongPubKey ? Buffer.alloc(this.subjectPublicKey.length, 0x42) : this.subjectPublicKey;
      reply.pubKeyAuth = this.inner.wrap(specHash(SERVER_MAGIC, req.clientNonce, key));
    }
    if (this.faults.echoNonce) reply.clientNonce = this.faults.echoNonce;
    this.phase = 'credentials';
    return Buffer.concat([out, await this.tls.write(encodeTSRequest(reply))]);
  }

  close(): void {
    this.tls.close();
  }
}
