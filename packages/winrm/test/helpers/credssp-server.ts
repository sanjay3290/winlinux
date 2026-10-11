// An in-process WinRM CredSSP endpoint for tests. It does what a
// Windows WinRM listener with CredSSP enabled does, independently of the
// client code under test:
//   - TLS inside the HTTP "Authorization: CredSSP" header (a Node TLS
//     server over an in-memory duplex, with the RSA test certificate),
//   - TSRequest version 6 (MS-CSSP 2.2.1) with an NTLMv2 acceptor in
//     SPNEGO, both mechListMICs checked and sent,
//   - the pubKeyAuth check and reply (MS-CSSP 3.1.5, SHA-256 with nonce),
//   - the TSCredentials decrypt,
//   - then MS-WSMV CredSSP message encryption of the SOAP bodies
//     (application/HTTP-CredSSP-session-encrypted, multi-part over 16 KiB).
// The NTLM password is a sentinel. MD4 is not in Node's OpenSSL 3 default
// provider, so the NT hash of the sentinel is a constant here.
import { createHash, createHmac, randomBytes, timingSafeEqual, X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { Duplex } from 'node:stream';
import tls from 'node:tls';
import { children, readTlv } from '../../src/winrm/der.js';
import { rawNtlmToken } from '../../src/winrm/ntlmssp.js';
import type { MockResponse, RecordedRequest } from './mock-server.js';

export const CREDSSP_PASSWORD = 'sentinel-password-126';
// MD4(UTF-16LE(CREDSSP_PASSWORD)), from hash-wasm md4(). The handshake
// test proves it: a wrong NT hash fails the NTLMv2 proof.
const NT_HASH = Buffer.from('ee4f15226fdd8f68c9aa30383239f8e4', 'hex');

export const CREDSSP_PROTOCOL = 'application/HTTP-CredSSP-session-encrypted';
const BOUNDARY = '--Encrypted Boundary';
const OCTET = '\tContent-Type: application/octet-stream\r\n';
const CHUNK = 16384;
const GCM_TRAILER = 16;

function fixture(name: string): Buffer {
  return readFileSync(new URL(`../fixtures/${name}`, import.meta.url));
}

const turn = (): Promise<void> => new Promise((resolve) => setImmediate(resolve));

// --- DER, the few shapes the server needs ---
function len(n: number): Buffer {
  if (n < 0x80) return Buffer.from([n]);
  const out: number[] = [];
  for (let v = n; v > 0; v = Math.floor(v / 256)) out.unshift(v & 0xff);
  return Buffer.from([0x80 | out.length, ...out]);
}
const tlv = (tag: number, content: Buffer) => Buffer.concat([Buffer.from([tag]), len(content.length), content]);
const seq = (...parts: Buffer[]) => tlv(0x30, Buffer.concat(parts));
const ctx = (n: number, inner: Buffer) => tlv(0xa0 + n, inner);
const octets = (b: Buffer) => tlv(0x04, b);

interface TsReq {
  version: number;
  negoToken?: Buffer;
  authInfo?: Buffer;
  pubKeyAuth?: Buffer;
  errorCode?: number;
  clientNonce?: Buffer;
}

function intOf(b: Buffer): number {
  let n = BigInt.asIntN(8, BigInt(b[0] as number));
  for (let i = 1; i < b.length; i++) n = n * 256n + BigInt(b[i] as number);
  return Number(n);
}

function decodeTs(buf: Buffer): TsReq {
  const outer = readTlv(buf, 0);
  if (outer.tag !== 0x30 || outer.total !== buf.length) throw new Error('credssp server: bad TSRequest');
  const out: TsReq = { version: -1 };
  for (const f of children(outer.content)) {
    const inner = readTlv(f.content, 0);
    switch (f.tag) {
      case 0xa0:
        out.version = intOf(inner.content);
        break;
      case 0xa1: {
        const item = children(inner.content)[0];
        if (!item) throw new Error('credssp server: empty negoTokens');
        const tokenField = readTlv(item.content, 0);
        out.negoToken = Buffer.from(readTlv(tokenField.content, 0).content);
        break;
      }
      case 0xa2:
        out.authInfo = Buffer.from(inner.content);
        break;
      case 0xa3:
        out.pubKeyAuth = Buffer.from(inner.content);
        break;
      case 0xa4:
        out.errorCode = intOf(inner.content);
        break;
      case 0xa5:
        out.clientNonce = Buffer.from(inner.content);
        break;
      default:
        throw new Error(`credssp server: unknown field 0x${f.tag.toString(16)}`);
    }
  }
  return out;
}

function encodeTs(version: number, fields: { negoToken?: Buffer; pubKeyAuth?: Buffer; errorCode?: number }): Buffer {
  const parts = [ctx(0, tlv(0x02, Buffer.from([version])))];
  if (fields.negoToken) parts.push(ctx(1, seq(seq(ctx(0, octets(fields.negoToken))))));
  if (fields.pubKeyAuth) parts.push(ctx(3, octets(fields.pubKeyAuth)));
  if (fields.errorCode !== undefined) {
    // A 4-byte NTSTATUS, with a leading zero when the top bit is set.
    const v = Buffer.alloc(4);
    v.writeUInt32BE(fields.errorCode >>> 0, 0);
    parts.push(ctx(4, tlv(0x02, v[0]! & 0x80 ? Buffer.concat([Buffer.from([0]), v]) : v)));
  }
  return seq(...parts);
}

// STATUS_LOGON_FAILURE: what Windows puts in the TSRequest errorCode for a
// wrong password.
export const STATUS_LOGON_FAILURE = 0xc000006d;

class WrongPassword extends Error {}

// --- NTLMv2 acceptor (MS-NLMP), server side ---
const md5 = (...p: Buffer[]) => createHash('md5').update(Buffer.concat(p)).digest();
const hmac = (key: Buffer, ...p: Buffer[]) => createHmac('md5', key).update(Buffer.concat(p)).digest();

class Rc4 {
  private s = new Uint8Array(256);
  private i = 0;
  private j = 0;
  constructor(key: Buffer) {
    for (let k = 0; k < 256; k++) this.s[k] = k;
    for (let k = 0, j = 0; k < 256; k++) {
      j = (j + (this.s[k] as number) + (key[k % key.length] as number)) & 0xff;
      [this.s[k], this.s[j]] = [this.s[j] as number, this.s[k] as number];
    }
  }
  update(data: Buffer): Buffer {
    const out = Buffer.alloc(data.length);
    for (let k = 0; k < data.length; k++) {
      this.i = (this.i + 1) & 0xff;
      this.j = (this.j + (this.s[this.i] as number)) & 0xff;
      [this.s[this.i], this.s[this.j]] = [this.s[this.j] as number, this.s[this.i] as number];
      out[k] = (data[k] as number) ^ (this.s[((this.s[this.i] as number) + (this.s[this.j] as number)) & 0xff] as number);
    }
    return out;
  }
}

const MAGIC = {
  clientSign: 'session key to client-to-server signing key magic constant\0',
  serverSign: 'session key to server-to-client signing key magic constant\0',
  clientSeal: 'session key to client-to-server sealing key magic constant\0',
  serverSeal: 'session key to server-to-client sealing key magic constant\0',
};
const MECH_LIST = Buffer.from('300c060a2b06010401823702020a', 'hex'); // { NTLMSSP }
const NTLMSSP_OID = Buffer.from('060a2b06010401823702020a', 'hex');

// One NTLM direction for the whole session, as Windows keeps it: the
// SPNEGO mechListMIC is its first signed message (seq 0), then its RC4
// state resets and the sequence number goes on (MS-SPNG 3.3.5.1), so the
// pubKeyAuth after it is seq 1.
class Direction {
  private readonly sign: Buffer;
  private readonly sealKey: Buffer;
  private rc4: Rc4;
  private seqNo = 0;
  constructor(key: Buffer, which: 'client' | 'server') {
    this.sign = md5(key, Buffer.from(which === 'client' ? MAGIC.clientSign : MAGIC.serverSign));
    this.sealKey = md5(key, Buffer.from(which === 'client' ? MAGIC.clientSeal : MAGIC.serverSeal));
    this.rc4 = new Rc4(this.sealKey);
  }
  resetRc4(): void {
    this.rc4 = new Rc4(this.sealKey);
  }
  private seqBuf(): Buffer {
    const b = Buffer.alloc(4);
    b.writeUInt32LE(this.seqNo++, 0);
    return b;
  }
  mac(message: Buffer): Buffer {
    const s = this.seqBuf();
    return Buffer.concat([Buffer.from([1, 0, 0, 0]), this.rc4.update(hmac(this.sign, s, message).subarray(0, 8)), s]);
  }
  seal(data: Buffer): Buffer {
    const s = this.seqBuf();
    const sealed = this.rc4.update(data);
    const checksum = this.rc4.update(hmac(this.sign, s, data).subarray(0, 8));
    return Buffer.concat([Buffer.from([1, 0, 0, 0]), checksum, s, sealed]);
  }
  unseal(blob: Buffer): Buffer {
    const s = this.seqBuf();
    if (!blob.subarray(12, 16).equals(s)) throw new Error(`credssp server: NTLM sequence mismatch (got ${blob.readUInt32LE(12)}, expected ${s.readUInt32LE(0)})`);
    const plain = this.rc4.update(blob.subarray(16));
    const checksum = this.rc4.update(Buffer.from(blob.subarray(4, 12)));
    if (!checksum.equals(hmac(this.sign, s, plain).subarray(0, 8))) throw new Error('credssp server: NTLM checksum mismatch');
    return plain;
  }
}

function negTokenResp(negState: number, fields: { responseToken?: Buffer; mechListMIC?: Buffer; mech?: boolean }): Buffer {
  const parts = [ctx(0, tlv(0x0a, Buffer.from([negState])))];
  if (fields.mech) parts.push(ctx(1, NTLMSSP_OID));
  if (fields.responseToken) parts.push(ctx(2, octets(fields.responseToken)));
  if (fields.mechListMIC) parts.push(ctx(3, octets(fields.mechListMIC)));
  return tlv(0xa1, seq(...parts));
}

function mechListMicOf(token: Buffer): Buffer | undefined {
  const outer = readTlv(token, 0);
  const s = readTlv(outer.content, 0);
  const field = children(s.content).find((f) => f.tag === 0xa3);
  return field ? Buffer.from(readTlv(field.content, 0).content) : undefined;
}

function av(id: number, value: Buffer): Buffer {
  const h = Buffer.alloc(4);
  h.writeUInt16LE(id, 0);
  h.writeUInt16LE(value.length, 2);
  return Buffer.concat([h, value]);
}

function challengeMessage(serverChallenge: Buffer): Buffer {
  const target = Buffer.from('EXAMPLE', 'utf16le');
  const ts = Buffer.alloc(8);
  ts.writeBigUInt64LE(BigInt(Date.now()) * 10000n + 116444736000000000n, 0);
  const info = Buffer.concat([av(2, target), av(1, Buffer.from('SERVER', 'utf16le')), av(7, ts), av(0, Buffer.alloc(0))]);
  const h = Buffer.alloc(56);
  h.write('NTLMSSP\0', 0, 'ascii');
  h.writeUInt32LE(2, 8);
  h.writeUInt16LE(target.length, 12);
  h.writeUInt16LE(target.length, 14);
  h.writeUInt32LE(56, 16);
  h.writeUInt32LE(0xe28a8235, 20); // UNICODE SIGN SEAL NTLM ESS TARGET_INFO VERSION 128 KEY_EXCH 56 ...
  serverChallenge.copy(h, 24);
  h.writeUInt16LE(info.length, 40);
  h.writeUInt16LE(info.length, 42);
  h.writeUInt32LE(56 + target.length, 44);
  return Buffer.concat([h, target, info]);
}

function secBuf(msg: Buffer, at: number): Buffer {
  return msg.subarray(msg.readUInt32LE(at + 4), msg.readUInt32LE(at + 4) + msg.readUInt16LE(at));
}

export interface DelegatedCredentials {
  domain: string;
  username: string;
  password: string;
}

export interface CredSSPServerOptions {
  password?: string; // must be CREDSSP_PASSWORD for the NT hash constant
  version?: number; // the server's TSRequest version (default 6)
}

// One CredSSP acceptor: one TLS session, one sign-in.
class Acceptor {
  private readonly wire: Duplex;
  private readonly socket: tls.TLSSocket;
  private readonly out: Buffer[] = [];
  private readonly plain: Buffer[] = [];
  private failure: Error | null = null;
  private readonly serverChallenge = randomBytes(8);
  private readonly spk: Buffer;
  private client: Direction | null = null;
  private server: Direction | null = null;
  private finalToken: Buffer | null = null;
  private pubKeyDone = false;
  versions: number[] = [];
  credentials: DelegatedCredentials | null = null;

  constructor(private readonly version: number) {
    const out = this.out;
    this.wire = new Duplex({
      read() {},
      write(chunk: Buffer, _e, cb) {
        out.push(Buffer.from(chunk));
        cb();
      },
    });
    const cert = fixture('tls-test-cert.pem');
    const secureContext = tls.createSecureContext({ cert, key: fixture('tls-test-key.pem') });
    this.socket = new tls.TLSSocket(this.wire, { isServer: true, secureContext });
    this.socket.on('data', (d: Buffer) => this.plain.push(d));
    this.socket.on('error', (e: Error) => {
      this.failure ??= e;
    });
    // RSAPublicKey: the BIT STRING value of the SubjectPublicKeyInfo.
    const spki = new X509Certificate(cert).publicKey.export({ type: 'spki', format: 'der' });
    const bits = children(readTlv(spki, 0).content)[1];
    if (!bits || bits.tag !== 0x03) throw new Error('credssp server: no subjectPublicKey');
    this.spk = Buffer.from(bits.content.subarray(1));
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

  async feed(records: Buffer): Promise<{ out: Buffer; plain: Buffer }> {
    this.wire.push(records);
    await this.settle();
    return { out: Buffer.concat(this.out.splice(0)), plain: Buffer.concat(this.plain.splice(0)) };
  }

  async write(data: Buffer): Promise<Buffer> {
    this.socket.write(data);
    await this.settle();
    return Buffer.concat(this.out.splice(0));
  }

  cipher(): string {
    return this.socket.getCipher()?.name ?? '';
  }

  private async ntlm(token: Buffer): Promise<Buffer | null> {
    const msg = rawNtlmToken(token);
    const type = msg.readUInt32LE(8);
    if (type === 1) return negTokenResp(1, { mech: true, responseToken: challengeMessage(this.serverChallenge) });
    if (type !== 3) throw new Error(`credssp server: unexpected NTLM message type ${type}`);
    const user = secBuf(msg, 36).toString('utf16le');
    const domain = secBuf(msg, 28).toString('utf16le');
    const nt = secBuf(msg, 20);
    const responseKey = hmac(NT_HASH, Buffer.from(user.toUpperCase() + domain, 'utf16le'));
    const proof = hmac(responseKey, this.serverChallenge, nt.subarray(16));
    if (!timingSafeEqual(proof, nt.subarray(0, 16))) throw new WrongPassword('credssp server: NTLMv2 proof does not verify (wrong password)');
    const key = new Rc4(hmac(responseKey, proof)).update(secBuf(msg, 52));
    const mic = mechListMicOf(token);
    const client = new Direction(key, 'client');
    const server = new Direction(key, 'server');
    if (!mic || !mic.equals(client.mac(MECH_LIST))) throw new Error('credssp server: bad client mechListMIC');
    client.resetRc4();
    this.finalToken = negTokenResp(0, { mechListMIC: server.mac(MECH_LIST) });
    server.resetRc4();
    this.client = client;
    this.server = server;
    return null;
  }

  private hash(magic: string, nonce: Buffer): Buffer {
    return createHash('sha256').update(Buffer.from(magic, 'ascii')).update(nonce).update(this.spk).digest();
  }

  // One client token in, the server token out (null: credentials received).
  async respond(token: Buffer): Promise<Buffer | null> {
    const { out, plain } = await this.feed(token);
    if (plain.length === 0) return out;
    const ts = decodeTs(plain);
    this.versions.push(ts.version);
    const reply = async (fields: { negoToken?: Buffer; pubKeyAuth?: Buffer; errorCode?: number }) =>
      Buffer.concat([out, await this.write(encodeTs(this.version, fields))]);
    if (ts.authInfo) {
      if (!this.client || !this.pubKeyDone) throw new Error('credssp server: authInfo before the pubKeyAuth exchange');
      if (ts.negoToken || ts.pubKeyAuth) throw new Error('credssp server: authInfo must come alone');
      const creds = this.client.unseal(ts.authInfo);
      const pw = children(readTlv(readTlv(children(readTlv(creds, 0).content)[1]?.content ?? Buffer.alloc(0), 0).content, 0).content);
      const [d, u, p] = pw.map((f) => readTlv(f.content, 0).content.toString('utf16le'));
      this.credentials = { domain: d ?? '', username: u ?? '', password: p ?? '' };
      return null;
    }
    // Windows drops CredSSP (plain 401 Negotiate) unless the TSRequest that
    // carries the NTLM AUTHENTICATE also carries pubKeyAuth and the
    // clientNonce, and pubKeyAuth verifies under its NTLM state.
    if (this.client || !ts.negoToken) throw new Error('credssp server: expected an NTLM token');
    let next: Buffer | null;
    try {
      next = await this.ntlm(ts.negoToken);
    } catch (err) {
      if (err instanceof WrongPassword) return reply({ errorCode: STATUS_LOGON_FAILURE });
      throw err;
    }
    if (next) {
      if (ts.pubKeyAuth || ts.clientNonce) throw new Error('credssp server: pubKeyAuth before NTLM finished');
      return reply({ negoToken: next });
    }
    // ntlm() set the two directions; re-read them past the narrowing above.
    const client = this.client as Direction | null;
    const server = this.server as Direction | null;
    if (!ts.pubKeyAuth || !ts.clientNonce || !client || !server) {
      throw new Error('credssp server: expected pubKeyAuth and clientNonce with the NTLM AUTHENTICATE');
    }
    const got = client.unseal(ts.pubKeyAuth);
    if (!got.equals(this.hash('CredSSP Client-To-Server Binding Hash\0', ts.clientNonce))) throw new Error('credssp server: client pubKeyAuth mismatch');
    this.pubKeyDone = true;
    return reply({ negoToken: this.finalToken ?? undefined, pubKeyAuth: server.seal(this.hash('CredSSP Server-To-Client Binding Hash\0', ts.clientNonce)) });
  }

  close(): void {
    this.socket.destroy();
    this.wire.destroy();
  }
}

export interface CredSSPEndpoint {
  // The 401 to answer with during the handshake, or null once the request
  // is authenticated and carries a SOAP body.
  check(req: RecordedRequest): Promise<MockResponse | null>;
  // Decrypts an authenticated request body; checks the CredSSP framing.
  unwrap(req: RecordedRequest): Promise<string>;
  // Encrypts a SOAP response (multi-part over 16 KiB).
  wrap(req: RecordedRequest, soap: string): Promise<MockResponse>;
  handshakes: number;
  credentials: DelegatedCredentials[];
  versions: number[];
  // Handshake requests that carried a body (CredSSP sends empty probes).
  handshakeBodies: number;
  // Why the server dropped CredSSP, one entry per bare 401 Negotiate.
  dropped: string[];
  requestContentTypes: string[];
  ciphers: string[];
  close(): void;
}

function splitParts(body: Buffer): Array<{ header: string; stream: Buffer }> {
  const sep = Buffer.from(`${BOUNDARY}\r\n`);
  const end = Buffer.from(`${BOUNDARY}--\r\n`);
  const raw: Buffer[] = [];
  let start = 0;
  for (;;) {
    const idx = body.indexOf(sep, start);
    if (idx === -1) {
      raw.push(body.subarray(start));
      break;
    }
    raw.push(body.subarray(start, idx));
    start = idx + sep.length;
  }
  const parts = raw.filter((p) => p.length > 0);
  if (parts.length % 2 !== 0) throw new Error('credssp server: odd MIME part count');
  const out: Array<{ header: string; stream: Buffer }> = [];
  for (let i = 0; i < parts.length; i += 2) {
    let payload = parts[i + 1] as Buffer;
    if (payload.subarray(payload.length - end.length).equals(end)) payload = payload.subarray(0, payload.length - end.length);
    if (!payload.subarray(0, OCTET.length).equals(Buffer.from(OCTET))) throw new Error('credssp server: no octet-stream header');
    out.push({ header: (parts[i] as Buffer).toString('utf8'), stream: payload.subarray(OCTET.length) });
  }
  return out;
}

export function credsspEndpoint(opts: CredSSPServerOptions = {}): CredSSPEndpoint {
  if ((opts.password ?? CREDSSP_PASSWORD) !== CREDSSP_PASSWORD) throw new Error('credssp server: only the sentinel password has an NT hash here');
  const sessions = new Map<number, { acceptor: Acceptor; authenticated: boolean }>();
  const all: Acceptor[] = [];
  const ep: CredSSPEndpoint = {
    handshakes: 0,
    credentials: [],
    versions: [],
    handshakeBodies: 0,
    dropped: [],
    requestContentTypes: [],
    ciphers: [],
    async check(req) {
      let s = sessions.get(req.socketId);
      const auth = req.headers.authorization;
      if (s?.authenticated && auth === undefined) return null;
      const m = /^CredSSP ([A-Za-z0-9+/=]+)$/.exec(auth ?? '');
      if (!m?.[1]) {
        sessions.delete(req.socketId);
        return { status: 401, headers: { 'WWW-Authenticate': 'CredSSP' } };
      }
      if (!s || s.authenticated) {
        s = { acceptor: new Acceptor(opts.version ?? 6), authenticated: false };
        all.push(s.acceptor);
        sessions.set(req.socketId, s);
      }
      if (req.body.length > 0) ep.handshakeBodies += 1;
      let out: Buffer | null;
      try {
        out = await s.acceptor.respond(Buffer.from(m[1], 'base64'));
      } catch (err) {
        // Windows drops CredSSP with a bare 401 Negotiate and no CredSSP
        // token when a step fails. The reason stays server side.
        ep.dropped.push((err as Error).message);
        sessions.delete(req.socketId);
        return { status: 401, headers: { 'WWW-Authenticate': 'Negotiate' } };
      }
      ep.versions = s.acceptor.versions;
      if (out === null) {
        s.authenticated = true;
        ep.handshakes += 1;
        if (s.acceptor.credentials) ep.credentials.push(s.acceptor.credentials);
        ep.ciphers.push(s.acceptor.cipher());
        // WinRM answers the credentials round (an empty POST) with 200.
        return { status: 200, body: '' };
      }
      return { status: 401, headers: { 'WWW-Authenticate': `CredSSP ${out.toString('base64')}` } };
    },
    async unwrap(req) {
      const s = sessions.get(req.socketId);
      if (!s?.authenticated) throw new Error('credssp server: unwrap on an unauthenticated socket');
      const type = req.headers['content-type'] ?? '';
      ep.requestContentTypes.push(type);
      if (!new RegExp(`^multipart/(x-multi-)?encrypted;protocol="${CREDSSP_PROTOCOL}";boundary="Encrypted Boundary"$`).test(type)) {
        throw new Error(`credssp server: bad request Content-Type ${type}`);
      }
      let soap = Buffer.alloc(0);
      for (const part of splitParts(req.body)) {
        if (!part.header.includes(`Content-Type: ${CREDSSP_PROTOCOL}`)) throw new Error('credssp server: wrong part protocol');
        const length = Number(/Length=(\d+)/.exec(part.header)?.[1]);
        if (part.stream.readUInt32LE(0) !== GCM_TRAILER) throw new Error(`credssp server: Length-Field ${part.stream.readUInt32LE(0)} is not the GCM trailer`);
        const { plain } = await s.acceptor.feed(part.stream.subarray(4));
        if (plain.length !== length) throw new Error('credssp server: OriginalContent Length mismatch');
        if (length > CHUNK) throw new Error('credssp server: a part holds more than one TLS record of plaintext');
        soap = Buffer.concat([soap, plain]);
      }
      return soap.toString('utf8');
    },
    async wrap(req, soap) {
      const s = sessions.get(req.socketId);
      if (!s?.authenticated) throw new Error('credssp server: wrap on an unauthenticated socket');
      const msg = Buffer.from(soap, 'utf8');
      const parts: Buffer[] = [];
      for (let off = 0; off < msg.length; off += CHUNK) {
        const chunk = msg.subarray(off, off + CHUNK);
        const records = await s.acceptor.write(chunk);
        const prefix = Buffer.alloc(4);
        prefix.writeUInt32LE(GCM_TRAILER, 0);
        const head =
          `${BOUNDARY}\r\n\tContent-Type: ${CREDSSP_PROTOCOL}\r\n` +
          `\tOriginalContent: type=application/soap+xml;charset=UTF-8;Length=${chunk.length}\r\n${BOUNDARY}\r\n${OCTET}`;
        parts.push(Buffer.from(head, 'utf8'), prefix, records);
      }
      parts.push(Buffer.from(`${BOUNDARY}--\r\n`));
      const multi = msg.length > CHUNK ? 'x-multi-encrypted' : 'encrypted';
      return {
        status: 200,
        headers: { 'Content-Type': `multipart/${multi};protocol="${CREDSSP_PROTOCOL}";boundary="Encrypted Boundary"` },
        body: Buffer.concat(parts),
      };
    },
    close() {
      for (const a of all) a.close();
    },
  };
  return ep;
}
