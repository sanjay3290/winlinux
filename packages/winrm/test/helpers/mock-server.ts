import http from 'node:http';
import https from 'node:https';
import type { TLSSocket } from 'node:tls';
import { NTLM_STUB, ntlmsspOffset } from './ntlm-wire.js';

export interface RecordedRequest {
  method: string;
  url: string;
  headers: http.IncomingHttpHeaders;
  body: Buffer;
  socketId: number;
  clientCertCN?: string;
}

export interface MockResponse {
  status: number;
  headers?: Record<string, string>;
  body?: string | Buffer;
}

export type MockHandler = (req: RecordedRequest, index: number) => MockResponse | Promise<MockResponse>;

export interface MockServer {
  port: number;
  requests: RecordedRequest[];
  connectionCount(): number;
  // TLS only: the certificate new connections get from now on, as a
  // load balancer with per-backend certificates would present.
  setSecureContext(opts: { cert: string | Buffer; key: string | Buffer }): void;
  close(): Promise<void>;
}

// Route helper: finds the WS-Man action name in a SOAP request body.
export function actionOf(body: Buffer): string {
  const text = body.toString('utf8');
  for (const action of ['Create', 'Command', 'Receive', 'Send', 'Signal', 'Delete']) {
    if (text.includes(`/${action}</wsa:Action>`) || text.includes(`/${action}<`)) return action;
  }
  return 'unknown';
}

export interface MockServerOptions {
  // HTTPS. Extra server options (requestCert, ca, ...) test certificate
  // sign-in.
  tls?: https.ServerOptions & { cert: string | Buffer; key: string | Buffer };
  // false: `requests` keeps every request with an empty body, so a long
  // transfer does not hold its data in memory. The handler still
  // gets the full body. Default true.
  recordBodies?: boolean;
}

export async function startMockServer(handler: MockHandler, opts?: MockServerOptions): Promise<MockServer> {
  const requests: RecordedRequest[] = [];
  const socketIds = new Map<object, number>();
  let connections = 0;

  const onRequest = (req: http.IncomingMessage, res: http.ServerResponse) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      void (async () => {
        let socketId = socketIds.get(req.socket);
        if (socketId === undefined) {
          socketId = socketIds.size;
          socketIds.set(req.socket, socketId);
        }
        const recorded: RecordedRequest = {
          method: req.method ?? '',
          url: req.url ?? '',
          headers: req.headers,
          body: Buffer.concat(chunks),
          socketId,
        };
        // The verified client certificate's CN, when the TLS peer sent one.
        const peer = (req.socket as Partial<TLSSocket>).getPeerCertificate?.();
        if (peer && typeof peer.subject?.CN === 'string') recorded.clientCertCN = peer.subject.CN;
        const index = requests.length;
        requests.push(opts?.recordBodies === false ? { ...recorded, body: Buffer.alloc(0) } : recorded);
        try {
          const out = await handler(recorded, index);
          res.writeHead(out.status, out.headers ?? {});
          res.end(out.body ?? '');
        } catch (err) {
          res.writeHead(500, {});
          res.end(String((err as Error)?.message ?? err));
        }
      })();
    });
  };

  const server = opts?.tls ? https.createServer(opts.tls, onRequest) : http.createServer(onRequest);
  server.on('connection', () => {
    connections += 1;
  });

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('mock server: no listen address');

  return {
    port: address.port,
    requests,
    connectionCount: () => connections,
    setSecureContext: (next) => {
      if (!(server instanceof https.Server)) throw new Error('mock server: setSecureContext needs TLS');
      server.setSecureContext(next);
    },
    close: () => new Promise<void>((resolve, reject) => server.close((e) => (e ? reject(e) : resolve()))),
  };
}

// --- Connection-bound Negotiate auth (HTTP.sys behaviour) ---
// A Negotiate handshake authenticates the TCP connection, not the request:
// later requests on that socket carry no Authorization header. A token on
// an authenticated socket starts a new handshake: the initial token gets a
// fresh challenge, and a completed token with no challenge before it (a
// stale AUTHENTICATE re-sent from the last handshake) is refused with a
// 401 and no token, as Windows does.
//
// Tokens: the gate knows one or more token sets (initial, challenge,
// response). The defaults are the scripted string tokens of
// helpers/stub-auth.ts challengeStub and the NTLMSSP-shaped ones of
// ntlmStub (helpers/ntlm-wire.ts NTLM_STUB). An NTLMSSP token is matched
// bare or inside a SPNEGO frame, and the gate remembers which
// framing authenticated each socket: Windows takes both, but holds a seal
// state after SPNEGO-wrapped NTLM that a client cannot match, so the fake
// Windows endpoint refuses a sealed body on such a connection.

export type NtlmFraming = 'raw' | 'spnego' | 'other';

export interface NegotiateGate {
  // The 401 to answer with, or null when the request is authenticated.
  check(req: RecordedRequest): MockResponse | null;
  // How the socket's AUTHENTICATE was framed, once authenticated.
  framingOf(socketId: number): NtlmFraming | undefined;
  // Completed handshakes.
  readonly handshakes: number;
  // Requests that re-sent a completed token on an authenticated socket.
  readonly staleTokens: number;
}

export interface NegotiateGateTokens {
  initial: string | Buffer;
  challenge: string | Buffer;
  response: string | Buffer;
}

export const STRING_STUB: NegotiateGateTokens = { initial: 'initial-token', challenge: 'server-challenge', response: 'response-token' };

interface Classified {
  inner: Buffer;
  framing: NtlmFraming;
}

// The NTLMSSP message in a header token (bare or SPNEGO-framed), or the
// token itself.
function classify(token: Buffer): Classified {
  const at = ntlmsspOffset(token);
  if (at === 0) return { inner: token, framing: 'raw' };
  if (at > 0 && (token[0] === 0x60 || token[0] === 0xa1)) return { inner: token.subarray(at), framing: 'spnego' };
  return { inner: token, framing: 'other' };
}

function matches(c: Classified, expected: Buffer): boolean {
  // A SPNEGO NegTokenResp may carry a mechListMIC after the message.
  return c.framing === 'spnego' ? c.inner.subarray(0, expected.length).equals(expected) : c.inner.equals(expected);
}

export function negotiateGate(tokens: NegotiateGateTokens | NegotiateGateTokens[] = [STRING_STUB, NTLM_STUB]): NegotiateGate {
  const sets = (Array.isArray(tokens) ? tokens : [tokens]).map((t) => ({
    initial: Buffer.from(t.initial),
    challenge: Buffer.from(t.challenge),
    response: Buffer.from(t.response),
  }));
  const sockets = new Map<number, { state: 'challenged' | 'authenticated'; framing: NtlmFraming }>();
  const stats = { handshakes: 0, staleTokens: 0 };
  const ask: MockResponse = { status: 401, headers: { 'WWW-Authenticate': 'Negotiate' } };
  return {
    check(req) {
      const auth = req.headers.authorization;
      const socket = sockets.get(req.socketId);
      if (auth === undefined) return socket?.state === 'authenticated' ? null : ask;
      const m = /^Negotiate ([A-Za-z0-9+/=]+)$/.exec(auth);
      if (!m?.[1]) return ask;
      const c = classify(Buffer.from(m[1], 'base64'));
      const initial = sets.find((t) => matches(c, t.initial));
      if (initial) {
        sockets.set(req.socketId, { state: 'challenged', framing: c.framing });
        return { status: 401, headers: { 'WWW-Authenticate': `Negotiate ${initial.challenge.toString('base64')}` } };
      }
      if (sets.some((t) => matches(c, t.response))) {
        if (socket?.state === 'challenged') {
          sockets.set(req.socketId, { state: 'authenticated', framing: c.framing });
          stats.handshakes += 1;
          return null;
        }
        if (socket?.state === 'authenticated') stats.staleTokens += 1;
        sockets.delete(req.socketId);
        return ask;
      }
      return ask;
    },
    framingOf(socketId) {
      const socket = sockets.get(socketId);
      return socket?.state === 'authenticated' ? socket.framing : undefined;
    },
    get handshakes() {
      return stats.handshakes;
    },
    get staleTokens() {
      return stats.staleTokens;
    },
  };
}

// --- Encrypted-framing test oracle (MS-WSMV 2.2.9.1.1.2, as pywinrm sends it) ---
// Independent of the transport: the server side of the mock builds and
// parses the wire format itself, with the 4-byte little-endian signature
// length in front of the NTLM signature.

export const SPNEGO_PROTOCOL = 'application/HTTP-SPNEGO-session-encrypted';
const BOUNDARY = '--Encrypted Boundary';
const NTLM_SIG_LEN = 16;

// seal returns signature(16) || sealed data, like an NTLM wrap().
export function mimeWrap(soap: string, seal: (data: Buffer) => Buffer): { contentType: string; body: Buffer } {
  const msg = Buffer.from(soap, 'utf8');
  const sealed = seal(msg);
  const prefix = Buffer.alloc(4);
  prefix.writeUInt32LE(NTLM_SIG_LEN, 0);
  const head =
    `${BOUNDARY}\r\n` +
    `\tContent-Type: ${SPNEGO_PROTOCOL}\r\n` +
    `\tOriginalContent: type=application/soap+xml;charset=UTF-8;Length=${msg.length}\r\n` +
    `${BOUNDARY}\r\n` +
    '\tContent-Type: application/octet-stream\r\n';
  return {
    contentType: `multipart/encrypted;protocol="${SPNEGO_PROTOCOL}";boundary="Encrypted Boundary"`,
    body: Buffer.concat([Buffer.from(head, 'utf8'), prefix, sealed, Buffer.from(`${BOUNDARY}--\r\n`, 'utf8')]),
  };
}

export function mimeUnwrap(body: Buffer, unseal: (data: Buffer) => Buffer): string {
  const parts = splitBuffer(body, Buffer.from(`${BOUNDARY}\r\n`)).filter((p) => p.length > 0);
  if (parts.length % 2 !== 0) throw new Error('mime oracle: odd part count');
  let out = '';
  for (let i = 0; i < parts.length; i += 2) {
    const header = (parts[i] as Buffer).toString('utf8');
    let payload = parts[i + 1] as Buffer;
    const m = /Length=(\d+)/.exec(header);
    if (!m) throw new Error('mime oracle: no Length in part header');
    const end = Buffer.from(`${BOUNDARY}--\r\n`);
    if (payload.subarray(payload.length - end.length).equals(end)) payload = payload.subarray(0, payload.length - end.length);
    const octet = Buffer.from('\tContent-Type: application/octet-stream\r\n');
    if (!payload.subarray(0, octet.length).equals(octet)) throw new Error('mime oracle: no octet-stream header');
    const stream = payload.subarray(octet.length);
    if (stream.readUInt32LE(0) !== NTLM_SIG_LEN) throw new Error('mime oracle: signature length prefix is not 16');
    const blob = stream.subarray(4);
    if (blob.length - NTLM_SIG_LEN !== Number(m[1])) throw new Error('mime oracle: encrypted data length != OriginalContent Length');
    const plain = unseal(blob);
    if (plain.length !== Number(m[1])) throw new Error('mime oracle: length mismatch');
    out += plain.toString('utf8');
  }
  return out;
}

// The same oracle for a split sealer (Kerberos via gss_wrap_iov):
// the Length-Field is the header length, then header, then the encrypted
// data of exactly OriginalContent Length bytes.
export function mimeWrapIov(soap: string, seal: (data: Buffer) => { header: Buffer; data: Buffer }): { contentType: string; body: Buffer } {
  const msg = Buffer.from(soap, 'utf8');
  const { header, data } = seal(msg);
  if (data.length !== msg.length) throw new Error('mime oracle: sealed data length != plaintext length');
  const prefix = Buffer.alloc(4);
  prefix.writeUInt32LE(header.length, 0);
  const head =
    `${BOUNDARY}\r\n` +
    `\tContent-Type: ${SPNEGO_PROTOCOL}\r\n` +
    `\tOriginalContent: type=application/soap+xml;charset=UTF-8;Length=${msg.length}\r\n` +
    `${BOUNDARY}\r\n` +
    '\tContent-Type: application/octet-stream\r\n';
  return {
    contentType: `multipart/encrypted;protocol="${SPNEGO_PROTOCOL}";boundary="Encrypted Boundary"`,
    body: Buffer.concat([Buffer.from(head, 'utf8'), prefix, header, data, Buffer.from(`${BOUNDARY}--\r\n`, 'utf8')]),
  };
}

export interface EncryptedPart {
  lengthField: number;
  header: Buffer;
  data: Buffer;
  originalLength: number;
}

// Splits every Encrypted Data part of a multipart/encrypted body by its
// Length-Field, without unsealing: header = the first Length-Field bytes
// after the prefix, data = the rest, which MUST be OriginalContent Length
// bytes (MS-WSMV 2.2.9.1.1.2.2).
export function mimeParts(body: Buffer): EncryptedPart[] {
  const parts = splitBuffer(body, Buffer.from(`${BOUNDARY}\r\n`)).filter((p) => p.length > 0);
  if (parts.length % 2 !== 0) throw new Error('mime oracle: odd part count');
  const out: EncryptedPart[] = [];
  for (let i = 0; i < parts.length; i += 2) {
    const header = (parts[i] as Buffer).toString('utf8');
    let payload = parts[i + 1] as Buffer;
    const m = /Length=(\d+)/.exec(header);
    if (!m) throw new Error('mime oracle: no Length in part header');
    const end = Buffer.from(`${BOUNDARY}--\r\n`);
    if (payload.subarray(payload.length - end.length).equals(end)) payload = payload.subarray(0, payload.length - end.length);
    const octet = Buffer.from('\tContent-Type: application/octet-stream\r\n');
    if (!payload.subarray(0, octet.length).equals(octet)) throw new Error('mime oracle: no octet-stream header');
    const stream = payload.subarray(octet.length);
    const lengthField = stream.readUInt32LE(0);
    const originalLength = Number(m[1]);
    if (stream.length !== 4 + lengthField + originalLength) {
      throw new Error(`mime oracle: ${stream.length - 4 - lengthField} bytes of encrypted data for OriginalContent Length ${originalLength}`);
    }
    out.push({ lengthField, header: stream.subarray(4, 4 + lengthField), data: stream.subarray(4 + lengthField), originalLength });
  }
  return out;
}

export function mimeUnwrapIov(body: Buffer, unseal: (header: Buffer, data: Buffer) => Buffer): string {
  let out = '';
  for (const part of mimeParts(body)) {
    const plain = unseal(part.header, part.data);
    if (plain.length !== part.originalLength) throw new Error('mime oracle: length mismatch');
    out += plain.toString('utf8');
  }
  return out;
}

function splitBuffer(buf: Buffer, sep: Buffer): Buffer[] {
  const parts: Buffer[] = [];
  let start = 0;
  for (;;) {
    const idx = buf.indexOf(sep, start);
    if (idx === -1) {
      parts.push(buf.subarray(start));
      return parts;
    }
    parts.push(buf.subarray(start, idx));
    start = idx + sep.length;
  }
}
