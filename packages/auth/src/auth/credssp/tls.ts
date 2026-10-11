// TLS inside the HTTP Authorization header (MS-CSSP 3.1.5 step 1): a Node
// TLS client over an in-memory duplex, with no network socket. The CredSSP
// context feeds it the server's TLS bytes from each WWW-Authenticate token
// and sends the bytes it writes in the next Authorization header.
//
// Certificate checks are off for this inner TLS only. Its server identity is
// bound by pubKeyAuth (MS-CSSP 3.1.5, the SHA-256 hash over the client nonce
// and the certificate's SubjectPublicKey), which the context verifies after
// the inner authentication and before it sends any credentials.
//
// TLS 1.2 with AES-GCM only: Windows CredSSP runs TLS 1.2, and MS-WSMV
// message encryption needs the record trailer length of the cipher in use
// (credsspTrailerLength below). A GCM record is a 5-byte header, an 8-byte
// explicit nonce, the ciphertext and a 16-byte tag.

import { Duplex } from 'node:stream';
import tls from 'node:tls';

const GCM_CIPHERS = [
  'ECDHE-RSA-AES256-GCM-SHA384',
  'ECDHE-RSA-AES128-GCM-SHA256',
  'ECDHE-ECDSA-AES256-GCM-SHA384',
  'ECDHE-ECDSA-AES128-GCM-SHA256',
  'DHE-RSA-AES256-GCM-SHA384',
  'DHE-RSA-AES128-GCM-SHA256',
  'AES256-GCM-SHA384',
  'AES128-GCM-SHA256',
].join(':');

const RECORD_HEADER = 5;
const GCM_EXPLICIT_NONCE = 8;
export const GCM_TAG_LENGTH = 16;
const CONTENT_ALERT = 21;
const CONTENT_HANDSHAKE = 22;
const CONTENT_APPLICATION_DATA = 23;
// The largest plaintext one TLS record carries (RFC 5246 6.2.1).
export const TLS_MAX_RECORD_PLAINTEXT = 16384;

// Event-loop turns to wait for the TLS layer before giving up. Each turn is
// one setImmediate; OpenSSL work runs synchronously inside those turns.
const MAX_TURNS = 5000;

const turn = (): Promise<void> => new Promise((resolve) => setImmediate(resolve));

// Plaintext bytes that a run of TLS 1.2 AES-GCM application-data records
// carries. Any other record type in an application-data stream is refused:
// an alert ends the session, and renegotiation is not supported.
export function gcmPlaintextLength(records: Buffer): number {
  let off = 0;
  let total = 0;
  while (off < records.length) {
    if (off + RECORD_HEADER > records.length) throw new Error('CredSSP: truncated TLS record header');
    const type = records[off] as number;
    const len = records.readUInt16BE(off + 3);
    if (off + RECORD_HEADER + len > records.length) throw new Error('CredSSP: truncated TLS record');
    if (type === CONTENT_ALERT) throw new Error('CredSSP: the server sent a TLS alert');
    if (type === CONTENT_HANDSHAKE) throw new Error('CredSSP: the server started a TLS renegotiation, which is not supported');
    if (type !== CONTENT_APPLICATION_DATA) throw new Error(`CredSSP: unexpected TLS record type ${type}`);
    if (len < GCM_EXPLICIT_NONCE + GCM_TAG_LENGTH) throw new Error('CredSSP: TLS record is shorter than its AES-GCM overhead');
    total += len - GCM_EXPLICIT_NONCE - GCM_TAG_LENGTH;
    off += RECORD_HEADER + len;
  }
  return total;
}

export class MemoryTlsClient {
  private readonly wire: Duplex;
  private readonly socket: tls.TLSSocket;
  private out: Buffer[] = [];
  private outBytes = 0;
  private plain: Buffer[] = [];
  private plainBytes = 0;
  private failure: Error | null = null;
  private secure = false;
  private closed = false;

  constructor() {
    const outgoing = (chunk: Buffer) => {
      this.out.push(Buffer.from(chunk));
      this.outBytes += chunk.length;
    };
    this.wire = new Duplex({
      read() {},
      write(chunk: Buffer, _encoding, callback) {
        outgoing(chunk);
        callback();
      },
    });
    // tls.connect({ socket }) wraps the duplex in a client tls.TLSSocket
    // and starts the handshake; no network socket is opened.
    this.socket = tls.connect({
      socket: this.wire,
      // The inner TLS identity is bound by pubKeyAuth, not by a CA chain.
      rejectUnauthorized: false,
      minVersion: 'TLSv1.2',
      maxVersion: 'TLSv1.2',
      ciphers: GCM_CIPHERS,
      // No SNI: Windows CredSSP does not use it, and the host may be an IP.
      servername: '',
    });
    this.socket.on('secureConnect', () => {
      this.secure = true;
    });
    this.socket.on('data', (chunk: Buffer) => {
      this.plain.push(chunk);
      this.plainBytes += chunk.length;
    });
    this.socket.on('error', (err: Error) => {
      this.failure ??= err;
    });
    this.wire.on('error', (err: Error) => {
      this.failure ??= err;
    });
  }

  get established(): boolean {
    return this.secure;
  }

  // The DER certificate of the inner TLS server, once established.
  peerCertificate(): Buffer {
    const raw = this.socket.getPeerCertificate()?.raw;
    if (!raw || raw.length === 0) throw new Error('CredSSP: the inner TLS server sent no certificate');
    return Buffer.from(raw);
  }

  // The OpenSSL name of the negotiated cipher, for example
  // ECDHE-RSA-AES256-GCM-SHA384.
  cipherName(): string {
    return this.socket.getCipher()?.name ?? '';
  }

  // MS-WSMV 2.2.9.1.2.2 (CredSSP): the Length-Field of an encrypted part is
  // the length of the TLS trailer that follows the encrypted data. For
  // AES-GCM that is the 16-byte tag, whatever the message length.
  trailerLength(): number {
    if (!/-GCM-/.test(this.cipherName())) throw new Error(`CredSSP: cipher ${this.cipherName() || 'none'} is not AES-GCM`);
    return GCM_TAG_LENGTH;
  }

  private check(): void {
    if (this.failure) throw new Error(`CredSSP: inner TLS failed: ${this.failure.message}`);
    if (this.closed) throw new Error('CredSSP: inner TLS is closed');
  }

  // Waits until `done()` holds and the TLS layer has been quiet for two
  // turns (no new outgoing or plaintext bytes).
  private async settle(done: () => boolean, what: string): Promise<void> {
    let quiet = 0;
    let last = -1;
    for (let i = 0; i < MAX_TURNS; i++) {
      await turn();
      this.check();
      const now = this.outBytes + this.plainBytes;
      quiet = now === last ? quiet + 1 : 0;
      last = now;
      if (quiet >= 2 && done()) return;
    }
    throw new Error(`CredSSP: inner TLS ${what} did not finish`);
  }

  private takeOut(): Buffer {
    const out = Buffer.concat(this.out);
    this.out = [];
    this.outBytes = 0;
    return out;
  }

  private takePlain(): Buffer {
    const plain = Buffer.concat(this.plain);
    this.plain = [];
    this.plainBytes = 0;
    return plain;
  }

  // The ClientHello.
  async start(): Promise<Buffer> {
    await this.settle(() => this.outBytes > 0, 'start');
    return this.takeOut();
  }

  // Feeds one server flight. Returns the client's next flight (empty once
  // the handshake is complete and the client has nothing to send).
  async handshake(input: Buffer): Promise<Buffer> {
    this.check();
    if (this.secure) throw new Error('CredSSP: the inner TLS handshake is already complete');
    this.wire.push(input);
    await this.settle(() => this.secure || this.outBytes > 0, 'handshake');
    if (this.plainBytes > 0) throw new Error('CredSSP: the server sent data before the TLS handshake finished');
    return this.takeOut();
  }

  // Encrypts `plaintext` into TLS records.
  async write(plaintext: Buffer): Promise<Buffer> {
    this.check();
    if (!this.secure) throw new Error('CredSSP: the inner TLS session is not established');
    let written = false;
    this.socket.write(plaintext, () => {
      written = true;
    });
    await this.settle(() => written && this.outBytes > 0, 'write');
    return this.takeOut();
  }

  // Decrypts TLS 1.2 AES-GCM application-data records.
  async read(records: Buffer): Promise<Buffer> {
    this.check();
    if (!this.secure) throw new Error('CredSSP: the inner TLS session is not established');
    const expected = gcmPlaintextLength(records);
    if (this.plainBytes > 0) throw new Error('CredSSP: unexpected data on the inner TLS session');
    this.wire.push(records);
    await this.settle(() => this.plainBytes >= expected, 'read');
    if (this.plainBytes !== expected) throw new Error('CredSSP: the TLS records decrypted to an unexpected length');
    if (this.outBytes > 0) throw new Error('CredSSP: the inner TLS session wrote data while reading');
    return this.takePlain();
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    this.socket.destroy();
    this.wire.destroy();
    for (const b of this.plain) b.fill(0);
    this.plain = [];
    this.out = [];
  }
}
