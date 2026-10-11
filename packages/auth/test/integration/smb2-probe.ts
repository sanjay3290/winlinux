// Minimal SMB2 NEGOTIATE + SESSION_SETUP probe for the live R1 check.
// Test-only: it records the raw status of each SESSION_SETUP so the test can
// show exactly what the server said to the provider's token. It does not
// sign or verify signatures (MS-SMB2 2.2.1, 2.2.3, 2.2.5, 2.2.6).
import { connect as tcpConnect, type Socket } from 'node:net';
import { randomBytes } from 'node:crypto';
import type { SecurityContext } from '../../src/auth/types.js';

export const STATUS_SUCCESS = 0x00000000;
export const STATUS_MORE_PROCESSING_REQUIRED = 0xc0000016;
export const SMB2_NEGOTIATE_SIGNING_REQUIRED = 0x02;

const CMD_NEGOTIATE = 0x0000;
const CMD_SESSION_SETUP = 0x0001;
const HEADER_LEN = 64;

export interface SetupLeg {
  status: number;
  sent: Buffer;
  received: Buffer;
}

export interface ProbeResult {
  dialect: number;
  legs: SetupLeg[];
  finalStatus: number;
}

class Wire {
  private buf = Buffer.alloc(0);
  private waiters: Array<(frame: Buffer) => void> = [];
  private failure: Error | null = null;

  constructor(private readonly sock: Socket) {
    sock.on('data', (d: Buffer) => {
      this.buf = Buffer.concat([this.buf, d]);
      this.drain();
    });
    const fail = (err: Error) => {
      this.failure = err;
    };
    sock.on('error', fail);
    sock.on('close', () => fail(new Error('SMB probe: connection closed')));
  }

  private drain(): void {
    while (this.buf.length >= 4 && this.waiters.length > 0) {
      const len = this.buf.readUInt32BE(0) & 0x00ffffff;
      if (this.buf.length < 4 + len) return;
      const frame = this.buf.subarray(4, 4 + len);
      this.buf = this.buf.subarray(4 + len);
      this.waiters.shift()!(Buffer.from(frame));
    }
  }

  async exchange(msg: Buffer, timeoutMs: number): Promise<Buffer> {
    if (this.failure) throw this.failure;
    const nb = Buffer.alloc(4);
    nb.writeUInt32BE(msg.length, 0);
    this.sock.write(Buffer.concat([nb, msg]));
    return new Promise<Buffer>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('SMB probe: response timeout')), timeoutMs);
      this.waiters.push((frame) => {
        clearTimeout(timer);
        resolve(frame);
      });
      this.drain();
    });
  }
}

function header(command: number, messageId: bigint, sessionId: bigint): Buffer {
  const h = Buffer.alloc(HEADER_LEN);
  h.write('\xfeSMB', 0, 'latin1');
  h.writeUInt16LE(64, 4); // StructureSize
  h.writeUInt16LE(command, 12);
  h.writeUInt16LE(1, 14); // CreditRequest
  h.writeBigUInt64LE(messageId, 24);
  h.writeBigUInt64LE(sessionId, 40);
  return h;
}

function negotiateRequest(): Buffer {
  const dialects = [0x0202, 0x0210];
  const body = Buffer.alloc(36 + dialects.length * 2);
  body.writeUInt16LE(36, 0); // StructureSize
  body.writeUInt16LE(dialects.length, 2);
  body.writeUInt16LE(0x0001, 4); // SecurityMode: signing enabled
  randomBytes(16).copy(body, 12); // ClientGuid
  dialects.forEach((d, i) => body.writeUInt16LE(d, 36 + i * 2));
  return Buffer.concat([header(CMD_NEGOTIATE, 0n, 0n), body]);
}

function sessionSetupRequest(messageId: bigint, sessionId: bigint, token: Buffer): Buffer {
  const body = Buffer.alloc(24);
  body.writeUInt16LE(25, 0); // StructureSize
  body.writeUInt8(0x01, 3); // SecurityMode: signing enabled
  body.writeUInt16LE(HEADER_LEN + 24, 12); // SecurityBufferOffset
  body.writeUInt16LE(token.length, 14);
  return Buffer.concat([header(CMD_SESSION_SETUP, messageId, sessionId), body, token]);
}

function parseResponse(frame: Buffer): { status: number; sessionId: bigint; body: Buffer } {
  if (frame.readUInt32BE(0) !== 0xfe534d42) throw new Error('SMB probe: not an SMB2 response');
  return {
    status: frame.readUInt32LE(8),
    sessionId: frame.readBigUInt64LE(40),
    body: frame.subarray(HEADER_LEN),
  };
}

// NEGOTIATE only: returns the server's SecurityMode so a test can prove
// whether the server requires signing (0x02) before it relies on that.
export async function probeNegotiate(
  host: string,
  port: number,
  timeoutMs = 15000,
): Promise<{ dialect: number; securityMode: number }> {
  const sock = await new Promise<Socket>((resolve, reject) => {
    const s = tcpConnect({ host, port }, () => resolve(s));
    s.once('error', reject);
  });
  try {
    const neg = parseResponse(await new Wire(sock).exchange(negotiateRequest(), timeoutMs));
    if (neg.status !== STATUS_SUCCESS) {
      throw new Error(`SMB probe: NEGOTIATE failed with 0x${neg.status.toString(16)}`);
    }
    return { dialect: neg.body.readUInt16LE(4), securityMode: neg.body.readUInt16LE(2) };
  } finally {
    sock.destroy();
  }
}

// Run NEGOTIATE then the SESSION_SETUP loop, driven by `ctx`. On the final
// STATUS_SUCCESS the server's last token (Kerberos AP-REP) is fed back to the
// context so the caller can check mutual auth completed.
export async function probeSessionSetup(
  host: string,
  port: number,
  ctx: SecurityContext,
  timeoutMs = 15000,
): Promise<ProbeResult> {
  const sock = await new Promise<Socket>((resolve, reject) => {
    const s = tcpConnect({ host, port }, () => resolve(s));
    s.once('error', reject);
  });
  try {
    const wire = new Wire(sock);
    const neg = parseResponse(await wire.exchange(negotiateRequest(), timeoutMs));
    if (neg.status !== STATUS_SUCCESS) {
      throw new Error(`SMB probe: NEGOTIATE failed with 0x${neg.status.toString(16)}`);
    }
    const dialect = neg.body.readUInt16LE(4);

    const legs: SetupLeg[] = [];
    let messageId = 1n;
    let sessionId = 0n;
    let step = await ctx.step();
    for (;;) {
      const sent = step.output ?? Buffer.alloc(0);
      const res = parseResponse(
        await wire.exchange(sessionSetupRequest(messageId, sessionId, sent), timeoutMs),
      );
      messageId += 1n;
      sessionId = res.sessionId;
      const offset = res.body.readUInt16LE(4);
      const length = res.body.readUInt16LE(6);
      const frameStart = HEADER_LEN;
      const received = Buffer.from(
        res.body.subarray(offset - frameStart, offset - frameStart + length),
      );
      legs.push({ status: res.status, sent, received });
      if (res.status === STATUS_MORE_PROCESSING_REQUIRED) {
        step = await ctx.step(received);
        continue;
      }
      if (res.status === STATUS_SUCCESS && received.length > 0 && !ctx.complete) {
        await ctx.step(received);
      }
      return { dialect, legs, finalStatus: res.status };
    }
  } finally {
    sock.destroy();
  }
}
