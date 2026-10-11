// Shared pieces for the live SMB captures: a TCP proxy that
// records each SMB2 frame by direction, a fixed client flow, and a replay
// server that serves the recorded frames back to the client offline.
import net from "node:net";
import crypto from "node:crypto";
import { connect } from "../../src/index.js";
import { NtlmTestProvider } from "./ntlm-provider.js";

export type Direction = "c2s" | "s2c";

export interface CapturedFrame {
  dir: Direction;
  hex: string; // bare SMB2 message, no 4-byte NetBIOS header
}

export interface CaptureResult {
  shares: Array<{ name: string; type: string }>;
  readBack: string;
}

export interface CaptureFixture {
  description: string;
  sambaVersion: string;
  signing: "required" | "disabled";
  host: string;
  // Test-only account of the dperson/samba container. Not a real person.
  credentials: { username: string; password: string; domain: string };
  workstation: string;
  clientChallenge: string;
  timestamp: string;
  result: CaptureResult;
  frames: CapturedFrame[];
}

// Fixed NTLM inputs so a replay derives the same session key as the capture.
export const CAPTURE_WORKSTATION = "WINLINUX-CAPTURE";
export const CAPTURE_CLIENT_CHALLENGE = "a1a2a3a4a5a6a7a8";
export const CAPTURE_FILE = "capture.txt";
export const CAPTURE_TEXT = "captured-by-winlinux";

// SMB2 header fields read straight from the bytes (MS-SMB2 2.2.1.2).
export const SMB2_FLAGS_SIGNED = 0x08;
export const frameCommand = (frame: Buffer): number => frame.readUInt16LE(12);
export const frameStatus = (frame: Buffer): number => frame.readUInt32LE(8);
export const frameFlags = (frame: Buffer): number => frame.readUInt32LE(16);
export const isSigned = (frame: Buffer): boolean => (frameFlags(frame) & SMB2_FLAGS_SIGNED) !== 0;

export function splitFrames(data: Buffer): { frames: Buffer[]; rest: Buffer } {
  const frames: Buffer[] = [];
  let rest = data;
  while (rest.length >= 4) {
    const length = rest.readUInt32BE(0) & 0xffffff;
    if (rest.length - 4 < length) break;
    frames.push(Buffer.from(rest.subarray(4, 4 + length)));
    rest = rest.subarray(4 + length);
  }
  return { frames, rest };
}

function frame(message: Buffer): Buffer {
  const prefix = Buffer.alloc(4);
  prefix.writeUInt32BE(message.length);
  return Buffer.concat([prefix, message]);
}

export interface FlowOptions {
  host: string;
  port: number;
  share: string;
  credentials: { username: string; password: string; domain: string };
  signing: "auto" | "required";
  timestamp: bigint;
}

// The one flow both the capture and the replay run: share enumeration over
// SRVSVC, a write, a read back, a delete, and a clean close.
export async function runCaptureFlow(opts: FlowOptions): Promise<CaptureResult> {
  const session = await connect({
    host: opts.host,
    port: opts.port,
    authProvider: new NtlmTestProvider({
      workstation: CAPTURE_WORKSTATION,
      clientChallenge: Buffer.from(CAPTURE_CLIENT_CHALLENGE, "hex"),
      timestamp: opts.timestamp,
    }),
    credentials: opts.credentials,
    signing: opts.signing,
    requestTimeoutMs: 15000,
    // The fixtures hold SMB 2.1 exchanges; replay needs byte-identical
    // requests, so offer the same two dialects as at capture time.
    maxDialect: "2.1",
  });
  let result: CaptureResult;
  try {
    const shares = (await session.listShares()).map(({ name, type }) => ({ name, type }));
    await session.writeFile(opts.share, CAPTURE_FILE, CAPTURE_TEXT);
    const readBack = (await session.readFile(opts.share, CAPTURE_FILE)).toString("utf8");
    await session.delete(opts.share, CAPTURE_FILE);
    result = { shares, readBack };
  } catch (error) {
    // A replay that went off script answers the LOGOFF with the next
    // recorded frame, which the client refuses; keep the first error.
    await session.close().catch(() => undefined);
    throw error;
  }
  await session.close();
  return result;
}

// Forwards 127.0.0.1:<port> to the upstream SMB server and records every
// complete frame in arrival order.
export class RecordingProxy {
  frames: CapturedFrame[] = [];
  port = 0;
  private server = net.createServer((client) => this.onClient(client));
  private sockets = new Set<net.Socket>();

  constructor(private readonly upstreamPort: number, private readonly upstreamHost = "127.0.0.1") {}

  async start(): Promise<void> {
    await new Promise<void>((resolve) => this.server.listen(0, "127.0.0.1", resolve));
    this.port = (this.server.address() as net.AddressInfo).port;
  }

  async stop(): Promise<void> {
    for (const socket of this.sockets) socket.destroy();
    await new Promise<void>((resolve) => this.server.close(() => resolve()));
  }

  private onClient(client: net.Socket): void {
    const upstream = net.connect(this.upstreamPort, this.upstreamHost);
    this.sockets.add(client);
    this.sockets.add(upstream);
    this.pipe(client, upstream, "c2s");
    this.pipe(upstream, client, "s2c");
  }

  private pipe(from: net.Socket, to: net.Socket, dir: Direction): void {
    let pending = Buffer.alloc(0);
    from.on("data", (data: Buffer) => {
      pending = Buffer.concat([pending, data]);
      const { frames, rest } = splitFrames(pending);
      pending = Buffer.from(rest);
      for (const message of frames) this.frames.push({ dir, hex: message.toString("hex") });
      to.write(data);
    });
    from.on("end", () => to.end());
    from.on("error", () => to.destroy());
  }
}

// Fields that differ per run by design: the client's random 4-byte
// ProcessId/Reserved (header offset 32), the signature that covers it
// (offset 48, checked separately), and NEGOTIATE's random ClientGuid, also
// repeated in FSCTL_VALIDATE_NEGOTIATE_INFO's input, which starts
// at InputOffset 120 with Capabilities (4) then the Guid (16).
function comparable(message: Buffer): Buffer {
  const copy = Buffer.from(message);
  copy.fill(0, 32, 36);
  copy.fill(0, 48, 64);
  if (frameCommand(copy) === 0x0000) copy.fill(0, 64 + 12, 64 + 28);
  if (frameCommand(copy) === 0x000b && copy.length >= 140 && copy.readUInt32LE(64 + 4) === 0x00140204) copy.fill(0, 124, 140);
  return copy;
}

// HMAC-SHA256 SMB2 signature check (MS-SMB2 3.1.4.1), done with node:crypto
// directly so it stays independent of src/signing.
export function signatureValid(message: Buffer, key: Buffer): boolean {
  const zeroed = Buffer.from(message);
  zeroed.fill(0, 48, 64);
  const want = crypto.createHmac("sha256", key).update(zeroed).digest().subarray(0, 16);
  return want.equals(message.subarray(48, 64));
}

export interface ReplayMismatch {
  index: number;
  expected: string;
  actual: string;
}

// Serves recorded server frames back in order. Each client frame must equal
// the recorded client frame at the same position (per-run fields masked, see
// comparable); a signed client frame must also carry a valid signature under
// sessionKey. After each client frame, every recorded server frame up to the
// next client frame is sent.
export class ReplayServer {
  port = 0;
  mismatches: ReplayMismatch[] = [];
  clientFramesSeen = 0;
  private cursor = 0;
  private server = net.createServer((socket) => this.onClient(socket));
  private sockets = new Set<net.Socket>();

  constructor(private readonly frames: CapturedFrame[], private readonly sessionKey?: Buffer) {}

  get consumedAll(): boolean {
    return this.cursor === this.frames.length;
  }

  async start(): Promise<void> {
    await new Promise<void>((resolve) => this.server.listen(0, "127.0.0.1", resolve));
    this.port = (this.server.address() as net.AddressInfo).port;
  }

  async stop(): Promise<void> {
    for (const socket of this.sockets) socket.destroy();
    await new Promise<void>((resolve) => this.server.close(() => resolve()));
  }

  private onClient(socket: net.Socket): void {
    this.sockets.add(socket);
    let pending = Buffer.alloc(0);
    socket.on("data", (data: Buffer) => {
      pending = Buffer.concat([pending, data]);
      const { frames, rest } = splitFrames(pending);
      pending = Buffer.from(rest);
      for (const message of frames) this.onClientFrame(socket, message);
    });
    socket.on("error", () => undefined);
  }

  private onClientFrame(socket: net.Socket, message: Buffer): void {
    this.clientFramesSeen++;
    const expected = this.frames[this.cursor];
    if (!expected || expected.dir !== "c2s") {
      this.mismatches.push({ index: this.cursor, expected: expected?.hex ?? "<end>", actual: message.toString("hex") });
      socket.destroy();
      return;
    }
    const want = Buffer.from(expected.hex, "hex");
    const badSignature = isSigned(message) && (!this.sessionKey || !signatureValid(message, this.sessionKey));
    if (badSignature || isSigned(message) !== isSigned(want) || !comparable(want).equals(comparable(message))) {
      this.mismatches.push({ index: this.cursor, expected: expected.hex, actual: message.toString("hex") });
    }
    this.cursor++;
    while (this.cursor < this.frames.length && this.frames[this.cursor].dir === "s2c") {
      socket.write(frame(Buffer.from(this.frames[this.cursor].hex, "hex")));
      this.cursor++;
    }
  }
}
