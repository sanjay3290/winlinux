// Scripted SMB2 server for the mock tests (localhost TCP, no Windows).
// Stateless per command except for handles and the pipe DCE queue. Signs and
// verifies with node:crypto directly, never with src/signing, so the signing
// assertions stay independent of the code under test.
import net from "node:net";
import crypto from "node:crypto";
import Smb2Packet from "../../src/protocol/smb2/Packet.js";
import HeaderFlag from "../../src/protocol/smb2/HeaderFlag.js";
import PacketType from "../../src/protocol/smb2/PacketType.js";
import StatusCode from "../../src/protocol/smb2/StatusCode.js";

export const MOCK_SESSION_ID = "0a0b0c0d0e0f1011";
export const MOCK_TREE_ID = 1;

export interface MockDirEntry {
  name: string;
  isDirectory: boolean;
  size: number;
  reparse?: boolean; // FILE_ATTRIBUTE_REPARSE_POINT
}

export interface MockFile {
  data: Buffer;
  isDirectory: boolean;
  attrs?: number;
}

export interface MockOptions {
  securityMode?: number;
  sessionKey?: Buffer;
  signResponses?: boolean;
  tamperSignatures?: boolean;
  token1?: Buffer;
  challenge?: Buffer;
  token2?: Buffer;
  files?: Map<string, MockFile>;
  createErrors?: Map<string, number>;
  dirEntries?: Array<MockDirEntry>; // entries of every directory, unless dirTree names it
  dirTree?: Map<string, MockDirEntry[]>; // directory path in Windows form ("" = root) -> entries
  enumStub?: Buffer;
  treeConnectErrors?: Map<string, number>; // share name -> TREE_CONNECT status
  shareFlags?: Map<string, number>; // share name -> shi1005_flags for NetrShareGetInfo
  shareInfoStatus?: number; // NET_API_STATUS for shares missing from shareFlags (default 2310)
  setInfoErrors?: Map<string, number>; // file name -> status for any SET_INFO on it
  smb3?: MockSmb3Options; // answer NEGOTIATE with SMB 3.1.1
  interimPending?: boolean; // send an async STATUS_PENDING before every READ result
  // Rewrites the framed bytes (NetBIOS header + message) of each response,
  // by request command; returns them unchanged to leave a response alone.
  mangle?: (type: number, framed: Buffer) => Buffer;
  // Rewrites each response message after signing and before encryption
  //; the TRANSFORM header keeps MOCK_SESSION_ID.
  mangleMessage?: (type: number, message: Buffer) => Buffer;
  sessionFlags?: number; // OR'ed into the final SESSION_SETUP SessionFlags
  // The PDUs that answer NetShareEnum, in place of one RESPONSE.
  enumPdus?: (callId: number) => Buffer[];
  // FSCTL_VALIDATE_NEGOTIATE_INFO answer: by default the values of the
  // NEGOTIATE response; a field set here replaces that value, and `status`
  // fails the IOCTL instead.
  validateNegotiate?: { capabilities?: number; guid?: Buffer; securityMode?: number; dialect?: number; status?: number };
}

export const MOCK_SERVER_GUID = Buffer.from("00112233445566778899aabbccddeeff", "hex");

// What a client sent in FSCTL_VALIDATE_NEGOTIATE_INFO.
export interface ValidateNegotiateInput {
  capabilities: number;
  guid: Buffer;
  securityMode: number;
  dialects: number[];
}

// SMB 3.1.1 mode. The mock derives keys, signs with AES-GMAC and
// encrypts with AES-128-GCM/CCM using node:crypto directly (its own KDF,
// nonce and transform code below), never src/smb3.ts, so the assertions
// stay independent of the code under test.
export interface MockSmb3Options {
  cipher: 0 | 1 | 2; // 0: no encryption context in the NEGOTIATE response
  encryptData?: boolean; // SMB2_SESSION_FLAG_ENCRYPT_DATA on the session
  encryptShares?: string[]; // SMB2_SHAREFLAG_ENCRYPT_DATA on these shares
  forcePlaintext?: boolean; // answer encrypted requests in plaintext (misbehaving server)
  tamperEncrypted?: boolean; // flip one ciphertext byte of every encrypted response
  unsignedFinal?: boolean; // do not sign the final SESSION_SETUP response
  // 0x0300 or 0x0302: no negotiate contexts or preauth hash, the
  // 3.0 key labels, AES-CMAC signing, AES-128-CCM when cipher is 1.
  dialect?: 0x0300 | 0x0302 | 0x0311;
}

const TRANSFORM_ID = Buffer.from([0xfd, 0x53, 0x4d, 0x42]);

function kdf16(ki: Buffer, label: string, context: Buffer): Buffer {
  const be = (n: number) => {
    const b = Buffer.alloc(4);
    b.writeUInt32BE(n);
    return b;
  };
  return crypto.createHmac("sha256", ki).update(be(1)).update(label, "latin1").update(Buffer.from([0])).update(context).update(be(128)).digest().subarray(0, 16);
}

function gmac16(key: Buffer, message: Buffer): Buffer {
  const zeroed = Buffer.from(message);
  zeroed.fill(0, 48, 64);
  const nonce = Buffer.alloc(12);
  zeroed.copy(nonce, 0, 24, 32);
  nonce.writeUInt32LE((zeroed.readUInt32LE(16) & 1) | (zeroed.readUInt16LE(12) === 0x0c ? 2 : 0), 8);
  const gcm = crypto.createCipheriv("aes-128-gcm", key, nonce);
  gcm.setAAD(zeroed);
  gcm.final();
  return gcm.getAuthTag();
}

// AES-CMAC (RFC 4493) as a plain CBC-MAC loop over 16-byte blocks.
function cmac16(key: Buffer, message: Buffer): Buffer {
  const zeroed = Buffer.from(message);
  zeroed.fill(0, 48, 64);
  const aes = (block: Buffer) => {
    const c = crypto.createCipheriv("aes-128-ecb", key, null);
    c.setAutoPadding(false);
    return c.update(block);
  };
  const shift = (block: Buffer) => {
    const out = Buffer.alloc(16);
    for (let i = 0; i < 16; i++) out[i] = ((block[i] << 1) | (i < 15 ? block[i + 1] >> 7 : 0)) & 0xff;
    if (block[0] & 0x80) out[15] ^= 0x87;
    return out;
  };
  const k1 = shift(aes(Buffer.alloc(16)));
  const k2 = shift(k1);
  const n = Math.max(1, Math.ceil(zeroed.length / 16));
  let state = Buffer.alloc(16);
  for (let b = 0; b < n; b++) {
    const block = Buffer.alloc(16);
    const chunk = zeroed.subarray(b * 16, b * 16 + 16);
    chunk.copy(block);
    if (b === n - 1) {
      const full = chunk.length === 16;
      if (!full) block[chunk.length] = 0x80;
      const k = full ? k1 : k2;
      for (let i = 0; i < 16; i++) block[i] ^= k[i];
    }
    for (let i = 0; i < 16; i++) block[i] ^= state[i];
    state = aes(block);
  }
  return state;
}

function mockEncrypt(message: Buffer, cipher: number, key: Buffer, sessionId: Buffer): Buffer {
  const header = Buffer.alloc(52);
  TRANSFORM_ID.copy(header, 0);
  const nonceLength = cipher === 2 ? 12 : 11;
  crypto.randomBytes(nonceLength).copy(header, 20);
  header.writeUInt32LE(message.length, 36);
  header.writeUInt16LE(1, 42);
  sessionId.copy(header, 44);
  const iv = header.subarray(20, 20 + nonceLength);
  const c = cipher === 2
    ? crypto.createCipheriv("aes-128-gcm", key, iv)
    : crypto.createCipheriv("aes-128-ccm", key, iv, { authTagLength: 16 });
  if (cipher === 2) (c as crypto.CipherGCM).setAAD(header.subarray(20));
  else (c as crypto.CipherCCM).setAAD(header.subarray(20), { plaintextLength: message.length });
  const body = Buffer.concat([c.update(message), c.final()]);
  (c as crypto.CipherGCM).getAuthTag().copy(header, 4);
  return Buffer.concat([header, body]);
}

function mockDecrypt(frame: Buffer, cipher: number, key: Buffer): Buffer | undefined {
  const nonceLength = cipher === 2 ? 12 : 11;
  const iv = frame.subarray(20, 20 + nonceLength);
  const body = frame.subarray(52);
  try {
    const d = cipher === 2
      ? crypto.createDecipheriv("aes-128-gcm", key, iv)
      : crypto.createDecipheriv("aes-128-ccm", key, iv, { authTagLength: 16 });
    (d as crypto.DecipherGCM).setAuthTag(frame.subarray(4, 20));
    if (cipher === 2) (d as crypto.DecipherGCM).setAAD(frame.subarray(20, 52));
    else (d as crypto.DecipherCCM).setAAD(frame.subarray(20, 52), { plaintextLength: body.length });
    return Buffer.concat([d.update(body), d.final()]);
  } catch {
    return undefined;
  }
}

function negotiateContexts(cipher: number): Buffer[] {
  const ctx = (type: number, data: Buffer) => {
    const head = Buffer.alloc(8);
    head.writeUInt16LE(type, 0);
    head.writeUInt16LE(data.length, 2);
    return Buffer.concat([head, data]);
  };
  const preauth = Buffer.alloc(38);
  preauth.writeUInt16LE(1, 0);
  preauth.writeUInt16LE(32, 2);
  preauth.writeUInt16LE(1, 4); // SHA-512
  crypto.randomBytes(32).copy(preauth, 6);
  const list = [ctx(1, preauth)];
  if (cipher) list.push(ctx(2, Buffer.from([1, 0, cipher, 0])));
  list.push(ctx(8, Buffer.from([1, 0, 2, 0]))); // AES-GMAC
  return list;
}

const NERR_NET_NAME_NOT_FOUND = 2310;

export interface SeenRequest {
  type: number;
  messageId: bigint;
  signed: boolean;
  signatureValid: boolean | null;
  creditCharge: number;
  encrypted: boolean; // arrived in a TRANSFORM_HEADER
  treeId: number;
}

const status = (name: string): number =>
  (StatusCode as unknown as Record<string, number>)[name];

function hmac16(key: Buffer, message: Buffer): Buffer {
  const zeroed = Buffer.from(message);
  zeroed.fill(0, 48, 64);
  return crypto.createHmac("sha256", key).update(zeroed).digest().subarray(0, 16);
}

export function filetimeUtc(
  year: number,
  month: number,
  day: number,
  hour: number,
  minute: number,
  second: number,
): bigint {
  return BigInt(Date.UTC(year, month - 1, day, hour, minute, second) + 11644473600000) * 10000n;
}

export const MOCK_FILETIME = filetimeUtc(2024, 0 + 1, 2, 3, 4, 5);

function splitFrames(data: Buffer): { frames: Buffer[]; rest: Buffer } {
  const frames: Buffer[] = [];
  let rest = data;
  while (rest.length >= 4) {
    const length = rest.readUInt32BE(0) & 0xffffff;
    if (rest.length - 4 < length) break;
    frames.push(rest.subarray(4, 4 + length));
    rest = rest.subarray(4 + length);
  }
  return { frames, rest };
}

export class MockSmbServer {
  connections = 0;
  connectionsClosed = 0;
  seen: SeenRequest[] = [];
  setupBuffers: Buffer[] = [];
  creates: Array<{ name: string; disposition: number; options: number }> = [];
  setInfos: Array<{ name: string; infoClass: number; buffer: Buffer }> = [];
  decryptFailures = 0;
  // SMB 3.1.1 state
  private preauth = Buffer.alloc(64);
  private keys: { signing: Buffer; c2s: Buffer; s2c: Buffer } | undefined;
  private shareIds = new Map<string, number>();
  shareOfTree = new Map<number, string>();
  handlesOpened = 0; // successful CREATEs (a refused CREATE opens nothing)
  treeConnects: string[] = []; // share names, in order
  shareInfoQueries: string[] = []; // NetrShareGetInfo share names, in order
  queryDirCount = 0;
  validateRequests: ValidateNegotiateInput[] = [];
  negotiateRequest: { securityMode: number; capabilities: number; guid: Buffer; dialects: number[] } | undefined;
  dceWrites: Buffer[] = [];
  written = new Map<string, Buffer[]>(); // file name -> written chunks

  private server: net.Server | undefined;
  private sockets = new Set<net.Socket>();
  private handles = new Map<string, string>(); // fileId hex -> name ('\pipe' for srvsvc)
  private handleCounter = 1;
  private setupCount = 0;
  private queryDirCalls = new Map<string, number>();
  private pipeOutbox: Buffer[] = [];
  private files: Map<string, MockFile>;

  constructor(private readonly opts: MockOptions = {}) {
    this.files = new Map(opts.files ?? []);
  }

  async listen(): Promise<number> {
    this.server = net.createServer((socket) => this.onConnection(socket));
    await new Promise<void>((resolve) => this.server!.listen(0, "127.0.0.1", resolve));
    return (this.server.address() as net.AddressInfo).port;
  }

  async close(): Promise<void> {
    for (const socket of this.sockets) socket.destroy();
    await new Promise<void>((resolve, reject) =>
      this.server!.close((error) => (error ? reject(error) : resolve())),
    );
  }

  writtenBytes(name: string): Buffer {
    return Buffer.concat(this.written.get(name) ?? []);
  }

  signedSeen(): SeenRequest[] {
    return this.seen.filter((request) => request.signed);
  }

  private onConnection(socket: net.Socket): void {
    this.connections++;
    this.sockets.add(socket);
    socket.on("close", () => {
      this.sockets.delete(socket);
      this.connectionsClosed++;
    });
    let pending = Buffer.alloc(0);
    socket.on("data", (data: Buffer) => {
      pending = Buffer.concat([pending, data]);
      const { frames, rest } = splitFrames(pending);
      pending = rest;
      for (const frame of frames) this.onFrame(socket, frame);
    });
  }

  private onFrame(socket: net.Socket, wireFrame: Buffer): void {
    const smb3 = this.opts.smb3;
    let frame = wireFrame;
    let encrypted = false;
    if (wireFrame.subarray(0, 4).equals(TRANSFORM_ID)) {
      const inner = smb3 && this.keys ? mockDecrypt(wireFrame, smb3.cipher, this.keys.c2s) : undefined;
      if (!inner) {
        this.decryptFailures++;
        socket.destroy();
        return;
      }
      frame = inner;
      encrypted = true;
    }
    const { header, body } = Smb2Packet.parse(frame);
    const signed = ((header.flags ?? 0) & HeaderFlag.Signed) !== 0;
    let signatureValid: boolean | null = null;
    if (signed) {
      signatureValid = this.keys
        ? crypto.timingSafeEqual(frame.subarray(48, 64), this.sign16(this.keys.signing, frame))
        : this.opts.sessionKey !== undefined &&
          crypto.timingSafeEqual(frame.subarray(48, 64), hmac16(this.opts.sessionKey, frame));
    }
    this.seen.push({ type: header.type, messageId: header.messageId as bigint, signed, signatureValid, creditCharge: header.creditCharge ?? 0, encrypted, treeId: header.treeId ?? 0 });
    if (smb3 && (header.type === PacketType.Negotiate || header.type === PacketType.SessionSetup)) {
      this.preauth = crypto.createHash("sha512").update(this.preauth).update(frame).digest();
    }
    const respond = (responseStatus: number, responseBody: Record<string, unknown> = {}, extra: Record<string, unknown> = {}) => {
      const responseHeader = {
        type: header.type,
        flags: HeaderFlag.Response,
        messageId: header.messageId,
        sessionId: MOCK_SESSION_ID,
        treeId: header.treeId ?? 0,
        status: responseStatus,
        credit: 126,
        ...extra,
      };
      let message = Smb2Packet.serializeMessage(responseHeader, responseBody);
      if (smb3 && header.type === PacketType.Negotiate && this.dialect === 0x0311) {
        // Append the 3.1.1 contexts, 8-byte aligned, and point at them.
        const parts: Buffer[] = [message];
        let length = message.length;
        const pad = () => {
          const n = (8 - (length % 8)) % 8;
          parts.push(Buffer.alloc(n));
          length += n;
        };
        pad();
        const offset = length;
        const contexts = negotiateContexts(smb3.cipher);
        contexts.forEach((c, i) => {
          if (i) pad();
          parts.push(c);
          length += c.length;
        });
        message = Buffer.concat(parts);
        message.writeUInt16LE(contexts.length, 64 + 6);
        message.writeUInt32LE(offset, 64 + 60);
      }
      const finalSetup = smb3 && header.type === PacketType.SessionSetup && responseStatus === StatusCode.Success;
      if (finalSetup && this.opts.sessionKey) {
        this.keys = this.dialect === 0x0311
          ? {
              signing: kdf16(this.opts.sessionKey, "SMBSigningKey\0", this.preauth),
              c2s: kdf16(this.opts.sessionKey, "SMBC2SCipherKey\0", this.preauth),
              s2c: kdf16(this.opts.sessionKey, "SMBS2CCipherKey\0", this.preauth),
            }
          : {
              signing: kdf16(this.opts.sessionKey, "SMB2AESCMAC\0", Buffer.from("SmbSign\0", "latin1")),
              c2s: kdf16(this.opts.sessionKey, "SMB2AESCCM\0", Buffer.from("ServerIn \0", "latin1")),
              s2c: kdf16(this.opts.sessionKey, "SMB2AESCCM\0", Buffer.from("ServerOut\0", "latin1")),
            };
      }
      const encryptReply = encrypted && !smb3?.forcePlaintext;
      // No key exists for NEGOTIATE or a MORE_PROCESSING SESSION_SETUP.
      const beforeKey = header.type === PacketType.Negotiate ||
        (header.type === PacketType.SessionSetup && responseStatus === StatusCode.MoreProcessingRequired);
      // Interim responses are never signed (MS-SMB2 3.3.4.1.1).
      const interim = responseStatus === 0x00000103 && ((extra.flags as number | undefined) ?? 0) & HeaderFlag.Async;
      if (interim) {
        // left unsigned
      } else if (this.keys && !encryptReply && (finalSetup ? !smb3?.unsignedFinal : this.opts.signResponses)) {
        message = Buffer.from(message);
        message.writeUInt32LE(message.readUInt32LE(16) | HeaderFlag.Signed, 16);
        this.sign16(this.keys.signing, message).copy(message, 48);
        if (this.opts.tamperSignatures && !finalSetup) message[60] ^= 0xff;
      } else if (!smb3 && this.opts.signResponses && this.opts.sessionKey && !beforeKey) {
        responseHeader.flags = HeaderFlag.Response | HeaderFlag.Signed;
        message = Smb2Packet.serializeMessage(responseHeader, responseBody);
        message = Buffer.from(message);
        hmac16(this.opts.sessionKey, message).copy(message, 48);
        if (this.opts.tamperSignatures) message[60] ^= 0xff;
      }
      if (smb3 && (header.type === PacketType.Negotiate || (header.type === PacketType.SessionSetup && responseStatus === StatusCode.MoreProcessingRequired))) {
        this.preauth = crypto.createHash("sha512").update(this.preauth).update(message).digest();
      }
      if (this.opts.mangleMessage) message = this.opts.mangleMessage(header.type, Buffer.from(message));
      let wire = message;
      if (encryptReply && this.keys && smb3) {
        wire = mockEncrypt(message, smb3.cipher, this.keys.s2c, Buffer.from(MOCK_SESSION_ID, "hex"));
        if (smb3.tamperEncrypted) wire[wire.length - 1] ^= 0x01;
      }
      const framed = Smb2Packet.prefixMessage(wire);
      socket.write(this.opts.mangle ? this.opts.mangle(header.type, framed) : framed);
    };

    switch (header.type) {
      case PacketType.Negotiate: {
        const count = frame.readUInt16LE(64 + 2);
        this.negotiateRequest = {
          securityMode: frame.readUInt16LE(64 + 4),
          capabilities: frame.readUInt32LE(64 + 8),
          guid: Buffer.from(frame.subarray(64 + 12, 64 + 28)),
          dialects: Array.from({ length: count }, (_, i) => frame.readUInt16LE(64 + 36 + 2 * i)),
        };
        respond(StatusCode.Success, {
          securityMode: this.opts.securityMode ?? 0,
          dialectRevision: this.negotiatedDialect,
          serverGuid: BigInt(`0x${Buffer.from(MOCK_SERVER_GUID).reverse().toString("hex")}`),
          capabilities: this.serverCapabilities,
        });
        return;
      }
      case PacketType.InputOutputControl: {
        if ((body.ctlCode as number) !== 0x00140204) {
          respond(0xc0000010, {}); // STATUS_INVALID_DEVICE_REQUEST
          return;
        }
        const input = body.buffer as Buffer;
        const count = input.readUInt16LE(22);
        this.validateRequests.push({
          capabilities: input.readUInt32LE(0),
          guid: Buffer.from(input.subarray(4, 20)),
          securityMode: input.readUInt16LE(20),
          dialects: Array.from({ length: count }, (_, i) => input.readUInt16LE(24 + 2 * i)),
        });
        const answer = this.opts.validateNegotiate ?? {};
        if (answer.status !== undefined) {
          respond(answer.status, {});
          return;
        }
        const output = Buffer.alloc(24);
        output.writeUInt32LE(answer.capabilities ?? this.serverCapabilities, 0);
        (answer.guid ?? MOCK_SERVER_GUID).copy(output, 4);
        output.writeUInt16LE(answer.securityMode ?? this.opts.securityMode ?? 0, 20);
        output.writeUInt16LE(answer.dialect ?? this.negotiatedDialect, 22);
        respond(StatusCode.Success, {
          structureSize: 49,
          ctlCode: 0x00140204,
          fileId: body.fileId,
          inputOffset: 64 + 48,
          outputOffset: 64 + 48,
          buffer: output,
        });
        return;
      }
      case PacketType.SessionSetup: {
        const token = body.buffer as Buffer;
        this.setupBuffers.push(Buffer.from(token));
        const index = this.setupCount++;
        if (index === 0) {
          respond(StatusCode.MoreProcessingRequired, { buffer: this.opts.challenge ?? Buffer.from("mock-challenge") });
        } else {
          respond(StatusCode.Success, { buffer: Buffer.alloc(0), sessionFlags: (smb3?.encryptData ? 0x0004 : 0) | (this.opts.sessionFlags ?? 0) });
        }
        return;
      }
      case PacketType.TreeConnect: {
        const unc = (body.buffer as Buffer).toString("ucs2"); // \\host\share
        const share = unc.slice(unc.lastIndexOf("\\") + 1);
        this.treeConnects.push(share);
        const forced = this.opts.treeConnectErrors?.get(share);
        // One tree id per share name; the first share gets MOCK_TREE_ID.
        let treeId = this.shareIds.get(share);
        if (treeId === undefined) {
          treeId = MOCK_TREE_ID + this.shareIds.size;
          this.shareIds.set(share, treeId);
          this.shareOfTree.set(treeId, share);
        }
        const shareFlags = smb3?.encryptShares?.includes(share) ? 0x8000 : 0;
        respond(forced ?? StatusCode.Success, forced ? {} : { shareType: share === "IPC$" ? 2 : 1, shareFlags }, { treeId });
        return;
      }
      case PacketType.Create: {
        const name = (body.buffer as Buffer).toString("ucs2");
        const disposition = body.createDisposition as number;
        const options = body.createOptions as number;
        this.creates.push({ name, disposition, options });
        const forced = this.opts.createErrors?.get(name);
        if (forced !== undefined) {
          respond(forced, {});
          return;
        }
        if (name === "srvsvc") {
          respond(StatusCode.Success, { fileId: this.addHandle("\\pipe"), endOfFile: 0 });
          return;
        }
        if (name === "") {
          respond(StatusCode.Success, { fileId: this.addHandle("\\root"), endOfFile: 0 });
          return;
        }
        const existing = this.files.get(name);
        if (existing?.isDirectory && (options & 1) === 0) {
          respond(status("AccessDenied"), {}); // strict servers need the DIRECTORY flag
          return;
        }
        if (existing && disposition === 2) {
          respond(0xc0000035, {}); // COLLISION
          return;
        }
        if (!existing) {
          if (disposition === 1) {
            respond(0xc0000034, {}); // NOT_FOUND
            return;
          }
          this.files.set(name, { data: Buffer.alloc(0), isDirectory: (options & 1) !== 0 });
        }
        const file = this.files.get(name)!;
        respond(StatusCode.Success, { fileId: this.addHandle(name), endOfFile: file.data.length });
        return;
      }
      case PacketType.Close:
        respond(StatusCode.Success, {});
        return;
      case PacketType.Read: {
        if (this.opts.interimPending) {
          // Async interim response (MS-SMB2 3.3.4.2): the final one follows.
          respond(0x00000103, {}, { flags: HeaderFlag.Response | HeaderFlag.Async });
        }
        const name = this.handles.get(body.fileId as string) ?? "";
        const length = body.length as number;
        const offset = Number(body.offset as bigint);
        if (name === "\\pipe") {
          respond(StatusCode.Success, { buffer: this.pipeOutbox.shift() ?? Buffer.alloc(0) });
          return;
        }
        const data = this.files.get(name)?.data ?? Buffer.alloc(0);
        respond(StatusCode.Success, { buffer: data.subarray(offset, offset + length) });
        return;
      }
      case PacketType.Write: {
        const name = this.handles.get(body.fileId as string) ?? "";
        const chunk = Buffer.from(body.buffer as Buffer);
        if (name === "\\pipe") {
          this.onPipeWrite(chunk);
        } else {
          const list = this.written.get(name) ?? [];
          list.push(chunk);
          this.written.set(name, list);
        }
        respond(StatusCode.Success, { count: chunk.length });
        return;
      }
      case PacketType.SetInfo: {
        const name = this.handles.get(body.fileId as string) ?? "";
        this.setInfos.push({ name, infoClass: body.fileInfoClass as number, buffer: Buffer.from(body.buffer as Buffer) });
        const forced = this.opts.setInfoErrors?.get(name);
        respond(forced ?? StatusCode.Success, {});
        return;
      }
      case PacketType.QueryInfo: {
        const name = this.handles.get(body.fileId as string) ?? "";
        const file = this.files.get(name) ?? { data: Buffer.alloc(0), isDirectory: false };
        const infoClass = body.fileInfoClass as number;
        respond(StatusCode.Success, {
          buffer: infoClass === 4 ? basicInfo(file) : standardInfo(file),
        });
        return;
      }
      case PacketType.QueryDirectory: {
        const handle = body.fileId as string;
        const calls = (this.queryDirCalls.get(handle) ?? 0) + 1;
        this.queryDirCalls.set(handle, calls);
        this.queryDirCount++;
        if (calls > 1) {
          respond(status("NoMoreFiles"), {});
          return;
        }
        const dirName = this.handles.get(handle) ?? "";
        const entries = this.opts.dirTree?.get(dirName === "\\root" ? "" : dirName) ?? this.opts.dirEntries ?? [];
        respond(StatusCode.Success, { buffer: dirEntries(entries) });
        return;
      }
      default:
        respond(StatusCode.Success, {});
    }
  }

  private get dialect(): number {
    return this.opts.smb3?.dialect ?? 0x0311;
  }

  private get negotiatedDialect(): number {
    return this.opts.smb3 ? this.dialect : 0x0210;
  }

  // 3.0.x has no negotiate contexts: encryption is a capability.
  private get serverCapabilities(): number {
    return this.opts.smb3 && this.dialect !== 0x0311 && this.opts.smb3.cipher ? 0x40 : 0;
  }

  // The SMB 3.x signature: AES-GMAC for 3.1.1 (the mock negotiates it),
  // AES-CMAC for 3.0 and 3.0.2.
  private sign16(key: Buffer, message: Buffer): Buffer {
    return this.dialect === 0x0311 ? gmac16(key, message) : cmac16(key, message);
  }

  private addHandle(name: string): string {
    this.handlesOpened++;
    const id = Buffer.alloc(16, this.handleCounter++).toString("hex");
    this.handles.set(id, name);
    return id;
  }

  private onPipeWrite(pdu: Buffer): void {
    this.dceWrites.push(Buffer.from(pdu));
    const callId = pdu.readUInt32LE(12);
    if (pdu[2] === 11) {
      this.pipeOutbox.push(bindAck(callId));
    } else if (pdu[2] === 0) {
      const opnum = pdu.readUInt16LE(22);
      if (opnum === 16) {
        this.pipeOutbox.push(rpcResponse(callId, this.shareGetInfoStub(pdu.subarray(24))));
      } else if (this.opts.enumPdus) {
        this.pipeOutbox.push(...this.opts.enumPdus(callId));
      } else {
        this.pipeOutbox.push(rpcResponse(callId, this.opts.enumStub ?? Buffer.alloc(0)));
      }
    }
  }

  // NetrShareGetInfo level 1005 (hand-built, no SUT code): the request stub
  // is ServerName NULL, then the NetName string pointee, then the level.
  private shareGetInfoStub(stub: Buffer): Buffer {
    const actual = stub.readUInt32LE(12);
    const share = stub.subarray(16, 16 + actual * 2).toString("utf16le").replace(/\0+$/, "");
    this.shareInfoQueries.push(share);
    const flags = this.opts.shareFlags?.get(share);
    const out: number[] = [1005];
    if (flags !== undefined) {
      out.push(0x20000, flags, 0); // referent, shi1005_flags, status 0
    } else {
      out.push(0, this.opts.shareInfoStatus ?? NERR_NET_NAME_NOT_FOUND); // NULL arm, status
    }
    const buffer = Buffer.alloc(out.length * 4);
    out.forEach((value, index) => buffer.writeUInt32LE(value >>> 0, index * 4));
    return buffer;
  }
}

// FILE_BASIC_INFORMATION (40 bytes) for a mock file.
function basicInfo(file: MockFile): Buffer {
  const out = Buffer.alloc(40);
  out.writeBigUInt64LE(MOCK_FILETIME, 0);
  out.writeBigUInt64LE(MOCK_FILETIME, 8);
  out.writeBigUInt64LE(MOCK_FILETIME, 16);
  out.writeBigUInt64LE(MOCK_FILETIME, 24);
  out.writeUInt32LE(file.attrs ?? (file.isDirectory ? 0x10 : 0x80), 32);
  return out;
}

// FILE_STANDARD_INFORMATION (24 bytes) for a mock file.
function standardInfo(file: MockFile): Buffer {
  const out = Buffer.alloc(24);
  out.writeBigUInt64LE(BigInt(file.data.length), 0);
  out.writeBigUInt64LE(BigInt(file.data.length), 8);
  out.writeUInt32LE(1, 16);
  out[20] = 0;
  out[21] = file.isDirectory ? 1 : 0;
  return out;
}

// FileIdBothDirectoryInformation entries (NextEntryOffset-chained).
function dirEntries(entries: MockDirEntry[]): Buffer {
  const parts: Buffer[] = [];
  entries.forEach((entry, index) => {
    const nameBytes = Buffer.from(entry.name, "ucs2");
    const total = 4 + 100 + nameBytes.length;
    const last = index === entries.length - 1;
    const out = Buffer.alloc(last ? total : total + ((8 - (total % 8)) % 8));
    out.writeUInt32LE(last ? 0 : out.length, 0);
    out.writeUInt32LE(index + 1, 4);
    out.writeBigUInt64LE(MOCK_FILETIME, 8);
    out.writeBigUInt64LE(MOCK_FILETIME, 16);
    out.writeBigUInt64LE(MOCK_FILETIME, 24);
    out.writeBigUInt64LE(MOCK_FILETIME, 32);
    out.writeBigUInt64LE(BigInt(entry.size), 40);
    out.writeBigUInt64LE(BigInt(entry.size), 48);
    out.writeUInt32LE((entry.isDirectory ? 0x10 : 0x80) | (entry.reparse ? 0x400 : 0), 56);
    out.writeUInt32LE(nameBytes.length, 60);
    out.writeUInt32LE(0, 64);
    out[68] = 0;
    out[69] = 0;
    out.writeUInt16LE(0, 94);
    Buffer.alloc(8, index + 1).copy(out, 96);
    nameBytes.copy(out, 104);
    parts.push(out);
  });
  return Buffer.concat(parts);
}

// Minimal BIND_ACK accepting context 0 over NDR (hand-built, no SUT code).
function bindAck(callId: number): Buffer {
  const out = Buffer.alloc(56);
  out[0] = 5;
  out[2] = 12;
  out[3] = 0x03;
  out.writeUInt32LE(0x10, 4);
  out.writeUInt16LE(56, 8);
  out.writeUInt32LE(callId, 12);
  out.writeUInt16LE(4280, 16);
  out.writeUInt16LE(4280, 18);
  out.writeUInt16LE(0, 24); // empty secondary address
  out[28] = 1; // one result
  out.writeUInt16LE(0, 32); // accept
  // NDR syntax UUID in mixed-endian wire order.
  const uuid = Buffer.from("8a885d041ceb11c99fe808002b104860", "hex");
  uuid.subarray(0, 4).reverse().copy(out, 36);
  uuid.subarray(4, 6).reverse().copy(out, 40);
  uuid.subarray(6, 8).reverse().copy(out, 42);
  uuid.subarray(8).copy(out, 44);
  out.writeUInt16LE(2, 52);
  out.writeUInt16LE(0, 54);
  return out;
}

function rpcResponse(callId: number, stub: Buffer): Buffer {
  const out = Buffer.alloc(24 + stub.length);
  out[0] = 5;
  out[2] = 2;
  out[3] = 0x03;
  out.writeUInt32LE(0x10, 4);
  out.writeUInt16LE(out.length, 8);
  out.writeUInt32LE(callId, 12);
  out.writeUInt32LE(stub.length, 16);
  stub.copy(out, 24);
  return out;
}
