// Test-only NTLM AuthProvider for the live Samba tests (@winlinux/auth
// ships the real one). Pure-JS NTLMv2 per MS-NLMP: NEGOTIATE, parse CHALLENGE,
// AUTHENTICATE with NTLMv2/LMv2 responses, and the NTLMv2 user session key
// for SMB2 signing. No DES needed: v2 is MD4 + HMAC-MD5 only.
import os from "node:os";
import crypto from "node:crypto";
import jsmd4 from "js-md4";
import NegotiateFlag from "./NegotiateFlag.js";
import type {
  AuthProvider,
  AuthTarget,
  Credentials,
  SecurityContext,
  StepResult,
} from "../../src/auth-contract.js";

export interface NtlmTestProviderOptions {
  includeSessionKey?: boolean; // false reproduces a provider without a key
  clientChallenge?: Buffer; // fixed 8 bytes for deterministic tests
  timestamp?: bigint; // fixed FILETIME for deterministic tests
  workstation?: string; // fixed name so captures do not leak the host name
}

export function md4(data: Buffer): Buffer {
  const hash = jsmd4.create();
  hash.update(data);
  return Buffer.from(hash.digest());
}

function hmacMd5(key: Buffer, ...parts: Buffer[]): Buffer {
  const hmac = crypto.createHmac("md5", key);
  for (const part of parts) hmac.update(part);
  return hmac.digest();
}

// NTLMSSP NEGOTIATE (MS-NLMP 2.2.1.1) with NTLMv2 flags only: Unicode,
// NTLM session security, always sign, extended session security, target
// info, version. Workstation and domain go out upper-cased as OEM strings;
// the fork's module did the same, so live captures replay unchanged.
export function encodeNegotiate(workstation: string, domain: string): Buffer {
  const workstationBytes = Buffer.from(workstation.toUpperCase(), "ascii");
  const domainBytes = Buffer.from(domain.toUpperCase(), "ascii");
  const message = Buffer.alloc(32 + workstationBytes.length + domainBytes.length);
  message.write("NTLMSSP", 0, 7, "ascii");
  message.writeUInt32LE(1, 8);
  const flags =
    NegotiateFlag.UnicodeEncoding |
    NegotiateFlag.NTLMSessionSecurity |
    NegotiateFlag.AlwaysSign |
    NegotiateFlag.ExtendedSessionSecurity |
    NegotiateFlag.TargetInfo |
    NegotiateFlag.Version;
  message.writeUInt32LE(flags >>> 0, 12);
  const workstationOffset = 32;
  const domainOffset = workstationOffset + workstationBytes.length;
  writeFields(message, 16, domainBytes.length, domainOffset);
  writeFields(message, 24, workstationBytes.length, workstationOffset);
  workstationBytes.copy(message, workstationOffset);
  domainBytes.copy(message, domainOffset);
  return message;
}

export interface NtlmChallenge {
  flags: number;
  serverChallenge: Buffer;
  targetInfo: Buffer;
}

export function parseChallenge(buffer: Buffer): NtlmChallenge {
  if (buffer.subarray(0, 7).toString("ascii") !== "NTLMSSP" || buffer[7] !== 0) {
    throw new Error("not an NTLMSSP message");
  }
  if (buffer.readUInt32LE(8) !== 2) throw new Error("not an NTLM challenge message");
  const flags = buffer.readUInt32LE(20);
  const serverChallenge = Buffer.from(buffer.subarray(24, 32));
  const infoLength = buffer.readUInt16LE(40);
  const infoOffset = buffer.readUInt32LE(44);
  const targetInfo = Buffer.from(buffer.subarray(infoOffset, infoOffset + infoLength));
  return { flags, serverChallenge, targetInfo };
}

function writeFields(buffer: Buffer, offset: number, length: number, valueOffset: number): number {
  buffer.writeUInt16LE(length, offset);
  buffer.writeUInt16LE(length, offset + 2);
  buffer.writeUInt32LE(valueOffset, offset + 4);
  return offset + 8;
}

export interface AuthenticateInput {
  username: string;
  domain: string;
  workstation: string;
  password: string;
  challenge: NtlmChallenge;
  clientChallenge: Buffer;
  timestamp: bigint;
}

export function buildAuthenticate(input: AuthenticateInput): { message: Buffer; sessionKey: Buffer } {
  const { username, domain, workstation, password, challenge } = input;
  const ntHash = md4(Buffer.from(password, "utf16le"));
  const v2hash = hmacMd5(ntHash, Buffer.from(username.toUpperCase() + domain, "utf16le"));

  const timestampBytes = Buffer.alloc(8);
  timestampBytes.writeBigUInt64LE(input.timestamp);
  const blob = Buffer.concat([
    Buffer.from([0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
    timestampBytes,
    input.clientChallenge,
    Buffer.alloc(4),
    challenge.targetInfo,
    Buffer.alloc(4),
  ]);
  const ntProof = hmacMd5(v2hash, challenge.serverChallenge, blob);
  const ntResponse = Buffer.concat([ntProof, blob]);
  const lmResponse = Buffer.concat([
    hmacMd5(v2hash, challenge.serverChallenge, input.clientChallenge),
    input.clientChallenge,
  ]);

  const domainBytes = Buffer.from(domain.toUpperCase(), "ucs2");
  const userBytes = Buffer.from(username, "ucs2");
  const workstationBytes = Buffer.from(workstation.toUpperCase(), "ucs2");

  const domainOffset = 64;
  const userOffset = domainOffset + domainBytes.length;
  const workstationOffset = userOffset + userBytes.length;
  const lmOffset = workstationOffset + workstationBytes.length;
  const ntOffset = lmOffset + lmResponse.length;

  const message = Buffer.alloc(ntOffset + ntResponse.length);
  message.write("NTLMSSP", 0, 7, "ascii");
  message.writeUInt32LE(3, 8);
  let offset = 12;
  offset = writeFields(message, offset, lmResponse.length, lmOffset);
  offset = writeFields(message, offset, ntResponse.length, ntOffset);
  offset = writeFields(message, offset, domainBytes.length, domainOffset);
  offset = writeFields(message, offset, userBytes.length, userOffset);
  offset = writeFields(message, offset, workstationBytes.length, workstationOffset);
  offset = writeFields(message, offset, 0, 0); // no encrypted session key
  // Echo the server flags, minus the ones we do not satisfy: we send no
  // version field and no encrypted session key.
  const flags = (challenge.flags & ~(NegotiateFlag.Version | NegotiateFlag.KeyExchange)) >>> 0;
  message.writeUInt32LE(flags, offset);
  domainBytes.copy(message, domainOffset);
  userBytes.copy(message, userOffset);
  workstationBytes.copy(message, workstationOffset);
  lmResponse.copy(message, lmOffset);
  ntResponse.copy(message, ntOffset);

  // MS-NLMP 3.4.3: for NTLMv2 without key exchange the user session key is
  // the session base key, HMAC-MD5(ResponseKeyNT, NTProofStr).
  const sessionKey = hmacMd5(v2hash, ntProof);
  return { message, sessionKey };
}

export function filetimeNow(): bigint {
  return BigInt(Date.now() + 11644473600000) * 10000n;
}

export class NtlmTestProvider implements AuthProvider {
  readonly mechanism = "ntlm" as const;

  constructor(private readonly opts: NtlmTestProviderOptions = {}) {}

  createContext(target: AuthTarget, credentials: Credentials): SecurityContext {
    return new NtlmTestContext(target, credentials, this.opts);
  }
}

class NtlmTestContext implements SecurityContext {
  complete = false;
  sessionKey: Buffer | undefined;
  private stepCount = 0;

  constructor(
    private readonly target: AuthTarget,
    private readonly credentials: Credentials,
    private readonly opts: NtlmTestProviderOptions,
  ) {}

  async step(inputToken?: Buffer): Promise<StepResult> {
    const index = this.stepCount++;
    if (index === 0) {
      const domain = this.credentials.domain ?? "";
      return {
        output: encodeNegotiate(this.target.host, domain),
        complete: false,
      };
    }
    if (!inputToken) throw new Error("NTLM test provider: missing server challenge");
    const challenge = parseChallenge(inputToken);
    const { message, sessionKey } = buildAuthenticate({
      username: this.credentials.username,
      domain: this.credentials.domain ?? "",
      workstation: this.opts.workstation ?? os.hostname(),
      password: this.credentials.password ?? "",
      challenge,
      clientChallenge: this.opts.clientChallenge ?? crypto.randomBytes(8),
      timestamp: this.opts.timestamp ?? filetimeNow(),
    });
    this.sessionKey = this.opts.includeSessionKey === false ? undefined : sessionKey;
    this.complete = true;
    return { output: message, complete: true };
  }
}
