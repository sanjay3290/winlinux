// NTLM and SPNEGO bytes for tests: a tiny DER writer, SPNEGO frames, the
// NTLMSSP-shaped stub tokens, an MS-NLMP 4.2.4 CHALLENGE_MESSAGE with a
// timestamp, and an AUTHENTICATE AV-pair reader. Independent of the
// transport's own DER code (src/winrm/der.ts).

export function tlv(tag: number, content: Buffer): Buffer {
  const n = content.length;
  const len = n < 0x80 ? Buffer.from([n]) : n < 0x100 ? Buffer.from([0x81, n]) : Buffer.from([0x82, n >> 8, n & 0xff]);
  return Buffer.concat([Buffer.from([tag]), len, content]);
}

export const OID_SPNEGO_DER = Buffer.from('06062b0601050502', 'hex'); // 1.3.6.1.5.5.2
export const OID_NTLMSSP_DER = Buffer.from('060a2b06010401823702020a', 'hex'); // 1.3.6.1.4.1.311.2.2.10

// InitialContextToken { SPNEGO OID, [0] NegTokenInit { mechTypes { NTLMSSP }, [2] mechToken } }.
export function spnegoInit(mechToken: Buffer): Buffer {
  const init = tlv(0x30, Buffer.concat([tlv(0xa0, tlv(0x30, OID_NTLMSSP_DER)), tlv(0xa2, tlv(0x04, mechToken))]));
  return tlv(0x60, Buffer.concat([OID_SPNEGO_DER, tlv(0xa0, init)]));
}

// NegTokenResp { negState, [2] responseToken, [3] mechListMIC? }.
export function spnegoResp(responseToken: Buffer, opts?: { negState?: number; mechListMIC?: Buffer }): Buffer {
  const parts = [tlv(0xa0, tlv(0x0a, Buffer.from([opts?.negState ?? 1]))), tlv(0xa2, tlv(0x04, responseToken))];
  if (opts?.mechListMIC) parts.push(tlv(0xa3, tlv(0x04, opts.mechListMIC)));
  return tlv(0xa1, tlv(0x30, Buffer.concat(parts)));
}

// NTLMSSP-shaped stub messages: signature, MessageType, then a label.
// They have the shape of NEGOTIATE/CHALLENGE/AUTHENTICATE on the wire and
// none of the crypto.
export function ntlmsspStub(type: 1 | 2 | 3, label: string): Buffer {
  const head = Buffer.alloc(12);
  head.write('NTLMSSP\0', 0, 'ascii');
  head.writeUInt32LE(type, 8);
  return Buffer.concat([head, Buffer.from(label, 'utf8')]);
}

export const NTLM_STUB = {
  initial: ntlmsspStub(1, 'initial-token'),
  challenge: ntlmsspStub(2, 'server-challenge'),
  response: ntlmsspStub(3, 'response-token'),
} as const;

export const AV_EOL = 0;
export const AV_TIMESTAMP = 7;
export const AV_CHANNEL_BINDINGS = 10;

export interface AvPair {
  id: number;
  value: Buffer;
}

function av(id: number, value: Buffer): Buffer {
  const h = Buffer.alloc(4);
  h.writeUInt16LE(id, 0);
  h.writeUInt16LE(value.length, 2);
  return Buffer.concat([h, value]);
}

// MS-NLMP 4.2.4.3 CHALLENGE_MESSAGE (the public spec vector: flags
// 0xe28a8233, ServerChallenge 0123456789abcdef, TargetName "Server",
// TargetInfo Domain/Server) plus a timestamp AV pair, so the client adds
// its own AV pairs (3.1.5.1.2) and a MIC. Bare NTLMSSP bytes.
export function challengeWithTimestamp(): Buffer {
  const name = Buffer.from('Server', 'utf16le');
  const stamp = Buffer.alloc(8);
  stamp.writeBigUInt64LE(0x01db9999abcdef01n, 0);
  const info = Buffer.concat([
    av(2, Buffer.from('Domain', 'utf16le')),
    av(1, Buffer.from('Server', 'utf16le')),
    av(AV_TIMESTAMP, stamp),
    av(AV_EOL, Buffer.alloc(0)),
  ]);
  const h = Buffer.alloc(56);
  Buffer.from('4e544c4d53535000020000000c000c003800000033828ae20123456789abcdef0000000000000000', 'hex').copy(h, 0);
  h.writeUInt32LE(56, 16);
  h.writeUInt16LE(info.length, 40);
  h.writeUInt16LE(info.length, 42);
  h.writeUInt32LE(56 + name.length, 44);
  h.writeUInt32LE(0x0f000000, 52); // version: W2K3 revision, zero build
  return Buffer.concat([h, name, info]);
}

// Where an NTLMSSP message starts inside `token` (bare, or inside a SPNEGO
// frame), or -1.
export function ntlmsspOffset(token: Buffer): number {
  return token.indexOf('NTLMSSP\0');
}

// MessageType of the NTLMSSP message in `token`, or null.
export function ntlmsspType(token: Buffer): number | null {
  const at = ntlmsspOffset(token);
  return at < 0 || at + 12 > token.length ? null : token.readUInt32LE(at + 8);
}

// The AV pairs of the NTLMv2 blob of the AUTHENTICATE in `token` (offsets
// in its header are relative to "NTLMSSP\0").
export function type3AvPairs(token: Buffer): AvPair[] {
  const at = ntlmsspOffset(token);
  if (at < 0 || token.readUInt32LE(at + 8) !== 3) throw new Error('no AUTHENTICATE_MESSAGE in the token');
  const type3 = token.subarray(at);
  const ntOff = type3.readUInt32LE(24);
  const ntLen = type3.readUInt16LE(20);
  const avs = type3.subarray(ntOff + 16 + 28, ntOff + ntLen);
  const out: AvPair[] = [];
  for (let off = 0; off + 4 <= avs.length; ) {
    const id = avs.readUInt16LE(off);
    const len = avs.readUInt16LE(off + 2);
    out.push({ id, value: avs.subarray(off + 4, off + 4 + len) });
    off += 4 + len;
    if (id === AV_EOL) break;
  }
  return out;
}
