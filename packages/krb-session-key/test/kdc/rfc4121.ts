// RFC 4121 4.2.6.2 Wrap token header, as parsed by the tests (the addon
// never looks inside the token; GSS does).
//
//   TOK_ID (2) = 05 04 | Flags (1) | Filler (1) = FF | EC (2) | RRC (2) | SND_SEQ (8)
//
// Flags: 0x01 SentByAcceptor, 0x02 Sealed, 0x04 AcceptorSubkey.
//
// With gss_wrap_iov and no TRAILER buffer, the mechanism rotates the
// trailer (E(filler + header copy) and the checksum) into the HEADER
// buffer by RRC bytes (RFC 4121 4.2.5), so for aes128-cts-hmac-sha1-96
// and aes256-cts-hmac-sha1-96 the header buffer is:
//   16 (token header) + 16 (confounder) + EC (filler) + 16 (header copy) + 12 (HMAC-SHA1-96)
// and RRC = EC + 16 + 12. The DATA buffer keeps the plaintext length.
export const TOKEN_HEADER_LENGTH = 16;
export const AES_CONFOUNDER_LENGTH = 16;
export const AES_SHA1_CHECKSUM_LENGTH = 12;
export const FLAG_SENT_BY_ACCEPTOR = 0x01;
export const FLAG_SEALED = 0x02;
export const FLAG_ACCEPTOR_SUBKEY = 0x04;

export interface WrapTokenHeader {
  flags: number;
  ec: number;
  rrc: number;
  sndSeq: bigint;
}

export function parseWrapTokenHeader(header: Buffer): WrapTokenHeader {
  if (header.length < TOKEN_HEADER_LENGTH) throw new Error(`wrap token header is ${header.length} bytes, shorter than 16`);
  if (header[0] !== 0x05 || header[1] !== 0x04) throw new Error(`TOK_ID is ${header.subarray(0, 2).toString('hex')}, not 0504`);
  if (header[3] !== 0xff) throw new Error(`Filler is ${header[3]?.toString(16)}, not ff`);
  return {
    flags: header[2] as number,
    ec: header.readUInt16BE(4),
    rrc: header.readUInt16BE(6),
    sndSeq: header.readBigUInt64BE(8),
  };
}

// The MS-WSMV encryption-header length RFC 4121 gives for an AES-SHA1
// enctype once the trailer is rotated into the header.
export function expectedAesHeaderLength(ec: number): number {
  return TOKEN_HEADER_LENGTH + AES_CONFOUNDER_LENGTH + ec + TOKEN_HEADER_LENGTH + AES_SHA1_CHECKSUM_LENGTH;
}

// Rotates the body of a wrap token (everything after the 16-byte header)
// so that its RRC becomes `rrc`, and writes the new RRC into the header.
// RFC 4121 4.2.5: the body on the wire is the encryption output rotated
// right by RRC octets, so the same message can carry any RRC. The
// encrypted header copy keeps RRC 0 whatever the outer header says, so a
// re-rotated token verifies like the original.
export function rotateWrapToken(token: Buffer, rrc: number): Buffer {
  const h = parseWrapTokenHeader(token);
  const body = token.subarray(TOKEN_HEADER_LENGTH);
  // Undo the sender's rotation (rotate left by h.rrc), then rotate right by rrc.
  const unrotated = Buffer.concat([body.subarray(h.rrc % body.length), body.subarray(0, h.rrc % body.length)]);
  const cut = body.length - (rrc % body.length);
  const rotated = Buffer.concat([unrotated.subarray(cut), unrotated.subarray(0, cut)]);
  const out = Buffer.concat([token.subarray(0, TOKEN_HEADER_LENGTH), rotated]);
  out.writeUInt16BE(rrc, 6);
  return out;
}

// The MS-WSMV split of a whole wrap token (2.2.9.1.1.2.2): the last
// `plaintextLength` bytes are the Encrypted Data, everything before them
// is the encryption header the Length-Field counts.
export function splitWinRM(token: Buffer, plaintextLength: number): { header: Buffer; data: Buffer } {
  if (token.length < TOKEN_HEADER_LENGTH + plaintextLength) throw new Error(`token of ${token.length} bytes cannot carry ${plaintextLength} bytes of data`);
  return { header: token.subarray(0, token.length - plaintextLength), data: token.subarray(token.length - plaintextLength) };
}
