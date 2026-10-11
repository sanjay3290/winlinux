import type { Mechanism, SecurityContext } from '../auth-provider.js';
import { WinRMProtocolError, WinRMTransportError } from './errors.js';

// MS-WSMV 2.2.9.1 Encrypted Message Types. The WinRM transport owns all
// of this framing. The auth provider only seals and unseals bytes: wrap()
// returns the sealed blob, unwrap() takes it back. The provider never sees
// MIME text or the 4-byte length prefix.
//
// Protocol string: this transport authenticates every non-Basic mechanism
// with the "Negotiate" HTTP scheme (RFC 4559). MS-WSMV 2.2.9.1.1.1 says a
// NegotiateEncryptedMessage MUST use "application/HTTP-SPNEGO-session-encrypted",
// whether SPNEGO picked NTLM or Kerberos (2.2.9.1.1.2.2). The MS-WSMV 4.5
// example ("Authorization: Negotiate TlRMTVNTUAAD...") and pywinrm's
// encryption.py (protocol "ntlm") use the same string.
// "application/HTTP-Kerberos-session-encrypted" belongs to the "Kerberos"
// HTTP scheme (2.2.9.1.2.1), which this transport never sends.
//
// Payload (2.2.9.1.1.2.2 Encrypted Data): "\tContent-Type:
// application/octet-stream\r\n", then a 32-bit little-endian Length-Field
// with the length of the encryption header, then the header (for NTLM the
// 16-byte Message Signature), then the encrypted data.
export const SPNEGO_PROTOCOL = 'application/HTTP-SPNEGO-session-encrypted';
// The protocols of the Negotiate family (NTLM, Kerberos, SPNEGO).
export const ENCRYPTED_PROTOCOLS: readonly string[] = [SPNEGO_PROTOCOL];
// CredSSP (MS-WSMV 2.2.9.1.1.1): the "CredSSP" HTTP scheme encrypts
// with the inner TLS session of the CredSSP context. wrap() returns TLS
// records and unwrap() takes them. The Length-Field is the TLS trailer
// length (for AES-GCM the 16-byte tag), which the context reports through
// the optional credsspTrailerLength extension below. One TLS record holds
// 16 KiB of plaintext at most, so a longer message goes out as one
// encrypted part per 16 KiB chunk, with the content type
// multipart/x-multi-encrypted (as pywinrm sends it).
export const CREDSSP_PROTOCOL = 'application/HTTP-CredSSP-session-encrypted';
export const CREDSSP_CHUNK_BYTES = 16384;

// Mirrors @winlinux/auth CredSSPMessageProtection (additive, like the
// Kerberos extension below; the LOCKED contract is unchanged).
export interface CredSSPMessageProtection {
  readonly credsspTrailerLength?: () => number;
}

export function protocolFor(mechanism: Mechanism | undefined): string {
  return mechanism === 'credssp' ? CREDSSP_PROTOCOL : SPNEGO_PROTOCOL;
}

// True when a message of this size goes out as several encrypted parts.
export function isMultiPart(mechanism: Mechanism | undefined, length: number): boolean {
  return mechanism === 'credssp' && length > CREDSSP_CHUNK_BYTES;
}
export const MIME_BOUNDARY = '--Encrypted Boundary';
const PART_END = Buffer.from(`${MIME_BOUNDARY}--\r\n`, 'utf8');
const OCTET_HEADER = Buffer.from('\tContent-Type: application/octet-stream\r\n', 'utf8');

// NTLM wrap() returns the 16-byte NTLMSSP_MESSAGE_SIGNATURE followed by
// the sealed data (MS-NLMP 2.2.2.9.1, 3.4.4.2), and unwrap() takes the
// same layout. On the wire, MS-WSMV puts a 4-byte little-endian signature
// length in front of the signature.
const NTLM_SIGNATURE_LENGTH = 16;

// Kerberos: the contract wrap() returns one RFC 4121 wrap token,
// which is longer than the plaintext by more than its 16-byte header, so
// a fixed split would break the MS-WSMV rule that the encrypted data has
// the OriginalContent Length. The optional SecurityContext extension
// below (mirrors @winlinux/auth winrm-extension.ts; the LOCKED contract
// is unchanged) gives the split gss_wrap_iov produces: `header` is the
// per-message token with the trailer rotated in (60 bytes for AES-SHA1),
// `data` is exactly plaintext.length bytes. The Length-Field is
// header.length. On the way back the server decides the split: the
// header is as long as its Length-Field says, and unwrapWinRM() takes
// any RRC and EC the server's token carries. Without the extension
// (the `kerberos` package fallback) the transport refuses Kerberos
// message encryption.
export interface WinRMSealed {
  header: Buffer;
  data: Buffer;
}

export interface WinRMMessageProtection {
  readonly wrapWinRM?: (plaintext: Buffer) => Promise<WinRMSealed>;
  readonly unwrapWinRM?: (header: Buffer, data: Buffer) => Promise<Buffer>;
}

// The extension is live: both members are functions.
export function hasWinRMMessageProtection(ctx: SecurityContext): ctx is SecurityContext & Required<WinRMMessageProtection> {
  const c = ctx as WinRMMessageProtection;
  return typeof c.wrapWinRM === 'function' && typeof c.unwrapWinRM === 'function';
}

// The context type declares the extension (the members exist, as
// accessors), even when they read undefined until the first step
// created the GSS layer. A context without them can never offer it.
export function declaresWinRMMessageProtection(ctx: SecurityContext): boolean {
  return 'wrapWinRM' in ctx && 'unwrapWinRM' in ctx;
}

// RFC 4121 4.2.6.2: a wrap token header is 16 bytes at least.
const KERBEROS_MIN_HEADER_LENGTH = 16;

// The RFC 4121 4.2.6.2 wrap token header, for error messages: a failed
// unseal names what the sender put on the wire (TOK_ID, Flags, EC, RRC,
// SND_SEQ), so a trace against a server this code never met (Windows
// SSPI) says which layout it sent. Diagnostics only: the GSS
// library is the one that parses the token.
export function describeWrapToken(header: Buffer): string {
  if (header.length < KERBEROS_MIN_HEADER_LENGTH) return `${header.length} bytes, shorter than a wrap token header`;
  const tokId = header.subarray(0, 2).toString('hex');
  const flags = header[2] as number;
  const names = [flags & 0x01 ? 'SentByAcceptor' : '', flags & 0x02 ? 'Sealed' : '', flags & 0x04 ? 'AcceptorSubkey' : ''].filter((n) => n);
  return (
    `TOK_ID ${tokId}${tokId === '0504' ? '' : ' (not a wrap token)'}, ` +
    `Flags 0x${flags.toString(16).padStart(2, '0')}${names.length ? ` (${names.join('|')})` : ''}, ` +
    `Filler ${(header[3] as number).toString(16).padStart(2, '0')}, ` +
    `EC ${header.readUInt16BE(4)}, RRC ${header.readUInt16BE(6)}, SND_SEQ ${header.readBigUInt64BE(8)}`
  );
}

export function encryptedContentType(protocol: string = SPNEGO_PROTOCOL, multi = false): string {
  return `multipart/${multi ? 'x-multi-encrypted' : 'encrypted'};protocol="${protocol}";boundary="Encrypted Boundary"`;
}

// Returns the protocol string in a multipart/encrypted (or, for CredSSP,
// multipart/x-multi-encrypted) Content-Type, or null when the response is
// not encrypted.
export function encryptedProtocolOf(contentType: string): string | null {
  if (!/^\s*multipart\/(?:encrypted|x-multi-encrypted)\s*;/i.test(contentType)) return null;
  const m = /protocol="([^"]*)"/i.exec(contentType);
  return m?.[1] ?? null;
}

function unsupported(mechanism: Mechanism | undefined): WinRMProtocolError {
  return new WinRMProtocolError(
    `WinRM message encryption over HTTP supports NTLM, Kerberos and CredSSP only, not '${mechanism ?? 'unknown'}'. ` +
      'Use HTTPS (tls:true, port 5986).',
  );
}

function signatureLength(mechanism: Mechanism | undefined): number {
  if (mechanism === 'ntlm') return NTLM_SIGNATURE_LENGTH;
  throw unsupported(mechanism);
}

export function kerberosNeedsIov(tls: boolean): WinRMProtocolError {
  return new WinRMProtocolError(
    tls
      ? 'WinRM message encryption with Kerberos needs the gss_wrap_iov split from @winlinux/krb-session-key, ' +
          'which this SecurityContext does not offer (the `kerberos` package fallback): install and build ' +
          "@winlinux/krb-session-key, or on HTTPS use encryption 'auto' or 'never' and let TLS protect the messages."
      : 'WinRM message encryption over plain HTTP with Kerberos needs the gss_wrap_iov split from @winlinux/krb-session-key, ' +
          'which this SecurityContext does not offer (the `kerberos` package fallback): install and build ' +
          '@winlinux/krb-session-key, or use HTTPS (tls:true, port 5986).',
  );
}

// header || sealed, where the Length-Field is the header length (MS-WSMV
// 2.2.9.1.1.2.2 Encrypted Data).
async function sealFor(ctx: SecurityContext, mechanism: Mechanism | undefined, soap: Buffer): Promise<{ lengthField: number; sealed: Buffer }> {
  if (mechanism === 'credssp') {
    const trailer = (ctx as CredSSPMessageProtection).credsspTrailerLength;
    if (!ctx.wrap || typeof trailer !== 'function') {
      throw new WinRMProtocolError('WinRM CredSSP encryption needs ctx.wrap and the credsspTrailerLength extension');
    }
    const sealed = await ctx.wrap(soap);
    const lengthField = trailer();
    if (sealed.length < soap.length + lengthField) throw new WinRMProtocolError('WinRM CredSSP wrap() returned less data than the message and its trailer');
    return { lengthField, sealed };
  }
  if (mechanism === 'kerberos') {
    if (!hasWinRMMessageProtection(ctx)) throw kerberosNeedsIov(false);
    const { header, data } = await ctx.wrapWinRM(soap);
    if (header.length < KERBEROS_MIN_HEADER_LENGTH) throw new WinRMProtocolError('WinRM wrapWinRM() returned a header shorter than a wrap token');
    if (data.length !== soap.length) {
      throw new WinRMProtocolError(
        `WinRM wrapWinRM() returned ${data.length} bytes of sealed data for ${soap.length} bytes of SOAP (MS-WSMV allows no padding)`,
      );
    }
    return { lengthField: header.length, sealed: Buffer.concat([header, data]) };
  }
  const sigLen = signatureLength(mechanism);
  if (!ctx.wrap) throw new WinRMProtocolError('WinRM encryption needs ctx.wrap');
  const sealed = await ctx.wrap(soap);
  if (sealed.length < sigLen) throw new WinRMProtocolError('WinRM wrap() returned less data than one signature');
  // signature || sealed data is exactly the wrap() output for NTLM.
  return { lengthField: sigLen, sealed };
}

// One encrypted part: the protocol header, the octet-stream header, the
// Length-Field and the sealed bytes.
async function encryptPart(ctx: SecurityContext, mechanism: Mechanism | undefined, soap: Buffer): Promise<Buffer> {
  const { lengthField, sealed } = await sealFor(ctx, mechanism, soap);
  const prefix = Buffer.alloc(4);
  prefix.writeUInt32LE(lengthField, 0);
  const head =
    `${MIME_BOUNDARY}\r\n` +
    `\tContent-Type: ${protocolFor(mechanism)}\r\n` +
    `\tOriginalContent: type=application/soap+xml;charset=UTF-8;Length=${soap.length}\r\n` +
    `${MIME_BOUNDARY}\r\n`;
  return Buffer.concat([Buffer.from(head, 'utf8'), OCTET_HEADER, prefix, sealed]);
}

// Builds the multipart/encrypted request body for one SOAP message. For
// CredSSP a message over 16 KiB becomes one part per 16 KiB chunk
// (multipart/x-multi-encrypted, see isMultiPart).
export async function encryptMessage(ctx: SecurityContext, mechanism: Mechanism | undefined, soap: Buffer): Promise<Buffer> {
  const parts: Buffer[] = [];
  if (isMultiPart(mechanism, soap.length)) {
    for (let off = 0; off < soap.length; off += CREDSSP_CHUNK_BYTES) {
      parts.push(await encryptPart(ctx, mechanism, soap.subarray(off, off + CREDSSP_CHUNK_BYTES)));
    }
  } else {
    parts.push(await encryptPart(ctx, mechanism, soap));
  }
  return Buffer.concat([...parts, PART_END]);
}

// Unseals one Encrypted Data stream (after the octet-stream header):
// Length-Field, then header, then encrypted data of `expected` bytes.
async function unsealStream(ctx: SecurityContext, mechanism: Mechanism | undefined, stream: Buffer, expected: number): Promise<Buffer> {
  if (stream.length < 4) throw new WinRMTransportError('WinRM encrypted response part is too short for a signature length');
  const wireSigLen = stream.readUInt32LE(0);
  if (mechanism === 'credssp') {
    // The stream after the Length-Field is whole TLS records; the inner
    // TLS session finds their boundaries. The Length-Field is the
    // trailer length and must fit in what follows the data.
    if (!ctx.unwrap) throw new WinRMProtocolError('WinRM got an encrypted response but ctx.unwrap is missing');
    if (4 + wireSigLen + expected > stream.length) {
      throw new WinRMTransportError(`WinRM encrypted response has a bad CredSSP trailer length ${wireSigLen} for ${stream.length - 4} bytes and OriginalContent Length ${expected}`);
    }
    try {
      return await ctx.unwrap(stream.subarray(4));
    } catch (err) {
      throw new WinRMTransportError(
        `WinRM could not unseal the encrypted response: the message may have been tampered with (${(err as Error).message})`,
      );
    }
  }
  if (mechanism === 'kerberos') {
    if (!hasWinRMMessageProtection(ctx)) throw kerberosNeedsIov(false);
    // The header length is whatever the acceptor's wrap produced; the
    // rest MUST be the encrypted data of exactly the OriginalContent
    // Length (MS-WSMV 2.2.9.1.1.2.2). Check the lengths before any crypto.
    if (wireSigLen < KERBEROS_MIN_HEADER_LENGTH || 4 + wireSigLen + expected !== stream.length) {
      throw new WinRMTransportError(
        `WinRM encrypted response has a bad Kerberos header length ${wireSigLen} for ${stream.length - 4} bytes and OriginalContent Length ${expected}` +
          ` (token: ${describeWrapToken(stream.subarray(4, 4 + Math.min(wireSigLen, KERBEROS_MIN_HEADER_LENGTH)))})`,
      );
    }
    const header = stream.subarray(4, 4 + wireSigLen);
    const data = stream.subarray(4 + wireSigLen);
    try {
      return await ctx.unwrapWinRM(header, data);
    } catch (err) {
      // Name the token the server sent, so the next trace is diagnostic.
      throw new WinRMTransportError(
        `WinRM could not unseal the encrypted response: the message may have been tampered with (${(err as Error).message}; ` +
          `header ${header.length} bytes: ${describeWrapToken(header)}; data ${data.length} bytes, OriginalContent Length ${expected})`,
      );
    }
  }
  const sigLen = signatureLength(mechanism);
  if (!ctx.unwrap) throw new WinRMProtocolError('WinRM got an encrypted response but ctx.unwrap is missing');
  if (wireSigLen !== sigLen || stream.length < 4 + wireSigLen) {
    throw new WinRMTransportError(`WinRM encrypted response has a bad signature length ${wireSigLen} (expected ${sigLen})`);
  }
  // For NTLM, unwrap() takes signature || sealed data: the stream
  // without its 4-byte length prefix.
  const blob = stream.subarray(4);
  try {
    return await ctx.unwrap(blob);
  } catch (err) {
    throw new WinRMTransportError(
      `WinRM could not unseal the encrypted response: the message may have been tampered with (${(err as Error).message})`,
    );
  }
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

// Parses a multipart/encrypted response body and returns the plaintext.
export async function decryptMessage(
  ctx: SecurityContext,
  mechanism: Mechanism | undefined,
  protocol: string,
  body: Buffer,
): Promise<string> {
  if (!ENCRYPTED_PROTOCOLS.includes(protocol) && protocol !== CREDSSP_PROTOCOL) {
    throw new WinRMTransportError(`WinRM got an encrypted response with an unknown protocol '${protocol}'`);
  }
  if (mechanism !== 'kerberos' && mechanism !== 'ntlm' && mechanism !== 'credssp') throw unsupported(mechanism);
  // The server answers in the protocol of the session: CredSSP with
  // CredSSP, the Negotiate family with SPNEGO.
  if (protocol !== protocolFor(mechanism)) {
    throw new WinRMTransportError(`WinRM got an encrypted response with protocol '${protocol}' on a ${mechanism} session`);
  }
  const parts = splitBuffer(body, Buffer.from(`${MIME_BOUNDARY}\r\n`, 'utf8')).filter((p) => p.length > 0);
  if (parts.length === 0 || parts.length % 2 !== 0) {
    throw new WinRMTransportError('WinRM encrypted response has a broken MIME structure');
  }
  let out = '';
  for (let i = 0; i < parts.length; i += 2) {
    const header = (parts[i] as Buffer).toString('utf8');
    let payload = parts[i + 1] as Buffer;
    if (!header.includes(`Content-Type: ${protocol}`)) {
      throw new WinRMTransportError('WinRM encrypted response part has the wrong protocol Content-Type');
    }
    const m = /OriginalContent:\s*type=[^\r\n]*;Length=(\d+)/i.exec(header);
    if (!m?.[1]) throw new WinRMTransportError('WinRM encrypted response part has no OriginalContent Length');
    const expected = Number(m[1]);
    if (payload.length >= PART_END.length && payload.subarray(payload.length - PART_END.length).equals(PART_END)) {
      payload = payload.subarray(0, payload.length - PART_END.length);
    }
    if (!payload.subarray(0, OCTET_HEADER.length).equals(OCTET_HEADER)) {
      throw new WinRMTransportError('WinRM encrypted response part has no octet-stream body');
    }
    const stream = payload.subarray(OCTET_HEADER.length);
    const plain = await unsealStream(ctx, mechanism, stream, expected);
    if (plain.length !== expected) {
      throw new WinRMTransportError('WinRM encrypted response length mismatch: the message may have been tampered with');
    }
    out += plain.toString('utf8');
  }
  return out;
}
