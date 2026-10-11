import { WinRMProtocolError } from './errors.js';
import { children, readTlv } from './der.js';

// Raw NTLMSSP on the wire for HTTP. The auth contract wraps every
// mechanism token in SPNEGO (RFC 4178), which SMB2 needs. Windows HTTP.sys
// accepts SPNEGO-wrapped NTLM too, but after that exchange it holds a seal
// state this client does not match, and the first sealed MS-WSMV body gets
// HTTP 400. With the NTLMSSP messages sent bare in the Negotiate header,
// as pywinrm/pyspnego do (and as the MS-WSMV 4.5 example shows:
// "Authorization: Negotiate TlRMTVNTUAAD..."), the sealed body is
// accepted. So when the mechanism that will seal is NTLM, the transport
// strips the SPNEGO frame from each outgoing token here. Incoming tokens
// need nothing: the NTLM provider takes a bare CHALLENGE_MESSAGE. Kerberos
// tokens, and Negotiate until it has picked NTLM, go out as SPNEGO.

export const NTLMSSP_SIGNATURE = Buffer.from('NTLMSSP\0', 'ascii');

export function isNtlmssp(token: Buffer): boolean {
  return token.length >= NTLMSSP_SIGNATURE.length && token.subarray(0, NTLMSSP_SIGNATURE.length).equals(NTLMSSP_SIGNATURE);
}

// The OCTET STRING inside context tag `tag` of a SPNEGO inner SEQUENCE.
function octetStringIn(seq: Buffer, tag: number): Buffer | null {
  const field = children(seq).find((f) => f.tag === tag);
  if (!field) return null;
  const [inner] = children(field.content);
  if (!inner || inner.tag !== 0x04) throw new WinRMProtocolError('WinRM: SPNEGO token field is not an OCTET STRING');
  return inner.content;
}

// The mechanism token of a SPNEGO NegTokenInit ([2] mechToken) or
// NegTokenResp ([2] responseToken): null when the frame carries none,
// undefined when the bytes are not a SPNEGO token at all.
function spnegoMechToken(token: Buffer): Buffer | null | undefined {
  if (token.length === 0 || (token[0] !== 0x60 && token[0] !== 0xa1)) return undefined;
  const outer = readTlv(token, 0);
  if (outer.total !== token.length) throw new WinRMProtocolError('WinRM: trailing bytes after the SPNEGO token');
  if (outer.tag === 0xa1) {
    const [seq] = children(outer.content);
    if (!seq || seq.tag !== 0x30) throw new WinRMProtocolError('WinRM: bad SPNEGO NegTokenResp');
    return octetStringIn(seq.content, 0xa2);
  }
  // InitialContextToken: OID, then [0] NegTokenInit { SEQUENCE { ... } }.
  const [oid, init] = children(outer.content);
  if (!oid || oid.tag !== 0x06 || !init || init.tag !== 0xa0) throw new WinRMProtocolError('WinRM: bad SPNEGO InitialContextToken');
  const [seq] = children(init.content);
  if (!seq || seq.tag !== 0x30) throw new WinRMProtocolError('WinRM: bad SPNEGO NegTokenInit');
  return octetStringIn(seq.content, 0xa2);
}

// The bytes to put in the Negotiate header for an NTLM step: the bare
// NTLMSSP message when `token` is a SPNEGO frame around one, else `token`
// unchanged (already bare, or not SPNEGO at all).
export function rawNtlmToken(token: Buffer): Buffer {
  if (isNtlmssp(token)) return token;
  let inner: Buffer | null | undefined;
  try {
    inner = spnegoMechToken(token);
  } catch (err) {
    if (err instanceof WinRMProtocolError) throw err;
    throw new WinRMProtocolError(`WinRM: malformed SPNEGO token for NTLM (${(err as Error).message})`);
  }
  if (inner === undefined) return token;
  if (inner === null || !isNtlmssp(inner)) throw new WinRMProtocolError('WinRM: the SPNEGO token for NTLM carries no NTLMSSP message');
  return inner;
}
