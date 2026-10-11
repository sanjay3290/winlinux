// Optional extension of SecurityContext for WinRM message encryption over
// plain HTTP with Kerberos. It is additive: the LOCKED contract
// (docs/contracts/auth-provider.md v1, mirrored in ./types.ts) is not
// changed, and every required member keeps its meaning. A context carries
// these two members only when its GSS layer can split a wrap token the way
// MS-WSMV 2.2.9.1.1.2.2 needs (gss_wrap_iov in @winlinux/krb-session-key).
// With the `kerberos` package fallback they are absent, and WinRM keeps
// refusing Kerberos message encryption with its usual error.
//
// The WinRM transport stays the protocol owner of the framing: it writes
// header.length into the MS-WSMV Length-Field, then header, then data.
// Auth only returns the sealed pieces. NTLM is unaffected: its wrap() is
// already signature || sealed data, and WinRM keeps using wrap()/unwrap()
// for it.
//
// Proposed for a contract v1.x follow-up: "SecurityContext
// MAY expose wrapWinRM / unwrapWinRM; WinRM uses them when present for
// Kerberos."

export interface WinRMSealed {
  // The encryption header: for Kerberos the RFC 4121 per-message token with
  // the trailer rotated in (60 bytes for aes128/aes256-cts-hmac-sha1-96 as
  // MIT and Heimdal produce it). On the way back, unwrapWinRM takes the
  // peer's header as it comes, whatever its length, RRC and EC.
  header: Buffer;
  // The sealed data, exactly plaintext.length bytes.
  data: Buffer;
}

export interface WinRMMessageProtection {
  // Present only when the context can produce the MS-WSMV split.
  readonly wrapWinRM?: (plaintext: Buffer) => Promise<WinRMSealed>;
  readonly unwrapWinRM?: (header: Buffer, data: Buffer) => Promise<Buffer>;
}

// True when ctx offers the split (both members present).
export function hasWinRMMessageProtection(ctx: object): ctx is Required<WinRMMessageProtection> {
  const c = ctx as WinRMMessageProtection;
  return typeof c.wrapWinRM === 'function' && typeof c.unwrapWinRM === 'function';
}
