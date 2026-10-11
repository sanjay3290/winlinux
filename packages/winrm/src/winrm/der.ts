// Minimal DER reader: enough to walk a Certificate to its
// signatureAlgorithm (channel-binding.ts) and a SPNEGO token to its
// mechanism token (ntlmssp.ts). No writer: the transport never builds DER.

export interface Tlv {
  tag: number;
  content: Buffer;
  total: number;
}

export function readTlv(buf: Buffer, offset: number): Tlv {
  if (offset + 2 > buf.length) throw new Error('DER: truncated TLV header');
  const tag = buf[offset] as number;
  let len = buf[offset + 1] as number;
  let header = 2;
  if (len & 0x80) {
    const count = len & 0x7f;
    if (count === 0 || count > 4) throw new Error('DER: bad length encoding');
    if (offset + 2 + count > buf.length) throw new Error('DER: truncated length');
    len = 0;
    for (let i = 0; i < count; i++) len = len * 256 + (buf[offset + 2 + i] as number);
    header = 2 + count;
  }
  if (offset + header + len > buf.length) throw new Error('DER: truncated value');
  return { tag, content: buf.subarray(offset + header, offset + header + len), total: header + len };
}

export function children(content: Buffer): Tlv[] {
  const out: Tlv[] = [];
  let off = 0;
  while (off < content.length) {
    const t = readTlv(content, off);
    out.push(t);
    off += t.total;
  }
  return out;
}

export function decodeOid(body: Buffer): string {
  if (body.length === 0) throw new Error('DER: empty OID');
  const first = body[0] as number;
  const arcs = [Math.floor(first / 40), first % 40];
  let n = 0;
  for (let i = 1; i < body.length; i++) {
    const b = body[i] as number;
    n = n * 128 + (b & 0x7f);
    if (!(b & 0x80)) {
      arcs.push(n);
      n = 0;
    }
  }
  if ((body[body.length - 1] as number) & 0x80) throw new Error('DER: truncated OID arc');
  return arcs.join('.');
}

