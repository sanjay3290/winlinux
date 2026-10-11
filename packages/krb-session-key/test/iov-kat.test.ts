// Known-answer tests for the MS-WSMV Kerberos encryption header.
// The fixtures are real gss_wrap_iov outputs from MIT krb5 1.20 against a
// local KDC (test/kdc/iov.live.ts with WINLINUX_WRITE_FIXTURES=1): one
// aes128-cts-hmac-sha1-96 context and one aes256-cts-hmac-sha1-96 context,
// initiator and acceptor tokens of each. No KDC is needed here: the test
// (read from test/fixtures, next to the sources) checks the token layout RFC 4121 fixes, which is what MS-WSMV
// 2.2.9.1.1.2.2 relies on (Length-Field = header length, encrypted data
// length = OriginalContent Length).
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  AES_CONFOUNDER_LENGTH,
  AES_SHA1_CHECKSUM_LENGTH,
  FLAG_ACCEPTOR_SUBKEY,
  FLAG_SEALED,
  FLAG_SENT_BY_ACCEPTOR,
  TOKEN_HEADER_LENGTH,
  expectedAesHeaderLength,
  parseWrapTokenHeader,
} from './kdc/rfc4121.js';

interface IovFixture {
  enctype: string;
  sessionKeyLength: number;
  plaintextLength: number;
  header: string;
  dataLength: number;
  acceptorHeader: string;
  acceptorPlaintextLength: number;
  acceptorDataLength: number;
}

const fixture = (name: string): IovFixture =>
  JSON.parse(readFileSync(new URL(`../../test/fixtures/${name}`, import.meta.url), 'utf8')) as IovFixture;

describe('MS-WSMV Kerberos encryption header: known answers (RFC 4121 wrap token, trailer rotated)', () => {
  for (const [name, keyLength] of [
    ['iov-aes128.json', 16],
    ['iov-aes256.json', 32],
  ] as const) {
    const f = fixture(name);

    it(`${f.enctype}: the initiator header is 60 bytes = 16 + 16 confounder + EC + 16 header copy + 12 checksum`, () => {
      assert.equal(f.sessionKeyLength, keyLength);
      const header = Buffer.from(f.header, 'hex');
      const h = parseWrapTokenHeader(header);
      assert.equal(h.flags & FLAG_SEALED, FLAG_SEALED, 'Sealed');
      assert.equal(h.flags & FLAG_SENT_BY_ACCEPTOR, 0, 'from the initiator');
      assert.equal(h.flags & FLAG_ACCEPTOR_SUBKEY, FLAG_ACCEPTOR_SUBKEY, 'AcceptorSubkey');
      assert.equal(h.ec, 0, 'EC: AES-CTS needs no filler');
      assert.equal(h.rrc, h.ec + TOKEN_HEADER_LENGTH + AES_SHA1_CHECKSUM_LENGTH, 'RRC = 28: the trailer sits in the header');
      assert.equal(header.length, expectedAesHeaderLength(h.ec));
      assert.equal(header.length, TOKEN_HEADER_LENGTH + AES_CONFOUNDER_LENGTH + 0 + TOKEN_HEADER_LENGTH + AES_SHA1_CHECKSUM_LENGTH);
      assert.equal(header.length, 60);
    });

    it(`${f.enctype}: the sealed data has exactly the plaintext length (no padding)`, () => {
      assert.equal(f.dataLength, f.plaintextLength);
      assert.equal(f.acceptorDataLength, f.acceptorPlaintextLength);
    });

    it(`${f.enctype}: the acceptor header has the same shape with SentByAcceptor set`, () => {
      const header = Buffer.from(f.acceptorHeader, 'hex');
      const h = parseWrapTokenHeader(header);
      assert.equal(h.flags & FLAG_SENT_BY_ACCEPTOR, FLAG_SENT_BY_ACCEPTOR);
      assert.equal(h.flags & FLAG_SEALED, FLAG_SEALED);
      assert.equal(h.rrc, 28);
      assert.equal(header.length, 60);
    });
  }

  it('the plain gss_wrap token would not split: 16 + plaintext is shorter than the token', () => {
    // RFC 4121 4.2.4 with RRC = 0: header(16) || E(confounder(16) || plaintext || header copy(16)) || checksum(12).
    const f = fixture('iov-aes256.json');
    const gssWrapLength = 16 + 16 + f.plaintextLength + 16 + 12;
    assert.ok(gssWrapLength - 16 > f.plaintextLength, 'a 16-byte Length-Field would leave more bytes than OriginalContent Length');
    assert.equal(gssWrapLength, 60 + f.dataLength, 'wrap_iov moves the same bytes into header || data');
  });

  it('parseWrapTokenHeader rejects a non-wrap token', () => {
    assert.throws(() => parseWrapTokenHeader(Buffer.from('0404', 'hex')), /shorter than 16/);
    assert.throws(() => parseWrapTokenHeader(Buffer.from('040400ff000000000000000000000000', 'hex')), /TOK_ID/);
  });
});
