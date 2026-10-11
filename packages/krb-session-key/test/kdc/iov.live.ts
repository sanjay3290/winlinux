// Live proof of wrapIov / unwrapIov against a real GSS acceptor
// (gss_accept_sec_context + gss_unwrap_iov / gss_wrap_iov in MIT krb5),
// with a throwaway local KDC. Linux only. Run with
//   npm run test:kdc -w @winlinux/krb-session-key
// Set WINLINUX_WRITE_FIXTURES=1 to refresh test/fixtures/iov-aes*.json
// (the known-answer inputs of test/iov-kat.test.ts).
import { after, before, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { KrbClient, iovSupported } from '../../src/index.js';
import { Acceptor, SERVICES, startLocalKdc, type LocalKdc } from './kdc.js';
import {
  FLAG_ACCEPTOR_SUBKEY,
  FLAG_SEALED,
  FLAG_SENT_BY_ACCEPTOR,
  expectedAesHeaderLength,
  parseWrapTokenHeader,
  rotateWrapToken,
  splitWinRM,
} from './rfc4121.js';

const fixturesDir = join(dirname(fileURLToPath(import.meta.url)), '../../../test/fixtures');

const PLAIN = Buffer.from(
  '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body>Kerberos over HTTP, é</s:Body></s:Envelope>',
  'utf8',
);

async function handshake(service: string, kdc: LocalKdc, acceptorConf?: string): Promise<{ client: KrbClient; acceptor: Acceptor }> {
  const client = await KrbClient.create(service.replace('/', '@'), { ccache: kdc.ccache });
  const acceptor = await Acceptor.start(kdc, { krb5Conf: acceptorConf });
  let token = Buffer.from(await client.step(''), 'base64');
  for (let round = 0; round < 3 && !client.contextComplete; round += 1) {
    const r = await acceptor.accept(token);
    if (!r.token) break;
    token = Buffer.from(await client.step(r.token.toString('base64')), 'base64');
  }
  assert.equal(client.contextComplete, true, 'initiator context complete');
  return { client, acceptor };
}

describe('wrapIov / unwrapIov against a real MIT acceptor (local KDC)', () => {
  let kdc: LocalKdc;

  before(async () => {
    kdc = await startLocalKdc();
  });

  after(async () => {
    await kdc?.stop();
  });

  it('the system GSSAPI library exports gss_wrap_iov', () => {
    assert.equal(iovSupported(), true);
  });

  for (const [enctype, keyLength] of [
    ['aes128', 16],
    ['aes256', 32],
  ] as const) {
    it(`${enctype}: header = RFC 4121 token + rotated trailer, data = plaintext length, acceptor unwraps it`, async () => {
      const { client, acceptor } = await handshake(SERVICES[enctype], kdc, enctype === 'aes128' ? kdc.krb5ConfAes128 : undefined);
      try {
        assert.equal(client.sessionKey().length, keyLength, `session key is ${enctype}`);
        assert.equal(typeof client.wrapIov, 'function');
        assert.equal(typeof client.unwrapIov, 'function');

        const sealed = await client.wrapIov!(PLAIN);
        assert.equal(sealed.data.length, PLAIN.length, 'DATA keeps exactly the plaintext length (MS-WSMV: no padding)');
        assert.notEqual(sealed.data.equals(PLAIN), true, 'DATA is sealed');
        const h = parseWrapTokenHeader(sealed.header);
        assert.equal(h.flags & FLAG_SEALED, FLAG_SEALED, 'Sealed flag');
        assert.equal(h.flags & FLAG_SENT_BY_ACCEPTOR, 0, 'initiator token');
        assert.equal(h.flags & FLAG_ACCEPTOR_SUBKEY, FLAG_ACCEPTOR_SUBKEY, 'MIT acceptor sends a subkey');
        assert.equal(h.ec, 0, 'EC = 0 for AES-CTS');
        assert.equal(h.rrc, h.ec + 16 + 12, 'RRC = the rotated trailer length');
        assert.equal(sealed.header.length, expectedAesHeaderLength(h.ec));
        assert.equal(sealed.header.length, 60);

        // The real acceptor unwraps what we sealed...
        assert.deepEqual(await acceptor.unwrapIov(sealed.header, sealed.data), PLAIN);
        // ...and we unwrap what it seals.
        const reply = Buffer.from(`reply from the acceptor (${enctype})`, 'utf8');
        const back = await acceptor.wrapIov(reply);
        assert.equal(back.data.length, reply.length);
        assert.equal(parseWrapTokenHeader(back.header).flags & FLAG_SENT_BY_ACCEPTOR, FLAG_SENT_BY_ACCEPTOR);
        assert.deepEqual(await client.unwrapIov!(back.header, back.data), reply);

        // A flipped data byte fails the checksum (the error names the GSS
        // call: gss_unwrap over header || data).
        const tampered = Buffer.from(back.data);
        tampered[3] = (tampered[3] as number) ^ 0x01;
        await assert.rejects(client.unwrapIov!(back.header, tampered), /gss_unwrap\(header \|\| data\): .*integrity/i);

        if (process.env.WINLINUX_WRITE_FIXTURES) {
          await writeFile(
            join(fixturesDir, `iov-${enctype}.json`),
            `${JSON.stringify(
              {
                source: 'MIT krb5 gss_wrap_iov (HEADER|ALLOCATE, DATA, PADDING|ALLOCATE), test/kdc/iov.live.ts',
                enctype: `${enctype}-cts-hmac-sha1-96`,
                sessionKeyLength: keyLength,
                plaintextLength: PLAIN.length,
                header: sealed.header.toString('hex'),
                dataLength: sealed.data.length,
                acceptorHeader: back.header.toString('hex'),
                acceptorPlaintextLength: reply.length,
                acceptorDataLength: back.data.length,
              },
              null,
              2,
            )}\n`,
          );
        }
      } finally {
        acceptor.close();
        client.dispose();
      }
    });
  }

  it('wrapIov output is not the gss_wrap token: a plain wrap() is longer than the plaintext by more than 16', async () => {
    const { client, acceptor } = await handshake(SERVICES.aes256, kdc);
    try {
      const plainWrap = Buffer.from(await client.wrap(PLAIN.toString('base64'), { protect: true }), 'base64');
      assert.ok(plainWrap.length - 16 > PLAIN.length, 'a 16-byte split of gss_wrap breaks the MS-WSMV length rule');
      const sealed = await client.wrapIov!(PLAIN);
      assert.equal(sealed.header.length + sealed.data.length, plainWrap.length, 'same bytes in total, split differently');
    } finally {
      acceptor.close();
      client.dispose();
    }
  });
});

// A Windows acceptor is not MIT. Whatever RRC and EC its wrap token
// carries, header || data (the MS-WSMV split) is one RFC 4121 token, and
// the addon unseals it with gss_unwrap. The layouts below are real MIT
// output in every shape the API can give (gss_wrap: RRC 0; gss_wrap_iov
// with a TRAILER: RRC 0, trailer apart), plus the same bytes re-rotated
// to other RRC values, which RFC 4121 4.2.5 allows a sender to pick.
describe('unwrapIov unseals any RFC 4121 wrap token layout', () => {
  let kdc: LocalKdc;

  before(async () => {
    kdc = await startLocalKdc();
  });

  after(async () => {
    await kdc?.stop();
  });

  for (const enctype of ['aes128', 'aes256'] as const) {
    it(`${enctype}: gss_wrap (RRC 0) and gss_wrap_iov with a TRAILER (RRC 0) from the acceptor unseal`, async () => {
      const { client, acceptor } = await handshake(SERVICES[enctype], kdc, enctype === 'aes128' ? kdc.krb5ConfAes128 : undefined);
      try {
        const reply = Buffer.from(`a reply in a foreign layout (${enctype})`, 'utf8');

        // gss_wrap: one token, the trailer at the end, RRC 0.
        const whole = await acceptor.wrapPlain(reply);
        const h = parseWrapTokenHeader(whole);
        assert.equal(h.rrc, 0, 'gss_wrap does not rotate');
        assert.equal(h.ec, 0);
        assert.equal(h.flags & FLAG_SENT_BY_ACCEPTOR, FLAG_SENT_BY_ACCEPTOR);
        const split = splitWinRM(whole, reply.length);
        assert.equal(split.header.length, 60, 'the header is still 60 bytes: the same bytes, differently arranged');
        assert.deepEqual(await client.unwrapIov!(split.header, split.data), reply);

        // gss_wrap_iov HEADER | DATA | TRAILER: header 32, trailer 28, RRC 0.
        const t = await acceptor.wrapTrailer(reply);
        assert.equal(parseWrapTokenHeader(t.header).rrc, 0);
        assert.equal(t.header.length, 32, 'token header + confounder');
        assert.equal(t.trailer.length, 28, 'E(header copy) + checksum');
        assert.equal(t.data.length, reply.length);
        const split2 = splitWinRM(Buffer.concat([t.header, t.data, t.trailer]), reply.length);
        assert.deepEqual(await client.unwrapIov!(split2.header, split2.data), reply);

        // The rotated layout (RRC 28, what MIT sends) still works.
        const rotated = await acceptor.wrapIov(reply);
        assert.equal(parseWrapTokenHeader(rotated.header).rrc, 28);
        assert.deepEqual(await client.unwrapIov!(rotated.header, rotated.data), reply);
      } finally {
        acceptor.close();
        client.dispose();
      }
    });
  }

  it('aes256: every RRC a sender may pick unseals, with the header as long as the sender makes it', async () => {
    const { client, acceptor } = await handshake(SERVICES.aes256, kdc);
    try {
      const reply = Buffer.from('rotate me', 'utf8');
      const bodyLength = 16 + reply.length + 16 + 12; // confounder, data, header copy, checksum (EC 0)
      for (const rrc of [1, 12, 16, 27, 29, 44, reply.length, bodyLength - 1]) {
        // A fresh token each time: the context checks the sequence number.
        const fresh = await acceptor.wrapIov(reply);
        const token = rotateWrapToken(Buffer.concat([fresh.header, fresh.data]), rrc);
        assert.equal(parseWrapTokenHeader(token).rrc, rrc);
        const split = splitWinRM(token, reply.length);
        assert.equal(split.header.length, 60);
        assert.deepEqual(await client.unwrapIov!(split.header, split.data), reply, `RRC ${rrc}`);
      }
      // A header length the sender chooses: Length-Field 16 + 16 + 28 + 5 with 5 bytes
      // less of "data" is still the same token; the addon does not assume 60.
      const fresh = await acceptor.wrapIov(reply);
      const token = Buffer.concat([fresh.header, fresh.data]);
      assert.deepEqual(await client.unwrapIov!(token.subarray(0, 65), token.subarray(65)), reply);
    } finally {
      acceptor.close();
      client.dispose();
    }
  });

  it('aes256: a flipped byte, a wrong RRC field and a replayed token still fail', async () => {
    const { client, acceptor } = await handshake(SERVICES.aes256, kdc);
    try {
      const reply = Buffer.from('do not tamper', 'utf8');
      const whole = await acceptor.wrapPlain(reply);
      const split = splitWinRM(whole, reply.length);
      const flipped = Buffer.from(split.data);
      flipped[2] = (flipped[2] as number) ^ 0x80;
      await assert.rejects(client.unwrapIov!(split.header, flipped), /gss_unwrap\(header \|\| data\)/);
      // RRC says 28 but the body is not rotated: the header copy does not verify.
      const lying = Buffer.from(split.header);
      lying.writeUInt16BE(28, 6);
      await assert.rejects(client.unwrapIov!(lying, split.data), /gss_unwrap\(header \|\| data\)/);
      // The genuine token unseals once; the same bytes again are a replay.
      assert.deepEqual(await client.unwrapIov!(split.header, split.data), reply);
      await assert.rejects(client.unwrapIov!(split.header, split.data), /gss_unwrap\(header \|\| data\)/);
    } finally {
      acceptor.close();
      client.dispose();
    }
  });

  it('the previous path, gss_unwrap_iov HEADER | DATA (now only in the harness), rejects RRC 0 and re-rotated tokens the new path unseals', async () => {
    const { client, acceptor } = await handshake(SERVICES.aes256, kdc);
    try {
      // The client's gss_wrap token: RRC 0.
      const whole = Buffer.from(await client.wrap(PLAIN.toString('base64'), { protect: true }), 'base64');
      assert.equal(parseWrapTokenHeader(whole).rrc, 0);
      const split = splitWinRM(whole, PLAIN.length);
      await assert.rejects(acceptor.unwrapIov(split.header, split.data), /gss_unwrap_iov/, 'MIT HEADER|DATA takes RRC 28 only');
      assert.deepEqual(await acceptor.unwrapToken(split.header, split.data), PLAIN, 'gss_unwrap takes it');

      // The client's gss_wrap_iov token re-rotated to RRC 5.
      const sealed = await client.wrapIov!(PLAIN);
      const token = rotateWrapToken(Buffer.concat([sealed.header, sealed.data]), 5);
      const split5 = splitWinRM(token, PLAIN.length);
      await assert.rejects(acceptor.unwrapIov(split5.header, split5.data), /gss_unwrap_iov/);
      assert.deepEqual(await acceptor.unwrapToken(split5.header, split5.data), PLAIN);

      // And the layout both sides produce, through both paths.
      const again = await client.wrapIov!(PLAIN);
      assert.deepEqual(await acceptor.unwrapToken(again.header, again.data), PLAIN);
      const once = await client.wrapIov!(PLAIN);
      assert.deepEqual(await acceptor.unwrapIov(once.header, once.data), PLAIN);
    } finally {
      acceptor.close();
      client.dispose();
    }
  });
});
