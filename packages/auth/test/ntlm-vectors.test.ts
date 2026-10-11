// MS-NLMP section 4.2 known-answer vectors (byte-exact) plus NTLMv2 edge cases.
// No network. Spec: [MS-NLMP] v20260330.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createHmac } from 'node:crypto';
import { RC4, desEncryptBlock, hmacMd5, md4, md5, ntowfv2, utf16 } from '../src/auth/ntlm/crypto.js';
import {
  AV_EOL,
  AV_FLAGS,
  AV_TIMESTAMP,
  buildType1,
  buildType3,
  negotiateResponseFlags,
  parseType2,
} from '../src/auth/ntlm/messages.js';
import { NtlmSealSession, sealKey, signKey } from '../src/auth/ntlm/seal.js';
import { TYPE2_424, TYPE3_424, V2 } from './fixtures.js';

describe('MS-NLMP section 4.2 vectors', () => {
  it('MD4 empty string (4.2.1-style sanity)', async () => {
    assert.equal((await md4(Buffer.alloc(0))).toString('hex'), '31d6cfe0d16ae931b73c59d7e0c089c0');
  });

  it('NT hash of "Password" (4.2.2.1.2 NTOWFv1 core)', async () => {
    assert.equal(
      (await md4(utf16('Password'))).toString('hex'),
      'a4f49c406510bdca b6824ee7c30fd852'.replace(/ /g, ''),
    );
  });

  it('DES vectors for LMOWFv1 (4.2.2.1.1)', () => {
    const constant = Buffer.from('KGS!@#$%', 'ascii');
    assert.equal(
      desEncryptBlock(Buffer.from('PASSWOR', 'ascii'), constant).toString('hex'),
      'e52cac67419a9a22',
    );
    const key2 = Buffer.concat([Buffer.from('D', 'ascii'), Buffer.alloc(6)]);
    assert.equal(desEncryptBlock(key2, constant).toString('hex'), '4a3b108f3fa6cb6d');
  });

  it('NTOWFv2 (4.2.4.1.1)', async () => {
    assert.equal((await ntowfv2(V2.password, V2.user, V2.domain)).toString('hex'), V2.responseKey);
  });

  it('RC4 session-key encryption (4.2.4.2.3)', () => {
    // KeyExchangeKey for NTLMv2 is the SessionBaseKey (MS-NLMP 3.4.5.1).
    const out = new RC4(Buffer.from(V2.sessionBaseKey, 'hex')).update(
      Buffer.from(V2.exportedSessionKey, 'hex'),
    );
    assert.equal(out.toString('hex'), V2.encSessionKey);
  });

  it('type1 layout is byte-exact (hand-derived from 2.2.1.1)', () => {
    const t1 = buildType1({ domain: 'Domain', workstation: 'COMPUTER', flags: 0xe2888235 });
    assert.equal(
      t1.toString('hex'),
      '4e544c4d5353500001000000358288e2' +
        '0c000c00280000001000100034000000' +
        '0a0000000000000f' +
        '44006f006d00610069006e00' +
        '43004f004d0050005500540045005200',
    );
  });

  it('type2 parses (4.2.4.3 CHALLENGE_MESSAGE)', () => {
    assert.equal(TYPE2_424.length, 104);
    const ch = parseType2(TYPE2_424);
    assert.equal(ch.flags, V2.challengeFlags);
    assert.equal(ch.serverChallenge.toString('hex'), V2.serverChallenge);
    assert.equal(ch.targetName.toString('utf16le'), 'Server');
    const ids = ch.targetInfo.map((p) => p.id);
    assert.deepEqual(ids, [2, 1, AV_EOL]);
    assert.equal(ch.targetInfo[0].value.toString('utf16le'), 'Domain');
    assert.equal(ch.targetInfo[1].value.toString('utf16le'), 'Server');
  });

  it('type3 is byte-exact (4.2.4.3 AUTHENTICATE_MESSAGE)', async () => {
    const ch = parseType2(TYPE2_424);
    const built = await buildType3({
      username: V2.user,
      password: V2.password,
      domain: V2.domain,
      workstation: V2.workstation,
      challenge: ch,
      responseFlags: V2.responseFlags,
      version: V2.version,
      clientChallenge: Buffer.from(V2.clientChallenge, 'hex'),
      timeOverride: 0n,
      exportedSessionKey: Buffer.from(V2.exportedSessionKey, 'hex'),
    });
    assert.equal(built.message.toString('hex'), TYPE3_424.toString('hex'));
    assert.equal(built.sessionBaseKey.toString('hex'), V2.sessionBaseKey);
    assert.equal(built.exportedSessionKey.toString('hex'), V2.exportedSessionKey);
    assert.equal(built.micIncluded, false);
  });

  it('seal/sign keys (4.2.4.4 SIGNKEY/SEALKEY)', () => {
    const exported = Buffer.from(V2.exportedSessionKey, 'hex');
    assert.equal(signKey(exported, 'Client').toString('hex'), '4788dc861b4782f35d43fd98fe1a2d39');
    assert.equal(
      sealKey(exported, V2.challengeFlags, 'Client').toString('hex'),
      '59f600973cc4960a25480a7c196e4c58',
    );
  });

  it('GSS_WrapEx seal output (4.2.4.4 SEAL)', () => {
    const session = new NtlmSealSession({
      exportedSessionKey: Buffer.from(V2.exportedSessionKey, 'hex'),
      negotiatedFlags: V2.challengeFlags,
      keyExchange: true,
    });
    const out = session.seal(utf16('Plaintext'));
    assert.equal(
      out.toString('hex'),
      '010000007fb38ec5c55d497600000000' + '54e50165bf1936dc996020c1811b0f06fb5f',
    );
  });
});

describe('128-bit keys only', () => {
  const F_128 = 0x20000000;
  const F_56 = 0x80000000;

  it('refuses a CHALLENGE without NEGOTIATE_128 (a 56- or 40-bit sealing key)', () => {
    // eslint-disable-next-line no-bitwise
    assert.throws(() => negotiateResponseFlags(0xe2888235, (V2.challengeFlags & ~F_128) >>> 0), /128-bit/);
    // eslint-disable-next-line no-bitwise
    assert.throws(() => negotiateResponseFlags(0xe2888235, (V2.challengeFlags & ~(F_128 | F_56)) >>> 0), /128-bit/);
  });

  it('still accepts NEGOTIATE_128 without NEGOTIATE_56', () => {
    // eslint-disable-next-line no-bitwise
    const f = negotiateResponseFlags(0xe2888235, (V2.challengeFlags & ~F_56) >>> 0);
    // eslint-disable-next-line no-bitwise
    assert.equal((f & F_128) >>> 0, F_128);
  });

  it('sealKey derives no key from negotiated flags without NEGOTIATE_128', () => {
    const exported = Buffer.from(V2.exportedSessionKey, 'hex');
    // eslint-disable-next-line no-bitwise
    assert.throws(() => sealKey(exported, (V2.responseFlags & ~F_128) >>> 0, 'Client'), /128-bit/);
    // eslint-disable-next-line no-bitwise
    assert.throws(() => new NtlmSealSession({ exportedSessionKey: exported, negotiatedFlags: (V2.responseFlags & ~(F_128 | F_56)) >>> 0, keyExchange: true }), /128-bit/);
  });
});

describe('response flag negotiation', () => {
  it('keeps the full offer when the server offers everything', () => {
    assert.equal(negotiateResponseFlags(0xe2888235, V2.challengeFlags), V2.responseFlags);
  });

  it('drops capabilities the server lacks, never echoes target type', () => {
    // eslint-disable-next-line no-bitwise
    const challenge = V2.challengeFlags & ~0x40000020; // no KEY_EXCH, no SEAL
    const f = negotiateResponseFlags(0xe2888235, challenge);
    // eslint-disable-next-line no-bitwise
    assert.equal(f & 0x40000000, 0);
    // eslint-disable-next-line no-bitwise
    assert.equal(f & 0x20, 0);
    // The server's target-type advertisement is not echoed (4.2.4.3).
    // eslint-disable-next-line no-bitwise
    assert.equal(negotiateResponseFlags(0xe28a8235, V2.challengeFlags) & 0x00070000, 0);
  });

  it('refuses servers without UNICODE, NTLM, or extended session security', () => {
    // eslint-disable-next-line no-bitwise
    assert.throws(() => negotiateResponseFlags(0xe2888235, V2.challengeFlags & ~1), /UNICODE/);
    assert.throws(
      // eslint-disable-next-line no-bitwise
      () => negotiateResponseFlags(0xe2888235, V2.challengeFlags & ~0x200),
      /NTLM/,
    );
    assert.throws(
      // eslint-disable-next-line no-bitwise
      () => negotiateResponseFlags(0xe2888235, V2.challengeFlags & ~0x80000),
      /extended session security/,
    );
  });
});

describe('NTLMv2 edge cases', () => {
  it('missing target info still builds a valid type3 (empty AV list)', async () => {
    const ch = parseType2(TYPE2_424);
    const built = await buildType3({
      username: V2.user,
      password: V2.password,
      domain: V2.domain,
      workstation: V2.workstation,
      challenge: { ...ch, targetInfo: [], targetInfoRaw: Buffer.alloc(0) },
      responseFlags: V2.responseFlags,
      clientChallenge: Buffer.from(V2.clientChallenge, 'hex'),
      timeOverride: 0n,
      exportedSessionKey: Buffer.from(V2.exportedSessionKey, 'hex'),
    });
    assert.equal(built.micIncluded, false);
    // NT response = proof (16) + temp head (28) + EOL (4).
    const ntLen = built.message.readUInt16LE(20);
    assert.equal(ntLen, 48);
    // LM is a real LMv2 response (not zeros) when no timestamp is present.
    const lmOff = built.message.readUInt32LE(16);
    const lm = built.message.subarray(lmOff, lmOff + 24);
    assert.equal(lm.length, 24);
    assert.ok(!lm.equals(Buffer.alloc(24)));
  });

  it('server timestamp triggers MIC, flag bit, and zeroed LM', async () => {
    const ch = parseType2(TYPE2_424);
    const stamp = Buffer.alloc(8);
    stamp.writeBigUInt64LE(0x01db9999abcdef01n, 0);
    const withTs = {
      ...ch,
      targetInfo: [...ch.targetInfo.filter((p) => p.id !== AV_EOL), { id: AV_TIMESTAMP, value: stamp }],
    };
    const type1 = buildType1({ domain: V2.domain, workstation: V2.workstation });
    const built = await buildType3({
      username: V2.user,
      password: V2.password,
      domain: V2.domain,
      workstation: V2.workstation,
      challenge: withTs,
      responseFlags: V2.responseFlags,
      clientChallenge: Buffer.from(V2.clientChallenge, 'hex'),
      exportedSessionKey: Buffer.from(V2.exportedSessionKey, 'hex'),
      targetName: 'HTTP/server.domain',
      negotiateMessage: type1,
    });
    assert.equal(built.micIncluded, true);
    // MIC field lives at 72..88 and verifies against an independent HMAC.
    const zeroed = Buffer.from(built.message);
    zeroed.fill(0, 72, 88);
    const expectMic = createHmac('md5', Buffer.from(V2.exportedSessionKey, 'hex'))
      .update(type1)
      .update(ch.raw)
      .update(zeroed)
      .digest();
    assert.ok(built.message.subarray(72, 88).equals(expectMic));
    // LM response is Z(24) per 3.1.5.1.2.
    const lmOff = built.message.readUInt32LE(16);
    assert.ok(built.message.subarray(lmOff, lmOff + 24).equals(Buffer.alloc(24)));
    // Blob echoes the server timestamp and carries the MIC flag AV pair.
    const ntOff = built.message.readUInt32LE(24);
    const ntLen = built.message.readUInt16LE(20);
    const blob = built.message.subarray(ntOff + 16, ntOff + ntLen);
    assert.equal(blob.subarray(8, 16).toString('hex'), stamp.toString('hex'));
    assert.ok(blob.includes(Buffer.from([0x06, 0x00, 0x04, 0x00, 0x02, 0x00, 0x00, 0x00])));
  });

  it('unseal verifies server-sealed packets built by an independent path', () => {
    const exported = Buffer.from(V2.exportedSessionKey, 'hex');
    const session = new NtlmSealSession({
      exportedSessionKey: exported,
      negotiatedFlags: V2.challengeFlags,
      keyExchange: true,
    });
    // Independent server-side seal with node:crypto only (plus the RC4 class).
    const serverSign = createHash('md5')
      .update(exported)
      .update('session key to server-to-client signing key magic constant\0', 'ascii')
      .digest();
    const serverSeal = createHash('md5')
      .update(exported)
      .update('session key to server-to-client sealing key magic constant\0', 'ascii')
      .digest();
    const rc4 = new RC4(serverSeal);
    const plain = Buffer.from('server says hi', 'utf8');
    const seq = Buffer.alloc(4); // seq 0
    const sealed = rc4.update(plain);
    const mac = rc4.update(createHmac('md5', serverSign).update(seq).update(plain).digest().subarray(0, 8));
    const packet = Buffer.concat([Buffer.from([1, 0, 0, 0]), mac, seq, sealed]);

    assert.ok(session.unseal(packet).equals(plain));
    // Tamper detection.
    const bad = Buffer.from(packet);
    bad[bad.length - 1] ^= 1;
    assert.throws(() => session.unseal(bad), /seq 1|checksum mismatch/);
    // Sequence enforcement: replay of seq 0 after seq advanced fails.
    assert.throws(() => session.unseal(packet), /expected seq 1/);
  });

  it('type2 parser rejects garbage', () => {
    assert.throws(() => parseType2(Buffer.alloc(10)), /too short/);
    const bad = Buffer.from(TYPE2_424);
    bad.write('BOGUS!!!', 0, 'ascii');
    assert.throws(() => parseType2(bad), /signature/);
    const wrongType = Buffer.from(TYPE2_424);
    wrongType.writeUInt32LE(3, 8);
    assert.throws(() => parseType2(wrongType), /CHALLENGE/);
  });
});
