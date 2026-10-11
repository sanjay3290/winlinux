// Channel bindings for NTLM: the gss_channel_bindings_struct packing,
// the MsvAvChannelBindings MD5, and the AV pair that is present only when
// the target carries a binding. No network.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createHmac } from 'node:crypto';
import {
  channelBindingsHash,
  packGssChannelBindings,
  type ChannelBoundTarget,
} from '../src/auth/channel-bindings.js';
import {
  AV_CHANNEL_BINDINGS,
  AV_EOL,
  AV_FLAGS,
  AV_FLAG_MIC,
  AV_TARGET_NAME,
  AV_TIMESTAMP,
  buildType1,
  buildType3,
  parseAvPairs,
  parseType2,
  type AvPair,
} from '../src/auth/ntlm/messages.js';
import { NtlmAuthProvider } from '../src/auth/ntlm/provider.js';
import { NegotiateAuthProvider } from '../src/auth/negotiate.js';
import { frameNegTokenResp, unframeSpnego } from '../src/auth/spnego.js';
import type { AuthTarget } from '../src/auth/types.js';
import { TYPE2_424, V2 } from './fixtures.js';

// A 32-byte stand-in for a SHA-256 certificate hash.
const CERT_HASH = Buffer.from(Array.from({ length: 32 }, (_, i) => i));
const TLS_BINDING = Buffer.concat([Buffer.from('tls-server-end-point:', 'ascii'), CERT_HASH]);

// MS-NLMP 4.2.4 type2 plus a timestamp AV pair, so type3 gets the MIC and
// the client-added AV pairs (3.1.5.1.2).
function type2WithTimestamp(): Buffer {
  const base = parseType2(TYPE2_424);
  const stamp = Buffer.alloc(8);
  stamp.writeBigUInt64LE(0x01db9999abcdef01n, 0);
  const pairs: AvPair[] = [...base.targetInfo.filter((p) => p.id !== AV_EOL), { id: AV_TIMESTAMP, value: stamp }, { id: AV_EOL, value: Buffer.alloc(0) }];
  const info = Buffer.concat(pairs.map((p) => {
    const h = Buffer.alloc(4);
    h.writeUInt16LE(p.id, 0);
    h.writeUInt16LE(p.value.length, 2);
    return Buffer.concat([h, p.value]);
  }));
  const name = base.targetName;
  const h = Buffer.alloc(56);
  h.write('NTLMSSP\0', 0, 'ascii');
  h.writeUInt32LE(2, 8);
  h.writeUInt16LE(name.length, 12);
  h.writeUInt16LE(name.length, 14);
  h.writeUInt32LE(56, 16);
  h.writeUInt32LE(base.flags, 20);
  base.serverChallenge.copy(h, 24);
  h.writeUInt16LE(info.length, 40);
  h.writeUInt16LE(info.length, 42);
  h.writeUInt32LE(56 + name.length, 44);
  return Buffer.concat([h, name, info]);
}

// The AV pairs of a type3's NTLMv2 blob.
function type3AvPairs(type3: Buffer): AvPair[] {
  const ntOff = type3.readUInt32LE(24);
  const ntLen = type3.readUInt16LE(20);
  const blob = type3.subarray(ntOff + 16, ntOff + ntLen);
  return parseAvPairs(blob.subarray(28));
}

describe('gss_channel_bindings_struct packing', () => {
  // pyspnego tests/test_channel_bindings.py test_channel_bindings_pack:
  // inet (2) initiator 01020304, unspecified acceptor 05060708, data "café".
  it('matches the pyspnego pack() vector with addresses', () => {
    const packed = packGssChannelBindings({
      initiatorAddrtype: 2,
      initiatorAddress: Buffer.from('01020304', 'hex'),
      acceptorAddrtype: 0,
      acceptorAddress: Buffer.from('05060708', 'hex'),
      applicationData: Buffer.from('café', 'utf8'),
    });
    assert.equal(
      packed.toString('hex'),
      '02000000' + '04000000' + '01020304' + '00000000' + '04000000' + '05060708' + '05000000' + '636166c3a9',
    );
  });

  // pyspnego test_channel_bindings_none_pack: everything empty is 20 zero bytes.
  it('packs empty bindings as 20 zero bytes', () => {
    assert.equal(packGssChannelBindings({ applicationData: Buffer.alloc(0) }).toString('hex'), '00'.repeat(20));
  });

  it('packs a tls-server-end-point binding with unspecified addresses', () => {
    assert.equal(
      packGssChannelBindings({ applicationData: TLS_BINDING }).toString('hex'),
      '00000000' + '00000000' + '00000000' + '00000000' + '35000000' + TLS_BINDING.toString('hex'),
    );
  });
});

describe('MsvAvChannelBindings value', () => {
  // Known answers computed independently with Python 3 hashlib over the
  // struct bytes above: md5(16 zero bytes + 35000000 + data) and md5(20
  // zero bytes). The struct layout is the pyspnego pack() vector; the MD5
  // is what MS-NLMP 3.1.5.1.2 puts in the AV pair.
  it('is the MD5 of the packed struct (known answer)', () => {
    assert.equal(channelBindingsHash(TLS_BINDING).toString('hex'), '8f1214c9c9cab8dc3bf866da9aba57a7');
    assert.equal(channelBindingsHash(Buffer.alloc(0)).toString('hex'), '441018525208457705bf09a8ee3c1093');
    assert.ok(channelBindingsHash(TLS_BINDING).equals(createHash('md5').update(packGssChannelBindings({ applicationData: TLS_BINDING })).digest()));
  });
});

describe('AUTHENTICATE channel-binding AV pair', () => {
  const challenge = parseType2(type2WithTimestamp());
  const type1 = buildType1({ domain: V2.domain, workstation: V2.workstation });
  const build = (channelBindings?: Buffer) =>
    buildType3({
      username: V2.user,
      password: V2.password,
      domain: V2.domain,
      workstation: V2.workstation,
      challenge,
      responseFlags: V2.responseFlags,
      clientChallenge: Buffer.from(V2.clientChallenge, 'hex'),
      exportedSessionKey: Buffer.from(V2.exportedSessionKey, 'hex'),
      targetName: 'HTTP/server.domain',
      negotiateMessage: type1,
      channelBindings,
    });

  it('carries the 16-byte binding when one is given, before the target name', async () => {
    const hash = channelBindingsHash(TLS_BINDING);
    const built = await build(hash);
    const pairs = type3AvPairs(built.message);
    const cbt = pairs.find((p) => p.id === AV_CHANNEL_BINDINGS);
    assert.ok(cbt, 'MsvAvChannelBindings present');
    assert.equal(cbt.value.toString('hex'), hash.toString('hex'));
    assert.ok(pairs.some((p) => p.id === AV_TARGET_NAME));
    // The MIC still covers the message with the pair in it.
    const zeroed = Buffer.from(built.message);
    zeroed.fill(0, 72, 88);
    const mic = createHmac('md5', Buffer.from(V2.exportedSessionKey, 'hex')).update(type1).update(challenge.raw).update(zeroed).digest();
    assert.ok(built.message.subarray(72, 88).equals(mic));
  });

  it('omits the pair when there is no binding (never an all-zero one)', async () => {
    const built = await build(undefined);
    const pairs = type3AvPairs(built.message);
    assert.equal(pairs.find((p) => p.id === AV_CHANNEL_BINDINGS), undefined);
    assert.ok(pairs.some((p) => p.id === AV_TARGET_NAME), 'the other client pairs are still added');
    assert.equal(built.micIncluded, true);
  });

  it('refuses a binding that is not a 16-byte MD5', async () => {
    await assert.rejects(() => build(Buffer.alloc(20)), /16-byte MD5/);
  });
});

describe('NTLM context reads the binding from its target', () => {
  const creds = { username: 'User', password: 'Password', domain: 'Domain' };
  const challengeToken = () => frameNegTokenResp({ negState: 1, responseToken: type2WithTimestamp() });

  function type3Of(output: Buffer): Buffer {
    const resp = unframeSpnego(output);
    if (resp.kind !== 'resp' || !resp.responseToken) throw new Error('expected NegTokenResp with a token');
    return resp.responseToken;
  }

  it('binds the AUTHENTICATE when the target gets channelBindings after creation', async () => {
    const target: AuthTarget & ChannelBoundTarget = { host: 'server.domain', service: 'HTTP' };
    const ctx = new NtlmAuthProvider().createContext(target, creds);
    await ctx.step();
    // The consumer learns the binding once its TLS socket is up.
    (target as { channelBindings?: Buffer }).channelBindings = TLS_BINDING;
    const out = await ctx.step(challengeToken());
    const cbt = type3AvPairs(type3Of(out.output!)).find((p) => p.id === AV_CHANNEL_BINDINGS);
    assert.ok(cbt);
    assert.equal(cbt.value.toString('hex'), channelBindingsHash(TLS_BINDING).toString('hex'));
  });

  it('sends no pair for a target without a binding (plain HTTP, SMB)', async () => {
    for (const service of ['HTTP', 'cifs'] as const) {
      const ctx = new NtlmAuthProvider().createContext({ host: 'server.domain', service }, creds);
      await ctx.step();
      const out = await ctx.step(challengeToken());
      assert.equal(type3AvPairs(type3Of(out.output!)).find((p) => p.id === AV_CHANNEL_BINDINGS), undefined, service);
    }
  });

  it('Negotiate falling back to NTLM binds with the same target', async () => {
    const target: AuthTarget & ChannelBoundTarget = { host: 'server.domain', service: 'HTTP' };
    const provider = new NegotiateAuthProvider({
      gss: async () => {
        throw new Error('no Kerberos here');
      },
    });
    const ctx = provider.createContext(target, creds);
    await ctx.step();
    assert.equal(ctx.negotiatedMechanism, 'ntlm');
    (target as { channelBindings?: Buffer }).channelBindings = TLS_BINDING;
    const out = await ctx.step(challengeToken());
    const cbt = type3AvPairs(type3Of(out.output!)).find((p) => p.id === AV_CHANNEL_BINDINGS);
    assert.ok(cbt);
    assert.equal(cbt.value.toString('hex'), channelBindingsHash(TLS_BINDING).toString('hex'));
  });
});

// A CHALLENGE with the 4.2.4 pairs plus `extra`, with or without a
// timestamp.
function type2With(extra: AvPair[], timestamp: boolean): Buffer {
  const base = parseType2(TYPE2_424);
  const stamp = Buffer.alloc(8);
  stamp.writeBigUInt64LE(0x01db9999abcdef01n, 0);
  const pairs: AvPair[] = [
    ...base.targetInfo.filter((p) => p.id !== AV_EOL),
    ...(timestamp ? [{ id: AV_TIMESTAMP, value: stamp }] : []),
    ...extra,
    { id: AV_EOL, value: Buffer.alloc(0) },
  ];
  const info = Buffer.concat(pairs.map((p) => {
    const h = Buffer.alloc(4);
    h.writeUInt16LE(p.id, 0);
    h.writeUInt16LE(p.value.length, 2);
    return Buffer.concat([h, p.value]);
  }));
  const name = base.targetName;
  const h = Buffer.alloc(56);
  h.write('NTLMSSP\0', 0, 'ascii');
  h.writeUInt32LE(2, 8);
  h.writeUInt16LE(name.length, 12);
  h.writeUInt16LE(name.length, 14);
  h.writeUInt32LE(56, 16);
  h.writeUInt32LE(base.flags, 20);
  base.serverChallenge.copy(h, 24);
  h.writeUInt16LE(info.length, 40);
  h.writeUInt16LE(info.length, 42);
  h.writeUInt32LE(56 + name.length, 44);
  return Buffer.concat([h, name, info]);
}

describe('the client, not the CHALLENGE, decides the binding and target name', () => {
  const SERVER_CBT = Buffer.alloc(16, 0xaa);
  const SERVER_NAME = Buffer.from('HTTP/attacker.example', 'utf16le');
  const clientHash = channelBindingsHash(TLS_BINDING);
  const type1 = buildType1({ domain: V2.domain, workstation: V2.workstation });
  const build = (type2: Buffer, channelBindings?: Buffer) =>
    buildType3({
      username: V2.user,
      password: V2.password,
      domain: V2.domain,
      workstation: V2.workstation,
      challenge: parseType2(type2),
      responseFlags: V2.responseFlags,
      clientChallenge: Buffer.from(V2.clientChallenge, 'hex'),
      exportedSessionKey: Buffer.from(V2.exportedSessionKey, 'hex'),
      targetName: 'HTTP/server.domain',
      negotiateMessage: type1,
      channelBindings,
    });
  const only = (pairs: AvPair[], id: number) => {
    const found = pairs.filter((p) => p.id === id);
    assert.equal(found.length, 1, `exactly one AV pair ${id}`);
    return found[0]!.value;
  };

  for (const timestamp of [true, false]) {
    const label = timestamp ? 'with MsvAvTimestamp' : 'without MsvAvTimestamp';

    it(`${label}: a server MsvAvChannelBindings is replaced by the client's`, async () => {
      const pairs = type3AvPairs((await build(type2With([{ id: AV_CHANNEL_BINDINGS, value: SERVER_CBT }], timestamp), clientHash)).message);
      assert.equal(only(pairs, AV_CHANNEL_BINDINGS).toString('hex'), clientHash.toString('hex'));
    });

    it(`${label}: a server MsvAvChannelBindings is dropped when the client has no binding`, async () => {
      const pairs = type3AvPairs((await build(type2With([{ id: AV_CHANNEL_BINDINGS, value: SERVER_CBT }], timestamp))).message);
      assert.equal(pairs.find((p) => p.id === AV_CHANNEL_BINDINGS), undefined);
    });

    it(`${label}: a server MsvAvTargetName is replaced by the client's SPN`, async () => {
      const pairs = type3AvPairs((await build(type2With([{ id: AV_TARGET_NAME, value: SERVER_NAME }], timestamp), clientHash)).message);
      assert.equal(only(pairs, AV_TARGET_NAME).toString('utf16le'), 'HTTP/server.domain');
    });

    it(`${label}: the client's binding and target name are sent`, async () => {
      const built = await build(type2With([], timestamp), clientHash);
      const pairs = type3AvPairs(built.message);
      assert.equal(only(pairs, AV_CHANNEL_BINDINGS).toString('hex'), clientHash.toString('hex'));
      assert.equal(only(pairs, AV_TARGET_NAME).toString('utf16le'), 'HTTP/server.domain');
      // The MIC needs the server timestamp (MS-NLMP 3.1.5.1.2).
      assert.equal(built.micIncluded, timestamp);
      assert.equal(pairs.some((p) => p.id === AV_FLAGS && (p.value.readUInt32LE(0) & AV_FLAG_MIC) !== 0), timestamp);
    });
  }
});
