// NTLM accepts one final SPNEGO NegTokenResp after type3
// and verifies the server's mechListMIC. The expected MIC is computed here
// independently (MS-NLMP 3.4.4.2, server-to-client keys, seq 0).
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createHmac } from 'node:crypto';
import { RC4 } from '../src/auth/ntlm/crypto.js';
import { NtlmAuthProvider, NtlmSecurityContext } from '../src/auth/ntlm/provider.js';
import { NegState, frameNegTokenResp, unframeSpnego } from '../src/auth/spnego.js';
import type { AuthTarget, SecurityContext } from '../src/auth/types.js';
import { TYPE2_424 } from './fixtures.js';

const TARGET: AuthTarget = { host: 'server.domain', service: 'cifs' };
const CREDS = { username: 'User', password: 'Password', domain: 'Domain' };
// DER MechTypeList { NTLMSSP }: the bytes the mechListMIC covers.
const MECH_TYPE_LIST = Buffer.from('300c060a2b06010401823702020a', 'hex');

const md5 = (...parts: Buffer[]) => createHash('md5').update(Buffer.concat(parts)).digest();

function serverMic(exportedSessionKey: Buffer, keyExchange: boolean, seq = 0): Buffer {
  const signKey = md5(exportedSessionKey, Buffer.from('session key to server-to-client signing key magic constant\0'));
  const seqBuf = Buffer.alloc(4);
  seqBuf.writeUInt32LE(seq, 0);
  let checksum = createHmac('md5', signKey).update(Buffer.concat([seqBuf, MECH_TYPE_LIST])).digest().subarray(0, 8);
  if (keyExchange) {
    const sealKey = md5(exportedSessionKey, Buffer.from('session key to server-to-client sealing key magic constant\0'));
    checksum = new RC4(sealKey).update(checksum);
  }
  return Buffer.concat([Buffer.from('01000000', 'hex'), checksum, seqBuf]);
}

async function completed(): Promise<{ ctx: SecurityContext; key: Buffer; keyExchange: boolean }> {
  const ctx = new NtlmAuthProvider().createContext(TARGET, CREDS);
  await ctx.step();
  const out = await ctx.step(frameNegTokenResp({ negState: NegState.acceptIncomplete, responseToken: TYPE2_424 }));
  const resp = unframeSpnego(out.output!);
  if (resp.kind !== 'resp') throw new Error('expected NegTokenResp');
  const flags = resp.responseToken!.readUInt32LE(60);
  return { ctx, key: ctx.sessionKey!, keyExchange: (flags & 0x40000000) !== 0 };
}

describe('NTLM final SPNEGO token and server mechListMIC', () => {
  it('accepts a final accept-completed token with a valid server mechListMIC', async () => {
    const { ctx, key, keyExchange } = await completed();
    assert.equal(keyExchange, true, 'the MS-NLMP 4.2.4 flags negotiate KEY_EXCH');
    const res = await ctx.step(frameNegTokenResp({ negState: NegState.acceptCompleted, mechListMIC: serverMic(key, keyExchange) }));
    assert.deepEqual(res, { output: null, complete: true });
    assert.equal(ctx.complete, true);
    assert.equal(ctx.sessionKey?.length, 16, 'the session key is unchanged');
    await assert.rejects(
      () => ctx.step(frameNegTokenResp({ negState: NegState.acceptCompleted })),
      /already complete/,
      'only one final token',
    );
  });

  it('accepts a final token without a mechListMIC', async () => {
    const { ctx } = await completed();
    assert.deepEqual(await ctx.step(frameNegTokenResp({ negState: NegState.acceptCompleted })), {
      output: null,
      complete: true,
    });
  });

  it('fails on a tampered server mechListMIC', async () => {
    for (const tamper of [
      (m: Buffer) => (m[4] ^= 0x01), // checksum
      (m: Buffer) => m.writeUInt32LE(1, 12), // sequence number
      (m: Buffer) => m.writeUInt32LE(2, 0), // version
    ]) {
      const { ctx, key, keyExchange } = await completed();
      const mic = serverMic(key, keyExchange);
      tamper(mic);
      await assert.rejects(
        () => ctx.step(frameNegTokenResp({ negState: NegState.acceptCompleted, mechListMIC: mic })),
        /server mechListMIC does not verify/,
      );
    }
  });

  it('fails on a client-direction MIC echoed back as the server MIC', async () => {
    const ctx = new NtlmAuthProvider().createContext(TARGET, CREDS);
    await ctx.step();
    const out = await ctx.step(frameNegTokenResp({ negState: NegState.acceptIncomplete, responseToken: TYPE2_424 }));
    const resp = unframeSpnego(out.output!);
    if (resp.kind !== 'resp' || !resp.mechListMIC) throw new Error('expected our mechListMIC');
    await assert.rejects(
      () => ctx.step(frameNegTokenResp({ negState: NegState.acceptCompleted, mechListMIC: resp.mechListMIC })),
      /server mechListMIC does not verify/,
    );
  });

  it('fails when the final token rejects the negotiation', async () => {
    const { ctx } = await completed();
    await assert.rejects(() => ctx.step(frameNegTokenResp({ negState: NegState.reject })), /not accept-completed/);
  });
});

// The seal state after the SPNEGO mechListMIC. 'separate' (the
// default, bare NTLMSSP on WinRM HTTP) starts wrap/unwrap at seq 0.
// 'spnego' (CredSSP) follows MS-SPNG 3.3.5.1: the MIC is seq 0 of its
// direction, the RC4 state resets, and the first sealed message is seq 1.
// The expected blobs are built here from MS-NLMP 3.4.4.2 directly.
function keys(key: Buffer, dir: 'client-to-server' | 'server-to-client') {
  return {
    sign: md5(key, Buffer.from(`session key to ${dir} signing key magic constant\0`)),
    seal: md5(key, Buffer.from(`session key to ${dir} sealing key magic constant\0`)),
  };
}

// A fresh RC4 state (the reset), then data and checksum at `seq`.
function sealAt(key: Buffer, dir: 'client-to-server' | 'server-to-client', seq: number, data: Buffer): Buffer {
  const k = keys(key, dir);
  const rc4 = new RC4(k.seal);
  const seqBuf = Buffer.alloc(4);
  seqBuf.writeUInt32LE(seq, 0);
  const sealed = rc4.update(data);
  const checksum = rc4.update(createHmac('md5', k.sign).update(Buffer.concat([seqBuf, data])).digest().subarray(0, 8));
  return Buffer.concat([Buffer.from('01000000', 'hex'), checksum, seqBuf, sealed]);
}

async function completedWith(mode: 'separate' | 'spnego'): Promise<{ ctx: NtlmSecurityContext; key: Buffer }> {
  const ctx = new NtlmSecurityContext(TARGET, CREDS, { mechListMICSealState: mode });
  await ctx.step();
  await ctx.step(frameNegTokenResp({ negState: NegState.acceptIncomplete, responseToken: TYPE2_424 }));
  return { ctx, key: ctx.sessionKey! };
}

describe('NTLM seal state after the SPNEGO mechListMIC', () => {
  const data = Buffer.from('sentinel pubKeyAuth');

  it('separate (default): the first wrap is seq 0 on a fresh state', async () => {
    const { ctx, key } = await completedWith('separate');
    assert.deepEqual(await ctx.wrap(data), sealAt(key, 'client-to-server', 0, data));
    await ctx.step(frameNegTokenResp({ negState: NegState.acceptCompleted, mechListMIC: serverMic(key, true) }));
    assert.deepEqual(await ctx.unwrap(sealAt(key, 'server-to-client', 0, data)), data);
  });

  it('the default context is the separate mode', async () => {
    const ctx = new NtlmAuthProvider().createContext(TARGET, CREDS);
    await ctx.step();
    await ctx.step(frameNegTokenResp({ negState: NegState.acceptIncomplete, responseToken: TYPE2_424 }));
    assert.deepEqual(await ctx.wrap!(data), sealAt(ctx.sessionKey!, 'client-to-server', 0, data));
  });

  it('spnego: the first wrap is seq 1 with the RC4 state reset, both directions', async () => {
    const { ctx, key } = await completedWith('spnego');
    assert.deepEqual(await ctx.wrap(data), sealAt(key, 'client-to-server', 1, data));
    await ctx.step(frameNegTokenResp({ negState: NegState.acceptCompleted, mechListMIC: serverMic(key, true) }));
    assert.deepEqual(await ctx.unwrap(sealAt(key, 'server-to-client', 1, data)), data);
  });

  it('spnego: a server message at seq 0 after the server mechListMIC is refused', async () => {
    const { ctx, key } = await completedWith('spnego');
    await ctx.step(frameNegTokenResp({ negState: NegState.acceptCompleted, mechListMIC: serverMic(key, true) }));
    await assert.rejects(ctx.unwrap(sealAt(key, 'server-to-client', 0, data)), /expected seq 1, got 0/);
  });

  it('spnego: the mechListMIC sent with type3 is the same as in separate mode (seq 0)', async () => {
    const ctx = new NtlmSecurityContext(TARGET, CREDS, { mechListMICSealState: 'spnego' });
    await ctx.step();
    const out = unframeSpnego((await ctx.step(frameNegTokenResp({ negState: NegState.acceptIncomplete, responseToken: TYPE2_424 }))).output!);
    assert.equal(out.kind, 'resp');
    const mic = out.kind === 'resp' ? out.mechListMIC : undefined;
    const k = keys(ctx.sessionKey!, 'client-to-server');
    const checksum = new RC4(k.seal).update(createHmac('md5', k.sign).update(Buffer.concat([Buffer.alloc(4), MECH_TYPE_LIST])).digest().subarray(0, 8));
    assert.deepEqual(mic, Buffer.concat([Buffer.from('01000000', 'hex'), checksum, Buffer.alloc(4)]));
  });
});
