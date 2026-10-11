// Kerberos session key, per-context ccache, and the final SPNEGO token
// with its mechListMIC. No network: the GSS layer is a fake.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { access } from 'node:fs/promises';
import { setTimeout as sleep } from 'node:timers/promises';
import { KerberosAuthProvider, withCcacheEnv, type GssClient, type GssInit } from '../src/auth/kerberos.js';
import { NegotiateAuthProvider } from '../src/auth/negotiate.js';
import { OID_KRB5, encodeMechTypeList, frameNegTokenResp, NegState } from '../src/auth/spnego.js';
import type { AuthTarget } from '../src/auth/types.js';

const TARGET: AuthTarget = { host: 'dc1.example.com', service: 'cifs' };
const AP_REQ = Buffer.from('fake-ap-req');
const AP_REP = Buffer.from('fake-ap-rep');
const KEY = Buffer.from('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f', 'hex');
const MECH_LIST = encodeMechTypeList([OID_KRB5]);

// A fake acceptor MIC: HMAC-SHA256(key, message). The real one is
// gss_get_mic on the server; the fake only has to be keyed and exact.
function fakeMic(message: Buffer, key: Buffer = KEY): Buffer {
  return createHmac('sha256', key).update(message).digest().subarray(0, 16);
}

// Mutual auth in two steps (AP-REQ out, AP-REP in), with the optional
// addon members: sessionKey and verifyMic.
class FakeAddonGss implements GssClient {
  contextComplete = false;
  steps = 0;
  disposed = false;
  verified: Buffer[] = [];

  constructor(private readonly withKey = true) {}

  async step(challenge: string): Promise<string> {
    this.steps += 1;
    if (this.steps === 1) return AP_REQ.toString('base64');
    assert.equal(Buffer.from(challenge, 'base64').toString(), AP_REP.toString());
    this.contextComplete = true;
    return '';
  }

  async wrap(data: string): Promise<string> {
    return data;
  }

  async unwrap(data: string): Promise<string> {
    return data;
  }

  sessionKey?(): Buffer;

  verifyMic(message: Buffer, mic: Buffer): boolean {
    this.verified.push(Buffer.from(message));
    return fakeMic(message).equals(mic);
  }

  dispose(): void {
    this.disposed = true;
  }

  static create(withKey = true): FakeAddonGss {
    const g = new FakeAddonGss(withKey);
    if (withKey) g.sessionKey = () => Buffer.from(KEY);
    return g;
  }
}

function provider(gss: GssClient, onInit?: (init: GssInit) => void) {
  return new KerberosAuthProvider({
    gss: async (_service, init) => {
      onInit?.(init);
      return gss;
    },
    kinit: async () => undefined,
  });
}

const ticketCache = { username: 'alice', realm: 'EXAMPLE.COM', useTicketCache: true };

async function handshake(gss: GssClient, finalFields: Parameters<typeof frameNegTokenResp>[0] = {}) {
  const ctx = provider(gss).createContext(TARGET, ticketCache);
  await ctx.step();
  const res = await ctx.step(frameNegTokenResp({ negState: NegState.acceptCompleted, responseToken: AP_REP, ...finalFields }));
  return { ctx, res };
}

describe('Kerberos sessionKey (addon GSS layer)', () => {
  it('is undefined until complete, then a copy of the full GSS key', async () => {
    const gss = FakeAddonGss.create();
    const ctx = provider(gss).createContext(TARGET, ticketCache);
    await ctx.step();
    assert.equal(ctx.sessionKey, undefined, 'no key before the AP-REP');
    await ctx.step(frameNegTokenResp({ negState: 0, responseToken: AP_REP }));
    const key = ctx.sessionKey!;
    assert.deepEqual(key, KEY, 'the full 32-byte key; smb2 applies the 16-byte rule');
    key.fill(0xff);
    assert.deepEqual(ctx.sessionKey, KEY, 'each read is a fresh copy');
    await ctx.dispose!();
    assert.deepEqual(key, Buffer.alloc(32, 0xff), 'a copy read before dispose is not zeroed');
    assert.equal(ctx.sessionKey, undefined);
    assert.equal(gss.disposed, true, 'dispose releases the GSS context');
  });

  it('zeroes the buffer the GSS layer returned once it holds its own copy', async () => {
    const gss = FakeAddonGss.create();
    const returned: Buffer[] = [];
    gss.sessionKey = () => {
      const b = Buffer.from(KEY);
      returned.push(b);
      return b;
    };
    const { ctx } = await handshake(gss);
    assert.deepEqual(ctx.sessionKey, KEY);
    assert.deepEqual(returned[0], Buffer.alloc(32), 'the native-returned buffer is zeroed');
  });

  it('stays undefined with a GSS layer that has no session key (the kerberos package)', async () => {
    const { ctx, res } = await handshake(FakeAddonGss.create(false));
    assert.equal(res.complete, true);
    assert.equal(ctx.sessionKey, undefined);
  });

  it('Negotiate delegates sessionKey to Kerberos when Kerberos wins', async () => {
    const gss = FakeAddonGss.create();
    const ctx = new NegotiateAuthProvider({ gss: async () => gss }).createContext(TARGET, ticketCache);
    await ctx.step();
    assert.equal(ctx.negotiatedMechanism, 'kerberos');
    await ctx.step(frameNegTokenResp({ negState: 0, responseToken: AP_REP }));
    assert.equal(ctx.complete, true);
    assert.deepEqual(ctx.sessionKey, KEY);
    await ctx.dispose!();
  });
});

describe('Kerberos per-context ccache (no process.env.KRB5CCNAME writes)', () => {
  it('two concurrent password contexts each get their own ccache and never touch the env', async () => {
    const before = process.env.KRB5CCNAME;
    const seenEnv: Array<string | undefined> = [];
    const inits: GssInit[] = [];
    const kinitEnv: string[] = [];
    const make = () =>
      new KerberosAuthProvider({
        gss: async (_s, init) => {
          seenEnv.push(process.env.KRB5CCNAME);
          await sleep(5);
          seenEnv.push(process.env.KRB5CCNAME);
          inits.push(init);
          return FakeAddonGss.create();
        },
        kinit: async (_args, _pw, env) => {
          kinitEnv.push(env.KRB5CCNAME!);
          await sleep(5);
        },
      }).createContext(TARGET, { username: 'alice', password: 'pw', realm: 'EXAMPLE.COM' });
    const a = make();
    const b = make();
    await Promise.all([a.step(), b.step()]);
    assert.equal(inits.length, 2);
    assert.notEqual(inits[0].ccache, inits[1].ccache, 'one ccache per context');
    assert.deepEqual(new Set(inits.map((i) => i.ccache)), new Set(kinitEnv), 'kinit filled the ccache GSS uses');
    assert.ok(seenEnv.every((v) => v === before), 'process.env.KRB5CCNAME never changed');
    await Promise.all([a.dispose!(), b.dispose!()]);
    assert.equal(process.env.KRB5CCNAME, before);
    for (const cc of kinitEnv) await assert.rejects(() => access(cc.slice('FILE:'.length)), 'temp ccache removed');
  });

  it('the kerberos-package fallback serializes its KRB5CCNAME window and always restores it', async () => {
    const before = process.env.KRB5CCNAME;
    const observed: string[] = [];
    const run = (cc: string) =>
      withCcacheEnv(cc, async () => {
        observed.push(`${cc}:start:${process.env.KRB5CCNAME}`);
        await sleep(5);
        observed.push(`${cc}:end:${process.env.KRB5CCNAME}`);
        if (cc === 'FILE:/b') throw new Error('boom');
        return cc;
      });
    const results = await Promise.allSettled([run('FILE:/a'), run('FILE:/b'), run('FILE:/c')]);
    assert.deepEqual(
      results.map((r) => r.status),
      ['fulfilled', 'rejected', 'fulfilled'],
    );
    assert.deepEqual(observed, [
      'FILE:/a:start:FILE:/a',
      'FILE:/a:end:FILE:/a',
      'FILE:/b:start:FILE:/b',
      'FILE:/b:end:FILE:/b',
      'FILE:/c:start:FILE:/c',
      'FILE:/c:end:FILE:/c',
    ]);
    assert.equal(process.env.KRB5CCNAME, before, 'restored after the last call');
  });
});

describe('Kerberos final SPNEGO token and mechListMIC', () => {
  it('accepts a valid mechListMIC that arrives with the AP-REP', async () => {
    const gss = FakeAddonGss.create();
    const { ctx, res } = await handshake(gss, { mechListMIC: fakeMic(MECH_LIST) });
    assert.equal(res.complete, true);
    assert.deepEqual(gss.verified, [MECH_LIST], 'the MIC covers the DER MechTypeList we sent');
    await assert.rejects(() => ctx.step(frameNegTokenResp({ negState: 0 })), /already complete/);
  });

  it('fails on a tampered mechListMIC with the AP-REP', async () => {
    const mic = fakeMic(MECH_LIST);
    mic[0] ^= 0x01;
    await assert.rejects(() => handshake(FakeAddonGss.create(), { mechListMIC: mic }), /mechListMIC does not verify/);
  });

  it('accepts one final NegTokenResp after complete, with a valid mechListMIC', async () => {
    const gss = FakeAddonGss.create();
    const { ctx } = await handshake(gss);
    const res = await ctx.step(frameNegTokenResp({ negState: NegState.acceptCompleted, mechListMIC: fakeMic(MECH_LIST) }));
    assert.deepEqual(res, { output: null, complete: true });
    await assert.rejects(
      () => ctx.step(frameNegTokenResp({ negState: 0 })),
      /already complete/,
      'only one final token',
    );
  });

  it('accepts a final accept-completed token without a mechListMIC', async () => {
    const { ctx } = await handshake(FakeAddonGss.create());
    assert.deepEqual(await ctx.step(frameNegTokenResp({ negState: 0 })), { output: null, complete: true });
  });

  it('fails a final token with a tampered mechListMIC, a reject state, or a stray mechanism token', async () => {
    const mic = fakeMic(MECH_LIST);
    mic[mic.length - 1] ^= 0x80;
    const tampered = await handshake(FakeAddonGss.create());
    await assert.rejects(
      () => tampered.ctx.step(frameNegTokenResp({ negState: 0, mechListMIC: mic })),
      /mechListMIC does not verify/,
    );
    const wrongKey = await handshake(FakeAddonGss.create());
    await assert.rejects(
      () => wrongKey.ctx.step(frameNegTokenResp({ negState: 0, mechListMIC: fakeMic(MECH_LIST, Buffer.alloc(32)) })),
      /mechListMIC does not verify/,
    );
    const rejected = await handshake(FakeAddonGss.create());
    await assert.rejects(() => rejected.ctx.step(frameNegTokenResp({ negState: NegState.reject })), /not accept-completed/);
    const stray = await handshake(FakeAddonGss.create());
    await assert.rejects(
      () => stray.ctx.step(frameNegTokenResp({ negState: 0, responseToken: Buffer.from('x') })),
      /unexpected mechanism token/,
    );
  });

  it('without verify_mic (the kerberos package), a server MIC is not checked and does not fail', async () => {
    const gss = FakeAddonGss.create(false);
    (gss as { verifyMic?: unknown }).verifyMic = undefined;
    const { res } = await handshake(gss, { mechListMIC: Buffer.from('unverifiable') });
    assert.equal(res.complete, true);
  });
});

describe('Negotiate: no NTLM fallback on a Kerberos credential failure (lockout guard)', () => {
  const pwCreds = { username: 'alice', password: 'wrong', realm: 'EXAMPLE.COM' };
  const kinitFailing = (stderr: string) => async () => {
    throw new Error(`kinit failed: ${stderr}`);
  };

  for (const stderr of [
    'kinit: Preauthentication failed while getting initial credentials',
    'kinit: Password incorrect while getting initial credentials',
    "kinit: Client's credentials have been revoked while getting initial credentials",
    'KRB5KDC_ERR_PREAUTH_FAILED',
  ]) {
    it(`fails with KerberosCredentialError and never starts NTLM: ${stderr}`, async () => {
      let gssCalls = 0;
      const ctx = new NegotiateAuthProvider({
        kinit: kinitFailing(stderr),
        gss: async () => {
          gssCalls += 1;
          return FakeAddonGss.create();
        },
      }).createContext(TARGET, pwCreds);
      await assert.rejects(
        () => ctx.step(),
        (err: Error) => err.name === 'KerberosCredentialError' && err.message.includes(stderr),
      );
      assert.equal(ctx.negotiatedMechanism, undefined, 'NTLM was not started, so no second bad-password count');
      assert.equal(gssCalls, 0);
    });
  }

  it('a GSS-level preauth failure on a later step also does not fall back', async () => {
    const gss = FakeAddonGss.create();
    gss.step = async () => {
      if (gss.steps++ === 0) return AP_REQ.toString('base64');
      throw new Error('gss_init_sec_context: Preauthentication failed');
    };
    const ctx = new NegotiateAuthProvider({ gss: async () => gss }).createContext(TARGET, ticketCache);
    await ctx.step();
    await assert.rejects(
      () => ctx.step(frameNegTokenResp({ negState: 1, responseToken: AP_REP })),
      (err: Error) => err.name === 'KerberosCredentialError',
    );
    assert.equal(ctx.negotiatedMechanism, 'kerberos');
  });

  for (const stderr of [
    'kinit: Cannot contact any KDC for realm EXAMPLE.COM while getting initial credentials',
    "kinit: Client 'alice@EXAMPLE.COM' not found in Kerberos database",
  ]) {
    it(`still falls back to NTLM on a non-credential failure: ${stderr}`, async () => {
      const ctx = new NegotiateAuthProvider({ kinit: kinitFailing(stderr) }).createContext(TARGET, pwCreds);
      await ctx.step();
      assert.equal(ctx.negotiatedMechanism, 'ntlm');
    });
  }

  it('falls back to NTLM when GSS has no ticket or an unknown SPN', async () => {
    const ctx = new NegotiateAuthProvider({
      gss: async () => {
        throw new Error('gss_acquire_cred: No credentials were supplied; Server not found in Kerberos database');
      },
    }).createContext(TARGET, { ...pwCreds, useTicketCache: true });
    await ctx.step();
    assert.equal(ctx.negotiatedMechanism, 'ntlm');
  });
});
