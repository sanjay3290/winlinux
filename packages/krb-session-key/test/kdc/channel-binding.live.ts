// Live proof of channel bindings against a real MIT acceptor with a
// throwaway local KDC: an initiator created with channelBindings produces
// an AP-REQ whose authenticator checksum carries them (RFC 4121 4.1.1.2),
// so an acceptor with the same bindings completes and reports
// GSS_C_CHANNEL_BOUND_FLAG, and one with other bindings refuses the token.
// Linux only: npm run test:kdc -w @winlinux/krb-session-key
import { after, before, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { KrbClient } from '../../src/index.js';
import { Acceptor, SERVICES, startLocalKdc, type AcceptStep, type LocalKdc } from './kdc.js';

const PREFIX = Buffer.from('tls-server-end-point:', 'ascii');
const BINDING = Buffer.concat([PREFIX, Buffer.from(Array.from({ length: 32 }, (_, i) => i))]);
const OTHER = Buffer.concat([PREFIX, Buffer.alloc(32, 0xab)]);

interface Outcome {
  complete: boolean;
  bound: boolean | null;
  error: string | null;
}

// One handshake: the initiator with `client` bindings, the acceptor
// expecting `acceptor` bindings.
async function handshake(kdc: LocalKdc, client?: Buffer, acceptor?: Buffer): Promise<Outcome> {
  const initiator = await KrbClient.create(SERVICES.aes256.replace('/', '@'), {
    ccache: kdc.ccache,
    ...(client ? { channelBindings: client } : {}),
  });
  const server = await Acceptor.start(kdc);
  try {
    assert.equal(initiator.channelBound, client !== undefined);
    const token = Buffer.from(await initiator.step(''), 'base64');
    let step: AcceptStep;
    try {
      step = await server.accept(token, acceptor);
    } catch (err) {
      return { complete: false, bound: null, error: (err as Error).message };
    }
    if (step.token) await initiator.step(step.token.toString('base64'));
    return { complete: step.complete && initiator.contextComplete, bound: step.bound, error: null };
  } finally {
    server.close();
    initiator.dispose();
  }
}

describe('channel bindings against a real MIT acceptor (local KDC)', () => {
  let kdc: LocalKdc;

  before(async () => {
    kdc = await startLocalKdc();
  });

  after(async () => {
    await kdc?.stop();
  });

  it('an acceptor with the same bindings completes the context and reports GSS_C_CHANNEL_BOUND_FLAG', async () => {
    const out = await handshake(kdc, BINDING, BINDING);
    assert.equal(out.error, null);
    assert.equal(out.complete, true);
    // MIT krb5 1.19 and later set the flag; an older library reports null.
    if (out.bound !== null) assert.equal(out.bound, true, 'the acceptor saw matching bindings');
  });

  it('an acceptor with other bindings refuses the AP-REQ: the bindings are in the token', async () => {
    const out = await handshake(kdc, BINDING, OTHER);
    assert.equal(out.complete, false);
    assert.match(out.error ?? '', /bindings/i, `expected a bad-bindings error, got ${out.error}`);
  });

  it('an acceptor with bindings accepts an unbound token only as unbound', async () => {
    const out = await handshake(kdc, undefined, BINDING);
    if (out.error === null) {
      // MIT krb5 1.19 and later: accepted, but not bound.
      assert.equal(out.complete, true);
      assert.equal(out.bound, false);
    } else {
      // Older libraries refuse the mismatch outright.
      assert.match(out.error, /bindings/i);
    }
  });

  it('without bindings on either side the handshake is unchanged', async () => {
    const out = await handshake(kdc);
    assert.equal(out.error, null);
    assert.equal(out.complete, true);
    if (out.bound !== null) assert.equal(out.bound, false);
  });
});
