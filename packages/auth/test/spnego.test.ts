// SPNEGO frame/unframe tests (RFC 4178). Byte vectors are hand-derived.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import {
  OID_KRB5,
  OID_NTLMSSP,
  frameNegTokenInit,
  frameNegTokenResp,
  unframeSpnego,
} from '../src/auth/spnego.js';

describe('SPNEGO framing', () => {
  it('NegTokenInit is byte-exact', () => {
    const out = frameNegTokenInit([OID_KRB5], Buffer.from('ABC', 'ascii'));
    assert.equal(
      out.toString('hex'),
      '602806062b0601050502a01e301c' +
        'a00d300b06092a864886f712010202' +
        'a10403020176' +
        'a2050403414243',
    );
  });

  it('NegTokenResp is byte-exact', () => {
    const out = frameNegTokenResp({
      negState: 1,
      supportedMech: OID_NTLMSSP,
      responseToken: Buffer.from('xy', 'ascii'),
    });
    assert.equal(
      out.toString('hex'),
      'a11b3019a0030a0101a10c060a2b06010401823702020aa20404027879',
    );
  });

  it('unframes what it frames, including long-form lengths', () => {
    const big = randomBytes(300);
    const init = frameNegTokenInit([OID_KRB5, OID_NTLMSSP], big);
    assert.ok(init[0] === 0x60); // still an InitToken (long-form length)
    const back = unframeSpnego(init);
    assert.equal(back.kind, 'init');
    if (back.kind !== 'init') throw new Error('unreachable');
    assert.deepEqual(back.mechTypes, [OID_KRB5, OID_NTLMSSP]);
    assert.ok(back.mechToken?.equals(big));
    assert.equal(back.reqFlags?.toString('hex'), '76');

    const resp = frameNegTokenResp({ negState: 0, responseToken: big });
    const rback = unframeSpnego(resp);
    assert.equal(rback.kind, 'resp');
    if (rback.kind !== 'resp') throw new Error('unreachable');
    assert.equal(rback.negState, 0);
    assert.equal(rback.supportedMech, undefined);
    assert.ok(rback.responseToken?.equals(big));
  });

  it('passes raw mechanism tokens through as raw', () => {
    const raw = Buffer.from('NTLMSSP\0garbage', 'ascii');
    const out = unframeSpnego(raw);
    assert.equal(out.kind, 'raw');
    if (out.kind !== 'raw') throw new Error('unreachable');
    assert.ok(out.token.equals(raw));
  });

  it('rejects truncated and trailing-garbage tokens', () => {
    assert.throws(() => unframeSpnego(Buffer.alloc(0)), /empty/);
    const init = frameNegTokenInit([OID_KRB5], Buffer.from('tok'));
    assert.throws(() => unframeSpnego(init.subarray(0, init.length - 3)), /truncated/);
    assert.throws(() => unframeSpnego(Buffer.concat([init, Buffer.from([0])])), /trailing/);
  });
});
