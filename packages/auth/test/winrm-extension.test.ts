// The optional WinRM extension (wrapWinRM / unwrapWinRM) on Kerberos
// and Negotiate contexts. No network: the GSS layer is a fake with and
// without the IOV split. The real split is proven by
// packages/krb-session-key (test:kdc) and packages/winrm (test:kdc).
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { KerberosAuthProvider, type GssClient } from '../src/auth/kerberos.js';
import { NegotiateAuthProvider } from '../src/auth/negotiate.js';
import { frameNegTokenResp, NegState } from '../src/auth/spnego.js';
import type { AuthTarget, SecurityContext } from '../src/auth/types.js';
import { hasWinRMMessageProtection, type WinRMMessageProtection, type WinRMSealed } from '../src/auth/winrm-extension.js';

const TARGET: AuthTarget = { host: 'dc1.example.com', service: 'HTTP' };
const AP_REQ = Buffer.from('fake-ap-req');
const AP_REP = Buffer.from('fake-ap-rep');
const TICKET_CACHE = { username: 'alice', realm: 'EXAMPLE.COM', useTicketCache: true };

// A fake 60-byte RFC 4121-shaped header and a XOR "cipher" of the data.
function fakeHeader(seq: number): Buffer {
  const h = Buffer.alloc(60);
  h.writeUInt16BE(0x0504, 0);
  h[2] = 0x06;
  h[3] = 0xff;
  h.writeUInt16BE(0, 4);
  h.writeUInt16BE(28, 6);
  h.writeBigUInt64BE(BigInt(seq), 8);
  return h;
}

class FakeGss implements GssClient {
  contextComplete = false;
  steps = 0;
  seq = 0;
  wrapIovCalls: Buffer[] = [];
  unwrapIovCalls: Array<{ header: Buffer; data: Buffer }> = [];
  wrapIov?: (data: Buffer) => Promise<WinRMSealed>;
  unwrapIov?: (header: Buffer, data: Buffer) => Promise<Buffer>;

  constructor(withIov: boolean, private readonly padding = 0) {
    if (withIov) {
      this.wrapIov = async (data) => {
        this.wrapIovCalls.push(Buffer.from(data));
        const sealed = Buffer.concat([Buffer.from(data.map((b) => b ^ 0x5a)), Buffer.alloc(this.padding)]);
        return { header: fakeHeader(this.seq++), data: sealed };
      };
      this.unwrapIov = async (header, data) => {
        this.unwrapIovCalls.push({ header: Buffer.from(header), data: Buffer.from(data) });
        if (header.length !== 60 || header.readUInt16BE(0) !== 0x0504) throw new Error('gss_unwrap_iov: bad header');
        return Buffer.from(data.map((b) => b ^ 0x5a));
      };
    }
  }

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
}

function kerberos(gss: GssClient): SecurityContext & WinRMMessageProtection {
  return new KerberosAuthProvider({ gss: async () => gss, kinit: async () => undefined }).createContext(TARGET, TICKET_CACHE);
}

async function complete(ctx: SecurityContext): Promise<void> {
  await ctx.step();
  await ctx.step(frameNegTokenResp({ negState: NegState.acceptCompleted, responseToken: AP_REP }));
  assert.equal(ctx.complete, true);
}

describe('Kerberos wrapWinRM / unwrapWinRM (optional extension)', () => {
  it('is absent before the GSS layer exists, present once the first step created it with IOV support', async () => {
    const gss = new FakeGss(true);
    const ctx = kerberos(gss);
    assert.equal(ctx.wrapWinRM, undefined, 'no GSS layer yet');
    assert.equal(hasWinRMMessageProtection(ctx), false);
    await ctx.step();
    assert.equal(typeof ctx.wrapWinRM, 'function');
    assert.equal(typeof ctx.unwrapWinRM, 'function');
    assert.equal(hasWinRMMessageProtection(ctx), true);
    await assert.rejects(ctx.wrapWinRM!(Buffer.from('x')), /not established/);
    await assert.rejects(ctx.unwrapWinRM!(fakeHeader(0), Buffer.from('x')), /not established/);
    assert.equal(gss.wrapIovCalls.length, 0, 'nothing reaches GSS before completion');
  });

  it('stays absent with a GSS layer that has no IOV split (the kerberos package)', async () => {
    const ctx = kerberos(new FakeGss(false));
    await complete(ctx);
    assert.equal(ctx.wrapWinRM, undefined);
    assert.equal(ctx.unwrapWinRM, undefined);
    assert.equal(hasWinRMMessageProtection(ctx), false);
    assert.equal(typeof ctx.wrap, 'function', 'the contract wrap() is still there');
  });

  it('returns the GSS header and data of the plaintext length, and unwraps header + data', async () => {
    const gss = new FakeGss(true);
    const ctx = kerberos(gss);
    await complete(ctx);
    const soap = Buffer.from('<s:Envelope>é</s:Envelope>', 'utf8');
    const sealed = await ctx.wrapWinRM!(soap);
    assert.equal(sealed.header.length, 60);
    assert.equal(sealed.data.length, soap.length);
    assert.equal(sealed.data.equals(soap), false);
    assert.deepEqual(gss.wrapIovCalls, [soap]);
    assert.deepEqual(await ctx.unwrapWinRM!(sealed.header, sealed.data), soap);
    assert.deepEqual(gss.unwrapIovCalls, [{ header: sealed.header, data: sealed.data }]);
  });

  it('refuses a split whose data is not the plaintext length (MS-WSMV forbids padding)', async () => {
    const ctx = kerberos(new FakeGss(true, 4));
    await complete(ctx);
    await assert.rejects(ctx.wrapWinRM!(Buffer.from('abc')), /sealed data is 7 bytes for 3 bytes of plaintext/);
  });

  it('rejects after dispose()', async () => {
    const ctx = kerberos(new FakeGss(true));
    await complete(ctx);
    const wrap = ctx.wrapWinRM!;
    const unwrap = ctx.unwrapWinRM!;
    await ctx.dispose!();
    await assert.rejects(wrap(Buffer.from('x')), /disposed/);
    await assert.rejects(unwrap(fakeHeader(0), Buffer.from('x')), /disposed/);
  });
});

describe('Negotiate delegates the WinRM extension to the mechanism that won', () => {
  it('Kerberos wins: the extension is the Kerberos one', async () => {
    const gss = new FakeGss(true);
    const ctx = new NegotiateAuthProvider({ gss: async () => gss }).createContext(TARGET, TICKET_CACHE) as SecurityContext &
      WinRMMessageProtection;
    assert.equal(ctx.wrapWinRM, undefined);
    await complete(ctx);
    assert.equal(ctx.negotiatedMechanism, 'kerberos');
    assert.equal(hasWinRMMessageProtection(ctx), true);
    const sealed = await ctx.wrapWinRM!(Buffer.from('soap'));
    assert.equal(sealed.header.length, 60);
    assert.deepEqual(await ctx.unwrapWinRM!(sealed.header, sealed.data), Buffer.from('soap'));
  });

  it('NTLM wins (client-side Kerberos failure): no extension; WinRM uses wrap()', async () => {
    const ctx = new NegotiateAuthProvider({
      gss: async () => {
        throw new Error('no credentials cache');
      },
      kinit: async () => undefined,
    }).createContext(TARGET, { username: 'alice', password: 'pw', domain: 'EXAMPLE' }) as SecurityContext & WinRMMessageProtection;
    const first = await ctx.step();
    assert.ok(first.output, 'NTLM NEGOTIATE token');
    assert.equal(ctx.negotiatedMechanism, 'ntlm');
    assert.equal(ctx.wrapWinRM, undefined);
    assert.equal(ctx.unwrapWinRM, undefined);
    assert.equal(hasWinRMMessageProtection(ctx), false);
    assert.equal(typeof ctx.wrap, 'function');
  });
});
