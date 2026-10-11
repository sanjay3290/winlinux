import { createHash, createHmac } from 'node:crypto';
import { RC4 } from '../src/auth/ntlm/crypto.js';
// Provider step() state machines with canned blobs, sessionKey matrix,
// wrap/unwrap gating, and the factory. No network: Kerberos runs on a fake GSS.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { BasicAuthProvider } from '../src/auth/basic.js';
import { KerberosAuthProvider, type GssClient } from '../src/auth/kerberos.js';
import { NegotiateAuthProvider } from '../src/auth/negotiate.js';
import { NtlmAuthProvider } from '../src/auth/ntlm/provider.js';
import { createAuthProvider } from '../src/auth/index.js';
import {
  OID_KRB5,
  OID_NTLMSSP,
  frameNegTokenInit,
  frameNegTokenResp,
  unframeSpnego,
} from '../src/auth/spnego.js';
import type { AuthTarget } from '../src/auth/types.js';
import { TYPE2_424 } from './fixtures.js';

const TARGET: AuthTarget = { host: 'server.domain', service: 'HTTP' };

type Scripted = { out: string; complete: boolean } | Error;

class FakeGss implements GssClient {
  contextComplete = false;
  seen: string[] = [];
  service = '';
  principal?: string;

  constructor(private readonly script: Scripted[]) {}

  async step(challenge: string): Promise<string> {
    this.seen.push(challenge);
    const next = this.script.shift();
    if (next === undefined) throw new Error('FakeGss: unexpected step');
    if (next instanceof Error) throw next;
    this.contextComplete = next.complete;
    return next.out;
  }

  async wrap(data: string): Promise<string> {
    return Buffer.from(`wrapped:${data}`, 'utf8').toString('base64');
  }

  async unwrap(data: string): Promise<string> {
    const raw = Buffer.from(data, 'base64').toString('utf8');
    if (!raw.startsWith('wrapped:')) throw new Error('FakeGss: bad wrapped blob');
    return raw.slice('wrapped:'.length);
  }
}

const AP_REQ = Buffer.from('fake-ap-req');
const AP_REP = Buffer.from('fake-ap-rep');

describe('Basic', () => {
  it('returns base64 user:pass and completes at once', async () => {
    const ctx = new BasicAuthProvider().createContext(TARGET, { username: 'alice', password: 's3cret' });
    assert.equal(ctx.negotiatedMechanism, 'basic');
    assert.equal(ctx.sessionKey, undefined);
    assert.equal(ctx.wrap, undefined);
    const res = await ctx.step();
    assert.equal(res.complete, true);
    assert.equal(res.output?.toString('ascii'), Buffer.from('alice:s3cret').toString('base64'));
    assert.equal(ctx.complete, true);
  });

  it('rejects an empty username', () => {
    assert.throws(() => new BasicAuthProvider().createContext(TARGET, { username: '' }), /username/);
  });
});

describe('NTLM provider', () => {
  // Canned server challenge: MS-NLMP 4.2.4 type2, SPNEGO-wrapped like a real server sends.
  const creds = { username: 'User', password: 'Password', domain: 'Domain' };

  it('runs the type1 -> type2 -> type3 loop and exposes a session key', async () => {
    const ctx = new NtlmAuthProvider().createContext(TARGET, creds);
    assert.equal(ctx.negotiatedMechanism, 'ntlm');
    assert.equal(ctx.sessionKey, undefined);
    await assert.rejects(() => ctx.wrap!(Buffer.alloc(1)), /not established/);

    const first = await ctx.step();
    assert.equal(first.complete, false);
    const init = unframeSpnego(first.output!);
    assert.equal(init.kind, 'init');
    if (init.kind !== 'init') throw new Error('unreachable');
    assert.deepEqual(init.mechTypes, [OID_NTLMSSP]);
    assert.equal(init.mechToken?.subarray(0, 8).toString('ascii'), 'NTLMSSP\0');
    assert.equal(init.mechToken?.readUInt32LE(8), 1);

    const challenge = frameNegTokenResp({ negState: 1, responseToken: TYPE2_424 });
    const second = await ctx.step(challenge);
    assert.equal(second.complete, true);
    assert.equal(ctx.complete, true);
    const resp = unframeSpnego(second.output!);
    assert.equal(resp.kind, 'resp');
    if (resp.kind !== 'resp') throw new Error('unreachable');
    assert.equal(resp.responseToken?.subarray(0, 8).toString('ascii'), 'NTLMSSP\0');
    assert.equal(resp.responseToken?.readUInt32LE(8), 3);
    assert.equal((ctx.sessionKey as Buffer | undefined)?.length, 16);

    const sealed = await ctx.wrap!(Buffer.from('secret'));
    assert.equal(sealed.length, 16 + 6);
    await assert.rejects(() => ctx.step(challenge), /already complete/);
  });

  it('sends a SPNEGO mechListMIC with type3 and keeps wrap at seq 0', async () => {
    const ctx = new NtlmAuthProvider().createContext(TARGET, creds);
    await ctx.step();
    const second = await ctx.step(frameNegTokenResp({ negState: 1, responseToken: TYPE2_424 }));
    const resp = unframeSpnego(second.output!);
    if (resp.kind !== 'resp') throw new Error('expected NegTokenResp');
    const flags = resp.responseToken!.readUInt32LE(60);
    assert.ok(flags & 0x10, 'SIGN negotiated');
    const esk = ctx.sessionKey as Buffer;
    // Independent MS-NLMP 3.4.4.2 MAC over DER MechTypeList { NTLMSSP }, seq 0.
    const mechTypeList = Buffer.from('300c060a2b06010401823702020a', 'hex');
    const md5 = (...p: Buffer[]) => createHash('md5').update(Buffer.concat(p)).digest();
    const signKey = md5(esk, Buffer.from('session key to client-to-server signing key magic constant\0'));
    let checksum = createHmac('md5', signKey)
      .update(Buffer.concat([Buffer.alloc(4), mechTypeList]))
      .digest()
      .subarray(0, 8);
    if (flags & 0x40000000) {
      const sealKey = md5(esk, Buffer.from('session key to client-to-server sealing key magic constant\0'));
      checksum = new RC4(sealKey).update(checksum);
    }
    const expected = Buffer.concat([Buffer.from('01000000', 'hex'), checksum, Buffer.alloc(4)]);
    assert.equal(resp.mechListMIC?.toString('hex'), expected.toString('hex'));
    const sealed = await ctx.wrap!(Buffer.from('secret'));
    assert.equal(sealed.readUInt32LE(12), 0, 'crypto state resets after the mechListMIC');
  });

  it('sends a mechListMIC when type3 carries a MIC, even without SIGN', async () => {
    // A type2 with an MsvAvTimestamp (so type3 carries a MIC) whose flags
    // offer neither SIGN, SEAL, ALWAYS_SIGN nor KEY_EXCH.
    const avPair = (id: number, value: Buffer) => {
      const head = Buffer.alloc(4);
      head.writeUInt16LE(id, 0);
      head.writeUInt16LE(value.length, 2);
      return Buffer.concat([head, value]);
    };
    const targetInfo = Buffer.concat([
      avPair(2, Buffer.from('Domain', 'utf16le')),
      avPair(7, Buffer.from('0090d336b734c301', 'hex')), // MsvAvTimestamp
      avPair(0, Buffer.alloc(0)),
    ]);
    const flags = (TYPE2_424.readUInt32LE(20) & ~(0x10 | 0x20 | 0x8000 | 0x40000000)) >>> 0;
    const head = Buffer.alloc(56);
    head.write('NTLMSSP\0', 0, 'ascii');
    head.writeUInt32LE(2, 8);
    head.writeUInt32LE(56, 16); // empty TargetName at offset 56
    head.writeUInt32LE(flags, 20);
    Buffer.from('0123456789abcdef', 'hex').copy(head, 24);
    head.writeUInt16LE(targetInfo.length, 40);
    head.writeUInt16LE(targetInfo.length, 42);
    head.writeUInt32LE(56, 44);
    TYPE2_424.copy(head, 48, 48, 56); // version
    const type2 = Buffer.concat([head, targetInfo]);

    const ctx = new NtlmAuthProvider().createContext(TARGET, creds);
    await ctx.step();
    const second = await ctx.step(frameNegTokenResp({ negState: 1, responseToken: type2 }));
    const resp = unframeSpnego(second.output!);
    if (resp.kind !== 'resp') throw new Error('expected NegTokenResp');
    const type3Flags = resp.responseToken!.readUInt32LE(60);
    assert.equal(type3Flags & 0x10, 0, 'SIGN not negotiated');
    const type3 = resp.responseToken!;
    const payloadStart = Math.min(...[16, 24, 32, 40, 48, 56].map((at) => type3.readUInt32LE(at)));
    assert.equal(payloadStart, 88, 'type3 has the 88-byte header that carries a MIC');
    // Independent MS-NLMP 3.4.4.2 MAC over DER MechTypeList { NTLMSSP }, seq 0, no key exchange.
    const esk = ctx.sessionKey as Buffer;
    const mechTypeList = Buffer.from('300c060a2b06010401823702020a', 'hex');
    const signKey = createHash('md5')
      .update(Buffer.concat([esk, Buffer.from('session key to client-to-server signing key magic constant\0')]))
      .digest();
    const checksum = createHmac('md5', signKey)
      .update(Buffer.concat([Buffer.alloc(4), mechTypeList]))
      .digest()
      .subarray(0, 8);
    const expected = Buffer.concat([Buffer.from('01000000', 'hex'), checksum, Buffer.alloc(4)]);
    assert.equal(resp.mechListMIC?.toString('hex'), expected.toString('hex'));
  });

  it('keeps a session key the caller read before dispose intact', async () => {
    const ctx = new NtlmAuthProvider().createContext(TARGET, creds);
    await ctx.step();
    await ctx.step(frameNegTokenResp({ negState: 1, responseToken: TYPE2_424 }));
    const key = ctx.sessionKey as Buffer;
    const before = key.toString('hex');
    assert.notEqual(before, '00'.repeat(16));
    await ctx.dispose!();
    assert.equal(key.toString('hex'), before, 'SMB2 signing still holds this key');
    assert.equal(ctx.sessionKey, undefined);
  });

  it('also accepts a raw (unframed) type2 challenge', async () => {
    const ctx = new NtlmAuthProvider().createContext(TARGET, creds);
    await ctx.step();
    const res = await ctx.step(TYPE2_424);
    assert.equal(res.complete, true);
  });

  it('rejects wrong-order and empty input', async () => {
    const ctx = new NtlmAuthProvider().createContext(TARGET, creds);
    await assert.rejects(() => ctx.step(TYPE2_424), /no input token/);
    await ctx.step();
    await assert.rejects(() => ctx.step(), /missing server challenge/);
    await assert.rejects(() => ctx.step(Buffer.alloc(0)), /missing server challenge/);
  });

  it('needs a username and password', async () => {
    const noUser = new NtlmAuthProvider().createContext(TARGET, { username: '' });
    await assert.rejects(() => noUser.step(), /username/);
    const noPass = new NtlmAuthProvider().createContext(TARGET, { username: 'u' });
    await assert.rejects(() => noPass.step(), /password/);
  });
});

describe('Kerberos provider (fake GSS)', () => {
  const kerberosTarget: AuthTarget = { host: 'host.domain', service: 'cifs' };

  it('frames the AP-REQ, consumes the AP-REP, and wraps after completion', async () => {
    const gss = new FakeGss([
      { out: AP_REQ.toString('base64'), complete: false },
      { out: '', complete: true },
    ]);
    const factory = async (service: string, init: { principal?: string }) => {
      gss.service = service;
      gss.principal = init.principal;
      return gss;
    };
    const ctx = new KerberosAuthProvider({ gss: factory }).createContext(kerberosTarget, {
      username: 'alice',
      useTicketCache: true,
    });
    assert.equal(ctx.negotiatedMechanism, 'kerberos');
    await assert.rejects(() => ctx.wrap!(Buffer.alloc(1)), /not established/);

    const first = await ctx.step();
    assert.equal(gss.service, 'cifs@host.domain');
    assert.equal(first.complete, false);
    const init = unframeSpnego(first.output!);
    assert.equal(init.kind, 'init');
    if (init.kind !== 'init') throw new Error('unreachable');
    assert.deepEqual(init.mechTypes, [OID_KRB5]);
    assert.ok(init.mechToken?.equals(AP_REQ));

    const second = await ctx.step(frameNegTokenResp({ negState: 0, responseToken: AP_REP }));
    assert.equal(second.complete, true);
    assert.equal(second.output, null); // AP-REP consumed, not sent
    assert.equal(ctx.sessionKey, undefined);

    const out = await ctx.wrap!(Buffer.from('hi'));
    assert.equal((await ctx.unwrap!(out)).toString(), 'hi');
    await assert.rejects(() => ctx.step(), /already complete/);
  });

  it('rejects wrong-order input and non-SPNEGO challenges', async () => {
    const ctx = new KerberosAuthProvider({
      gss: async () => new FakeGss([{ out: 'eA==', complete: false }]),
    }).createContext(kerberosTarget, { username: 'alice', useTicketCache: true });
    await assert.rejects(() => ctx.step(Buffer.from('x')), /no input token/);
    await ctx.step();
    await assert.rejects(() => ctx.step(Buffer.from('raw-bytes')), /NegTokenResp/);
  });

  it('surfaces GSS failures with context', async () => {
    const ctx = new KerberosAuthProvider({
      gss: async () => new FakeGss([new Error('no credentials')]),
    }).createContext(kerberosTarget, { username: 'alice', useTicketCache: true });
    await assert.rejects(() => ctx.step(), /Kerberos step failed: no credentials/);
  });

  // An IP address has no principal in the KDC. Refuse before kinit
  // and before the GSS layer, unless the caller names the SPN host.
  it('refuses an IP address as host before touching kinit or GSS', async () => {
    let touched = 0;
    for (const host of ['192.0.2.10', '2001:db8::10']) {
      const ctx = new KerberosAuthProvider({
        gss: async () => {
          touched++;
          return new FakeGss([]);
        },
        kinit: async () => {
          touched++;
        },
      }).createContext({ host, service: 'HTTP' }, { username: 'alice', password: 'pw', realm: 'EXAMPLE.COM' });
      await assert.rejects(() => ctx.step(), (err: unknown) => {
        assert.ok(err instanceof Error);
        assert.equal(
          err.message,
          `Kerberos needs the server's DNS name, not an IP address (${host}); use the FQDN, name the SPN host explicitly, or use NTLM`,
        );
        return true;
      });
      assert.equal(ctx.complete, false);
    }
    assert.equal(touched, 0, 'no kinit, no GSS init');
  });

  it('accepts an IP address as host when the SPN names the server', async () => {
    const gss = new FakeGss([{ out: 'eA==', complete: true }]);
    const ctx = new KerberosAuthProvider({
      gss: async (service: string) => {
        gss.service = service;
        return gss;
      },
    }).createContext({ host: '192.0.2.10', service: 'cifs', spn: 'cifs/files.example.com' }, { username: 'a' });
    await ctx.step();
    assert.equal(gss.service, 'cifs@files.example.com');
  });

  it('honors an explicit SPN override', async () => {
    const gss = new FakeGss([{ out: 'eA==', complete: true }]);
    const ctx = new KerberosAuthProvider({
      gss: async (service: string) => {
        gss.service = service;
        return gss;
      },
    }).createContext({ host: 'h', service: 'HTTP', spn: 'HTTP/custom.domain' }, { username: 'a' });
    await ctx.step();
    assert.equal(gss.service, 'HTTP@custom.domain');
  });

  it('runs kinit into a temp ccache for password auth, then cleans up', async () => {
    const calls: Array<{ args: string[]; password: string | undefined; env: NodeJS.ProcessEnv }> = [];
    const gss = new FakeGss([{ out: 'eA==', complete: true }]);
    const before = process.env.KRB5CCNAME;
    let gssCcache: string | undefined;
    const ctx = new KerberosAuthProvider({
      gss: async (_service, init) => {
        gssCcache = init.ccache;
        return gss;
      },
      kinit: async (args, password, env) => {
        calls.push({ args, password, env });
      },
    }).createContext(TARGET, { username: 'alice', password: 'pw', domain: 'example.com' });
    await ctx.step();
    assert.equal(calls.length, 1);
    assert.deepEqual(calls[0].args, ['alice@EXAMPLE.COM']);
    assert.equal(calls[0].password, 'pw');
    assert.match(calls[0].env.KRB5CCNAME ?? '', /^FILE:/);
    // The ccache goes to the GSS layer; process.env is untouched.
    assert.equal(gssCcache, calls[0].env.KRB5CCNAME);
    assert.equal(process.env.KRB5CCNAME, before);
    await ctx.dispose!();
    assert.equal(process.env.KRB5CCNAME, before);
    const { access } = await import('node:fs/promises');
    await assert.rejects(() => access(calls[0].env.KRB5CCNAME!.slice('FILE:'.length)));
  });

  it('skips kinit when a ticket cache is requested or no realm exists', async () => {
    let ran = 0;
    const deps = { gss: async () => new FakeGss([{ out: 'eA==', complete: true }]), kinit: async () => { ran += 1; } };
    const cached = new KerberosAuthProvider(deps).createContext(TARGET, {
      username: 'alice',
      password: 'pw',
      useTicketCache: true,
    });
    await cached.step();
    assert.equal(ran, 0);
    const noRealm = new KerberosAuthProvider(deps).createContext(TARGET, {
      username: 'alice',
      password: 'pw',
    });
    await assert.rejects(() => noRealm.step(), /realm/);
  });
});

describe('Negotiate provider', () => {
  // Ticket cache: the Kerberos leg must not shell out to a real kinit here.
  const creds = { username: 'User', password: 'Password', domain: 'Domain', useTicketCache: true };

  it('prefers Kerberos when GSS succeeds', async () => {
    const ctx = new NegotiateAuthProvider({
      gss: async () => new FakeGss([{ out: AP_REQ.toString('base64'), complete: false }]),
    }).createContext(TARGET, creds);
    assert.equal(ctx.negotiatedMechanism, undefined);
    const res = await ctx.step();
    assert.equal(res.complete, false);
    assert.equal(ctx.negotiatedMechanism, 'kerberos');
    const init = unframeSpnego(res.output!);
    assert.equal(init.kind, 'init');
    if (init.kind !== 'init') throw new Error('unreachable');
    assert.deepEqual(init.mechTypes, [OID_KRB5]);
    assert.equal(ctx.sessionKey, undefined);
  });

  it('falls back to NTLM on hard GSS failure', async () => {
    const ctx = new NegotiateAuthProvider({
      gss: async () => new FakeGss([new Error('no KDC')]),
    }).createContext(TARGET, creds);
    const res = await ctx.step();
    assert.equal(ctx.negotiatedMechanism, 'ntlm');
    const init = unframeSpnego(res.output!);
    if (init.kind !== 'init') throw new Error('unreachable');
    assert.deepEqual(init.mechTypes, [OID_NTLMSSP]);
    // The restarted NTLM handshake completes against a canned challenge.
    const done = await ctx.step(frameNegTokenResp({ negState: 1, responseToken: TYPE2_424 }));
    assert.equal(done.complete, true);
    assert.equal((ctx.sessionKey as Buffer | undefined)?.length, 16);
  });

  // With a password, an IP address as host skips Kerberos entirely
  // (no kinit, no KDC) and goes to NTLM.
  it('falls back to NTLM for an IP address host without a kinit or GSS init', async () => {
    let touched = 0;
    const ctx = new NegotiateAuthProvider({
      gss: async () => {
        touched++;
        return new FakeGss([]);
      },
      kinit: async () => {
        touched++;
      },
    }).createContext({ host: '192.0.2.10', service: 'HTTP' }, { username: 'User', password: 'Password', domain: 'Domain' });
    const res = await ctx.step();
    assert.equal(ctx.negotiatedMechanism, 'ntlm');
    const init = unframeSpnego(res.output!);
    if (init.kind !== 'init') throw new Error('unreachable');
    assert.deepEqual(init.mechTypes, [OID_NTLMSSP]);
    assert.equal(touched, 0);
  });

  // Once a Kerberos token has gone to the server, the server cannot
  // move the exchange to NTLM. Only client-side failures before that token
  // (no realm, no ticket, no KDC, unknown SPN) fall back.
  describe('after the Kerberos token is sent, no NTLM fallback', () => {
    const started = async (script: Array<{ out: string; complete: boolean } | Error>) => {
      const gss = new FakeGss([{ out: AP_REQ.toString('base64'), complete: false }, ...script]);
      const ctx = new NegotiateAuthProvider({ gss: async () => gss }).createContext(TARGET, creds);
      await ctx.step();
      assert.equal(ctx.negotiatedMechanism, 'kerberos');
      return ctx;
    };

    it('refuses a supportedMech of NTLM, which the client did not offer (RFC 4178 4.2.2)', async () => {
      const ctx = await started([]);
      await assert.rejects(ctx.step(frameNegTokenResp({ negState: 1, supportedMech: OID_NTLMSSP })), /server picked .*NTLM.*not offered/);
      assert.equal(ctx.negotiatedMechanism, 'kerberos');
    });

    it('refuses a supportedMech of NTLM that comes with an NTLM challenge', async () => {
      const ctx = await started([]);
      await assert.rejects(
        ctx.step(frameNegTokenResp({ negState: 1, supportedMech: OID_NTLMSSP, responseToken: TYPE2_424 })),
        /not offered/,
      );
      assert.equal(ctx.negotiatedMechanism, 'kerberos');
    });

    it('a server reject is fatal', async () => {
      const ctx = await started([]);
      await assert.rejects(ctx.step(frameNegTokenResp({ negState: 2, responseToken: Buffer.from('krb-error') })), /rejected/);
      assert.equal(ctx.negotiatedMechanism, 'kerberos');
    });

    it('a malformed server token is fatal', async () => {
      const ctx = await started([]);
      await assert.rejects(ctx.step(Buffer.from('not spnego at all')));
      assert.equal(ctx.negotiatedMechanism, 'kerberos');
    });

    it('an AP-REP that GSS refuses (mutual authentication) is fatal', async () => {
      const ctx = await started([new Error('gss_init_sec_context: KRB5KRB_AP_ERR_MODIFIED')]);
      await assert.rejects(ctx.step(frameNegTokenResp({ negState: 0, supportedMech: OID_KRB5, responseToken: AP_REP })), /AP_ERR_MODIFIED/);
      assert.equal(ctx.negotiatedMechanism, 'kerberos');
    });

    it('accepts the Microsoft Kerberos OID as supportedMech, as Windows may send it', async () => {
      const ctx = await started([{ out: '', complete: true }]);
      const done = await ctx.step(frameNegTokenResp({ negState: 0, supportedMech: '1.2.840.48018.1.2.2', responseToken: AP_REP }));
      assert.equal(done.complete, true);
      assert.equal(ctx.negotiatedMechanism, 'kerberos');
    });
  });
});

describe('sessionKey matrix', () => {
  it('basic absent, ntlm present, kerberos absent', async () => {
      const basic = new BasicAuthProvider().createContext(TARGET, { username: 'a', password: 'b' });
    await basic.step();
    assert.equal(basic.sessionKey, undefined);

    const ntlm = new NtlmAuthProvider().createContext(TARGET, {
      username: 'u',
      password: 'p',
      domain: 'd',
    });
    await ntlm.step();
    await ntlm.step(frameNegTokenResp({ negState: 1, responseToken: TYPE2_424 }));
    assert.equal(ntlm.sessionKey?.length, 16);

    const krb = new KerberosAuthProvider({
      gss: async () => new FakeGss([{ out: 'eA==', complete: true }]),
    }).createContext(TARGET, { username: 'a', useTicketCache: true });
    await krb.step();
    assert.equal(krb.sessionKey, undefined);
  });
});

describe('createAuthProvider', () => {
  it('builds all four providers and rejects unknown mechanisms', () => {
    assert.equal(createAuthProvider('basic').mechanism, 'basic');
    assert.equal(createAuthProvider('ntlm').mechanism, 'ntlm');
    assert.equal(createAuthProvider('kerberos').mechanism, 'kerberos');
    assert.equal(createAuthProvider('negotiate').mechanism, 'negotiate');
    assert.throws(() => createAuthProvider('digest' as never), /Unknown auth mechanism/);
  });
});
