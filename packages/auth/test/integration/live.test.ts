// Live Kerberos/NTLM tests against a Samba AD DC. Started by run.ts, which
// sets the env below; see README.md in this directory. No host config is
// touched: KRB5_CONFIG points at a temp file and the SPN comes from the
// AuthTarget `spn` override.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { performance } from 'node:perf_hooks';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { connect, SmbAuthError } from '@winlinux/smb2';
import {
  KerberosAuthProvider,
  defaultKinitRunner,
  loadKrbSessionKey,
  type KinitRunner,
} from '../../src/auth/kerberos.js';
import { NegotiateAuthProvider } from '../../src/auth/negotiate.js';
import { NtlmAuthProvider } from '../../src/auth/ntlm/provider.js';
import { OID_KRB5, frameNegTokenResp, unframeSpnego } from '../../src/auth/spnego.js';
import type { AuthProvider, AuthTarget, Credentials, SecurityContext } from '../../src/auth/types.js';
import {
  probeNegotiate,
  probeSessionSetup,
  SMB2_NEGOTIATE_SIGNING_REQUIRED,
  STATUS_SUCCESS,
} from './smb2-probe.js';

function need(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`live test: set ${name} (run through run.ts, see README.md)`);
  return v;
}

const KDC_HOST = need('WINLINUX_KDC_HOST'); // FQDN in the SPNs, e.g. dc1.example.com
const REALM = need('WINLINUX_REALM');
const USER = need('WINLINUX_USER');
const PASS = need('WINLINUX_PASSWORD');
const SMB_HOST = need('WINLINUX_SMB_HOST'); // address to dial; may differ from KDC_HOST
const SMB_PORT = Number(need('WINLINUX_SMB_PORT'));
const NETBIOS_DOMAIN = process.env.WINLINUX_DOMAIN ?? REALM.split('.')[0];

const execFileAsync = promisify(execFile);

async function klist(ccache: string): Promise<string> {
  const { stdout } = await execFileAsync('klist', [], {
    env: { ...process.env, KRB5CCNAME: ccache },
  });
  return stdout;
}

// A GSS krb5 initial token is [APPLICATION 0] { OID krb5, TOK_ID 01 00, AP-REQ }.
function assertKrb5ApReq(inner: Buffer): void {
  assert.equal(inner[0], 0x60, 'GSS initial context token tag');
  let i = 1;
  const lenByte = inner[i++];
  if (lenByte & 0x80) i += lenByte & 0x7f;
  assert.equal(inner[i], 0x06, 'mech OID tag');
  const oidLen = inner[i + 1];
  const oid = inner.subarray(i + 2, i + 2 + oidLen).toString('hex');
  assert.equal(oid, '2a864886f712010202', 'mech OID is krb5 1.2.840.113554.1.2.2');
  i += 2 + oidLen;
  assert.equal(inner.readUInt16BE(i), 0x0100, 'TOK_ID is KRB_AP_REQ');
  assert.equal(inner[i + 2], 0x6e, 'AP-REQ is [APPLICATION 14]');
}

function assertKerberosInit(output: Buffer | null): Buffer {
  assert.ok(output && output.length > 0, 'first step returns a token');
  const framed = unframeSpnego(output);
  assert.equal(framed.kind, 'init');
  if (framed.kind !== 'init') throw new Error('unreachable');
  assert.equal(framed.mechTypes[0], OID_KRB5);
  assert.ok(framed.mechToken, 'NegTokenInit carries a mechToken');
  assertKrb5ApReq(framed.mechToken);
  return framed.mechToken;
}

// run.ts dials 127.0.0.1 on macOS, so the SPN must come from the override.
function withSpn(inner: AuthProvider): AuthProvider {
  return {
    mechanism: inner.mechanism,
    createContext: (target: AuthTarget, creds) =>
      inner.createContext({ ...target, spn: `${target.service}/${KDC_HOST}` }, creds),
  };
}

// Records the ccache that kinit filled; kinit itself is the real one.
function recordingKinit(): { kinit: KinitRunner; ccaches: string[] } {
  const ccaches: string[] = [];
  return {
    ccaches,
    kinit: async (args, password, env) => {
      ccaches.push(env.KRB5CCNAME ?? '');
      await defaultKinitRunner(args, password, env);
    },
  };
}

describe('live Kerberos: password path (kinit into a per-context ccache)', () => {
  for (const service of ['cifs', 'HTTP'] as const) {
    it(`gets an AP-REQ for ${service}/${KDC_HOST} without touching process.env.KRB5CCNAME`, async () => {
      const saved = process.env.KRB5CCNAME;
      const rec = recordingKinit();
      const ctx = new KerberosAuthProvider({ kinit: rec.kinit }).createContext(
        { host: SMB_HOST, service, spn: `${service}/${KDC_HOST}` },
        { username: USER, password: PASS, realm: REALM },
      );
      try {
        const first = await ctx.step();
        assertKerberosInit(first.output);
        assert.equal(process.env.KRB5CCNAME, saved, 'process.env.KRB5CCNAME is never changed');
        assert.equal(rec.ccaches.length, 1);
        const ccache = rec.ccaches[0];
        assert.match(ccache, /^FILE:/);
        const tickets = await klist(ccache);
        assert.match(tickets, new RegExp(`${USER}@${REALM}`, 'i'), tickets);
        assert.match(tickets, new RegExp(`${service}/${KDC_HOST}@${REALM}`, 'i'), 'the service ticket went to this ccache');
      } finally {
        await ctx.dispose?.();
      }
      assert.equal(process.env.KRB5CCNAME, saved);
    });
  }

  it('two concurrent password contexts use separate ccaches and never cross-restore the env', async () => {
    const saved = process.env.KRB5CCNAME;
    const rec = recordingKinit();
    const make = (service: 'cifs' | 'HTTP') =>
      new KerberosAuthProvider({ kinit: rec.kinit }).createContext(
        { host: SMB_HOST, service, spn: `${service}/${KDC_HOST}` },
        { username: USER, password: PASS, realm: REALM },
      );
    const a = make('cifs');
    const b = make('HTTP');
    try {
      const [ra, rb] = await Promise.all([a.step(), b.step()]);
      assertKerberosInit(ra.output);
      assertKerberosInit(rb.output);
      assert.equal(new Set(rec.ccaches).size, 2, 'one ccache per context');
      assert.equal(process.env.KRB5CCNAME, saved);
    } finally {
      await Promise.all([a.dispose?.(), b.dispose?.()]);
    }
    assert.equal(process.env.KRB5CCNAME, saved);
  });
});

describe('live Kerberos: ticket-cache path (useTicketCache)', () => {
  it('uses a ccache created by kinit, without running kinit itself', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'winlinux-live-cc-'));
    const ccache = `FILE:${join(dir, 'ccache')}`;
    const saved = process.env.KRB5CCNAME;
    try {
      await defaultKinitRunner([`${USER}@${REALM}`], PASS, { ...process.env, KRB5CCNAME: ccache });
      process.env.KRB5CCNAME = ccache;
      let kinitRuns = 0;
      const ctx = new KerberosAuthProvider({
        kinit: async () => {
          kinitRuns += 1;
        },
      }).createContext(
        { host: SMB_HOST, service: 'cifs', spn: `cifs/${KDC_HOST}` },
        { username: USER, realm: REALM, useTicketCache: true },
      );
      try {
        assertKerberosInit((await ctx.step()).output);
        assert.equal(kinitRuns, 0, 'ticket-cache path must not call kinit');
        assert.equal(process.env.KRB5CCNAME, ccache, 'the kinit ccache stays the default');
        assert.match(await klist(ccache), new RegExp(`cifs/${KDC_HOST}@${REALM}`, 'i'));
      } finally {
        await ctx.dispose?.();
      }
    } finally {
      if (saved === undefined) delete process.env.KRB5CCNAME;
      else process.env.KRB5CCNAME = saved;
      await rm(dir, { recursive: true, force: true });
    }
  });
});

describe('live risk R1: SMB2 SESSION_SETUP with the Negotiate token', () => {
  it('Samba accepts the module-framed SPNEGO NegTokenInit (STATUS_SUCCESS)', async (t) => {
    const ctx: SecurityContext = withSpn(new NegotiateAuthProvider()).createContext(
      { host: SMB_HOST, service: 'cifs' },
      { username: USER, password: PASS, realm: REALM },
    );
    try {
      const result = await probeSessionSetup(SMB_HOST, SMB_PORT, ctx);
      const first = result.legs[0];
      t.diagnostic(`R1 platform=${process.platform} dialect=0x${result.dialect.toString(16)}`);
      for (const [n, leg] of result.legs.entries()) {
        t.diagnostic(
          `R1 leg ${n + 1}: status=0x${leg.status.toString(16).padStart(8, '0')} ` +
            `sent=${leg.sent.length}B received=${leg.received.length}B`,
        );
      }
      t.diagnostic(`R1 NegTokenInit hex: ${first.sent.toString('hex')}`);
      assert.equal(ctx.negotiatedMechanism, 'kerberos', 'Negotiate must not fall back to NTLM');
      assertKerberosInit(first.sent);
      assert.equal(
        result.finalStatus,
        STATUS_SUCCESS,
        `SESSION_SETUP ended with 0x${result.finalStatus.toString(16)}; token hex: ${first.sent.toString('hex')}`,
      );
      assert.equal(ctx.complete, true, 'mutual auth: the AP-REP completed the context');
    } finally {
      await ctx.dispose?.();
    }
  });
});

describe('live NTLM through @winlinux/smb2 against the DC', () => {
  it('connects with the auth NTLM provider, signs, and lists shares', async () => {
    const session = await connect({
      host: SMB_HOST,
      port: SMB_PORT,
      authProvider: new NtlmAuthProvider(),
      credentials: { username: USER, password: PASS, domain: NETBIOS_DOMAIN },
      signing: 'required',
    });
    try {
      const names = (await session.listShares()).map((s) => s.name.toLowerCase());
      for (const share of ['sysvol', 'netlogon', 'ipc$']) {
        assert.ok(names.includes(share), `share ${share} in ${names.join(',')}`);
      }
      const entries = await session.list('sysvol');
      assert.ok(
        entries.some((e) => e.name.toLowerCase() === REALM.toLowerCase()),
        `sysvol lists the realm folder: ${entries.map((e) => e.name).join(',')}`,
      );
    } finally {
      await session.close();
    }
  });
});

// Wraps a provider: SPN override, and a record of what smb2 read from the
// context (mechanism and session key length). `mutate` can alter the key.
function recording(inner: AuthProvider, mutate?: (key: Buffer) => Buffer) {
  const rec: { mechanism?: string; keyLength?: number } = {};
  const provider: AuthProvider = {
    mechanism: inner.mechanism,
    createContext: (target: AuthTarget, creds: Credentials) => {
      const ctx = inner.createContext({ ...target, spn: `${target.service}/${KDC_HOST}` }, creds);
      return {
        step: (token?: Buffer) => ctx.step(token),
        get complete() {
          return ctx.complete;
        },
        get negotiatedMechanism() {
          return ctx.negotiatedMechanism;
        },
        get sessionKey() {
          const key = ctx.sessionKey;
          rec.mechanism = ctx.negotiatedMechanism;
          rec.keyLength = key?.length;
          return key && mutate ? mutate(key) : key;
        },
        dispose: () => ctx.dispose?.() ?? Promise.resolve(),
      };
    },
  };
  return { provider, rec };
}

const sha256 = (b: Buffer) => createHash('sha256').update(b).digest('hex');

// Phase 1 runs with the DC default (server signing mandatory). With
// @winlinux/krb-session-key, Kerberos signs SMB2 with the first 16 bytes
// of the GSS session key.
describe('live Kerberos through @winlinux/smb2, server signing required', () => {
  it('the DC requires signing (test premise)', async () => {
    const { securityMode } = await probeNegotiate(SMB_HOST, SMB_PORT);
    assert.ok(
      securityMode & SMB2_NEGOTIATE_SIGNING_REQUIRED,
      `NEGOTIATE SecurityMode 0x${securityMode.toString(16)} lacks SIGNING_REQUIRED`,
    );
  });

  it('the session-key addon is installed and loads on this host', async () => {
    assert.ok(await loadKrbSessionKey(), '@winlinux/krb-session-key must be built for the live run');
  });

  const cases: Array<[string, () => AuthProvider, 'password' | 'ticket-cache']> = [
    ['Kerberos, password', () => new KerberosAuthProvider(), 'password'],
    ['Kerberos, ticket cache', () => new KerberosAuthProvider(), 'ticket-cache'],
    ['Negotiate, password', () => new NegotiateAuthProvider(), 'password'],
  ];
  for (const [label, make, mode] of cases) {
    it(`${label}: signing 'required' lists shares, then puts and gets a file with equal SHA-256`, async (t) => {
      const saved = process.env.KRB5CCNAME;
      const dir = await mkdtemp(join(tmpdir(), 'winlinux-live-cc-'));
      let credentials: Credentials = { username: USER, password: PASS, realm: REALM };
      if (mode === 'ticket-cache') {
        // The user's own ticket cache: kinit here, then point KRB5CCNAME at it.
        const ccache = `FILE:${join(dir, 'ccache')}`;
        await defaultKinitRunner([`${USER}@${REALM}`], PASS, { ...process.env, KRB5CCNAME: ccache });
        process.env.KRB5CCNAME = ccache;
        credentials = { username: USER, realm: REALM, useTicketCache: true };
      }
      const { provider, rec } = recording(make());
      const name = `winlinux-krb-${process.platform}-${randomBytes(4).toString('hex')}.bin`;
      const data = randomBytes(200_000);
      try {
        const session = await connect({
          host: SMB_HOST,
          port: SMB_PORT,
          authProvider: provider,
          credentials,
          signing: 'required',
          requestTimeoutMs: 15000,
        });
        try {
          assert.equal(rec.mechanism, 'kerberos', 'Kerberos authenticated the session (no NTLM fallback)');
          assert.equal(rec.keyLength, 32, 'the full aes256 GSS key reached smb2');
          const names = (await session.listShares()).map((s) => s.name.toLowerCase());
          for (const share of ['sysvol', 'netlogon', 'ipc$']) {
            assert.ok(names.includes(share), `share ${share} in ${names.join(',')}`);
          }
          await session.writeFile('netlogon', name, data);
          const back = await session.readFile('netlogon', name);
          assert.equal(sha256(back), sha256(data), 'put then get returns the same bytes');
          t.diagnostic(`${label}: ${data.length} bytes round-tripped, sha256 ${sha256(data).slice(0, 16)}`);
          await session.delete('netlogon', name);
        } finally {
          await session.close();
        }
      } finally {
        if (saved === undefined) delete process.env.KRB5CCNAME;
        else process.env.KRB5CCNAME = saved;
        await rm(dir, { recursive: true, force: true });
      }
    });
  }

  it('negative control: a session key with one bit flipped cannot sign a session', async () => {
    const { provider, rec } = recording(new KerberosAuthProvider(), (key) => {
      const bad = Buffer.from(key);
      bad[0] ^= 0x01;
      return bad;
    });
    await assert.rejects(
      () =>
        connect({
          host: SMB_HOST,
          port: SMB_PORT,
          authProvider: provider,
          credentials: { username: USER, password: PASS, realm: REALM },
          signing: 'required',
          requestTimeoutMs: 15000,
        }).then(async (s) => {
          try {
            await s.listShares();
          } finally {
            await s.close().catch(() => undefined);
          }
        }),
    );
    assert.equal(rec.keyLength, 32);
  });

  it('the addon runs the KDC round trip off the JS thread (the event loop keeps ticking)', async (t) => {
    const addon = await loadKrbSessionKey();
    assert.ok(addon);
    const dir = await mkdtemp(join(tmpdir(), 'winlinux-live-cc-'));
    const ccache = `FILE:${join(dir, 'ccache')}`;
    try {
      await defaultKinitRunner([`${USER}@${REALM}`], PASS, { ...process.env, KRB5CCNAME: ccache });
      assert.doesNotMatch(await klist(ccache), /cifs\//i, 'only a TGT before the step');
      const client = await addon.gssFactory(`cifs@${KDC_HOST}`, { ccache });
      let ticks = 0;
      let pending = true;
      const spin = () => {
        if (!pending) return;
        ticks += 1;
        setImmediate(spin);
      };
      const t0 = performance.now();
      const stepping = client.step(''); // the TGS-REQ for cifs/ happens here
      const syncMs = performance.now() - t0;
      setImmediate(spin);
      const token = await stepping;
      pending = false;
      const totalMs = performance.now() - t0;
      t.diagnostic(`event loop: ${ticks} ticks during the step; sync part ${syncMs.toFixed(2)} ms, total ${totalMs.toFixed(2)} ms`);
      assert.ok(token.length > 0, 'the step produced an AP-REQ');
      assert.match(await klist(ccache), new RegExp(`cifs/${KDC_HOST}@${REALM}`, 'i'), 'the step did a TGS round trip');
      assert.ok(ticks > 0, 'setImmediate callbacks ran while the KDC round trip was in flight');
      client.dispose?.();
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

// The server's final SPNEGO token after the handshake.
describe('live final SPNEGO token and mechListMIC', () => {
  function ntlmContext(): SecurityContext {
    return new NtlmAuthProvider().createContext(
      { host: SMB_HOST, service: 'cifs' },
      { username: USER, password: PASS, domain: NETBIOS_DOMAIN },
    );
  }

  it('NTLM: the DC mechListMIC in the final NegTokenResp verifies', async (t) => {
    const ctx = ntlmContext();
    try {
      const result = await probeSessionSetup(SMB_HOST, SMB_PORT, ctx);
      assert.equal(result.finalStatus, STATUS_SUCCESS);
      const final = result.legs[result.legs.length - 1].received;
      const framed = unframeSpnego(final);
      assert.equal(framed.kind, 'resp');
      if (framed.kind !== 'resp') throw new Error('unreachable');
      assert.ok(framed.mechListMIC, 'Samba sends a mechListMIC with accept-completed');
      t.diagnostic(`NTLM server mechListMIC ${framed.mechListMIC.toString('hex')}`);
      assert.deepEqual(await ctx.step(final), { output: null, complete: true });
    } finally {
      await ctx.dispose?.();
    }
  });

  it('NTLM: a tampered DC mechListMIC fails', async () => {
    const ctx = ntlmContext();
    try {
      const result = await probeSessionSetup(SMB_HOST, SMB_PORT, ctx);
      const framed = unframeSpnego(result.legs[result.legs.length - 1].received);
      if (framed.kind !== 'resp' || !framed.mechListMIC) throw new Error('expected a mechListMIC');
      const mic = Buffer.from(framed.mechListMIC);
      mic[5] ^= 0x01;
      await assert.rejects(
        () => ctx.step(frameNegTokenResp({ negState: framed.negState, mechListMIC: mic })),
        /server mechListMIC does not verify/,
      );
    } finally {
      await ctx.dispose?.();
    }
  });

  it('Kerberos: the AP-REP token completes the context; any mechListMIC in it is verified', async (t) => {
    const ctx = withSpn(new KerberosAuthProvider()).createContext(
      { host: SMB_HOST, service: 'cifs' },
      { username: USER, password: PASS, realm: REALM },
    );
    try {
      const result = await probeSessionSetup(SMB_HOST, SMB_PORT, ctx);
      assert.equal(result.finalStatus, STATUS_SUCCESS);
      const framed = unframeSpnego(result.legs[result.legs.length - 1].received);
      if (framed.kind !== 'resp') throw new Error('expected NegTokenResp');
      t.diagnostic(`Kerberos final token: negState=${framed.negState} mechListMIC=${framed.mechListMIC ? 'present' : 'absent'}`);
      assert.equal(ctx.complete, true);
      assert.equal(ctx.sessionKey?.length, 32);
    } finally {
      await ctx.dispose?.();
    }
  });
});

describe('live auth errors', () => {
  it('Kerberos wrong password rejects with a kinit error that names the cause', async () => {
    const ctx = new KerberosAuthProvider().createContext(
      { host: SMB_HOST, service: 'cifs', spn: `cifs/${KDC_HOST}` },
      { username: USER, password: 'not-the-password', realm: REALM },
    );
    try {
      await assert.rejects(
        () => ctx.step(),
        (err: Error) => {
          assert.match(err.message, /^kinit failed: /);
          assert.match(err.message, /password incorrect|preauthentication failed/i);
          return true;
        },
      );
    } finally {
      await ctx.dispose?.();
    }
  });

  it('Kerberos unknown user rejects with a kinit error that names the cause', async () => {
    const ctx = new KerberosAuthProvider().createContext(
      { host: SMB_HOST, service: 'cifs', spn: `cifs/${KDC_HOST}` },
      { username: 'no-such-user-4711', password: PASS, realm: REALM },
    );
    try {
      await assert.rejects(
        () => ctx.step(),
        (err: Error) => {
          assert.match(err.message, /^kinit failed: /);
          assert.match(err.message, /not found in kerberos database|unknown/i);
          return true;
        },
      );
    } finally {
      await ctx.dispose?.();
    }
  });

  for (const [label, username, password] of [
    ['wrong password', USER, 'not-the-password'],
    ['unknown user', 'no-such-user-4711', PASS],
  ] as const) {
    it(`NTLM ${label} rejects with SmbAuthError`, async () => {
      await assert.rejects(
        () =>
          connect({
            host: SMB_HOST,
            port: SMB_PORT,
            authProvider: new NtlmAuthProvider(),
            credentials: { username, password, domain: NETBIOS_DOMAIN },
          }),
        SmbAuthError,
      );
    });
  }
});
