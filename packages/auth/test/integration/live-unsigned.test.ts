// Phase 2 of the live run: run.ts sets `server signing = auto` on the DC and
// reloads smbd, so SMB2 signing is offered but not required. Kerberos must
// still complete SESSION_SETUP through @winlinux/smb2 and list shares (with
// @winlinux/krb-session-key it also signs, since the server offers signing).
// Env as in live.test.ts; see README.md.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { connect } from '@winlinux/smb2';
import { KerberosAuthProvider, defaultKinitRunner } from '../../src/auth/kerberos.js';
import { NegotiateAuthProvider } from '../../src/auth/negotiate.js';
import type { AuthProvider, AuthTarget, SecurityContext } from '../../src/auth/types.js';
import { probeNegotiate, SMB2_NEGOTIATE_SIGNING_REQUIRED } from './smb2-probe.js';

function need(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`live test: set ${name} (run through run.ts, see README.md)`);
  return v;
}

const KDC_HOST = need('WINLINUX_KDC_HOST');
const REALM = need('WINLINUX_REALM');
const USER = need('WINLINUX_USER');
const PASS = need('WINLINUX_PASSWORD');
const SMB_HOST = need('WINLINUX_SMB_HOST');
const SMB_PORT = Number(need('WINLINUX_SMB_PORT'));

// SPN override (the host leg dials 127.0.0.1) plus a handle on the context,
// so the test can check the mechanism and that mutual auth completed.
function tracked(inner: AuthProvider): { provider: AuthProvider; contexts: SecurityContext[] } {
  const contexts: SecurityContext[] = [];
  const provider: AuthProvider = {
    mechanism: inner.mechanism,
    createContext: (target: AuthTarget, creds) => {
      const ctx = inner.createContext({ ...target, spn: `${target.service}/${KDC_HOST}` }, creds);
      contexts.push(ctx);
      return ctx;
    },
  };
  return { provider, contexts };
}

async function assertListsShares(provider: AuthProvider, credentials: Parameters<typeof connect>[0]['credentials']) {
  const session = await connect({ host: SMB_HOST, port: SMB_PORT, authProvider: provider, credentials });
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
}

describe('live Kerberos through @winlinux/smb2, server signing not required', () => {
  it('the DC offers signing but does not require it (test premise)', async () => {
    const { securityMode } = await probeNegotiate(SMB_HOST, SMB_PORT);
    assert.equal(
      securityMode & SMB2_NEGOTIATE_SIGNING_REQUIRED,
      0,
      `NEGOTIATE SecurityMode 0x${securityMode.toString(16)} still requires signing`,
    );
  });

  it('Kerberos from a kinit ccache connects and lists shares', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'winlinux-live-cc-'));
    const ccache = `FILE:${join(dir, 'ccache')}`;
    const saved = process.env.KRB5CCNAME;
    try {
      await defaultKinitRunner([`${USER}@${REALM}`], PASS, { ...process.env, KRB5CCNAME: ccache });
      process.env.KRB5CCNAME = ccache;
      let kinitRuns = 0;
      const { provider, contexts } = tracked(
        new KerberosAuthProvider({
          kinit: async () => {
            kinitRuns += 1;
          },
        }),
      );
      await assertListsShares(provider, { username: USER, realm: REALM, useTicketCache: true });
      assert.equal(kinitRuns, 0, 'ticket-cache path must not call kinit');
      assert.equal(contexts.length, 1);
      assert.equal(contexts[0].complete, true, 'the AP-REP completed the context');
    } finally {
      if (saved === undefined) delete process.env.KRB5CCNAME;
      else process.env.KRB5CCNAME = saved;
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('Negotiate (password) picks Kerberos, connects and lists shares', async () => {
    const { provider, contexts } = tracked(new NegotiateAuthProvider());
    await assertListsShares(provider, { username: USER, password: PASS, realm: REALM });
    assert.equal(contexts.length, 1);
    assert.equal(contexts[0].negotiatedMechanism, 'kerberos', 'Negotiate must not fall back to NTLM');
    assert.equal(contexts[0].complete, true, 'the AP-REP completed the context');
  });
});
