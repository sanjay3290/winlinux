// CredSSP in the facade and the CLI options: explicit opt-in, the
// refusals, the WinRM-only plan, and the notice hook. No network.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import type { Mechanism } from '@winlinux/auth';
import { CREDSSP_HTTP_REASON, CREDSSP_INSECURE_REASON } from '@winlinux/winrm';
import { connect, WinLinuxUsageError, type ConnectOptions } from '../../dist/index.js';
import { createClient } from '../../dist/client.js';
import { CREDSSP_OVER_SMB_REASON, planAuth } from '../../dist/plan-auth.js';
import { HELP, buildConnectOptions, credsspNotice, withCredsspNotice } from '../../dist/cli/app.js';
import { parseConfig } from '../../dist/cli/config.js';
import { fakeDeps } from '../helpers/fakes.js';

const PASSWORD = 'sentinel-password-126';
const HTTPS_OPTS: ConnectOptions = { username: 'u', password: PASSWORD, auth: 'credssp', winrm: { tls: true } };

async function rejectsUsage(host: string, options: ConnectOptions, pattern: RegExp | string): Promise<void> {
  await assert.rejects(connect(host, options), (err: unknown) => {
    assert.ok(err instanceof WinLinuxUsageError, `expected WinLinuxUsageError, got ${String(err)}`);
    if (typeof pattern === 'string') assert.equal((err as Error).message, pattern);
    else assert.match((err as Error).message, pattern);
    assert.ok(!(err as Error).message.includes(PASSWORD));
    return true;
  });
}

describe('planAuth: credssp', () => {
  it('plans credssp for WinRM only and refuses SMB', () => {
    for (const e of [true, false]) {
      for (const addon of [true, false]) {
        assert.deepEqual(planAuth('credssp', { password: PASSWORD }, e, addon), {
          winrm: { refused: false, mechanism: 'credssp' },
          smb: { refused: true, mechanism: 'credssp', reason: 'CredSSP is WinRM-only; use another mechanism for files' },
        });
      }
    }
    assert.equal(CREDSSP_OVER_SMB_REASON, 'CredSSP is WinRM-only; use another mechanism for files');
  });

  it('no other mechanism ever plans credssp', () => {
    const creds = [{ password: PASSWORD }, { useTicketCache: true }, { password: PASSWORD, realm: 'EXAMPLE.TEST' }, { keytab: '/k', realm: 'EXAMPLE.TEST' }];
    for (const auth of ['negotiate', 'ntlm', 'kerberos', 'basic'] as Mechanism[]) {
      for (const c of creds) {
        for (const e of [true, false]) {
          for (const addon of [true, false]) {
            const plan = planAuth(auth, c, e, addon);
            assert.notEqual(plan.winrm.mechanism, 'credssp', `${auth} winrm`);
            assert.notEqual(plan.smb.mechanism, 'credssp', `${auth} smb`);
          }
        }
      }
    }
  });
});

describe('connect(): credssp refusals', () => {
  it('needs a password; refuses -K and a keytab', async () => {
    await rejectsUsage('h', { ...HTTPS_OPTS, password: undefined }, "auth 'credssp' needs a password");
    await rejectsUsage('h', { ...HTTPS_OPTS, password: '' }, "auth 'credssp' needs a password");
    await rejectsUsage('h', { ...HTTPS_OPTS, password: undefined, useTicketCache: true }, /cannot use the ticket cache \(-K\)/);
    await rejectsUsage('h', { ...HTTPS_OPTS, useTicketCache: true }, /cannot use the ticket cache \(-K\)/);
    await rejectsUsage('h', { ...HTTPS_OPTS, password: undefined, keytab: '/tmp/sentinel.keytab', realm: 'EXAMPLE.TEST' }, /cannot use a keytab/);
  });

  it('refuses tlsVerify false (--insecure)', async () => {
    await rejectsUsage('h', { ...HTTPS_OPTS, winrm: { tls: true, tlsVerify: false } }, CREDSSP_INSECURE_REASON);
    await rejectsUsage('h', { ...HTTPS_OPTS, winrm: { tlsVerify: false, credsspAllowHttp: true } }, CREDSSP_INSECURE_REASON);
  });

  it('refuses plain HTTP unless winrm.credsspAllowHttp, and the text names the risk', async () => {
    await rejectsUsage('h', { ...HTTPS_OPTS, winrm: {} }, CREDSSP_HTTP_REASON);
    await rejectsUsage('h', { ...HTTPS_OPTS, winrm: { tls: false, credsspAllowHttp: false } }, CREDSSP_HTTP_REASON);
    assert.match(CREDSSP_HTTP_REASON, /no certificate check/);
    assert.match(CREDSSP_HTTP_REASON, /delegates your password/);
    assert.match(CREDSSP_INSECURE_REASON, /delegates your password/);
    const ok = await connect('h', { ...HTTPS_OPTS, winrm: { credsspAllowHttp: true } });
    await ok.close();
  });

  it('refuses an IP address when the realm makes Kerberos the inner mechanism', async () => {
    await rejectsUsage('192.0.2.10', { ...HTTPS_OPTS, realm: 'EXAMPLE.TEST' }, /DNS name/);
    const ok = await connect('192.0.2.10', { ...HTTPS_OPTS });
    await ok.close();
  });
});

describe('createClient: credssp', () => {
  it('opens WinRM with the credssp provider, the flag and the notice hook; refuses files', async () => {
    const deps = fakeDeps({});
    const seen: string[] = [];
    const client = createClient('server.example.test', { ...HTTPS_OPTS, winrm: { tls: false, credsspAllowHttp: true, onCredSSPDelegation: (h) => seen.push(h) } }, deps);
    try {
      await client.run('hostname');
      assert.deepEqual(deps.mechanisms, ['credssp']);
      const opened = deps.winrmOpens[0];
      assert.equal(opened?.credsspAllowHttp, true);
      assert.equal(typeof opened?.onCredSSPDelegation, 'function');
      opened?.onCredSSPDelegation?.('server.example.test');
      assert.deepEqual(seen, ['server.example.test']);
      await assert.rejects(client.ls('C$'), (err: unknown) => err instanceof WinLinuxUsageError && (err as Error).message === CREDSSP_OVER_SMB_REASON);
      assert.equal(deps.smbOpens.length, 0, 'no SMB socket');
    } finally {
      await client.close();
    }
  });

  it('never passes the notice hook to another mechanism', async () => {
    const deps = fakeDeps({});
    const client = createClient('h', { username: 'u', password: PASSWORD, auth: 'ntlm', winrm: { onCredSSPDelegation: () => undefined } }, deps);
    try {
      await client.run('hostname');
      assert.equal(deps.winrmOpens[0]?.onCredSSPDelegation, undefined);
    } finally {
      await client.close();
    }
  });
});

describe('CLI options: credssp', () => {
  const target = { target: { host: 'server.example.test', username: 'u' }, profile: {} };
  const creds = { useTicketCache: false };

  it('-a credssp is the only way in; --credssp-allow-http needs it', () => {
    const opts = buildConnectOptions({ auth: 'credssp', 'credssp-allow-http': true } as never, target, creds, PASSWORD);
    assert.equal(opts.auth, 'credssp');
    assert.equal(opts.winrm?.credsspAllowHttp, true);
    assert.equal(buildConnectOptions({ auth: 'credssp' } as never, target, creds, PASSWORD).winrm?.credsspAllowHttp, undefined);
    assert.throws(() => buildConnectOptions({ 'credssp-allow-http': true } as never, target, creds, PASSWORD), /--credssp-allow-http applies to -a credssp only/);
    assert.equal(buildConnectOptions({} as never, target, creds, PASSWORD).auth, 'negotiate');
  });

  it('a profile cannot select credssp, and has no CredSSPAllowHTTP key', () => {
    assert.throws(() => parseConfig('Host a\n  Auth credssp\n', '/tmp/config'), /Auth must be one of negotiate, ntlm, kerberos, basic, certificate, got credssp \(CredSSP delegates your password, so a profile cannot select it; use -a credssp per command\)/);
    assert.throws(() => parseConfig('Host a\n  CredSSPAllowHTTP yes\n', '/tmp/config'), /CredSSPAllowHTTP/);
  });

  it('the notice is one stderr line naming the host, for credssp only', () => {
    assert.equal(credsspNotice('server.example.test'), 'winlinux: CredSSP: your password is delegated to server.example.test\n');
    const lines: string[] = [];
    const stderr = { write: (s: string) => lines.push(s) } as unknown as NodeJS.WritableStream;
    const opts = withCredsspNotice({ username: 'u', auth: 'credssp', winrm: { tls: true } }, { stderr });
    assert.equal(opts.winrm?.tls, true, 'other WinRM options stay');
    opts.winrm?.onCredSSPDelegation?.('server.example.test');
    assert.deepEqual(lines, ['winlinux: CredSSP: your password is delegated to server.example.test\n']);
    const ntlm = withCredsspNotice({ username: 'u', auth: 'ntlm' }, { stderr });
    assert.equal(ntlm.winrm?.onCredSSPDelegation, undefined);
  });

  it('help lists credssp and the HTTP flag with the risk', () => {
    assert.match(HELP, /-a, --auth <negotiate\|ntlm\|kerberos\|basic\|credssp\|certificate>/);
    assert.match(HELP, /--credssp-allow-http/);
    assert.match(HELP, /sends your password to the server/);
  });
});
