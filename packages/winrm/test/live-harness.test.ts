// Offline test of the live WinRM runner. The same
// scenario functions that run against a real Windows Server run here
// against the fake Windows endpoint, so a harness bug fails `npm test`.
// NTLM and Kerberos use the scripted stub contexts (the real NTLM crypto
// is covered by @winlinux/auth's vectors and the pywinrm golden; the real
// Kerberos gss_wrap_iov split by the local-KDC suites, `npm run test:kdc`);
// Basic uses the real @winlinux/auth provider.
import { after, before, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync, type SpawnSyncReturns } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createAuthProvider } from '@winlinux/auth';
import type { AuthProvider, Mechanism } from '../src/auth-provider.js';
import { kerberosProblems, krb5Conf, liveConfigFromEnv, type LiveConfig } from './live/config.js';
import { EXIT_COMMAND_LINE, registerLiveTests, SCENARIOS, splitScenarios, type LiveDeps, type Scenario } from './live/scenarios.js';
import { connect } from '../src/winrm/index.js';
import { startFakeWindows, type FakeWindows, type FakeWindowsOptions } from './helpers/fake-windows.js';
import { kerberosStub, ntlmStub } from './helpers/stub-auth.js';

const USER = 'winlinux';
const PASS = 'Live-Test-1';

const deps: LiveDeps = {
  providerFor: (mechanism: Mechanism): AuthProvider =>
    mechanism === 'ntlm' ? ntlmStub({ seal: true }) : mechanism === 'kerberos' ? kerberosStub() : createAuthProvider(mechanism),
  log: () => undefined,
};

function baseConfig(general: { tls: boolean; mechanism: Mechanism }): LiveConfig {
  return {
    host: '127.0.0.1',
    httpPort: 0,
    httpsPort: 0,
    tlsVerify: false,
    credentials: { username: USER, password: PASS },
    ...general,
  };
}

function scenario(prefix: string): Scenario {
  const found = SCENARIOS.find((s) => s.name.startsWith(prefix));
  if (!found) throw new Error(`no scenario starts with ${prefix}`);
  return found;
}

async function startPair(faults?: FakeWindowsOptions['faults']): Promise<{ http: FakeWindows; https: FakeWindows }> {
  const http = await startFakeWindows({ tls: false, username: USER, password: PASS, faults });
  const https = await startFakeWindows({ tls: true, username: USER, password: PASS, faults });
  return { http, https };
}

for (const general of [
  { tls: true, mechanism: 'ntlm' as const },
  { tls: false, mechanism: 'ntlm' as const },
]) {
  describe(`live scenarios against the fake Windows server (general = ${general.tls ? 'HTTPS' : 'HTTP'}+NTLM)`, () => {
    const cfg = baseConfig(general);
    let servers: { http: FakeWindows; https: FakeWindows };

    before(async () => {
      servers = await startPair();
      cfg.httpPort = servers.http.port;
      cfg.httpsPort = servers.https.port;
    });
    after(async () => {
      await servers.http.close();
      await servers.https.close();
    });

    registerLiveTests(cfg, deps);

    it('left no shell open and sent no plain SOAP over HTTP', () => {
      assert.deepEqual(servers.http.openShells(), []);
      assert.deepEqual(servers.https.openShells(), []);
      assert.equal(servers.http.plainSoapRequests, 0);
      assert.ok(servers.http.sealedRequests >= 5);
    });

    it('never re-sent a completed AUTHENTICATE token on an authenticated connection', () => {
      // The fake refuses a stale token with 401 like Windows; the exit-code
      // and streaming scenarios above passed on connections that
      // authenticated once and then sent no Authorization header.
      assert.ok(servers.http.handshakes >= 1);
      assert.ok(servers.https.handshakes >= 1);
      assert.equal(servers.http.staleTokens, 0);
      assert.equal(servers.https.staleTokens, 0);
    });

    it('sent NTLM bare, so the fake accepted every sealed body', () => {
      // The NTLM stub frames its tokens in SPNEGO like the real provider;
      // the fake refuses a sealed body on a connection that authenticated
      // that way, as Windows does, and it refused none.
      assert.equal(servers.http.spnegoSealsRefused, 0);
      assert.ok(servers.http.sealedRequests >= 5);
    });
  });
}

describe('live scenarios catch a misbehaving server', () => {
  async function runAgainst(faults: FakeWindowsOptions['faults'], prefix: string, extra?: Partial<LiveDeps>): Promise<void> {
    const servers = await startPair(faults);
    const cfg = baseConfig({ tls: true, mechanism: 'ntlm' });
    cfg.httpPort = servers.http.port;
    cfg.httpsPort = servers.https.port;
    try {
      await scenario(prefix).run(cfg, { ...deps, ...extra });
    } finally {
      await servers.http.close();
      await servers.https.close();
    }
  }

  it('fails the exit-code scenario when the exit code is lost', async () => {
    await assert.rejects(runAgainst({ exitCodeAlwaysZero: true }, 'HTTPS + NTLM'), assert.AssertionError);
  });

  // WinRS can report 0 for a process that exits at once with no
  // output. The scenario's command writes a line first, so it passes on a
  // server with that race, where a silent `cmd /c exit 7` reads 0.
  it('passes the exit-code scenario on a server that reports 0 for a silent instant exit', async () => {
    await runAgainst({ silentExitReportsZero: true }, 'HTTPS + NTLM');
    const servers = await startPair({ silentExitReportsZero: true });
    const cfg = baseConfig({ tls: true, mechanism: 'ntlm' });
    cfg.httpsPort = servers.https.port;
    try {
      const session = await connect({
        host: cfg.host,
        port: cfg.httpsPort,
        tls: true,
        tlsVerify: false,
        authProvider: deps.providerFor('ntlm'),
        credentials: cfg.credentials,
      });
      try {
        const silent = await session.runCommand('cmd', ['/c', 'exit 7']);
        assert.equal(silent.exitCode, 0, 'the fake models the race for a silent exit');
        const loud = await session.runCommand('cmd', ['/c', EXIT_COMMAND_LINE]);
        assert.equal(loud.stdout.trim(), 'x');
        assert.equal(loud.exitCode, 7);
      } finally {
        await session.close();
      }
    } finally {
      await servers.http.close();
      await servers.https.close();
    }
  });

  it('fails the streaming scenario when a chunk is dropped', async () => {
    await assert.rejects(runAgainst({ dropStreamChunk: true }, 'Streaming'), assert.AssertionError);
  });

  it('fails the abort scenario when the aborted shell survives', async () => {
    await assert.rejects(
      runAgainst({ ignoreDelete: true }, 'Abort', { shellGoneTimeoutMs: 0 }),
      /orphan shell/,
    );
  });

  it('fails the Basic scenario when the password is wrong', async () => {
    const servers = await startPair();
    const cfg = baseConfig({ tls: true, mechanism: 'ntlm' });
    cfg.httpPort = servers.http.port;
    cfg.httpsPort = servers.https.port;
    cfg.credentials = { username: USER, password: 'wrong' };
    try {
      await assert.rejects(scenario('HTTPS + Basic').run(cfg, deps), /credentials were rejected/);
    } finally {
      await servers.http.close();
      await servers.https.close();
    }
  });
});

describe('live runner configuration', () => {
  it('lists every missing required variable', () => {
    const r = liveConfigFromEnv({});
    assert.equal(r.ok, false);
    if (r.ok) return;
    assert.deepEqual(r.problems, ['WINRM_HOST is not set', 'WINRM_USER is not set', 'WINRM_PASS is not set']);
  });

  it('applies defaults and maps WINRM_PORT to the listener WINRM_TLS selects', () => {
    const base = { WINRM_HOST: 'win', WINRM_USER: 'u', WINRM_PASS: 'p' };
    const d = liveConfigFromEnv(base);
    assert.ok(d.ok);
    if (!d.ok) return;
    assert.deepEqual(d.config, {
      host: 'win',
      httpPort: 5985,
      httpsPort: 5986,
      tlsVerify: true,
      credentials: { username: 'u', password: 'p' },
      tls: true,
      mechanism: 'ntlm',
    });
    const http = liveConfigFromEnv({ ...base, WINRM_TLS: '0', WINRM_PORT: '15985', WINRM_DOMAIN: 'LAB', WINRM_TLS_VERIFY: '0' });
    assert.ok(http.ok);
    if (!http.ok) return;
    assert.equal(http.config.httpPort, 15985);
    assert.equal(http.config.httpsPort, 5986);
    assert.equal(http.config.tlsVerify, false);
    assert.equal(http.config.credentials.domain, 'LAB');
  });

  it('rejects a bad mechanism, flag or port', () => {
    const r = liveConfigFromEnv({
      WINRM_HOST: 'win',
      WINRM_USER: 'u',
      WINRM_PASS: 'p',
      WINRM_MECHANISM: 'digest',
      WINRM_TLS: 'yes',
      WINRM_PORT: '99999',
    });
    assert.equal(r.ok, false);
    if (r.ok) return;
    assert.equal(r.problems.length, 3);
  });

  it('takes the Kerberos realm from WINRM_REALM, or WINRM_DOMAIN upper-cased, and a KDC from WINRM_KDC', () => {
    const base = { WINRM_HOST: 'win', WINRM_USER: 'u', WINRM_PASS: 'p' };
    const none = liveConfigFromEnv(base);
    assert.ok(none.ok);
    if (!none.ok) return;
    assert.equal(none.config.credentials.realm, undefined);
    assert.equal(none.config.kdc, undefined);
    assert.equal(kerberosProblems(none.config).length, 1);
    assert.match(kerberosProblems(none.config)[0] ?? '', /WINRM_REALM.*WINRM_KDC.*krb5\.conf/);

    const realm = liveConfigFromEnv({ ...base, WINRM_REALM: 'LAB.EXAMPLE', WINRM_KDC: 'dc1.lab.example' });
    assert.ok(realm.ok);
    if (!realm.ok) return;
    assert.equal(realm.config.credentials.realm, 'LAB.EXAMPLE');
    assert.equal(realm.config.credentials.domain, undefined);
    assert.equal(realm.config.kdc, 'dc1.lab.example');
    assert.deepEqual(kerberosProblems(realm.config), []);

    const domain = liveConfigFromEnv({ ...base, WINRM_DOMAIN: 'lab' });
    assert.ok(domain.ok);
    if (!domain.ok) return;
    assert.equal(domain.config.credentials.domain, 'lab');
    assert.equal(domain.config.credentials.realm, 'LAB');
    assert.deepEqual(kerberosProblems(domain.config), []);

    const both = liveConfigFromEnv({ ...base, WINRM_DOMAIN: 'lab', WINRM_REALM: 'LAB.EXAMPLE' });
    assert.ok(both.ok);
    if (both.ok) assert.equal(both.config.credentials.realm, 'LAB.EXAMPLE');

    const kdcOnly = liveConfigFromEnv({ ...base, WINRM_KDC: 'dc1' });
    assert.equal(kdcOnly.ok, false);
    if (!kdcOnly.ok) assert.deepEqual(kdcOnly.problems, ['WINRM_KDC needs WINRM_REALM (or WINRM_DOMAIN)']);
  });

  it('krb5Conf names the realm, its KDC and the target host', () => {
    const conf = krb5Conf('LAB.EXAMPLE', 'dc1.lab.example', 'Win1.lab.example');
    assert.match(conf, /^\[libdefaults\]\n {4}default_realm = LAB\.EXAMPLE\n/);
    assert.match(conf, /\[realms\]\n {4}LAB\.EXAMPLE = \{\n {8}kdc = dc1\.lab\.example\n {4}\}\n/);
    assert.match(conf, /\[domain_realm\]\n {4}win1\.lab\.example = LAB\.EXAMPLE\n {4}\.lab\.example = LAB\.EXAMPLE\n$/);
    // An IP address maps itself only.
    assert.match(krb5Conf('LAB', '10.0.0.5', '10.0.0.7'), /\[domain_realm\]\n {4}10\.0\.0\.7 = LAB\n$/);
  });

  it('splits off the Kerberos scenario as env incomplete without a realm, and runs it with one', () => {
    const cfg = baseConfig({ tls: true, mechanism: 'ntlm' });
    const without = splitScenarios(cfg);
    assert.equal(without.runnable.length, SCENARIOS.length - 1);
    assert.equal(without.incomplete.length, 1);
    assert.equal(without.incomplete[0]?.scenario, scenario('HTTP + Kerberos'));
    assert.match(without.incomplete[0]?.problems[0] ?? '', /WINRM_REALM/);
    const withRealm = splitScenarios({ ...cfg, credentials: { ...cfg.credentials, realm: 'LAB' } });
    assert.deepEqual(withRealm.runnable, SCENARIOS);
    assert.deepEqual(withRealm.incomplete, []);
  });

  function runLive(vars: Record<string, string>, nodeArgs: string[] = []): SpawnSyncReturns<string> {
    const env: NodeJS.ProcessEnv = {};
    for (const [k, v] of Object.entries(process.env)) if (!k.startsWith('WINRM_')) env[k] = v;
    Object.assign(env, vars);
    const script = fileURLToPath(new URL('./live/run-live.js', import.meta.url));
    return spawnSync(process.execPath, [...nodeArgs, script], { env, encoding: 'utf8' });
  }

  it('run-live exits 2 and names what it needs when WINRM_HOST is missing', () => {
    const r = runLive({});
    assert.equal(r.status, 2, r.stderr);
    assert.match(r.stderr, /WINRM_HOST is not set/);
    assert.match(r.stderr, /README\.md/);
  });

  // The other scenarios are filtered out with --test-skip-pattern so the
  // run touches no host; only the runner's env-incomplete path is on trial.
  it('run-live reports the Kerberos scenario as env incomplete and exits 2 without a realm', () => {
    const r = runLive({ WINRM_HOST: 'nowhere.invalid', WINRM_USER: 'u', WINRM_PASS: 'p' }, ['--test-skip-pattern=.']);
    assert.equal(r.status, 2, r.stderr);
    assert.match(r.stdout, /# env incomplete: HTTP \+ Kerberos/);
    assert.match(r.stdout, /WINRM_REALM \(or WINRM_DOMAIN\) is not set.*KDC/);
    assert.match(r.stdout, /realm=- kdc=-/);
    assert.match(r.stderr, /env incomplete for 1 scenario/);
    assert.doesNotMatch(r.stdout, /HTTP \+ Kerberos.*\n.*not ok/);
  });

  it('run-live with WINRM_REALM and WINRM_KDC registers the Kerberos scenario and writes a krb5.conf', () => {
    const r = runLive(
      { WINRM_HOST: 'nowhere.invalid', WINRM_USER: 'u', WINRM_PASS: 'p', WINRM_REALM: 'LAB.EXAMPLE', WINRM_KDC: 'dc1.lab.example' },
      ['--test-skip-pattern=.'],
    );
    assert.equal(r.status, 0, r.stderr);
    assert.doesNotMatch(r.stdout, /env incomplete/);
    assert.match(r.stdout, /realm=LAB\.EXAMPLE kdc=dc1\.lab\.example/);
    const file = /KRB5_CONFIG=(\S+)/.exec(r.stdout)?.[1];
    assert.ok(file, r.stdout);
    assert.equal(readFileSync(file, 'utf8'), krb5Conf('LAB.EXAMPLE', 'dc1.lab.example', 'nowhere.invalid'));
  });
});
