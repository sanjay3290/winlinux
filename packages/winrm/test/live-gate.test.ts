// The live gate against the fake PSRP endpoint, inside `npm test`:
// the target file format, the checks and their three outcomes, the
// fixture deny-list check, the redacted Markdown, and the exit code. NTLM
// and Kerberos use the stub contexts; Basic the real provider. Kerberos
// over HTTPS needs a verified certificate, so that path runs in a child
// process that trusts the test certificate through NODE_EXTRA_CA_CERTS.
import { after, before, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtempSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { createAuthProvider } from '@winlinux/auth';
import type { AuthProvider, Mechanism } from '../src/auth-provider.js';
import { liveConfigFromEnv } from './live/config.js';
import { counts, exitCodeFor, FIXTURES_CHECK, gateTarget, identifyingNames, matrixScenarios, negotiateProblem, PSRP_TRANSPORTS, parseTargets, renderMarkdown, targetFromLiveConfig, transportProblems, type GateDeps, type GateTarget, type TargetReport } from './live/gate.js';
import { PSRP_SCENARIOS } from './live/psrp-scenarios.js';
import { SENTINELS } from './live/redact.js';
import { FAKE_PSRP_HOSTNAME, FAKE_SERVER_INFO, startFakePsrp, type FakePsrp, type FakePsrpOptions } from './helpers/fake-psrp.js';
import { kerberosStub, ntlmStub } from './helpers/stub-auth.js';

const USER = 'gatetester';
const PASS = 'Gate-Test-Pw-91';
const HOST = '127.0.0.1';
const here = (name: string) => fileURLToPath(new URL(name, import.meta.url));

const providerFor = (mechanism: Mechanism): AuthProvider =>
  mechanism === 'ntlm' ? ntlmStub({ seal: true }) : mechanism === 'kerberos' ? kerberosStub() : mechanism === 'negotiate' ? kerberosStub({ mechanism: 'negotiate' }) : createAuthProvider(mechanism);

// The matrix scenarios minus the long ones, so the suite stays fast; the
// 5 MB and stop scenarios run in psrp-live-harness.test.ts.
const QUICK = PSRP_SCENARIOS.filter((s) => s.pinned || !/5 MB|stop\(\)/.test(s.name));

function target(http: FakePsrp, https: FakePsrp, extra: Partial<GateTarget> = {}): GateTarget {
  return { name: 'fake', host: HOST, httpPort: http.port, httpsPort: https.port, tlsVerify: false, credentials: { username: USER, password: PASS, realm: 'EXAMPLE.TEST' }, problems: [], ...extra };
}

function deps(recordDir: string): GateDeps {
  return { providerFor, log: () => undefined, recordDir, version: '0.0.0-test', now: () => new Date('2026-01-02T03:04:05Z'), timeoutScale: 0.25 };
}

async function startPair(extra: Partial<FakePsrpOptions> = {}): Promise<{ http: FakePsrp; https: FakePsrp }> {
  const http = await startFakePsrp({ tls: false, username: USER, password: PASS, ...extra });
  const https = await startFakePsrp({ tls: true, username: USER, password: PASS, ...extra });
  return { http, https };
}

const rows = (report: TargetReport, transport: string, prefix = '[PSRP]') => report.checks.filter((c) => c.transport === transport && c.check.startsWith(prefix));

describe('live gate: target file', () => {
  const env = { WINRM_PASS: 'from-env', WINRM_PASS_LAB: 'lab-pw' };

  it('reads several targets, passwords from the named env vars, defaults for the rest', () => {
    const parsed = parseTargets({ targets: [{ name: 'a', host: 'a.example.test', user: 'u1' }, { name: 'b', host: 'b.example.test', user: 'u2', passwordEnv: 'WINRM_PASS_LAB', domain: 'lab', kdc: 'dc.example.test', httpPort: 15985, httpsPort: 15986, tlsVerify: false }] }, env);
    assert.ok(parsed.ok, JSON.stringify(parsed));
    const [a, b] = parsed.targets;
    assert.deepEqual(a, { name: 'a', host: 'a.example.test', httpPort: 5985, httpsPort: 5986, tlsVerify: true, credentials: { username: 'u1', password: 'from-env' }, problems: [] });
    assert.deepEqual(b, { name: 'b', host: 'b.example.test', httpPort: 15985, httpsPort: 15986, tlsVerify: false, credentials: { username: 'u2', password: 'lab-pw', domain: 'lab', realm: 'LAB' }, kdc: 'dc.example.test', problems: [] });
  });

  it('a missing password env var keeps the target as not run, never as a pass', () => {
    const parsed = parseTargets({ targets: [{ name: 'c', host: 'c.example.test', user: 'u', passwordEnv: 'WINRM_PASS_MISSING' }] }, env);
    assert.ok(parsed.ok);
    assert.deepEqual(parsed.targets[0]?.problems, ['WINRM_PASS_MISSING is not set (the password of c)']);
  });

  it('refuses a password in the file, unknown keys, duplicates, bad ports and a kdc without a realm', () => {
    const parsed = parseTargets(
      { targets: [{ name: 'x', host: 'h', user: 'u', password: 's3cret' }, { name: 'x', host: 'h', user: 'u', hostname: 'h', httpPort: 70000, kdc: 'dc' }, { host: 'h' }] },
      env,
    );
    assert.ok(!parsed.ok);
    const text = parsed.problems.join('\n');
    assert.match(text, /x: a password never goes in the target file/);
    assert.doesNotMatch(text, /s3cret/);
    assert.match(text, /unknown key "hostname"/);
    assert.match(text, /the name is used twice/);
    assert.match(text, /"httpPort" must be a TCP port/);
    assert.match(text, /"kdc" needs "realm"/);
    assert.match(text, /targets\[2\]: "name" is required/);
    assert.match(text, /targets\[2\]: "user" is required/);
  });

  it('an empty or malformed file is refused', () => {
    assert.ok(!parseTargets({}, env).ok);
    assert.ok(!parseTargets({ targets: [] }, env).ok);
    assert.ok(!parseTargets('x', env).ok);
  });

  it('the WINRM_* env makes one target named after the host', () => {
    const cfg = liveConfigFromEnv({ WINRM_HOST: 'srv01.example.test', WINRM_USER: 'u', WINRM_PASS: 'p', WINRM_TLS_VERIFY: '0', WINRM_REALM: 'EXAMPLE.TEST', WINRM_KDC: 'dc.example.test' });
    assert.ok(cfg.ok);
    const t = targetFromLiveConfig(cfg.config);
    assert.equal(t.name, 'srv01');
    assert.equal(t.tlsVerify, false);
    assert.equal(t.kdc, 'dc.example.test');
    assert.deepEqual(t.problems, []);
  });
});

describe('live gate: what cannot run is not run', () => {
  const base: GateTarget = { name: 't', host: 'h.example.test', httpPort: 5985, httpsPort: 5986, tlsVerify: false, credentials: { username: 'u', password: 'p' }, problems: [] };
  it('Kerberos needs a realm; Kerberos over HTTPS needs tlsVerify; Negotiate says NTLM would be picked', () => {
    assert.deepEqual(transportProblems(base, PSRP_TRANSPORTS[0]!), []);
    assert.match(transportProblems(base, PSRP_TRANSPORTS[1]!).join(), /WINRM_REALM \(or WINRM_DOMAIN\) is not set/);
    const httpsKrb = transportProblems({ ...base, credentials: { ...base.credentials, realm: 'R' } }, { label: 'HTTPS+Kerberos', tls: true, mechanism: 'kerberos' });
    assert.equal(httpsKrb.length, 1);
    assert.match(httpsKrb[0]!, /tlsVerify is false/);
    assert.deepEqual(transportProblems({ ...base, tlsVerify: true, credentials: { ...base.credentials, realm: 'R' } }, { label: 'HTTPS+Kerberos', tls: true, mechanism: 'kerberos' }), []);
    assert.match(transportProblems(base, { label: 'HTTPS+Negotiate', tls: true, mechanism: 'negotiate' }).join(), /Negotiate picks NTLM/);
  });
  it('a target without a password runs nothing', () => {
    const problems = transportProblems({ ...base, problems: ['WINRM_PASS is not set'] }, PSRP_TRANSPORTS[2]!);
    assert.deepEqual(problems, ['WINRM_PASS is not set']);
  });
});

describe('live gate: identifying names never print', () => {
  const t: GateTarget = { name: 'lab', host: 'ws01.corp.contoso.com', httpPort: 5985, httpsPort: 5986, tlsVerify: true, credentials: { username: 'alice', password: 'Pw-12345', domain: 'CORP', realm: 'CORP.CONTOSO.COM' }, kdc: 'dc01.corp.contoso.com', problems: [] };
  const report = (detail: string, serverNames: string[] = []): TargetReport => ({
    target: t,
    startedAt: '2026-01-02T03:04:05.000Z',
    version: 'x',
    server: null,
    cbtHardeningLevel: null,
    checks: [{ check: '[HTTPS-Kerberos] HTTPS + Kerberos: run a PSRP pipeline', transport: 'HTTPS+Kerberos', result: 'fail', detail, ms: 0 }],
    fixtureFiles: 0,
    fixtureProblems: [],
    recordDir: '',
    serverNames,
  });

  it('the realm, the KDC, the DNS labels of the host and the machine name are redacted, also inside error text', () => {
    const markdown = renderMarkdown(
      report('Error: kinit failed: Cannot find KDC for realm "CORP.CONTOSO.COM"; Hostname/IP does not match certificate\'s altnames: DNS:WS01, DNS:ws01.contoso.com; machine LAB-WS01', ['LAB-WS01']),
    );
    for (const leak of ['CONTOSO', 'contoso', 'WS01', 'ws01', 'LAB-WS01', 'dc01', 'CORP']) assert.ok(!markdown.includes(leak), `${leak} leaked: ${markdown}`);
    assert.match(markdown, /Cannot find KDC for realm "<host>"/);
    assert.match(markdown, /machine <host>/);
  });

  it('generic DNS labels and the sentinels stay readable', () => {
    const names = identifyingNames({ ...t, host: 'srv.example.test', credentials: { ...t.credentials, realm: 'EXAMPLE.TEST', domain: '' }, kdc: undefined });
    assert.deepEqual(names, ['srv.example.test', 'srv']);
    const ip = identifyingNames({ ...t, host: '10.1.2.3', credentials: { username: 'u', password: 'p' }, kdc: undefined });
    assert.deepEqual(ip, [], 'an IP address is left to the IPv4 rule');
  });
});

describe('live gate: a Negotiate row must sign in with Kerberos', () => {
  it('a fallback to NTLM, or an unknown mechanism, is a problem; Kerberos and the other mechanisms are not', () => {
    assert.match(negotiateProblem('negotiate', 'ntlm')!, /Negotiate signed in with ntlm, not Kerberos/);
    assert.match(negotiateProblem('negotiate', undefined)!, /an unknown mechanism/);
    assert.equal(negotiateProblem('negotiate', 'kerberos'), null);
    assert.equal(negotiateProblem('kerberos', undefined), null);
    assert.equal(negotiateProblem('ntlm', undefined), null);
  });
});

describe('live gate against the fake PSRP endpoint', { timeout: 120_000 }, () => {
  let servers: { http: FakePsrp; https: FakePsrp };
  let dir: string;
  before(async () => {
    servers = await startPair();
    dir = mkdtempSync(join(tmpdir(), 'winlinux-live-gate-test-'));
  });
  after(async () => {
    await servers.http.close();
    await servers.https.close();
    rmSync(dir, { recursive: true, force: true });
  });

  it('runs the PSRP matrix and the HTTPS-Kerberos rows, records redacted fixtures, and prints a redacted table', async () => {
    const t = target(servers.http, servers.https);
    const recordDir = join(dir, 'pass');
    const report = await gateTarget(t, deps(recordDir), QUICK);
    const quick = matrixScenarios(QUICK).length;
    assert.equal(quick, 5);
    for (const tr of PSRP_TRANSPORTS) {
      const r = rows(report, tr.label);
      assert.equal(r.length, quick, tr.label);
      assert.deepEqual(r.map((c) => c.result), Array(quick).fill('pass'), `${tr.label}: ${JSON.stringify(r)}`);
    }
    assert.deepEqual(report.server, { productName: FAKE_SERVER_INFO.ProductName, displayVersion: FAKE_SERVER_INFO.DisplayVersion, build: FAKE_SERVER_INFO.Build, psVersion: FAKE_SERVER_INFO.PSVersion, psEdition: FAKE_SERVER_INFO.PSEdition, protocolVersion: '2.3' });
    assert.equal(report.cbtHardeningLevel, 'Strict');
    const cbt = report.checks.find((c) => c.check.includes('CbtHardeningLevel'));
    assert.equal(cbt?.result, 'pass', JSON.stringify(cbt));
    // Kerberos over HTTPS cannot run with tlsVerify false: not run, with the reason.
    for (const label of ['HTTPS+Kerberos', 'HTTPS+Negotiate']) {
      const r = rows(report, label, '[HTTPS-Kerberos]');
      assert.equal(r.length, 2, label);
      assert.deepEqual(r.map((c) => c.result), ['not run', 'not run']);
      assert.match(r[0]!.detail, /tlsVerify is false/);
    }
    const fixtures = report.checks.find((c) => c.check === FIXTURES_CHECK);
    assert.equal(fixtures?.result, 'pass', JSON.stringify(fixtures));
    assert.ok(report.fixtureFiles > 20, `${report.fixtureFiles} fixture files`);
    assert.deepEqual(report.fixtureProblems, []);
    const files = readdirSync(recordDir);
    assert.ok(files.some((f) => f.startsWith('http-ntlm-') && f.endsWith('-in-PIPELINE_OUTPUT.xml')), files.join(','));
    assert.ok(files.some((f) => f.startsWith('https-basic-')));
    assert.ok(files.some((f) => f.startsWith('info-')));
    const markdown = renderMarkdown(report);
    assert.ok(markdown.startsWith('### live:gate: target `fake` (`<host>`), 2026-01-02T03:04:05.000Z, winlinux 0.0.0-test\n'), markdown.split('\n')[0]);
    assert.match(markdown, /^Server: Windows Server 2022 Datacenter 21H2 build 20348\.1; PowerShell 5\.1\.20348\.1 \(Desktop\); PSRP protocolversion 2\.3; CbtHardeningLevel Strict$/m);
    assert.match(markdown, /^Result: \d+ pass, 0 fail, 4 not run\. PSRP per transport: HTTP\+NTLM 5\/5, HTTP\+Kerberos 5\/5, HTTPS\+Basic 5\/5, HTTPS\+NTLM 5\/5\. Fixtures: \d+ files, deny list clean\.$/m);
    assert.match(markdown, /^\| 1 \| server info \(OS build, PowerShell, PSRP protocolversion\) \| HTTPS\+NTLM \| pass \| /m);
    assert.match(markdown, /\| HTTP\+Kerberos \| pass \| server protocolversion = 2\.3 \(\d+\.\d s\) \|/);
    assert.match(markdown, /\| HTTPS\+Kerberos \| not run \| tlsVerify is false/);
    assert.ok(!markdown.includes(PASS), 'the password never prints');
    assert.ok(!markdown.includes(HOST), 'the host never prints');
    assert.ok(!markdown.includes(USER), 'the user never prints');
    assert.ok(markdown.includes(SENTINELS.host));
    assert.equal(exitCodeFor([report]), 2, 'not-run rows give exit 2');
    assert.deepEqual(servers.http.openShells(), [], 'no shell left on the HTTP fake');
    assert.deepEqual(servers.https.openShells(), [], 'no shell left on the HTTPS fake');
  });

  it('a target without a password reports every row as not run and exits 2', async () => {
    const t = target(servers.http, servers.https, { problems: ['WINRM_PASS_FAKE is not set (the password of fake)'] });
    const report = await gateTarget(t, deps(join(dir, 'nopw')), QUICK);
    assert.ok(report.checks.length > 20);
    assert.deepEqual([...new Set(report.checks.map((c) => c.result))], ['not run']);
    assert.equal(report.fixtureFiles, 0);
    assert.equal(exitCodeFor([report]), 2);
    assert.match(renderMarkdown(report), /Result: 0 pass, 0 fail, \d+ not run/);
  });

  it('a wrong password fails the rows that sign in, and the exit code is 1', async () => {
    const t = target(servers.http, servers.https, { credentials: { username: USER, password: 'Wrong-Pw-00', realm: 'EXAMPLE.TEST' } });
    const report = await gateTarget(t, deps(join(dir, 'wrongpw')), QUICK);
    const basic = rows(report, 'HTTPS+Basic');
    assert.ok(basic.every((c) => c.result === 'fail'), JSON.stringify(basic));
    assert.match(basic[0]!.detail, /WinRMAuthError/);
    assert.equal(exitCodeFor([report]), 1);
    const markdown = renderMarkdown(report);
    assert.match(markdown, /\| \*\*FAIL\*\* \|/);
    assert.ok(!markdown.includes('Wrong-Pw-00'));
  });

  it('a relaxed server makes the CBT row not run, with the command to fix it', async () => {
    const relaxed = await startPair({ cbtHardeningLevel: 'Relaxed' });
    try {
      const report = await gateTarget(target(relaxed.http, relaxed.https), deps(join(dir, 'relaxed')), QUICK.filter((s) => s.pinned));
      const cbt = report.checks.find((c) => c.check.includes('CbtHardeningLevel'));
      assert.equal(cbt?.result, 'not run');
      assert.match(cbt!.detail, /CbtHardeningLevel = Relaxed; the server does not enforce channel binding: set CbtHardeningLevel to Strict/);
      assert.equal(report.cbtHardeningLevel, 'Relaxed');
    } finally {
      await relaxed.http.close();
      await relaxed.https.close();
    }
  });

  it('a fixture that still holds the host name fails the deny-list row, and nothing is deleted', async () => {
    const recordDir = join(dir, 'leak');
    const t = target(servers.http, servers.https, { host: '127.0.0.1' });
    // A file the gate did not write, as a leaked host name would look.
    const planted = join(recordDir, 'planted-0001-response.xml');
    const { mkdirSync } = await import('node:fs');
    mkdirSync(recordDir, { recursive: true });
    writeFileSync(planted, '<S N="PSComputerName">10.1.2.3</S>');
    const report = await gateTarget(t, deps(recordDir), QUICK.filter((s) => s.pinned));
    const fixtures = report.checks.find((c) => c.check === FIXTURES_CHECK);
    assert.equal(fixtures?.result, 'fail');
    assert.match(fixtures!.detail, /planted-0001-response\.xml contains IPv4 address other than loopback/);
    assert.ok(readdirSync(recordDir).includes('planted-0001-response.xml'), 'the gate deletes nothing');
    assert.equal(exitCodeFor([report]), 1);
  });

  it('a scenario that hangs is reported as a timed-out failure', async () => {
    const t = target(servers.http, servers.https);
    const report = await gateTarget(t, { ...deps(join(dir, 'hang')), timeoutScale: 0.001 }, [{ name: 'PSRP: hangs', timeoutMs: 1000, run: () => new Promise(() => undefined) }]);
    const row = rows(report, 'HTTP+NTLM')[0];
    assert.equal(row?.result, 'fail');
    assert.match(row!.detail, /timed out after 1 ms/);
  });

  it('counts and the exit code', () => {
    assert.deepEqual(counts([{ check: 'a', transport: '', result: 'pass', detail: '', ms: 0 }, { check: 'b', transport: '', result: 'not run', detail: '', ms: 0 }]), { pass: 1, fail: 0, 'not run': 1 });
    assert.equal(exitCodeFor([]), 1, 'no target is a failure');
  });

  // Kerberos and Negotiate over HTTPS: the transport insists on a verified
  // certificate, so a child process trusts the test certificate.
  it('Kerberos and Negotiate over HTTPS pass with a verified certificate (child process with NODE_EXTRA_CA_CERTS)', async () => {
    const script = `
      const [gateJs, stubJs, fakeJs, httpPort, httpsPort, recordDir] = process.argv.slice(1);
      const { gateTarget } = await import(gateJs);
      const { kerberosStub, ntlmStub } = await import(stubJs);
      const { createAuthProvider } = await import('@winlinux/auth');
      const providerFor = (m) => (m === 'ntlm' ? ntlmStub({ seal: true }) : m === 'kerberos' ? kerberosStub() : m === 'negotiate' ? kerberosStub({ mechanism: 'negotiate' }) : createAuthProvider(m));
      const target = { name: 'fake', host: '127.0.0.1', httpPort: Number(httpPort), httpsPort: Number(httpsPort), tlsVerify: true, credentials: { username: ${JSON.stringify(USER)}, password: ${JSON.stringify(PASS)}, realm: 'EXAMPLE.TEST' }, problems: [] };
      const report = await gateTarget(target, { providerFor, log: () => undefined, recordDir, version: 'x', timeoutScale: 0.25 }, []);
      console.log(JSON.stringify(report.checks.filter((c) => c.check.startsWith('[HTTPS-Kerberos]'))));
    `;
    const { stdout } = await promisify(execFile)(
      process.execPath,
      ['--input-type=module', '-e', script, here('./live/gate.js'), here('./helpers/stub-auth.js'), here('./helpers/fake-psrp.js'), String(servers.http.port), String(servers.https.port), join(dir, 'child')],
      { env: { ...process.env, NODE_EXTRA_CA_CERTS: here('./fixtures/tls-test-cert.pem') }, timeout: 60_000, cwd: here('..') },
    );
    const checks = JSON.parse(stdout) as Array<{ check: string; transport: string; result: string; detail: string }>;
    assert.equal(checks.length, 5, JSON.stringify(checks));
    for (const c of checks) assert.equal(c.result, 'pass', JSON.stringify(c));
    assert.match(checks.find((c) => c.transport === 'HTTPS+Kerberos' && /hostname/.test(c.check))!.detail, /^hostname read; negotiated kerberos$/);
    assert.match(checks.find((c) => c.transport === 'HTTPS+Negotiate' && /hostname/.test(c.check))!.detail, /negotiated kerberos/);
    assert.match(checks.find((c) => c.transport === 'HTTPS+Negotiate' && /pipeline/.test(c.check))!.detail, /protocolversion 2\.3; negotiated kerberos/);
    // The server's machine name identifies it: never in a detail.
    for (const c of checks) assert.ok(!c.detail.includes(FAKE_PSRP_HOSTNAME), JSON.stringify(c));
  });
});
