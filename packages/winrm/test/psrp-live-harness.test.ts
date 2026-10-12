// The PSRP live scenarios against the fake PSRP endpoint, inside
// `npm test`, so a harness bug fails here before the maintainer's live run.
// NTLM and Kerberos use the scripted stub contexts; Basic the real provider.
import { after, before, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createAuthProvider } from '@winlinux/auth';
import type { AuthProvider, Mechanism } from '../src/auth-provider.js';
import type { LiveConfig } from './live/config.js';
import { PSRP_SCENARIOS, registerPsrpLiveTests, splitPsrpScenarios, type PsrpLiveDeps, type PsrpScenario } from './live/psrp-scenarios.js';
import { createRecorder } from './live/psrp-recorder.js';
import { startFakePsrp, type FakePsrp, type FakePsrpOptions } from './helpers/fake-psrp.js';
import { kerberosStub, ntlmStub } from './helpers/stub-auth.js';

const USER = 'winlinux';
const PASS = 'Live-Test-1';

const deps: PsrpLiveDeps = {
  providerFor: (mechanism: Mechanism): AuthProvider => (mechanism === 'ntlm' ? ntlmStub({ seal: true }) : mechanism === 'kerberos' ? kerberosStub() : createAuthProvider(mechanism)),
  log: () => undefined,
};

function baseConfig(general: { tls: boolean; mechanism: Mechanism }): LiveConfig {
  return { host: '127.0.0.1', httpPort: 0, httpsPort: 0, tlsVerify: false, credentials: { username: USER, password: PASS }, ...general };
}

function scenario(prefix: string): PsrpScenario {
  const found = PSRP_SCENARIOS.find((s) => s.name.startsWith(prefix));
  if (!found) throw new Error(`no scenario starts with ${prefix}`);
  return found;
}

async function startPair(faults?: FakePsrpOptions['faults'], extra: Partial<FakePsrpOptions> = {}): Promise<{ http: FakePsrp; https: FakePsrp }> {
  const http = await startFakePsrp({ tls: false, username: USER, password: PASS, faults, ...extra });
  const https = await startFakePsrp({ tls: true, username: USER, password: PASS, faults, ...extra });
  return { http, https };
}

for (const general of [
  { tls: false, mechanism: 'ntlm' as const },
  { tls: true, mechanism: 'basic' as const },
]) {
  describe(`PSRP live scenarios against the fake endpoint (general = ${general.tls ? 'HTTPS' : 'HTTP'}+${general.mechanism})`, () => {
    const cfg = baseConfig(general);
    let servers: { http: FakePsrp; https: FakePsrp };
    before(async () => {
      servers = await startPair();
      cfg.httpPort = servers.http.port;
      cfg.httpsPort = servers.https.port;
    });
    after(async () => {
      await servers.http.close();
      await servers.https.close();
      assert.deepEqual(servers.http.openShells(), [], 'no shell left on the HTTP fake');
      assert.deepEqual(servers.https.openShells(), [], 'no shell left on the HTTPS fake');
    });
    // The Kerberos scenario runs against the fake with the stub context,
    // which needs no realm: the split is for the live env only.
    registerPsrpLiveTests(cfg, deps, PSRP_SCENARIOS);
  });
}

describe('the PSRP scenarios catch what they check', () => {
  it('a 2.1 server fails the open scenario with the version message', async () => {
    const servers = await startPair(undefined, { protocolVersion: '2.1' });
    const cfg = baseConfig({ tls: false, mechanism: 'ntlm' });
    cfg.httpPort = servers.http.port;
    cfg.httpsPort = servers.https.port;
    try {
      await assert.rejects(scenario('PSRP: open and close').run(cfg, deps), /needs 2.2 or newer/);
    } finally {
      await servers.http.close();
      await servers.https.close();
    }
  });

  it('a server that keeps the shell after Delete fails the open scenario', async () => {
    const servers = await startPair({ ignoreDelete: true });
    const cfg = baseConfig({ tls: false, mechanism: 'ntlm' });
    cfg.httpPort = servers.http.port;
    cfg.httpsPort = servers.https.port;
    try {
      await assert.rejects(scenario('PSRP: open and close').run(cfg, deps), /is gone after close/);
    } finally {
      await servers.http.close();
      await servers.https.close();
    }
  });

  it('a server that drops a ReceiveResponse fails the 5 MB scenario', async () => {
    const servers = await startPair({ dropReceive: true });
    const cfg = baseConfig({ tls: false, mechanism: 'ntlm' });
    cfg.httpPort = servers.http.port;
    cfg.httpsPort = servers.https.port;
    try {
      await assert.rejects(scenario('PSRP: 5 MB').run(cfg, deps));
    } finally {
      await servers.http.close();
      await servers.https.close();
    }
  });

  it('the env split reports the Kerberos scenario as incomplete without a realm', () => {
    const { runnable, incomplete } = splitPsrpScenarios(baseConfig({ tls: false, mechanism: 'ntlm' }));
    assert.equal(incomplete.length, 1);
    assert.match(incomplete[0]?.scenario.name ?? '', /Kerberos/);
    assert.equal(runnable.length, PSRP_SCENARIOS.length - 1);
  });
});

describe('the fixture recorder', () => {
  it('writes every request, response and message of a pool, redacted', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'winlinux-psrp-record-'));
    const server = await startFakePsrp({ tls: false, username: USER, password: PASS });
    const cfg = baseConfig({ tls: false, mechanism: 'ntlm' });
    cfg.httpPort = server.port;
    cfg.httpsPort = server.port;
    try {
      const recorder = createRecorder(dir, 'harness', { host: 'fakeps01', user: USER });
      await scenario('PSRP: error, warning').run(cfg, { ...deps, trace: (e) => recorder.trace(e) });
      const files = readdirSync(dir).sort();
      assert.ok(files.some((f) => f.endsWith('-request.xml')));
      assert.ok(files.some((f) => f.endsWith('-response.xml')));
      assert.ok(files.some((f) => f.endsWith('-out-SESSION_CAPABILITY.xml')));
      assert.ok(files.some((f) => f.endsWith('-out-CREATE_PIPELINE.xml')));
      assert.ok(files.some((f) => f.endsWith('-in-PIPELINE_OUTPUT.xml')));
      assert.ok(files.some((f) => f.endsWith('-in-PIPELINE_STATE.xml')));
      const all = files.map((f) => readFileSync(join(dir, f), 'utf8')).join('\n');
      assert.ok(!all.toLowerCase().includes('fakeps01'), 'the host name is redacted');
      assert.ok(!all.includes(`\\${USER}`) && !/N="User">[^<]*winlinux/.test(all), 'the user name is redacted');
      assert.ok(all.includes('<host>') || all.includes('<user>'), 'sentinels are written');
    } finally {
      await server.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
