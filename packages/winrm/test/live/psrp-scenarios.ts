// The PSRP live scenarios: the same functions
// run against the fake PSRP endpoint inside `npm test`
// (test/psrp-live-harness.test.ts) and against a real Windows Server by
// run-live-psrp.ts (`npm run test:live:psrp`).
import assert from 'node:assert/strict';
import { it } from 'node:test';
import { connect, openRunspacePool, type PSConnectOptions, type PSStreamEvent, type PsrpTraceEvent, type RunspacePool } from '../../src/winrm/index.js';
import { isPSObject } from '../../src/winrm/psrp/clixml.js';
import { PSRemotingError } from '../../src/winrm/errors.js';
import type { AuthProvider, Mechanism } from '../../src/auth-provider.js';
import { kerberosProblems, type LiveConfig } from './config.js';
import { LIST_SHELLS_SCRIPT } from './scenarios.js';

export interface PsrpLiveDeps {
  providerFor(mechanism: Mechanism): AuthProvider;
  log(message: string): void;
  trace?: (event: PsrpTraceEvent) => void;
}

export interface PsrpScenario {
  name: string;
  timeoutMs: number;
  needs?: 'kerberos';
  // True for a scenario that pins its own transport instead of using the
  // general one: the live gate (gate.ts) runs the general scenarios over
  // every transport of its matrix and skips these, which that covers.
  pinned?: boolean;
  run(cfg: LiveConfig, deps: PsrpLiveDeps): Promise<void>;
}

interface Transport {
  tls: boolean;
  mechanism: Mechanism;
}

function poolOptions(cfg: LiveConfig, deps: PsrpLiveDeps, t: Transport): PSConnectOptions {
  return {
    host: cfg.host,
    port: t.tls ? cfg.httpsPort : cfg.httpPort,
    tls: t.tls,
    tlsVerify: cfg.tlsVerify,
    authProvider: deps.providerFor(t.mechanism),
    credentials: cfg.credentials,
    ...(deps.trace ? { trace: deps.trace } : {}),
  };
}

async function withPool<T>(cfg: LiveConfig, deps: PsrpLiveDeps, t: Transport, fn: (pool: RunspacePool) => Promise<T>): Promise<T> {
  const pool = await openRunspacePool(poolOptions(cfg, deps, t));
  try {
    return await fn(pool);
  } finally {
    await pool.close();
  }
}

async function shellIds(cfg: LiveConfig, deps: PsrpLiveDeps, t: Transport): Promise<string[]> {
  const session = await connect({ host: cfg.host, port: t.tls ? cfg.httpsPort : cfg.httpPort, tls: t.tls, tlsVerify: cfg.tlsVerify, authProvider: deps.providerFor(t.mechanism), credentials: cfg.credentials });
  try {
    const r = await session.runPowerShell(LIST_SHELLS_SCRIPT);
    assert.equal(r.exitCode, 0, `shell listing failed: ${r.stderr || r.stdout}`);
    const parsed = JSON.parse(r.stdout.trim()) as { ids?: unknown };
    const ids = parsed.ids === null || parsed.ids === undefined ? [] : Array.isArray(parsed.ids) ? parsed.ids : [parsed.ids];
    return ids.map((id) => String(id).toUpperCase());
  } finally {
    await session.close();
  }
}

const general = (cfg: LiveConfig): Transport => ({ tls: cfg.tls, mechanism: cfg.mechanism });

export const BIG_OUTPUT_BYTES = 5 * 1024 * 1024;

export const PSRP_SCENARIOS: PsrpScenario[] = [
  {
    name: 'PSRP: open and close leave no shell, and the server speaks 2.2 or newer',
    timeoutMs: 120_000,
    run: async (cfg, deps) => {
      const t = general(cfg);
      let shellId = '';
      await withPool(cfg, deps, t, async (pool) => {
        shellId = pool.shellId.toUpperCase();
        deps.log(`server protocolversion = ${pool.serverProtocolVersion}`);
        assert.match(pool.serverProtocolVersion, /^2\.(2|3)(\.|$)/);
        const during = await shellIds(cfg, deps, t);
        assert.ok(during.includes(shellId), `the pool ${shellId} is listed while open: ${during.join(',')}`);
      });
      const after = await shellIds(cfg, deps, t);
      assert.ok(!after.includes(shellId), `the pool ${shellId} is gone after close: ${after.join(',')}`);
    },
  },
  {
    name: 'PSRP: state persists in one pool ($x = 1, then $x), and objects carry type names',
    timeoutMs: 120_000,
    run: (cfg, deps) =>
      withPool(cfg, deps, general(cfg), async (pool) => {
        await pool.invoke('$x = 41').result();
        const second = await pool.invoke('$x').result();
        assert.equal(second.state, 'Completed');
        assert.deepEqual(second.output, [41]);
        const processes = await pool.invoke('Get-Process | Select-Object -First 3').result();
        assert.equal(processes.state, 'Completed', processes.reason instanceof Error ? processes.reason.message : String(processes.reason?.message));
        assert.equal(processes.output.length, 3);
        for (const p of processes.output) {
          assert.ok(isPSObject(p), 'a PSObject');
          assert.ok(p.typeNames.includes('System.Diagnostics.Process'), p.typeNames.join(','));
          assert.ok(p.adapted.has('Id') || p.extended.has('Id'), 'an Id property');
        }
      }),
  },
  {
    name: 'PSRP: error, warning, verbose, debug and information records arrive on their streams',
    timeoutMs: 120_000,
    run: (cfg, deps) =>
      withPool(cfg, deps, general(cfg), async (pool) => {
        const events: PSStreamEvent[] = [];
        const pipeline = pool.invoke("Write-Output 'out'; Write-Error 'err'; Write-Warning 'warn'; Write-Verbose 'verb' -Verbose; Write-Debug 'dbg' -Debug; Write-Information 'info'");
        for await (const e of pipeline) events.push(e);
        const result = await pipeline.result();
        assert.equal(result.state, 'Completed');
        assert.deepEqual(result.output, ['out']);
        const byStream = (s: string) => events.filter((e) => e.stream === s);
        assert.equal((byStream('error')[0] as { record: { message: string } } | undefined)?.record.message, 'err');
        assert.equal((byStream('warning')[0] as { message: string } | undefined)?.message, 'warn');
        assert.equal((byStream('verbose')[0] as { message: string } | undefined)?.message, 'verb');
        assert.equal((byStream('debug')[0] as { message: string } | undefined)?.message, 'dbg');
        if (pool.serverProtocolVersion.startsWith('2.3')) {
          const info = byStream('information')[0] as { record: { messageData: unknown } } | undefined;
          assert.ok(info, 'an information record on a 2.3 server');
        }
      }),
  },
  {
    name: 'PSRP: 5 MB of output arrives complete across Receives',
    timeoutMs: 300_000,
    run: (cfg, deps) =>
      withPool(cfg, deps, general(cfg), async (pool) => {
        const result = await pool.invoke(`'x' * ${BIG_OUTPUT_BYTES}`).result();
        assert.equal(result.state, 'Completed');
        assert.equal(result.output.length, 1);
        const value = result.output[0];
        assert.equal(typeof value, 'string');
        assert.equal((value as string).length, BIG_OUTPUT_BYTES);
        const lines = await pool.invoke('1..2000 | ForEach-Object { "line$_" }').result();
        assert.deepEqual(lines.output, Array.from({ length: 2000 }, (_, i) => `line${i + 1}`));
      }),
  },
  {
    name: 'PSRP: stop() ends Start-Sleep 60 within 2 s, the pool survives and $x is still set',
    timeoutMs: 120_000,
    run: (cfg, deps) =>
      withPool(cfg, deps, general(cfg), async (pool) => {
        await pool.invoke('$x = 7').result();
        const pipeline = pool.invoke('Start-Sleep 60');
        await new Promise((r) => setTimeout(r, 500));
        const started = Date.now();
        await pipeline.stop();
        const took = Date.now() - started;
        deps.log(`stop took ${took} ms`);
        assert.ok(took < 2000, `stop took ${took} ms`);
        assert.equal(pipeline.state, 'Stopped');
        assert.equal(pool.state, 'Opened');
        assert.deepEqual((await pool.invoke('$x').result()).output, [7]);
      }),
  },
  {
    name: 'PSRP: Read-Host with no host fails fast with an error record, exit state Failed',
    timeoutMs: 120_000,
    run: (cfg, deps) =>
      withPool(cfg, deps, general(cfg), async (pool) => {
        const started = Date.now();
        const result = await pool.invoke('Read-Host x').result();
        assert.ok(Date.now() - started < 5000, 'no hang');
        assert.equal(result.state, 'Failed');
        assert.ok(result.reason, 'a reason');
        assert.ok(!(result.reason instanceof PSRemotingError), 'the server refused it, not the client');
      }),
  },
  {
    name: 'PSRP: Out-String -Stream returns formatted lines',
    timeoutMs: 120_000,
    run: (cfg, deps) =>
      withPool(cfg, deps, general(cfg), async (pool) => {
        const result = await pool.invoke('Get-Process | Select-Object -First 2', { outString: { width: 120 } }).result();
        assert.equal(result.state, 'Completed');
        assert.ok(result.output.length >= 2);
        assert.ok(result.output.every((line) => typeof line === 'string'), 'every output is a string line');
      }),
  },
  {
    name: 'PSRP: HTTP + NTLM seals every body',
    timeoutMs: 120_000,
    pinned: true,
    run: (cfg, deps) =>
      withPool(cfg, deps, { tls: false, mechanism: 'ntlm' }, async (pool) => {
        assert.deepEqual((await pool.invoke("'sealed'").result()).output, ['sealed']);
      }),
  },
  {
    name: 'PSRP: HTTPS + Basic runs a pipeline',
    timeoutMs: 120_000,
    pinned: true,
    run: (cfg, deps) =>
      withPool(cfg, deps, { tls: true, mechanism: 'basic' }, async (pool) => {
        assert.deepEqual((await pool.invoke("'basic'").result()).output, ['basic']);
      }),
  },
  {
    name: 'PSRP: HTTP + Kerberos runs a pipeline (needs @winlinux/krb-session-key)',
    timeoutMs: 120_000,
    needs: 'kerberos',
    pinned: true,
    run: (cfg, deps) =>
      withPool(cfg, deps, { tls: false, mechanism: 'kerberos' }, async (pool) => {
        assert.deepEqual((await pool.invoke("'kerberos'").result()).output, ['kerberos']);
      }),
  },
];

export interface PsrpScenarioSplit {
  runnable: PsrpScenario[];
  incomplete: Array<{ scenario: PsrpScenario; problems: string[] }>;
}

export function splitPsrpScenarios(cfg: LiveConfig, scenarios: PsrpScenario[] = PSRP_SCENARIOS): PsrpScenarioSplit {
  const split: PsrpScenarioSplit = { runnable: [], incomplete: [] };
  for (const scenario of scenarios) {
    const problems = scenario.needs === 'kerberos' ? kerberosProblems(cfg) : [];
    if (problems.length === 0) split.runnable.push(scenario);
    else split.incomplete.push({ scenario, problems });
  }
  return split;
}

export function registerPsrpLiveTests(cfg: LiveConfig, deps: PsrpLiveDeps, scenarios: PsrpScenario[] = PSRP_SCENARIOS): void {
  for (const scenario of scenarios) {
    it(scenario.name, { timeout: scenario.timeoutMs }, () => scenario.run(cfg, deps));
  }
}
