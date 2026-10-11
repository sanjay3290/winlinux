// The live WinRM scenarios. Each one is a named
// node:test test. run-live.ts registers them against a real Windows server
// with the @winlinux/auth providers; test/live-harness.test.ts registers the
// same functions against the fake Windows server so the harness itself is
// tested offline inside `npm test`.
import assert from 'node:assert/strict';
import { it } from 'node:test';
import { connect, type WinRMSession } from '../../src/winrm/index.js';
import { WinRMProtocolError } from '../../src/winrm/errors.js';
import type { AuthProvider, Mechanism, SecurityContext } from '../../src/auth-provider.js';
import { kerberosProblems, type LiveConfig } from './config.js';

export interface LiveDeps {
  providerFor(mechanism: Mechanism): AuthProvider;
  log(message: string): void;
  // How long the abort scenario waits for the server to drop the shell.
  shellGoneTimeoutMs?: number;
}

export interface Scenario {
  name: string;
  timeoutMs: number;
  // Env beyond the required variables: run-live reports the scenario
  // as env incomplete when kerberosProblems(cfg) is not empty.
  needs?: 'kerberos';
  run(cfg: LiveConfig, deps: LiveDeps): Promise<void>;
}

interface Transport {
  tls: boolean;
  mechanism: Mechanism;
}

async function withSession<T>(
  cfg: LiveConfig,
  deps: LiveDeps,
  t: Transport,
  fn: (s: WinRMSession) => Promise<T>,
  provider?: AuthProvider,
): Promise<T> {
  const session = await connect({
    host: cfg.host,
    port: t.tls ? cfg.httpsPort : cfg.httpPort,
    tls: t.tls,
    tlsVerify: cfg.tlsVerify,
    authProvider: provider ?? deps.providerFor(t.mechanism),
    credentials: cfg.credentials,
  });
  try {
    return await fn(session);
  } finally {
    await session.close();
  }
}

function general(cfg: LiveConfig): Transport {
  return { tls: cfg.tls, mechanism: cfg.mechanism };
}

// Wraps a provider and counts wrap()/unwrap() on its contexts. The counts
// prove from the client side that every SOAP body was sealed.
export class SealCounter implements AuthProvider {
  wraps = 0;
  unwraps = 0;
  constructor(private readonly inner: AuthProvider) {}

  get mechanism(): Mechanism {
    return this.inner.mechanism;
  }

  createContext(...args: Parameters<AuthProvider['createContext']>): SecurityContext {
    const ctx = this.inner.createContext(...args);
    const counted: SecurityContext = {
      step: (token) => ctx.step(token),
      get complete() {
        return ctx.complete;
      },
      get negotiatedMechanism() {
        return ctx.negotiatedMechanism;
      },
      get sessionKey() {
        return ctx.sessionKey;
      },
    };
    if (ctx.wrap && ctx.unwrap) {
      const wrap = ctx.wrap.bind(ctx);
      const unwrap = ctx.unwrap.bind(ctx);
      counted.wrap = async (plaintext) => {
        this.wraps += 1;
        return wrap(plaintext);
      };
      counted.unwrap = async (ciphertext) => {
        this.unwraps += 1;
        return unwrap(ciphertext);
      };
    }
    if (ctx.dispose) counted.dispose = ctx.dispose.bind(ctx);
    return counted;
  }
}

// Shell IDs the server lists for this account. Get-WSManInstance is the
// primary check. If the loopback WSMan call is refused inside a
// remote session, the script falls back to winrshost.exe process IDs
// (one per cmd shell). The lines are joined with newlines, never `; `:
// PowerShell rejects `}; catch` ("The Try statement is missing its Catch
// or Finally block"), and -EncodedCommand carries newlines.
export const LIST_SHELLS_SCRIPT = [
  "$ErrorActionPreference = 'Stop'",
  'try { $ids = @(Get-WSManInstance -ResourceURI shell -Enumerate | ForEach-Object { [string]$_.ShellId }); $m = \'wsman\' }',
  "catch { $ids = @(Get-CimInstance Win32_Process -Filter \"Name='winrshost.exe'\" | ForEach-Object { [string]$_.ProcessId }); $m = 'winrshost' }",
  'ConvertTo-Json -Compress -InputObject @{ method = $m; ids = $ids }',
].join('\n');

interface ShellList {
  method: string;
  ids: string[];
}

async function listShells(session: WinRMSession): Promise<ShellList> {
  const r = await session.runPowerShell(LIST_SHELLS_SCRIPT);
  assert.equal(r.exitCode, 0, `shell listing failed: ${r.stderr || r.stdout}`);
  const parsed = JSON.parse(r.stdout.trim()) as { method?: unknown; ids?: unknown };
  const ids = parsed.ids === null || parsed.ids === undefined ? [] : Array.isArray(parsed.ids) ? parsed.ids : [parsed.ids];
  return { method: String(parsed.method), ids: ids.map(String) };
}

export const STREAM_LINES = 100_000;
export const STREAM_SCRIPT = `1..${STREAM_LINES} | ForEach-Object { 'line{0:D7}' -f $_ }`;
export const streamLine = (i: number): string => `line${String(i).padStart(7, '0')}`;
export const PS_OUT_MARKER = 'winlinux-live-out';
export const PS_ERR_MARKER = 'winlinux-live-err';
export const PS_SCRIPT = `Write-Output '${PS_OUT_MARKER}'; Write-Error '${PS_ERR_MARKER}'`;
export const LONG_COMMAND = { cmd: 'ping', args: ['-n', '120', '127.0.0.1'] };
// The cmd.exe line of the exit-code scenario: output first, then exit 7.
export const EXIT_COMMAND_LINE = 'echo x& exit 7';

export const SCENARIOS: Scenario[] = [
  {
    name: 'HTTPS + Basic: run hostname returns the host name with exit code 0',
    timeoutMs: 60_000,
    run: (cfg, deps) =>
      withSession(cfg, deps, { tls: true, mechanism: 'basic' }, async (s) => {
        const r = await s.runCommand('hostname');
        assert.equal(r.exitCode, 0);
        const name = r.stdout.trim();
        assert.match(name, /^[A-Za-z0-9-]{1,63}$/, `hostname output: ${JSON.stringify(r.stdout)}`);
        const env = await s.runCommand('cmd', ['/c', 'echo %COMPUTERNAME%']);
        assert.equal(name.toUpperCase(), env.stdout.trim().toUpperCase());
        deps.log(`hostname = ${name}`);
      }),
  },
  {
    // The command writes a line before it exits. WinRS can report exit
    // code 0 for a process that exits at once with no output (about
    // 1 run in 10 with `cmd /c exit 7` on Windows Server 2022, with
    // pywinrm too), so a silent instant exit would test the server's
    // race and not the client's exit-code handling.
    name: 'HTTPS + NTLM: a non-zero exit code is reported exactly (cmd /c "echo x& exit 7" -> x, 7)',
    timeoutMs: 60_000,
    run: (cfg, deps) =>
      withSession(cfg, deps, { tls: true, mechanism: 'ntlm' }, async (s) => {
        const r = await s.runCommand('cmd', ['/c', EXIT_COMMAND_LINE]);
        assert.equal(r.stdout.trim(), 'x', `stdout: ${JSON.stringify(r.stdout)}`);
        assert.equal(r.exitCode, 7);
      }),
  },
  {
    name: 'HTTP + NTLM: message encryption works and every SOAP body is sealed',
    timeoutMs: 60_000,
    run: async (cfg, deps) => {
      const counter = new SealCounter(deps.providerFor('ntlm'));
      const out = await withSession(cfg, deps, { tls: false, mechanism: 'ntlm' }, (s) => s.runCommand('hostname'), counter);
      assert.equal(out.exitCode, 0);
      assert.ok(out.stdout.trim().length > 0, 'hostname printed nothing');
      // Create, Command, Receive, Signal, Delete: five requests, five replies.
      assert.ok(counter.wraps >= 5, `expected >= 5 sealed requests, saw ${counter.wraps}`);
      assert.ok(counter.unwraps >= 5, `expected >= 5 sealed responses, saw ${counter.unwraps}`);
      deps.log(`sealed requests = ${counter.wraps}, sealed responses = ${counter.unwraps}`);
    },
  },
  {
    // With the gss_wrap_iov split (@winlinux/krb-session-key) the command runs
    // over plain HTTP with every body sealed, Length-Field 60. A provider
    // without the split (the `kerberos` package fallback) is still refused
    // before any wrap(), with an error that names the addon and HTTPS.
    name: 'HTTP + Kerberos: message encryption with the gss_wrap_iov split, or a refusal that names @winlinux/krb-session-key',
    timeoutMs: 60_000,
    needs: 'kerberos',
    run: async (cfg, deps) => {
      let result: Awaited<ReturnType<WinRMSession['runCommand']>>;
      try {
        result = await withSession(cfg, deps, { tls: false, mechanism: 'kerberos' }, (s) => s.runCommand('hostname'));
      } catch (err) {
        if (err instanceof WinRMProtocolError && /krb-session-key/.test(err.message) && /HTTPS/.test(err.message)) {
          deps.log('Kerberos over HTTP refused: this SecurityContext has no gss_wrap_iov split');
          return;
        }
        throw err;
      }
      assert.equal(result.exitCode, 0);
      assert.match(result.stdout.trim(), /^[A-Za-z0-9-]{1,63}$/, `hostname output: ${JSON.stringify(result.stdout)}`);
      deps.log(`Kerberos over HTTP: hostname = ${result.stdout.trim()}`);
    },
  },
  {
    name: 'Streaming: more than 1 MB of output arrives complete and in order',
    timeoutMs: 300_000,
    run: (cfg, deps) =>
      withSession(cfg, deps, general(cfg), async (s) => {
        let stdout = '';
        let stderr = '';
        let chunks = 0;
        for await (const chunk of s.runPowerShellStream(STREAM_SCRIPT)) {
          chunks += 1;
          if (chunk.stream === 'stdout') stdout += chunk.data;
          else stderr += chunk.data;
        }
        assert.ok(Buffer.byteLength(stdout) > 1024 * 1024, `only ${Buffer.byteLength(stdout)} bytes of stdout`);
        assert.ok(chunks > 1, 'expected the output in more than one chunk');
        assert.equal(stderr, '');
        const lines = stdout.split(/\r?\n/);
        if (lines[lines.length - 1] === '') lines.pop();
        assert.equal(lines.length, STREAM_LINES);
        for (let i = 0; i < STREAM_LINES; i += 1) {
          if (lines[i] !== streamLine(i + 1)) assert.fail(`line ${i + 1} is ${JSON.stringify(lines[i])}`);
        }
        deps.log(`streamed ${Buffer.byteLength(stdout)} bytes in ${chunks} chunks`);
      }),
  },
  {
    name: 'PowerShell: a script returns CLIXML-parsed output and errors',
    timeoutMs: 60_000,
    run: (cfg, deps) =>
      withSession(cfg, deps, general(cfg), async (s) => {
        const r = await s.runPowerShell(PS_SCRIPT);
        assert.equal(r.stdout.trim(), PS_OUT_MARKER);
        assert.ok(!r.stderr.startsWith('#< CLIXML'), `stderr is still CLIXML: ${r.stderr.slice(0, 80)}`);
        assert.ok(r.stderr.includes(PS_ERR_MARKER), `stderr lacks the error: ${r.stderr}`);
      }),
  },
  {
    name: 'Event log: read the last 10 System events',
    timeoutMs: 120_000,
    run: (cfg, deps) =>
      withSession(cfg, deps, general(cfg), async (s) => {
        const events = await s.readEventLog({ logName: 'System', maxEvents: 10 });
        assert.equal(events.length, 10);
        let previous = Infinity;
        for (const e of events) {
          assert.ok(Number.isInteger(e.id) && e.id >= 0, `bad event id ${e.id}`);
          assert.ok(e.provider.length > 0, 'event without a provider');
          const time = Date.parse(e.timeCreated);
          assert.ok(!Number.isNaN(time), `bad timeCreated ${e.timeCreated}`);
          assert.ok(time <= previous, 'events are not newest first');
          previous = time;
        }
        deps.log(`newest System event: ${events[0]?.provider} ${events[0]?.id} at ${events[0]?.timeCreated}`);
      }),
  },
  {
    name: 'Abort: breaking out of a long command leaves no orphan shell',
    timeoutMs: 120_000,
    run: (cfg, deps) =>
      withSession(cfg, deps, general(cfg), async (s) => {
        const before = await listShells(s);
        const started = Date.now();
        for await (const chunk of s.runCommandStream(LONG_COMMAND.cmd, LONG_COMMAND.args)) {
          if (chunk.stream === 'stdout' && chunk.data.length > 0) break;
        }
        const elapsed = Date.now() - started;
        assert.ok(elapsed < 60_000, `abort took ${elapsed} ms; the command did not stop early`);
        // The listing's own shell is new in every listing, so one new ID is
        // expected. Two or more means the aborted shell survived.
        const deadline = Date.now() + (deps.shellGoneTimeoutMs ?? 15_000);
        for (;;) {
          const after = await listShells(s);
          assert.equal(after.method, before.method, 'shell listing method changed between calls');
          const fresh = after.ids.filter((id) => !before.ids.includes(id));
          if (fresh.length <= 1) {
            deps.log(`no orphan shell (checked with ${after.method}); abort took ${elapsed} ms`);
            return;
          }
          if (Date.now() > deadline) assert.fail(`orphan shell(s) after abort (${after.method}): ${fresh.join(', ')}`);
          await new Promise((resolve) => setTimeout(resolve, 1000));
        }
      }),
  },
];

export interface ScenarioSplit {
  runnable: Scenario[];
  incomplete: Array<{ scenario: Scenario; problems: string[] }>;
}

// The scenarios the env can run, and the ones it cannot with why.
export function splitScenarios(cfg: LiveConfig, scenarios: Scenario[] = SCENARIOS): ScenarioSplit {
  const split: ScenarioSplit = { runnable: [], incomplete: [] };
  for (const scenario of scenarios) {
    const problems = scenario.needs === 'kerberos' ? kerberosProblems(cfg) : [];
    if (problems.length === 0) split.runnable.push(scenario);
    else split.incomplete.push({ scenario, problems });
  }
  return split;
}

export function registerLiveTests(cfg: LiveConfig, deps: LiveDeps, scenarios: Scenario[] = SCENARIOS): void {
  for (const scenario of scenarios) {
    it(scenario.name, { timeout: scenario.timeoutMs }, () => scenario.run(cfg, deps));
  }
}
