// The live gate: the maintainer's checks for PSRP (the PSRP scenarios over
// four transports) and HTTPS sign-in (Kerberos and Negotiate over HTTPS,
// CbtHardeningLevel Strict), run against every target of a list, with
// redacted PSRP fixtures and one Markdown table per target. Pure over its
// inputs where it can be: the target list comes from parseTargets, the
// checks run through gateTarget with injected providers, and
// renderMarkdown prints. run-live-gate.ts is the entry.
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { connect, openRunspacePool, type PSConnectOptions, type PsrpTraceEvent } from '../../src/winrm/index.js';
import { isPSObject, type PSObject, type PSValue } from '../../src/winrm/psrp/clixml.js';
import type { AuthProvider, Credentials, Mechanism, SecurityContext } from '../../src/auth-provider.js';
import { kerberosProblems, type LiveConfig } from './config.js';
import { PSRP_SCENARIOS, type PsrpLiveDeps, type PsrpScenario } from './psrp-scenarios.js';
import { createRecorder, type Recorder } from './psrp-recorder.js';
import { denyList, redactText, SENTINELS, type RedactNames } from './redact.js';

// --- targets ---

export interface GateTarget {
  // The maintainer's label for the server; it is printed, the host name is not.
  name: string;
  host: string;
  httpPort: number;
  httpsPort: number;
  tlsVerify: boolean;
  credentials: Credentials;
  kdc?: string;
  // Why the target cannot run at all (no password in the env): every
  // check of such a target is reported "not run".
  problems: string[];
}

export interface TargetFileEntry {
  name: string;
  host: string;
  user: string;
  // The env var that holds the password (default WINRM_PASS). The file
  // never holds a password.
  passwordEnv?: string;
  domain?: string;
  realm?: string;
  kdc?: string;
  httpPort?: number;
  httpsPort?: number;
  tlsVerify?: boolean;
}

const FILE_KEYS = new Set(['name', 'host', 'user', 'passwordEnv', 'domain', 'realm', 'kdc', 'httpPort', 'httpsPort', 'tlsVerify']);
export const DEFAULT_TARGETS_FILE = 'live-targets.json';
export const DEFAULT_PASSWORD_ENV = 'WINRM_PASS';

export const TARGETS_HELP = [
  'The live gate needs one or more Windows Server targets. Either:',
  '  - the WINRM_* variables of the live runners (WINRM_HOST, WINRM_USER, WINRM_PASS, and the',
  '    optional WINRM_DOMAIN, WINRM_REALM, WINRM_KDC, WINRM_PORT, WINRM_TLS, WINRM_TLS_VERIFY), or',
  `  - a target file (default ./${DEFAULT_TARGETS_FILE}, git-ignored; WINLINUX_LIVE_TARGETS=<path> names another):`,
  '    {"targets": [{"name": "ws2022", "host": "<host>", "user": "<user>", "passwordEnv": "WINRM_PASS_WS2022",',
  '                  "domain": "", "realm": "", "kdc": "", "httpPort": 5985, "httpsPort": 5986, "tlsVerify": false}]}',
  '    Passwords come only from the env var each entry names (default WINRM_PASS); a "password" key is refused.',
  'See docs/live-gate.md for the runbook.',
].join('\n');

function port(value: unknown, name: string, fallback: number, problems: string[]): number {
  if (value === undefined) return fallback;
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 1 || value > 65535) {
    problems.push(`${name} must be a TCP port, got ${JSON.stringify(value)}`);
    return fallback;
  }
  return value;
}

// The target list of a target file, with the passwords read from the env.
// A malformed file is an error (ok false); a target whose password env
// var is empty is kept with a problem, so it is reported as not run.
export function parseTargets(json: unknown, env: NodeJS.ProcessEnv): { ok: true; targets: GateTarget[] } | { ok: false; problems: string[] } {
  const problems: string[] = [];
  const root = typeof json === 'object' && json !== null ? (json as Record<string, unknown>) : null;
  const list = root?.['targets'];
  if (!Array.isArray(list) || list.length === 0) return { ok: false, problems: ['the target file needs a non-empty "targets" array'] };
  const targets: GateTarget[] = [];
  const names = new Set<string>();
  list.forEach((raw, index) => {
    const entry = typeof raw === 'object' && raw !== null ? (raw as Record<string, unknown>) : {};
    const label = typeof entry['name'] === 'string' && entry['name'] ? (entry['name'] as string) : `targets[${index}]`;
    for (const key of Object.keys(entry)) {
      if (key === 'password' || key === 'pass') problems.push(`${label}: a password never goes in the target file; name the env var in "passwordEnv"`);
      else if (!FILE_KEYS.has(key)) problems.push(`${label}: unknown key "${key}"`);
    }
    for (const key of ['name', 'host', 'user'] as const) {
      if (typeof entry[key] !== 'string' || !(entry[key] as string)) problems.push(`${label}: "${key}" is required`);
    }
    if (names.has(label)) problems.push(`${label}: the name is used twice`);
    names.add(label);
    if (!/^[A-Za-z0-9._-]+$/.test(label)) problems.push(`${label}: the name may hold letters, digits, ".", "_" and "-" only (it names the fixture directory)`);
    for (const key of ['passwordEnv', 'domain', 'realm', 'kdc'] as const) {
      if (entry[key] !== undefined && typeof entry[key] !== 'string') problems.push(`${label}: "${key}" must be a string`);
    }
    if (entry['tlsVerify'] !== undefined && typeof entry['tlsVerify'] !== 'boolean') problems.push(`${label}: "tlsVerify" must be true or false`);
    const httpPort = port(entry['httpPort'], `${label}: "httpPort"`, 5985, problems);
    const httpsPort = port(entry['httpsPort'], `${label}: "httpsPort"`, 5986, problems);
    const passwordEnv = typeof entry['passwordEnv'] === 'string' && entry['passwordEnv'] ? (entry['passwordEnv'] as string) : DEFAULT_PASSWORD_ENV;
    const password = env[passwordEnv];
    const targetProblems: string[] = [];
    if (!password) targetProblems.push(`${passwordEnv} is not set (the password of ${label})`);
    const credentials: Credentials = { username: String(entry['user'] ?? ''), password: password ?? '' };
    const domain = typeof entry['domain'] === 'string' ? entry['domain'] : '';
    if (domain) credentials.domain = domain;
    const realm = (typeof entry['realm'] === 'string' && entry['realm']) || (domain ? domain.toUpperCase() : '');
    if (realm) credentials.realm = realm;
    const kdc = typeof entry['kdc'] === 'string' && entry['kdc'] ? entry['kdc'] : undefined;
    if (kdc && !realm) problems.push(`${label}: "kdc" needs "realm" (or "domain")`);
    targets.push({
      name: label,
      host: String(entry['host'] ?? ''),
      httpPort,
      httpsPort,
      tlsVerify: entry['tlsVerify'] !== false,
      credentials,
      ...(kdc ? { kdc } : {}),
      problems: targetProblems,
    });
  });
  if (problems.length > 0) return { ok: false, problems };
  return { ok: true, targets };
}

// One target from the WINRM_* variables (the live runners' env), named
// after WINRM_HOST's first label.
export function targetFromLiveConfig(cfg: LiveConfig): GateTarget {
  const name = (cfg.host.split('.')[0] || 'target').replace(/[^A-Za-z0-9._-]/g, '-');
  return { name, host: cfg.host, httpPort: cfg.httpPort, httpsPort: cfg.httpsPort, tlsVerify: cfg.tlsVerify, credentials: cfg.credentials, ...(cfg.kdc ? { kdc: cfg.kdc } : {}), problems: [] };
}

// --- checks ---

export interface Transport {
  label: string;
  tls: boolean;
  mechanism: Mechanism;
}

// The PSRP matrix: the four transports the PSRP scenarios run over.
export const PSRP_TRANSPORTS: readonly Transport[] = [
  { label: 'HTTP+NTLM', tls: false, mechanism: 'ntlm' },
  { label: 'HTTP+Kerberos', tls: false, mechanism: 'kerberos' },
  { label: 'HTTPS+Basic', tls: true, mechanism: 'basic' },
  { label: 'HTTPS+NTLM', tls: true, mechanism: 'ntlm' },
];
export const HTTPS_KERBEROS: Transport = { label: 'HTTPS+Kerberos', tls: true, mechanism: 'kerberos' };
export const HTTPS_NEGOTIATE: Transport = { label: 'HTTPS+Negotiate', tls: true, mechanism: 'negotiate' };
export const HTTPS_NTLM: Transport = { label: 'HTTPS+NTLM', tls: true, mechanism: 'ntlm' };

export type CheckOutcome = 'pass' | 'fail' | 'not run';

export interface CheckResult {
  check: string;
  transport: string;
  result: CheckOutcome;
  detail: string;
  ms: number;
}

export interface ServerInfo {
  productName: string;
  displayVersion: string;
  build: string;
  psVersion: string;
  psEdition: string;
  protocolVersion: string;
}

export interface TargetReport {
  target: GateTarget;
  startedAt: string;
  version: string;
  server: ServerInfo | null;
  cbtHardeningLevel: string | null;
  checks: CheckResult[];
  // Redacted fixture files written for this target, and what the deny
  // list found in them (empty when clean).
  fixtureFiles: number;
  fixtureProblems: string[];
  recordDir: string;
  // Names the server reported about itself (its machine name): redacted
  // like the configured names, never printed.
  serverNames: string[];
}

export interface GateDeps {
  providerFor(mechanism: Mechanism): AuthProvider;
  // Progress lines (stderr). The gate never prints a secret; the host,
  // domain and user names go through redaction too.
  log(message: string): void;
  // Where this target's fixtures go (one directory per target).
  recordDir: string;
  version: string;
  now?: () => Date;
  // Test seam: shorter scenario timeouts.
  timeoutScale?: number;
}

// Reads the OS version, the PowerShell version and edition on the server
// as one object. The fake PSRP endpoint answers it by exact match.
export const SERVER_INFO_SCRIPT = [
  "$os = Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion'",
  "[PSCustomObject]@{ ProductName = [string]$os.ProductName; DisplayVersion = [string]$os.DisplayVersion; Build = \"$($os.CurrentBuild).$($os.UBR)\"; PSVersion = $PSVersionTable.PSVersion.ToString(); PSEdition = [string]$PSVersionTable.PSEdition }",
].join('\n');
// `winrm get winrm/config/service/auth` prints `CbtHardeningLevel = <level>`.
export const WINRM_AUTH_CONFIG_COMMAND = { cmd: 'winrm', args: ['get', 'winrm/config/service/auth'] };
export const CBT_LEVEL = /CbtHardeningLevel\s*=\s*(\w+)/i;

const prop = (obj: PSObject, name: string): string => {
  const value = obj.extended.get(name) ?? obj.adapted.get(name) ?? null;
  return value === null ? '' : typeof value === 'string' ? value : isPSObject(value) ? String(value.value ?? value.toStringValue ?? '') : String(value as PSValue);
};

function liveConfigOf(target: GateTarget, t: Transport): LiveConfig {
  return { host: target.host, httpPort: target.httpPort, httpsPort: target.httpsPort, tlsVerify: target.tlsVerify, credentials: target.credentials, tls: t.tls, mechanism: t.mechanism, ...(target.kdc ? { kdc: target.kdc } : {}) };
}

function poolOptions(target: GateTarget, deps: GateDeps, t: Transport, trace?: (e: PsrpTraceEvent) => void, provider?: AuthProvider): PSConnectOptions {
  return { host: target.host, port: t.tls ? target.httpsPort : target.httpPort, tls: t.tls, tlsVerify: target.tlsVerify, authProvider: provider ?? deps.providerFor(t.mechanism), credentials: target.credentials, ...(trace ? { trace } : {}) };
}

// --- identifying names ---

// Labels too common to identify a network; redacting them would mangle
// the table.
const GENERIC_LABELS = new Set(['com', 'net', 'org', 'edu', 'gov', 'local', 'lan', 'internal', 'test', 'example', 'www', SENTINELS.domain]);
const escapeName = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const nameRe = (name: string) => new RegExp(`(?<![A-Za-z0-9-])${escapeName(name)}(?![A-Za-z0-9-])`, 'gi');

// Every name that identifies the target's network beyond the exact host
// string: the host, realm, domain and KDC, each of their DNS labels, and
// the names the server reported (its machine name). An error text (a kinit
// failure naming the realm, a TLS altname list) or a fixture can carry any
// of them. Longest first, so a full name goes before its labels.
export function identifyingNames(target: GateTarget, serverNames: string[] = []): string[] {
  const out = new Set<string>();
  const add = (value: string) => {
    const v = value.trim();
    if (v.length < 3 || /^[\d.:]+$/.test(v) || GENERIC_LABELS.has(v.toLowerCase())) return;
    out.add(v);
  };
  for (const value of [target.host, target.credentials.realm, target.credentials.domain, target.kdc, ...serverNames]) {
    if (!value) continue;
    add(value);
    for (const label of value.split(/[.\\/@]/)) add(label);
  }
  return [...out].sort((a, b) => b.length - a.length);
}

export function redactIdentifying(text: string, names: string[]): string {
  let out = text;
  for (const name of names) out = out.replace(nameRe(name), SENTINELS.host);
  return out;
}

// An HTTPS-Kerberos Negotiate row checks Kerberos: Negotiate falls back to NTLM on any
// client-side Kerberos failure (no KDC, unknown SPN, no ticket), and that
// sign-in proves nothing about Kerberos over HTTPS.
export function negotiateProblem(mechanism: Mechanism, negotiated: Mechanism | undefined): string | null {
  if (mechanism !== 'negotiate' || negotiated === 'kerberos') return null;
  return `Negotiate signed in with ${negotiated ?? 'an unknown mechanism'}, not Kerberos, so this row proves nothing about Kerberos (check the realm, the KDC and the SPN HTTP/<host>)`;
}

// Why a transport cannot run on a target, before any byte goes out: the
// target has no password, Kerberos has no realm, or Kerberos over HTTPS
// has no verified certificate (the transport refuses tlsVerify false).
export function transportProblems(target: GateTarget, t: Transport): string[] {
  const problems = [...target.problems];
  if (t.mechanism === 'kerberos' || t.mechanism === 'negotiate') {
    problems.push(...kerberosProblems(liveConfigOf(target, t)).map((p) => (t.mechanism === 'negotiate' ? `${p}; without a realm Negotiate picks NTLM, which the HTTPS+NTLM rows cover` : p)));
    if (t.tls && !target.tlsVerify) problems.push('tlsVerify is false: Kerberos over HTTPS refuses an unverified certificate (set WINRM_TLS_VERIFY=1 or "tlsVerify": true, and trust the certificate, for example with NODE_EXTRA_CA_CERTS)');
  }
  return problems;
}

const firstLine = (err: unknown): string => {
  const text = err instanceof Error ? `${err.name}: ${err.message}` : String(err);
  return text.split('\n')[0] ?? text;
};

async function withTimeout<T>(ms: number, what: string, fn: () => Promise<T>): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => reject(new Error(`${what} timed out after ${ms} ms`)), ms);
  });
  try {
    return await Promise.race([fn(), timeout]);
  } finally {
    clearTimeout(timer);
  }
}

// Wraps a provider to read the mechanism its last context negotiated.
class NegotiatedCapture implements AuthProvider {
  private last: SecurityContext | null = null;
  constructor(private readonly inner: AuthProvider) {}
  get mechanism(): Mechanism {
    return this.inner.mechanism;
  }
  createContext(...args: Parameters<AuthProvider['createContext']>): SecurityContext {
    this.last = this.inner.createContext(...args);
    return this.last;
  }
  negotiated(): Mechanism | undefined {
    return this.last?.negotiatedMechanism;
  }
}

// Runs one check: pass when fn resolves, fail with the error's first line
// otherwise. `logs` collects the detail lines fn reports.
async function check(name: string, transport: string, timeoutMs: number, fn: (log: (m: string) => void) => Promise<void>): Promise<CheckResult> {
  const logs: string[] = [];
  const started = Date.now();
  try {
    await withTimeout(timeoutMs, name, () => fn((m) => logs.push(m)));
    return { check: name, transport, result: 'pass', detail: logs.join('; '), ms: Date.now() - started };
  } catch (err) {
    return { check: name, transport, result: 'fail', detail: [...logs, firstLine(err)].join('; '), ms: Date.now() - started };
  }
}

const notRun = (name: string, transport: string, problems: string[]): CheckResult => ({ check: name, transport, result: 'not run', detail: problems.join('; '), ms: 0 });

export const PSRP_PREFIX = '[PSRP]';
export const HTTPS_KERBEROS_PREFIX = '[HTTPS-Kerberos]';
const SERVER_INFO_CHECK = 'server info (OS build, PowerShell, PSRP protocolversion)';
const CBT_CHECK = `${HTTPS_KERBEROS_PREFIX} HTTPS + NTLM with CbtHardeningLevel Strict (channel binding enforced)`;
export const FIXTURES_CHECK = 'PSRP fixtures recorded and redacted (deny list)';

// The scenarios the matrix runs over every transport: the general ones.
export const matrixScenarios = (scenarios: PsrpScenario[] = PSRP_SCENARIOS): PsrpScenario[] => scenarios.filter((s) => !s.pinned);

// The deny list of a target: the patterns, the target's own names, and
// its password.
function fixtureDenyList(target: GateTarget, serverNames: string[]): Array<{ name: string; test: (text: string) => boolean }> {
  const list = denyList({ WINRM_HOST: target.host, WINRM_DOMAIN: target.credentials.domain, WINRM_USER: target.credentials.username });
  for (const name of identifyingNames(target, serverNames)) list.push({ name: 'a host, realm, domain, KDC or machine name of the target', test: (t) => nameRe(name).test(t) });
  const password = target.credentials.password;
  if (password) list.push({ name: 'the password', test: (t) => t.includes(password) });
  return list;
}

function walk(dir: string): string[] {
  let names: string[];
  try {
    names = readdirSync(dir);
  } catch {
    return [];
  }
  const out: string[] = [];
  for (const name of names) {
    const file = join(dir, name);
    if (statSync(file).isDirectory()) out.push(...walk(file));
    else out.push(file);
  }
  return out;
}

export async function gateTarget(target: GateTarget, deps: GateDeps, scenarios: PsrpScenario[] = PSRP_SCENARIOS): Promise<TargetReport> {
  const scale = deps.timeoutScale ?? 1;
  const report: TargetReport = {
    target,
    startedAt: (deps.now?.() ?? new Date()).toISOString(),
    version: deps.version,
    server: null,
    cbtHardeningLevel: null,
    checks: [],
    fixtureFiles: 0,
    fixtureProblems: [],
    recordDir: deps.recordDir,
    serverNames: [],
  };
  const names: RedactNames = { host: target.host, domain: target.credentials.domain, user: target.credentials.username };
  const recorders: Recorder[] = [];
  const recorderFor = (label: string): Recorder | undefined => {
    if (target.problems.length > 0) return undefined;
    const r = createRecorder(deps.recordDir, label, names);
    recorders.push(r);
    return r;
  };
  const psrpDeps = (recorder: Recorder | undefined, log: (m: string) => void): PsrpLiveDeps => ({ providerFor: (m) => deps.providerFor(m), log, ...(recorder ? { trace: (e) => recorder.trace(e) } : {}) });

  // 1. Server info, over the first transport that can run.
  const infoTransport = [HTTPS_NTLM, PSRP_TRANSPORTS[0] as Transport, PSRP_TRANSPORTS[2] as Transport].find((t) => transportProblems(target, t).length === 0);
  if (!infoTransport) report.checks.push(notRun(SERVER_INFO_CHECK, '-', target.problems));
  else {
    const recorder = recorderFor('info');
    report.checks.push(
      await check(SERVER_INFO_CHECK, infoTransport.label, 120_000 * scale, async (log) => {
        const pool = await openRunspacePool(poolOptions(target, deps, infoTransport, recorder ? (e) => recorder.trace(e) : undefined));
        try {
          const result = await pool.invoke(SERVER_INFO_SCRIPT).result();
          if (result.state !== 'Completed') throw new Error(`the server info pipeline ${result.state}: ${result.reason instanceof Error ? result.reason.message : (result.reason?.message ?? '')}`);
          const obj = result.output.find(isPSObject);
          if (!obj) throw new Error('the server info pipeline returned no object');
          report.server = { productName: prop(obj, 'ProductName'), displayVersion: prop(obj, 'DisplayVersion'), build: prop(obj, 'Build'), psVersion: prop(obj, 'PSVersion'), psEdition: prop(obj, 'PSEdition'), protocolVersion: pool.serverProtocolVersion };
          log(`${report.server.productName} ${report.server.displayVersion} build ${report.server.build}; PowerShell ${report.server.psVersion} (${report.server.psEdition}); PSRP protocolversion ${report.server.protocolVersion}`);
        } finally {
          await pool.close();
        }
      }),
    );
  }

  // 2. CbtHardeningLevel over HTTPS + NTLM: the server enforces the
  // channel binding only at Strict, so the row passes only then.
  const cbtProblems = transportProblems(target, HTTPS_NTLM);
  if (cbtProblems.length > 0) report.checks.push(notRun(CBT_CHECK, HTTPS_NTLM.label, cbtProblems));
  else {
    const row = await check(CBT_CHECK, HTTPS_NTLM.label, 60_000 * scale, async (log) => {
      const session = await connect({ host: target.host, port: target.httpsPort, tls: true, tlsVerify: target.tlsVerify, authProvider: deps.providerFor('ntlm'), credentials: target.credentials });
      try {
        const r = await session.runCommand(WINRM_AUTH_CONFIG_COMMAND.cmd, WINRM_AUTH_CONFIG_COMMAND.args);
        const level = CBT_LEVEL.exec(r.stdout)?.[1];
        if (!level) throw new Error(`could not read CbtHardeningLevel (exit ${r.exitCode}): ${(r.stderr || r.stdout).trim().split('\n')[0] ?? ''}`);
        report.cbtHardeningLevel = level;
        log(`CbtHardeningLevel = ${level}`);
      } finally {
        await session.close();
      }
    });
    if (row.result === 'pass' && report.cbtHardeningLevel?.toLowerCase() !== 'strict') {
      row.result = 'not run';
      row.detail = `${row.detail}; the server does not enforce channel binding: set CbtHardeningLevel to Strict (winrm set winrm/config/service/auth '@{CbtHardeningLevel="Strict"}') and run again`;
    }
    report.checks.push(row);
  }

  // 3. PSRP: the general PSRP scenarios over each transport of the matrix.
  for (const t of PSRP_TRANSPORTS) {
    const problems = transportProblems(target, t);
    const recorder = problems.length === 0 ? recorderFor(t.label.toLowerCase().replace('+', '-')) : undefined;
    const cfg = liveConfigOf(target, t);
    for (const scenario of matrixScenarios(scenarios)) {
      const name = `${PSRP_PREFIX} ${scenario.name}`;
      if (problems.length > 0) {
        report.checks.push(notRun(name, t.label, problems));
        continue;
      }
      deps.log(`${target.name}: ${t.label}: ${scenario.name}`);
      report.checks.push(await check(name, t.label, scenario.timeoutMs * scale, (log) => scenario.run(cfg, psrpDeps(recorder, log))));
    }
  }

  // 4. HTTPS-Kerberos: Kerberos and Negotiate over HTTPS, WinRS and PSRP.
  for (const t of [HTTPS_KERBEROS, HTTPS_NEGOTIATE]) {
    const problems = transportProblems(target, t);
    const winrs = `${HTTPS_KERBEROS_PREFIX} ${t.label.replace('+', ' + ')}: run hostname over WinRS (channel binding in the first token)`;
    const psrp = `${HTTPS_KERBEROS_PREFIX} ${t.label.replace('+', ' + ')}: run a PSRP pipeline`;
    if (problems.length > 0) {
      report.checks.push(notRun(winrs, t.label, problems), notRun(psrp, t.label, problems));
      continue;
    }
    deps.log(`${target.name}: ${t.label}: hostname and a pipeline`);
    report.checks.push(
      await check(winrs, t.label, 60_000 * scale, async (log) => {
        const provider = new NegotiatedCapture(deps.providerFor(t.mechanism));
        const session = await connect({ host: target.host, port: target.httpsPort, tls: true, tlsVerify: target.tlsVerify, authProvider: provider, credentials: target.credentials });
        try {
          const r = await session.runCommand('hostname');
          if (r.exitCode !== 0 || !/^[A-Za-z0-9-]{1,63}$/.test(r.stdout.trim())) throw new Error(`hostname exited ${r.exitCode}: ${JSON.stringify((r.stderr || r.stdout).trim())}`);
          // The machine name identifies the server: it is redacted, not printed.
          if (!report.serverNames.includes(r.stdout.trim())) report.serverNames.push(r.stdout.trim());
          const problem = negotiateProblem(t.mechanism, provider.negotiated());
          if (problem) throw new Error(problem);
          log(`hostname read${provider.negotiated() ? `; negotiated ${provider.negotiated()}` : ''}`);
        } finally {
          await session.close();
        }
      }),
    );
    const recorder = recorderFor(t.label.toLowerCase().replace('+', '-'));
    report.checks.push(
      await check(psrp, t.label, 120_000 * scale, async (log) => {
        const provider = new NegotiatedCapture(deps.providerFor(t.mechanism));
        const pool = await openRunspacePool(poolOptions(target, deps, t, recorder ? (e) => recorder.trace(e) : undefined, provider));
        try {
          const result = await pool.invoke(`'${t.mechanism}'`).result();
          if (result.state !== 'Completed' || result.output.length !== 1 || result.output[0] !== t.mechanism) throw new Error(`the pipeline ${result.state} with ${JSON.stringify(result.output)}`);
          const problem = negotiateProblem(t.mechanism, provider.negotiated());
          if (problem) throw new Error(problem);
          log(`protocolversion ${pool.serverProtocolVersion}${provider.negotiated() ? `; negotiated ${provider.negotiated()}` : ''}`);
        } finally {
          await pool.close();
        }
      }),
    );
  }

  // 5. The fixtures, checked against the deny list before anything prints.
  const files = walk(deps.recordDir);
  report.fixtureFiles = files.length;
  const deny = fixtureDenyList(target, report.serverNames);
  for (const file of files) {
    const text = readFileSync(file, 'utf8');
    for (const entry of deny) if (entry.test(text)) report.fixtureProblems.push(`${file.slice(deps.recordDir.length + 1)} contains ${entry.name}`);
  }
  if (target.problems.length > 0) report.checks.push(notRun(FIXTURES_CHECK, '-', target.problems));
  else if (report.fixtureProblems.length > 0) report.checks.push({ check: FIXTURES_CHECK, transport: '-', result: 'fail', detail: `${report.fixtureProblems.length} file(s) match the deny list; do not commit them: ${report.fixtureProblems.slice(0, 3).join('; ')}`, ms: 0 });
  else report.checks.push({ check: FIXTURES_CHECK, transport: '-', result: 'pass', detail: `${files.length} files, deny list clean`, ms: 0 });
  return report;
}

// --- output ---

export function counts(checks: CheckResult[]): Record<CheckOutcome, number> {
  const out: Record<CheckOutcome, number> = { pass: 0, fail: 0, 'not run': 0 };
  for (const c of checks) out[c.result] += 1;
  return out;
}

const cell = (text: string) => text.replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');
const seconds = (ms: number) => (ms > 0 ? ` (${(ms / 1000).toFixed(1)} s)` : '');

// One Markdown table per target, redacted: the target's host, realm,
// domain, KDC and machine names (and their DNS labels), its user name and
// its password never appear, whatever the detail text holds.
export function renderMarkdown(report: TargetReport): string {
  const { target } = report;
  const summary = counts(report.checks);
  const perTransport = PSRP_TRANSPORTS.map((t) => {
    const rows = report.checks.filter((c) => c.transport === t.label && c.check.startsWith(PSRP_PREFIX));
    const n = counts(rows);
    return `${t.label} ${n.pass}/${rows.length}${n['not run'] > 0 ? ` (${n['not run']} not run)` : ''}`;
  });
  const server = report.server
    ? `${report.server.productName} ${report.server.displayVersion} build ${report.server.build}; PowerShell ${report.server.psVersion} (${report.server.psEdition}); PSRP protocolversion ${report.server.protocolVersion}`
    : 'not read';
  const lines = [
    `### live:gate: target \`${target.name}\` (\`${SENTINELS.host}\`), ${report.startedAt}, winlinux ${report.version}`,
    '',
    `Server: ${server}; CbtHardeningLevel ${report.cbtHardeningLevel ?? 'not read'}`,
    `Result: ${summary.pass} pass, ${summary.fail} fail, ${summary['not run']} not run. PSRP per transport: ${perTransport.join(', ')}. Fixtures: ${report.fixtureFiles} files, ${report.fixtureProblems.length === 0 ? 'deny list clean' : `${report.fixtureProblems.length} deny-list hits`}.`,
    '',
    '| # | Check | Transport | Result | Detail |',
    '|---|---|---|---|---|',
    ...report.checks.map((c, i) => `| ${i + 1} | ${cell(c.check)} | ${c.transport} | ${c.result === 'fail' ? '**FAIL**' : c.result} | ${cell(c.detail)}${seconds(c.ms)} |`),
    '',
  ];
  let text = lines.join('\n');
  const password = target.credentials.password;
  if (password && password.length >= 2) text = text.split(password).join('<password>');
  text = redactIdentifying(text, identifyingNames(target, report.serverNames));
  return redactText(text, { host: target.host, domain: target.credentials.domain, user: target.credentials.username });
}

// 0 when every check of every target passed, 1 when one failed (or a
// fixture is not redacted), else 2 when one was not run.
export function exitCodeFor(reports: TargetReport[]): number {
  const all = reports.flatMap((r) => r.checks);
  if (reports.length === 0 || all.some((c) => c.result === 'fail')) return 1;
  if (all.some((c) => c.result === 'not run')) return 2;
  return 0;
}
