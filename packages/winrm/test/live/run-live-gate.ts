// The live gate entry: npm run live:gate. Targets come from
// live-targets.json (or WINLINUX_LIVE_TARGETS=<path>), else from the
// WINRM_* variables; passwords only from the env. Fixtures go under
// WINLINUX_PSRP_RECORD (or a temp directory), one directory per target,
// and are checked against the deny list before the Markdown prints.
// Exit 0: every check passed; 1: a check failed or a fixture is not
// redacted; 2: a check was not run (a missing password, realm or target).
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { createAuthProvider } from '@winlinux/auth';
import { krb5Conf, liveConfigFromEnv } from './config.js';
import { DEFAULT_TARGETS_FILE, TARGETS_HELP, exitCodeFor, gateTarget, parseTargets, renderMarkdown, targetFromLiveConfig, type GateTarget } from './gate.js';

const env = process.env;
// npm runs the script in packages/winrm; relative paths are the maintainer's,
// from the directory npm was started in (INIT_CWD), usually the repo root.
const fromStart = (path: string) => resolve(env['INIT_CWD'] || process.cwd(), path);
const say = (message: string) => process.stderr.write(`live:gate: ${message}\n`);

function loadTargets(): GateTarget[] {
  const file = fromStart(env['WINLINUX_LIVE_TARGETS'] || DEFAULT_TARGETS_FILE);
  if (env['WINLINUX_LIVE_TARGETS'] || existsSync(file)) {
    let json: unknown;
    try {
      json = JSON.parse(readFileSync(file, 'utf8'));
    } catch (err) {
      // Not the parser's message: on Node 22 it quotes the file, which holds
      // host and user names.
      const reason = err instanceof SyntaxError ? 'it is not valid JSON' : ((err as NodeJS.ErrnoException).code ?? 'unreadable');
      say(`cannot read ${file}: ${reason}\n\n${TARGETS_HELP}`);
      process.exit(2);
    }
    const parsed = parseTargets(json, env);
    if (!parsed.ok) {
      say(`${file} is not usable:\n  - ${parsed.problems.join('\n  - ')}\n\n${TARGETS_HELP}`);
      process.exit(2);
    }
    say(`${parsed.targets.length} target(s) from ${file}`);
    return parsed.targets;
  }
  const result = liveConfigFromEnv(env);
  if (!result.ok) {
    say(`no ${DEFAULT_TARGETS_FILE} and the WINRM_* env is incomplete:\n  - ${result.problems.join('\n  - ')}\n\n${TARGETS_HELP}`);
    process.exit(2);
  }
  say('one target from the WINRM_* variables');
  return [targetFromLiveConfig(result.config)];
}

const version = (JSON.parse(readFileSync(new URL('../../../package.json', import.meta.url), 'utf8')) as { version: string }).version;
const recordRoot = env['WINLINUX_PSRP_RECORD'] ? fromStart(env['WINLINUX_PSRP_RECORD']) : mkdtempSync(join(tmpdir(), 'winlinux-live-gate-'));
mkdirSync(recordRoot, { recursive: true });
say(`fixtures go to ${recordRoot}/<target> (review them before they go under packages/winrm/test/fixtures/psrp/)`);

const reports = [];
const ownKrb5Config = env['KRB5_CONFIG'];
for (const target of loadTargets()) {
  // kinit and the GSS library read KRB5_CONFIG: a target with a KDC gets
  // its own file, for that target only. The next target starts from the
  // maintainer's own setting, and the file (realm, KDC, host) is removed.
  let krb5Dir: string | undefined;
  if (target.kdc && target.credentials.realm) {
    krb5Dir = mkdtempSync(join(tmpdir(), 'winlinux-live-gate-krb5-'));
    writeFileSync(join(krb5Dir, 'krb5.conf'), krb5Conf(target.credentials.realm, target.kdc, target.host));
    env['KRB5_CONFIG'] = join(krb5Dir, 'krb5.conf');
  }
  try {
    say(`target ${target.name}${target.problems.length > 0 ? `: not run (${target.problems.join('; ')})` : ''}`);
    const report = await gateTarget(target, { providerFor: (m) => createAuthProvider(m), log: say, recordDir: join(recordRoot, target.name), version });
    reports.push(report);
    process.stdout.write(`${renderMarkdown(report)}\n`);
  } finally {
    if (ownKrb5Config === undefined) delete env['KRB5_CONFIG'];
    else env['KRB5_CONFIG'] = ownKrb5Config;
    if (krb5Dir) rmSync(krb5Dir, { recursive: true, force: true });
  }
}
const code = exitCodeFor(reports);
say(code === 0 ? 'every check passed' : code === 1 ? 'a check failed, or a fixture is not redacted' : 'a check was not run');
process.exitCode = code;
