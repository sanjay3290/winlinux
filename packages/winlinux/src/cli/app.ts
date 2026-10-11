// The winlinux CLI. Node built-ins only.
import { parseArgs } from 'node:util';
import { readFileSync } from 'node:fs';
import { readFile, stat } from 'node:fs/promises';
import { homedir } from 'node:os';
import path from 'node:path';
import { WinRMAbortError, type EventLogQuery } from '@winlinux/winrm';
import { createClient, resolveGetDestination } from '../client.js';
import { realDeps } from '../real-deps.js';
import { EXIT, WinLinuxUsageError, exitCodeFor } from '../errors.js';
import { redact, type RedactSecrets } from '../redact.js';
import { terminalSafe } from '../terminal.js';
import type { AuthMechanism, ConnectOptions, TransferVia, WinLinuxClient } from '../types.js';
import { MAX_PARALLEL, type TreeTransferOptions, type TreeTransferSummary } from '../tree.js';
import {
  DEFAULT_HOSTS_PARALLEL,
  MAX_HOSTS_PARALLEL,
  dedupeHosts,
  expandHostList,
  labelOf,
  runFleet,
  type FleetHost,
} from './fleet.js';
import {
  dirEntriesToJson,
  filterProcesses,
  filterServices,
  formatEvents,
  formatLs,
  formatProcesses,
  formatServices,
  formatShares,
  formatStat,
  runJson,
  statToJson,
  type ServiceFilter,
} from './output.js';
import {
  PromptInterrupted,
  pemKeyIsEncrypted,
  resolvePassphrase,
  resolvePassword,
  takeEnvPassphrase,
  takeEnvPassword,
} from './password.js';
import { runShell } from './shell.js';
import { splitSharePath, type Target } from './target.js';
import { parseConfig, resolveTarget, type HostConfig, type ProfileSettings } from './config.js';

export const COMMANDS = ['run', 'logs', 'services', 'ps', 'shares', 'ls', 'get', 'put', 'stat', 'mkdir', 'rm', 'rmdir', 'mv'] as const;
export type Command = (typeof COMMANDS)[number];

const LOGS_OPTIONS = {
  log: { type: 'string' },
  max: { type: 'string' },
  level: { type: 'string' },
  provider: { type: 'string' },
  since: { type: 'string' },
  oldest: { type: 'boolean' },
} as const;

// `services --status`, `services --name`, `ps --name`.
const STATE_OPTIONS = {
  status: { type: 'string' },
  name: { type: 'string' },
} as const;

// `mkdir -p`.
const FILE_OPTIONS = {
  parents: { type: 'boolean', short: 'p' },
  recursive: { type: 'boolean', short: 'r' },
  parallel: { type: 'string' },
  via: { type: 'string' },
} as const;

// Which subcommands each per-command flag belongs to.
const FLAG_OWNERS: Record<string, readonly Command[]> = {
  ...Object.fromEntries(Object.keys(LOGS_OPTIONS).map((k) => [k, ['logs']])),
  status: ['services'],
  name: ['services', 'ps'],
  parents: ['mkdir'],
  recursive: ['get', 'put'],
  parallel: ['get', 'put', 'run'],
  hosts: ['run'],
  via: ['get', 'put'],
};

export const LINE_OPTIONS = { json: { type: 'boolean' }, ...LOGS_OPTIONS, ...STATE_OPTIONS, ...FILE_OPTIONS } as const;

const OPTIONS = {
  auth: { type: 'string', short: 'a' },
  domain: { type: 'string', short: 'd' },
  realm: { type: 'string' },
  'use-ticket-cache': { type: 'boolean', short: 'K' },
  keytab: { type: 'string' },
  config: { type: 'string', short: 'F' },
  hosts: { type: 'string' },
  cert: { type: 'string' },
  key: { type: 'string' },
  'krb-hostname': { type: 'string' },
  'connect-timeout': { type: 'string' },
  tls: { type: 'boolean' },
  insecure: { type: 'boolean' },
  'credssp-allow-http': { type: 'boolean' },
  'winrm-port': { type: 'string' },
  'smb-port': { type: 'string' },
  json: { type: 'boolean' },
  verbose: { type: 'boolean', short: 'v' },
  help: { type: 'boolean', short: 'h' },
  version: { type: 'boolean', short: 'V' },
  ...LOGS_OPTIONS,
  ...STATE_OPTIONS,
  ...FILE_OPTIONS,
} as const;

export const HELP = `Usage:
  winlinux [flags] <target>                          interactive shell
  winlinux run    [flags] <target> [--] <cmd> [args...]
  winlinux run    [flags] --hosts <list> [--] <cmd> [args...]
  winlinux logs   [flags] <target>
  winlinux services [flags] <target>
  winlinux ps     [flags] <target>
  winlinux shares [flags] <target>
  winlinux ls     [flags] <target> <share>[/<path>]
  winlinux get    [flags] <target> <share>/<path> [<localPath>]
  winlinux put    [flags] <target> <localPath> <share>/<path>
  winlinux get -r [flags] <target> <share>[/<dir>] [<localDir>]
  winlinux put -r [flags] <target> <localDir> <share>[/<dir>]
  winlinux stat   [flags] <target> <share>/<path>
  winlinux mkdir  [flags] [-p] <target> <share>/<path>
  winlinux rm     [flags] <target> <share>/<path>          (files only)
  winlinux rmdir  [flags] <target> <share>/<path>          (empty directories only)
  winlinux mv     [flags] <target> <share>/<from> <share>/<to>

<target> is [DOMAIN\\]user@host, or a host alias from ~/.winlinux/config
(alias, user@alias, DOMAIN\\user@alias). The password comes from
WINLINUX_PASSWORD or a terminal prompt; -K uses the Kerberos ticket cache
instead, and --keytab a Kerberos keytab file (chmod 600; needs a realm).

Flags:
  -a, --auth <negotiate|ntlm|kerberos|basic|credssp|certificate>   default negotiate
  --cert <file> --key <file>   (-a certificate: PEM client certificate and key, HTTPS only;
                             an encrypted key reads WINLINUX_KEY_PASSPHRASE or prompts)
  -d, --domain <name>        --realm <REALM>   -K, --use-ticket-cache
  --keytab <file>            (Kerberos keytab: no password; unattended use)
  --krb-hostname <fqdn>      (Kerberos SPN host when <host> is an IP address)
  --connect-timeout <s>      WinRM TCP connect + TLS handshake limit (default 10)
  --tls                      --insecure        (skip TLS certificate checks)
  --credssp-allow-http       (-a credssp over plain HTTP: no certificate check)
  --winrm-port <n>           --smb-port <n>
  -F, --config <file|none>   host profiles (default ~/.winlinux/config; none: ignore)
  --json                     -v, --verbose     -h, --help   -V, --version
Host profiles: a flag beats the target text, which beats the profile, which
beats the default. No key can hold a password.
CredSSP (-a credssp) sends your password to the server for the double hop.
Use it only with servers you trust. It needs a password (no -K, no keytab),
--tls with a verified certificate (or --credssp-allow-http), and it works
for WinRM commands only. Every CredSSP sign-in prints a notice on stderr.
logs flags:
  --log <name> (System)  --max <n> (20)  --level <1-5>  --provider <name>
  --since <ISO-8601>     --oldest
services flags:
  --status <running|stopped>  --name <substring>   (filtered on the client)
ps flags:
  --name <substring>
mkdir flags:
  -p, --parents          create missing parent directories; an existing directory is fine
run --hosts flags:
  --hosts <list>         comma-separated alias, user@host, DOMAIN\\user@host or @group
  --parallel <n>         hosts in flight (1-${MAX_HOSTS_PARALLEL}, default ${DEFAULT_HOSTS_PARALLEL})
  Output lines are prefixed '<host> | '; a summary table goes to stderr. --json
  prints one object per host instead. One sign-in serves every host; after an
  auth failure no new host starts. Exit: 0 only if every host ran and exited 0,
  else the smallest per-host code (2 auth, 3 connection, 4 remote).
get/put flags:
  -r, --recursive        copy a directory tree; symlinks and reparse points are skipped
  --parallel <n>         files in flight with -r (1-${MAX_PARALLEL}, default 1)
  --via <auto|smb|winrm> how the file travels (default auto): smb uses port 445;
                         winrm uses PowerShell over WinRM, slower, for networks
                         that block 445; auto uses SMB and falls back to WinRM
                         when port 445 does not answer. -r copies use SMB.

Exit codes: 0 ok, 1 usage, 2 auth, 3 connection, 4 remote command/WinRM error,
5 file or share error, 6 internal error, 130 interrupted.
`;

export const SHELL_HELP = `Commands (no <target>):
  run <cmd> [args...]   or just <cmd> [args...]
  cd [<dir>]            change (or print) the working directory for later lines
  logs [--log <name>] [--max <n>] [--level <1-5>] [--provider <name>] [--since <date>] [--oldest] [--json]
  services [--status <running|stopped>] [--name <substring>] [--json]
  ps [--name <substring>] [--json]
  shares [--json]
  ls <share>[/<path>] [--json]
  get [-r] [--parallel <n>] [--via <auto|smb|winrm>] <share>/<path> [<localPath>] [--json]
  put [-r] [--parallel <n>] [--via <auto|smb|winrm>] <localPath> <share>/<path> [--json]
  stat <share>/<path> [--json]
  mkdir [-p] <share>/<path> [--json]
  rm <share>/<path> [--json]            files only
  rmdir <share>/<path> [--json]         empty directories only
  mv <share>/<from> <share>/<to> [--json]
  help, exit, quit, Ctrl+D
`;

export interface Io {
  env: NodeJS.ProcessEnv;
  stdin: NodeJS.ReadStream;
  stdout: NodeJS.WritableStream;
  stderr: NodeJS.WritableStream;
  // Ends the process with a code (flushes output first). Used by SIGINT paths.
  exit?: (code: number) => void;
}

export type LineValues = { [K in keyof typeof LINE_OPTIONS]?: (typeof LINE_OPTIONS)[K]['type'] extends 'boolean' ? boolean : string };

function version(): string {
  const pkg = JSON.parse(readFileSync(new URL('../../package.json', import.meta.url), 'utf8')) as { version: string };
  return pkg.version;
}

function parsePort(name: string, value: string | undefined): number | undefined {
  if (value === undefined) return undefined;
  if (!/^\d+$/.test(value)) throw new WinLinuxUsageError(`--${name} must be an integer from 1 to 65535`);
  const port = Number(value);
  if (port < 1 || port > 65535) throw new WinLinuxUsageError(`--${name} must be an integer from 1 to 65535`);
  return port;
}

const MECHANISMS: readonly string[] = ['negotiate', 'ntlm', 'kerberos', 'basic', 'credssp', 'certificate'];

// The notice on every CredSSP sign-in. stderr, with --json too.
export function credsspNotice(host: string): string {
  return `winlinux: CredSSP: your password is delegated to ${host}\n`;
}

// Adds the stderr notice hook to options that sign in with CredSSP.
export function withCredsspNotice(options: ConnectOptions, io: Pick<Io, 'stderr'>): ConnectOptions {
  if (options.auth !== 'credssp') return options;
  return { ...options, winrm: { ...options.winrm, onCredSSPDelegation: (host: string) => void io.stderr.write(credsspNotice(host)) } };
}

export function buildLogQuery(values: LineValues): EventLogQuery {
  const query: EventLogQuery = { logName: values.log ?? 'System', maxEvents: 20 };
  if (values.max !== undefined) {
    if (!/^\d+$/.test(values.max) || Number(values.max) < 1) throw new WinLinuxUsageError('--max must be a positive integer');
    query.maxEvents = Number(values.max);
  }
  if (values.level !== undefined) {
    if (!/^[1-5]$/.test(values.level)) throw new WinLinuxUsageError('--level must be 1, 2, 3, 4 or 5');
    query.level = Number(values.level) as 1 | 2 | 3 | 4 | 5;
  }
  if (values.provider !== undefined) query.provider = values.provider;
  if (values.since !== undefined) {
    const since = new Date(values.since);
    if (Number.isNaN(since.getTime())) throw new WinLinuxUsageError(`--since is not a valid ISO-8601 date: ${values.since}`);
    query.startTime = since;
  }
  if (values.oldest) query.oldest = true;
  return query;
}

// Rejects every per-command flag that `command` does not own.
function rejectForeignFlags(command: string, values: LineValues): void {
  for (const [name, owners] of Object.entries(FLAG_OWNERS)) {
    if ((values as Record<string, unknown>)[name] !== undefined && !(owners as readonly string[]).includes(command)) {
      throw new WinLinuxUsageError(`--${name} applies to ${owners.join(' and ')} only, not ${command}`);
    }
  }
}

export function buildServiceFilter(values: LineValues): ServiceFilter {
  const filter: ServiceFilter = {};
  if (values.status !== undefined) {
    const status = values.status.toLowerCase();
    if (status !== 'running' && status !== 'stopped') throw new WinLinuxUsageError('--status must be running or stopped');
    filter.status = status;
  }
  if (values.name !== undefined) filter.name = values.name;
  return filter;
}

const ARITY: Record<Command, [number, number]> = {
  run: [1, Infinity],
  logs: [0, 0],
  services: [0, 0],
  ps: [0, 0],
  shares: [0, 0],
  ls: [1, 1],
  get: [1, 2],
  put: [2, 2],
  stat: [1, 1],
  mkdir: [1, 1],
  rm: [1, 1],
  rmdir: [1, 1],
  mv: [2, 2],
};

// `--via`. The CLI default is auto: SMB, or WinRM when port 445 does
// not answer. A recursive copy runs over SMB only for now.
export function parseVia(values: LineValues): TransferVia {
  const via = values.via ?? 'auto';
  if (via !== 'auto' && via !== 'smb' && via !== 'winrm') throw new WinLinuxUsageError('--via must be auto, smb or winrm');
  if (values.recursive === true && via === 'winrm') {
    throw new WinLinuxUsageError('--via winrm with -r: not supported yet. Use -r over SMB, or copy single files with --via winrm');
  }
  return via;
}

// Per call: --via when given; otherwise the client's transfer.via (the
// profile's Via, or auto) decides.
function transferOptions(values: LineValues, via: TransferVia, signal: AbortSignal | undefined): { via?: TransferVia; signal?: AbortSignal } {
  const opts: { via?: TransferVia; signal?: AbortSignal } = {};
  if (values.via !== undefined) opts.via = via;
  if (signal) opts.signal = signal;
  return opts;
}

// The one stderr line when `auto` switches to WinRM.
export function fallbackNotice(smbPort: number): string {
  return `winlinux: SMB port ${smbPort} unreachable; copying over WinRM\n`;
}

// `<share>/<path>` with a non-empty path, for the commands that need a file
// or directory, not a share.
function parseParallel(values: LineValues): number | undefined {
  if (values.parallel === undefined) return undefined;
  if (values.recursive !== true) throw new WinLinuxUsageError('--parallel needs -r');
  const n = Number(values.parallel);
  if (!/^\d+$/.test(values.parallel) || n < 1 || n > MAX_PARALLEL) {
    throw new WinLinuxUsageError(`--parallel must be an integer from 1 to ${MAX_PARALLEL}`);
  }
  return n;
}

// get -r / put -r: progress on a TTY stderr, skipped entries always
// reported, one summary line or object.
async function recursiveCopy(
  command: 'get' | 'put',
  args: string[],
  values: LineValues,
  io: Io,
  client: WinLinuxClient,
  signal: AbortSignal | undefined,
): Promise<number> {
  const json = values.json === true;
  const tty = (io.stderr as { isTTY?: boolean }).isTTY === true;
  let done = 0;
  let total = 0;
  const opts: TreeTransferOptions = {
    onSkip: (e) => io.stderr.write(`${tty ? '\r\x1b[K' : ''}winlinux: skipped ${e.reason} ${terminalSafe(e.path)}\n`),
    onFile: (e) => {
      total = e.total;
      if (tty) io.stderr.write(`\r\x1b[K[${e.index}/${e.total}] ${terminalSafe(e.path)}`);
    },
    onFileDone: () => void done++,
  };
  const parallel = parseParallel(values);
  if (parallel !== undefined) opts.parallel = parallel;
  if (signal) opts.signal = signal;
  let summary: TreeTransferSummary;
  try {
    if (command === 'get') {
      const { share, path: remoteDir } = splitSharePath(args[0] as string);
      summary = await client.getDir(share, remoteDir ?? '', args[1] ?? '.', opts);
    } else {
      const { share, path: remoteDir } = splitSharePath(args[1] as string);
      summary = await client.putDir(args[0] as string, share, remoteDir ?? '', opts);
    }
  } catch (err) {
    if (tty) io.stderr.write('\r\x1b[K');
    if (total > 0 && !(err instanceof Error && err.name === 'WinLinuxAbortError')) {
      io.stderr.write(`winlinux: ${command} -r stopped after ${done} of ${total} files; copied files stay\n`);
    }
    throw err;
  }
  if (tty) io.stderr.write('\r\x1b[K');
  const { files, directories, bytes, skipped } = summary;
  const remote = terminalSafe(summary.remotePath ? `${summary.share}/${summary.remotePath}` : summary.share);
  const local = terminalSafe(summary.localPath);
  const counts = `${files} files, ${directories} directories, ${bytes} bytes, ${skipped} skipped`;
  io.stdout.write(
    json
      ? JSON.stringify({ files, directories, bytes, skipped }) + '\n'
      : command === 'get'
        ? `downloaded ${remote} -> ${local} (${counts})\n`
        : `uploaded ${local} -> ${remote} (${counts})\n`,
  );
  return EXIT.ok;
}

function sharePath(command: Command, text: string): { share: string; path: string } {
  const { share, path: remotePath } = splitSharePath(text);
  if (!remotePath) throw new WinLinuxUsageError(`${command} needs <share>/<path>: ${text}`);
  return { share, path: remotePath };
}

export function checkArity(command: Command, args: string[]): void {
  const [min, max] = ARITY[command];
  if (args.length < min || args.length > max) {
    throw new WinLinuxUsageError(`wrong number of arguments for ${command}; see winlinux --help`);
  }
}

// Runs one subcommand against an open client (shared by one-shot mode and the shell).
// `args` excludes the target. Returns the exit code.
export async function execute(
  client: WinLinuxClient,
  command: Command,
  args: string[],
  values: LineValues,
  io: Io,
  signal?: AbortSignal,
): Promise<number> {
  const json = values.json === true;
  const out = (text: string) => io.stdout.write(text);
  rejectForeignFlags(command, values);
  checkArity(command, args);
  switch (command) {
    case 'run': {
      if (values.parallel !== undefined) throw new WinLinuxUsageError('--parallel with run needs --hosts');
      const [cmd, ...rest] = args as [string, ...string[]];
      const result = await client.run(cmd, rest, { signal });
      if (json) {
        out(runJson(result) + '\n');
      } else {
        io.stdout.write(result.stdout);
        io.stderr.write(result.stderr);
        if (result.exitCode !== 0) io.stderr.write(`winlinux: remote command exited with code ${result.exitCode}\n`);
      }
      return result.exitCode === 0 ? EXIT.ok : EXIT.remote;
    }
    case 'logs': {
      const events = await client.readEventLog(buildLogQuery(values));
      out(json ? JSON.stringify(events) + '\n' : formatEvents(events));
      return EXIT.ok;
    }
    case 'services': {
      const services = filterServices(await client.listServices(), buildServiceFilter(values));
      out(json ? JSON.stringify(services) + '\n' : formatServices(services));
      return EXIT.ok;
    }
    case 'ps': {
      const processes = filterProcesses(await client.listProcesses(), values.name === undefined ? {} : { name: values.name });
      out(json ? JSON.stringify(processes) + '\n' : formatProcesses(processes));
      return EXIT.ok;
    }
    case 'shares': {
      const shares = await client.listShares();
      out(json ? JSON.stringify(shares) + '\n' : formatShares(shares));
      return EXIT.ok;
    }
    case 'ls': {
      const { share, path: dir } = splitSharePath(args[0] as string);
      const entries = await client.ls(share, dir);
      out(json ? JSON.stringify(dirEntriesToJson(entries)) + '\n' : formatLs(entries));
      return EXIT.ok;
    }
    case 'get': {
      const via = parseVia(values);
      if (values.recursive === true) return recursiveCopy('get', args, values, io, client, signal);
      if (values.parallel !== undefined) throw new WinLinuxUsageError('--parallel needs -r');
      const remote = args[0] as string;
      const { share, path: remotePath } = splitSharePath(remote);
      if (!remotePath) throw new WinLinuxUsageError(`get needs <share>/<path>: ${remote}`);
      const base = remotePath.split(/[\\/]/).filter(Boolean).pop();
      if (!base) throw new WinLinuxUsageError(`cannot take a file name from ${remote}`);
      // Resolved here too, so the output names the file that was written.
      const localPath = await resolveGetDestination(remotePath, args[1] ?? `.${path.sep}${base}`);
      await client.get(share, remotePath, localPath, transferOptions(values, via, signal));
      const size = (await stat(localPath)).size;
      out(
        json
          ? JSON.stringify({ share, remotePath, localPath, sizeBytes: String(size) }) + '\n'
          : `downloaded ${remote} -> ${localPath} (${size} bytes)\n`,
      );
      return EXIT.ok;
    }
    case 'put': {
      const via = parseVia(values);
      if (values.recursive === true) return recursiveCopy('put', args, values, io, client, signal);
      if (values.parallel !== undefined) throw new WinLinuxUsageError('--parallel needs -r');
      const localPath = args[0] as string;
      const remote = args[1] as string;
      const { share, path: remotePath } = splitSharePath(remote);
      if (!remotePath) throw new WinLinuxUsageError(`put needs <share>/<path>: ${remote}`);
      await client.put(localPath, share, remotePath, transferOptions(values, via, signal));
      const size = (await stat(localPath)).size;
      out(
        json
          ? JSON.stringify({ share, remotePath, localPath, sizeBytes: String(size) }) + '\n'
          : `uploaded ${localPath} -> ${remote} (${size} bytes)\n`,
      );
      return EXIT.ok;
    }
    case 'stat': {
      const { share, path: remotePath } = sharePath(command, args[0] as string);
      const info = await client.stat(share, remotePath);
      out(json ? JSON.stringify(statToJson(share, remotePath, info)) + '\n' : formatStat(share, remotePath, info));
      return EXIT.ok;
    }
    case 'mkdir': {
      const { share, path: dirPath } = sharePath(command, args[0] as string);
      await client.mkdir(share, dirPath, { parents: values.parents === true });
      out(json ? JSON.stringify({ share, path: dirPath }) + '\n' : `created directory ${share}/${dirPath}\n`);
      return EXIT.ok;
    }
    case 'rm': {
      const { share, path: remotePath } = sharePath(command, args[0] as string);
      await client.rm(share, remotePath);
      out(json ? JSON.stringify({ share, path: remotePath }) + '\n' : `removed ${share}/${remotePath}\n`);
      return EXIT.ok;
    }
    case 'rmdir': {
      const { share, path: dirPath } = sharePath(command, args[0] as string);
      await client.rmdir(share, dirPath);
      out(json ? JSON.stringify({ share, path: dirPath }) + '\n' : `removed directory ${share}/${dirPath}\n`);
      return EXIT.ok;
    }
    case 'mv': {
      const from = sharePath(command, args[0] as string);
      const to = sharePath(command, args[1] as string);
      if (from.share !== to.share) {
        throw new WinLinuxUsageError(`mv works within one share: ${from.share} and ${to.share} differ`);
      }
      await client.mv(from.share, from.path, to.path);
      out(
        json
          ? JSON.stringify({ share: from.share, from: from.path, to: to.path }) + '\n'
          : `moved ${from.share}/${from.path} -> ${to.share}/${to.path}\n`,
      );
      return EXIT.ok;
    }
  }
}

// Error printer: redacts the message and every cause message and stack.
export function printError(
  err: unknown,
  io: Io,
  secrets: RedactSecrets,
  opts: { json: boolean; verbose: boolean; redact?: (text: string) => string },
): number {
  const code = exitCodeFor(err);
  const scrub = opts.redact ?? ((text: string) => redact(text, secrets));
  const name = err instanceof Error ? err.name : 'Error';
  const message = scrub(err instanceof Error ? err.message : String(err));
  if (opts.json) {
    io.stderr.write(JSON.stringify({ error: { name, message, exitCode: code } }) + '\n');
  } else {
    // A message can carry server text (a fault reason, a file name).
    io.stderr.write(`winlinux: ${name}: ${terminalSafe(message, { newlines: true })}\n`);
  }
  if (opts.verbose) {
    let cause = err instanceof Error ? (err as { cause?: unknown }).cause : undefined;
    let depth = 0;
    while (cause !== undefined && depth < 10) {
      const text = cause instanceof Error ? `${cause.name}: ${cause.message}` : String(cause);
      io.stderr.write(`winlinux: cause: ${terminalSafe(scrub(text), { newlines: true })}\n`);
      if (cause instanceof Error && cause.stack) io.stderr.write(terminalSafe(scrub(cause.stack), { newlines: true }) + '\n');
      cause = cause instanceof Error ? (cause as { cause?: unknown }).cause : undefined;
      depth += 1;
    }
  }
  return code;
}

interface Parsed {
  command: Command | 'shell';
  values: ReturnType<typeof parse>['values'];
  target: string;
  rest: string[];
  fleet?: boolean; // run --hosts: no positional target
}

function parse(argv: string[]) {
  return parseArgs({ args: argv, options: OPTIONS, allowPositionals: true, strict: true });
}

function interpret(argv: string[]): Parsed | { help: true } | { version: true } {
  const { values, positionals } = parse(argv);
  if (values.help) return { help: true };
  if (values.version) return { version: true };
  const first = positionals[0];
  if (first === undefined) throw new WinLinuxUsageError('missing <target>; see winlinux --help');
  if (values.hosts !== undefined && first !== 'run') throw new WinLinuxUsageError('--hosts applies to run only');
  if (first === 'run' && values.hosts !== undefined) {
    return { command: 'run', values, target: '', rest: positionals.slice(1), fleet: true };
  }
  if ((COMMANDS as readonly string[]).includes(first)) {
    const target = positionals[1];
    if (target === undefined) throw new WinLinuxUsageError(`${first} needs a <target>; see winlinux --help`);
    return { command: first as Command, values, target, rest: positionals.slice(2) };
  }
  if (positionals.length > 1) throw new WinLinuxUsageError(`unknown command: ${first}; see winlinux --help`);
  return { command: 'shell', values, target: first, rest: [] };
}

function wait(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms).unref());
}

// Closes the client, bounded by 3 s.
export async function closeWithin(client: WinLinuxClient, ms = 3000): Promise<void> {
  await Promise.race([client.close(), wait(ms)]);
}

// First SIGINT during a subcommand. Resolves when the CLI
// may exit 130: after close(), or after 3 s at most.
export function interruptSubcommand(
  command: Command,
  client: WinLinuxClient,
  running: Promise<unknown> | undefined,
  abort: AbortController,
  recursive = false,
): Promise<void> {
  abort.abort();
  // get -r / put -r: the abort stops the copy after the files in
  // flight, which complete (no temp file is left); then close. No time
  // bound: a second Ctrl+C closes at once and removes the temp file.
  if (recursive && running !== undefined) return running.then(() => client.close(), () => client.close());
  // Other commands have no abort path: close now, so a stalled get
  // still removes its .part file.
  if (command !== 'run' || running === undefined) return closeWithin(client);
  // Let the aborted run send Signal and Delete before close(); the
  // whole wait stays inside the 3 s bound.
  const settled = running.then(() => client.close(), () => client.close());
  return Promise.race([settled, wait(3000)]);
}

// `~/` at the start of a path from the config file means $HOME.
function expandHome(file: string | undefined, env: NodeJS.ProcessEnv): string | undefined {
  if (file === undefined || !file.startsWith('~/')) return file;
  return path.join(env.HOME || homedir(), file.slice(2));
}

// Reads the host profiles: `-F <file>`, `-F none`, or the default
// ~/.winlinux/config. A missing default file is fine; a missing -F file is a
// usage error. The file holds no secrets, but it maps the estate, so a file
// that group or others can read or write gets one warning.
export async function loadHostConfig(flag: string | undefined, io: Pick<Io, 'env' | 'stderr'>): Promise<HostConfig | undefined> {
  if (flag === 'none') return undefined;
  const file = flag ?? path.join(io.env.HOME || homedir(), '.winlinux', 'config');
  let text: string;
  try {
    text = await readFile(file, 'utf8');
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === 'ENOENT' && flag === undefined) return undefined;
    throw new WinLinuxUsageError(`config file ${file}: ${code === 'ENOENT' ? 'no such file' : (err as Error).message}`, { cause: err });
  }
  // eslint-disable-next-line no-bitwise
  if (((await stat(file)).mode & 0o077) !== 0) {
    io.stderr.write(`winlinux: warning: ${file} is accessible by group or others; run chmod 600 ${file}\n`);
  }
  return parseConfig(text, file);
}

type GlobalValues = ReturnType<typeof parse>['values'];

// The credential source. A credential flag (-K or --keytab)
// replaces the profile's UseTicketCache and Keytab keys.
export function credentialSource(
  values: Pick<GlobalValues, 'use-ticket-cache' | 'keytab'>,
  profile: ProfileSettings,
  env: NodeJS.ProcessEnv,
): { useTicketCache: boolean; keytab?: string } {
  const flagTicketCache = values['use-ticket-cache'] === true;
  if (values.keytab !== undefined && flagTicketCache) throw new WinLinuxUsageError('--keytab and -K cannot be used together');
  if (flagTicketCache) return { useTicketCache: true };
  if (values.keytab !== undefined) return { useTicketCache: false, keytab: values.keytab };
  const keytab = expandHome(profile.keytab, env);
  return keytab === undefined ? { useTicketCache: profile.useTicketCache === true } : { useTicketCache: profile.useTicketCache === true, keytab };
}

// --connect-timeout <s>, or the profile's ConnectTimeout: seconds,
// whole or decimal, from 0.1 to 600. The flag beats the profile.
export function parseConnectTimeout(value: string): number {
  const seconds = Number(value);
  if (!/^\d+(\.\d+)?$/.test(value) || seconds < 0.1 || seconds > 600) {
    throw new WinLinuxUsageError(`--connect-timeout must be a number of seconds from 0.1 to 600, got ${value}`);
  }
  return Math.round(seconds * 1000);
}

function connectTimeoutOption(flag: string | undefined, profileMs: number | undefined): { connectTimeoutMs?: number } {
  if (flag !== undefined) return { connectTimeoutMs: parseConnectTimeout(flag) };
  return profileMs === undefined ? {} : { connectTimeoutMs: profileMs };
}

// ConnectOptions from the flags, the target and the profile.
// Precedence: flag, then the target text, then the profile, then the default.
// Boolean flags can only turn a setting on; a profile `no` stays off.
export function buildConnectOptions(
  values: GlobalValues,
  resolved: { target: Target; profile: ProfileSettings },
  credentials: { useTicketCache: boolean; keytab?: string },
  password: string | undefined,
  env: NodeJS.ProcessEnv = {},
): ConnectOptions {
  const { target, profile } = resolved;
  const auth = (values.auth ?? profile.auth ?? 'negotiate') as AuthMechanism;
  // CredSSP over HTTP is a command-line choice only: no profile key.
  if (values['credssp-allow-http'] === true && auth !== 'credssp') {
    throw new WinLinuxUsageError('--credssp-allow-http applies to -a credssp only');
  }
  const options: ConnectOptions = {
    username: target.username,
    auth,
    winrm: {
      tls: values.tls === true || profile.tls === true,
      tlsVerify: !(values.insecure === true || profile.insecure === true),
      port: parsePort('winrm-port', values['winrm-port']) ?? profile.winrmPort,
      ...(values['credssp-allow-http'] === true ? { credsspAllowHttp: true } : {}),
      ...connectTimeoutOption(values['connect-timeout'], profile.connectTimeout),
    },
    smb: { port: parsePort('smb-port', values['smb-port']) ?? profile.smbPort },
  };
  if (password !== undefined) options.password = password;
  if (target.domain !== undefined) options.domain = target.domain;
  const realm = values.realm ?? profile.realm;
  if (realm !== undefined) options.realm = realm;
  if (credentials.useTicketCache) options.useTicketCache = true;
  if (credentials.keytab !== undefined) options.keytab = credentials.keytab;
  const krbHostname = values['krb-hostname'] ?? profile.krbHostname;
  if (krbHostname !== undefined) options.kerberosHostname = krbHostname;
  // Profile CertFile and KeyFile apply only when the resolved method is
  // certificate, so `-a ntlm` against a certificate profile just works.
  // The flags always apply; with another method they are a usage error.
  const profileCert = options.auth === 'certificate';
  const clientCert = values.cert ?? (profileCert ? expandHome(profile.certFile, env) : undefined);
  const clientKey = values.key ?? (profileCert ? expandHome(profile.keyFile, env) : undefined);
  if (clientCert !== undefined) options.clientCert = clientCert;
  if (clientKey !== undefined) options.clientKey = clientKey;
  return options;
}

export function parseHostsParallel(value: string | undefined): number {
  if (value === undefined) return DEFAULT_HOSTS_PARALLEL;
  const n = Number(value);
  if (!/^\d+$/.test(value) || n < 1 || n > MAX_HOSTS_PARALLEL) {
    throw new WinLinuxUsageError(`--parallel with --hosts must be an integer from 1 to ${MAX_HOSTS_PARALLEL}`);
  }
  return n;
}

// winlinux run --hosts. Every usage error comes before any host
// starts. One sign-in serves every host: one prompt (or WINLINUX_PASSWORD,
// -K, a keytab), whatever user each profile names.
async function runFleetCommand(
  values: GlobalValues,
  rest: string[],
  io: Io,
  envPassword: string | undefined,
  envPassphrase: string | undefined,
  setSecrets: (s: RedactSecrets) => void,
): Promise<number> {
  rejectForeignFlags('run', values);
  const args = rest[0] === '--' ? rest.slice(1) : rest;
  checkArity('run', args);
  const parallel = parseHostsParallel(values.parallel);
  const config = await loadHostConfig(values.config, io);
  const items = expandHostList(values.hosts ?? '', config);
  const resolved = items.map((item) => {
    const r = resolveTarget(item, values.domain, config);
    return { item, ...r, credentials: credentialSource(values, r.profile, io.env) };
  });
  const isCertificate = (r: (typeof resolved)[number]) => (values.auth ?? r.profile.auth) === 'certificate';
  const needsPassword = resolved.some((r) => !isCertificate(r) && !r.credentials.useTicketCache && r.credentials.keytab === undefined);
  const password = needsPassword ? await resolvePassword(false, envPassword, io) : undefined;
  const usernames = [...new Set(resolved.map((r) => r.target.username))];
  setSecrets({ username: usernames[0] ?? '', password });
  const scrub = (text: string) => usernames.reduce((out, username) => redact(out, { username, password }), text);

  const hosts: FleetHost[] = dedupeHosts(
    resolved.map((r) => {
      const ownPassword = isCertificate(r) || r.credentials.useTicketCache || r.credentials.keytab !== undefined ? undefined : password;
      return {
        label: labelOf(r.item),
        host: r.target.host,
        username: r.target.username,
        options: withCredsspNotice(buildConnectOptions(values, r, r.credentials, ownPassword, io.env), io),
      };
    }),
  );
  // One key passphrase for every host whose key is encrypted.
  let passphrase: string | undefined;
  for (const h of hosts) {
    if (h.options.auth !== 'certificate') continue;
    passphrase ??= await keyPassphrase(h.options, envPassphrase, io);
    if (passphrase !== undefined) h.options.clientKeyPassphrase = passphrase;
    warnInsecureCertificate(h.options, io);
  }
  if (password === undefined && passphrase !== undefined) setSecrets({ username: usernames[0] ?? '', password: passphrase });
  // createClient validates and opens nothing, so a usage error in any host's
  // options stops the run before the first host starts.
  const width = Math.max(...hosts.map((h) => h.label.length));
  const clients = new Map<FleetHost, WinLinuxClient>();
  for (const h of hosts) {
    const log = values.verbose === true ? (line: string) => io.stderr.write(`${h.label.padEnd(width)} | winlinux: ${line}\n`) : undefined;
    clients.set(h, createClient(h.host, h.options, realDeps({ log })));
  }

  const abort = new AbortController();
  let interrupted = false;
  const onSigint = () => {
    if (interrupted) return (io.exit ?? (() => undefined))(EXIT.interrupted);
    interrupted = true;
    io.stderr.write('interrupted; stopping every host (Ctrl+C again to exit now)\n');
    abort.abort();
  };
  process.on('SIGINT', onSigint);
  try {
    const run = await runFleet(hosts, args[0] as string, args.slice(1), {
      parallel,
      json: values.json === true,
      io,
      signal: abort.signal,
      connect: (h) => clients.get(h) as WinLinuxClient,
      redact: scrub,
    });
    return run.exitCode;
  } finally {
    process.removeListener('SIGINT', onSigint);
    await Promise.all([...clients.values()].map((c) => closeWithin(c)));
  }
}

// Certificate sign-in: the key passphrase, only when the key file
// is an encrypted PEM key. A key the CLI cannot read is left to the client,
// which names the file in a usage error.
async function keyPassphrase(options: ConnectOptions, fromEnv: string | undefined, io: Io): Promise<string | undefined> {
  if (options.auth !== 'certificate' || options.clientKey === undefined) return undefined;
  let pem: string;
  try {
    pem = await readFile(options.clientKey, 'utf8');
  } catch {
    return undefined;
  }
  return pemKeyIsEncrypted(pem) ? resolvePassphrase(fromEnv, io) : undefined;
}

// --insecure with a certificate: the client proves its identity to a
// server it has not verified.
function warnInsecureCertificate(options: ConnectOptions, io: Pick<Io, 'stderr'>): void {
  if (options.auth === 'certificate' && options.winrm?.tlsVerify === false) {
    io.stderr.write('winlinux: warning: --insecure with a client certificate: the server is not verified, so you prove your identity to an unverified server\n');
  }
}

// Entry point. Returns the process exit code.
export async function runCli(argv: string[], io: Io): Promise<number> {
  const envPassword = takeEnvPassword(io.env);
  const envPassphrase = takeEnvPassphrase(io.env);
  let secrets: RedactSecrets = { username: '' };
  let json = argv.includes('--json');
  let verbose = argv.includes('--verbose') || argv.includes('-v');
  let client: WinLinuxClient | undefined;
  let removeSigint: (() => void) | undefined;
  try {
    const parsed = interpret(argv);
    if ('help' in parsed) {
      io.stdout.write(HELP);
      return EXIT.ok;
    }
    if ('version' in parsed) {
      io.stdout.write(`${version()}\n`);
      return EXIT.ok;
    }
    const { values } = parsed;
    json = values.json === true;
    verbose = values.verbose === true;

    if (values.auth !== undefined && !MECHANISMS.includes(values.auth)) {
      throw new WinLinuxUsageError(`--auth must be one of ${MECHANISMS.join(', ')}`);
    }
    if (parsed.fleet) {
      return await runFleetCommand(values, parsed.rest, io, envPassword, envPassphrase, (s) => {
        secrets = s;
      });
    }
    // Host profiles. Precedence: flag, then the target text, then
    // the profile, then the default.
    const config = await loadHostConfig(values.config, io);
    const { target, profile, matched } = resolveTarget(parsed.target, values.domain, config);
    if (verbose && config) {
      io.stderr.write(`winlinux: config ${config.file}\n`);
      io.stderr.write(`winlinux: config: ${matched.length > 0 ? `matched ${matched.join(', ')}` : 'no Host block matched'}\n`);
    }
    if (parsed.command === 'shell') {
      rejectForeignFlags('the shell', values);
      if (json) throw new WinLinuxUsageError('--json does not apply to the interactive shell; use it per line');
    } else {
      rejectForeignFlags(parsed.command, values);
    }
    if (parsed.command !== 'shell') checkArity(parsed.command, parsed.rest);

    const { useTicketCache, keytab } = credentialSource(values, profile, io.env);
    const certificate = (values.auth ?? profile.auth) === 'certificate';
    // A keytab or a certificate replaces the password: no
    // prompt, and WINLINUX_PASSWORD is ignored.
    const password = keytab !== undefined || certificate ? undefined : await resolvePassword(useTicketCache, envPassword, io);
    const options = withCredsspNotice(buildConnectOptions(values, { target, profile }, { useTicketCache, keytab }, password, io.env), io);
    const passphrase = await keyPassphrase(options, envPassphrase, io);
    if (passphrase !== undefined) options.clientKeyPassphrase = passphrase;
    // The passphrase is redacted like a password; certificate sign-in has none.
    secrets = { username: target.username, password: password ?? passphrase };
    warnInsecureCertificate(options, io);
    // get/put pass --via per call; without the flag the profile's Via, or
    // auto, applies. onFallback prints the one line when auto switches to
    // WinRM.
    options.transfer = {
      via: profile.via ?? 'auto',
      onFallback: (event) => io.stderr.write(fallbackNotice(event.smbPort)),
    };

    const log = verbose ? (line: string) => io.stderr.write(`winlinux: ${line}\n`) : undefined;
    client = createClient(target.host, options, realDeps({ log }));

    if (parsed.command === 'shell') {
      return await runShell(client, io, {
        verbose,
        secrets,
        canReprompt: io.stdin.isTTY === true && !useTicketCache && keytab === undefined && !certificate,
      });
    }

    const current = client;
    const exit = io.exit ?? (() => undefined);
    let interrupted = false;
    // `run` passes this signal to WinRM: the abort cuts the in-flight
    // Receive and sends Signal and Delete.
    const abort = new AbortController();
    let running: Promise<number> | undefined;
    const recursive = values.recursive === true && (parsed.command === 'get' || parsed.command === 'put');
    const onSigint = () => {
      if (interrupted) {
        // close() removes the .part files of downloads in flight at once.
        if (recursive) void current.close();
        return exit(EXIT.interrupted);
      }
      interrupted = true;
      io.stderr.write(recursive ? 'interrupted; finishing the files in flight (Ctrl+C again to stop now)\n' : 'interrupted; closing\n');
      void interruptSubcommand(command, current, running, abort, recursive).then(() => exit(EXIT.interrupted));
    };
    const command: Command = parsed.command;
    process.on('SIGINT', onSigint);
    removeSigint = () => process.removeListener('SIGINT', onSigint);

    let args = parsed.rest;
    if (command === 'run' && args[0] === '--') args = args.slice(1);
    running = execute(client, command, args, values, io, abort.signal);
    return await running;
  } catch (err) {
    if (err instanceof PromptInterrupted) return EXIT.interrupted;
    if (err instanceof WinRMAbortError) return EXIT.interrupted;
    return printError(err, io, secrets, { json, verbose });
  } finally {
    removeSigint?.();
    if (client) await client.close();
  }
}
