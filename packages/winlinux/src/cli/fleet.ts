// winlinux run --hosts: one command on many hosts, with bounded
// concurrency, prefixed live output or --json lines, a summary table and
// the exit code rule. CLI only; no library API change.
import { StringDecoder } from 'node:string_decoder';
import type { OutputChunk } from '@winlinux/winrm';
import { WinRMAbortError } from '@winlinux/winrm';
import { EXIT, WinLinuxUsageError, exitCodeFor } from '../errors.js';
import type { ConnectOptions } from '../types.js';
import type { HostConfig } from './config.js';

export const MAX_HOSTS_PARALLEL = 32;
export const DEFAULT_HOSTS_PARALLEL = 4;

export interface FleetHost {
  label: string; // the alias or host as typed
  host: string; // where the client connects
  username: string;
  options: ConnectOptions;
}

// The part of WinLinuxClient a host needs.
export interface FleetClient {
  runStream(cmd: string, args?: string[], opts?: { signal?: AbortSignal }): AsyncIterable<OutputChunk>;
  close(): Promise<void>;
}

export interface HostOutcome {
  host: string;
  label: string;
  // The remote command's exit code; null when it did not run to the end.
  exitCode: number | null;
  stdout: string;
  stderr: string;
  durationMs: number;
  error?: { name: string; message: string; exitCode: number };
  // The per-host CLI code (0, or what exitCodeFor gives): input to the rule.
  code: number;
  result: string;
  skipped?: boolean;
}

export interface FleetRun {
  outcomes: HostOutcome[]; // input order; hosts that never started are absent
  exitCode: number;
}

export interface FleetIo {
  stdout: NodeJS.WritableStream;
  stderr: NodeJS.WritableStream;
}

export interface FleetOptions {
  parallel: number;
  json: boolean;
  io: FleetIo;
  signal?: AbortSignal;
  connect: (host: FleetHost) => FleetClient;
  redact?: (text: string) => string;
  now?: () => number;
  closeTimeoutMs?: number; // default 3000
}

// --- List expansion ---------------------------------------------------

// `--hosts a,user@b,@group`: groups expanded (members from the config),
// input order kept. Items stay as typed; resolveFleet turns them into hosts.
export function expandHostList(list: string, config: HostConfig | undefined): string[] {
  const items = list.split(',').map((s) => s.trim());
  if (items.length === 0 || items.some((s) => s.length === 0)) {
    throw new WinLinuxUsageError(`--hosts needs a comma-separated list without empty items: ${list}`);
  }
  const out: string[] = [];
  for (const item of items) {
    if (!item.startsWith('@')) {
      out.push(item);
      continue;
    }
    const name = item.slice(1);
    const members = config?.groups.get(name.toLowerCase());
    if (!members) throw new WinLinuxUsageError(`unknown group ${item}${config ? ` in ${config.file}` : ''}`);
    out.push(...members);
  }
  return out;
}

// Duplicates (same user, host and WinRM port, case-insensitive) are
// dropped; the first one stays. The port counts because two profiles can
// reach two servers through one address (port forwarding).
export function dedupeHosts<T extends { host: string; username: string; options?: ConnectOptions }>(hosts: T[]): T[] {
  const seen = new Set<string>();
  return hosts.filter((h) => {
    const port = h.options?.winrm?.port ?? (h.options?.winrm?.tls ? 5986 : 5985);
    const key = `${h.username.toLowerCase()}@${h.host.toLowerCase()}:${port}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

// The text the label shows: the alias or host as typed, without user@.
export function labelOf(item: string): string {
  const at = item.lastIndexOf('@');
  return at === -1 ? item : item.slice(at + 1);
}

// --- Output -----------------------------------------------------------

// Prefixes each complete line with `<label> | `. A partial line waits for
// its newline or for flush() at the end of the command. Buffers go through
// a UTF-8 decoder, so a character split across chunks comes out whole.
export class LinePrefixer {
  private pending = '';
  private readonly decoder = new StringDecoder('utf8');

  constructor(
    private readonly prefix: string,
    private readonly write: (text: string) => void,
  ) {}

  push(data: string | Buffer): void {
    const text = this.pending + (typeof data === 'string' ? data : this.decoder.write(data));
    const end = text.lastIndexOf('\n');
    if (end === -1) {
      this.pending = text;
      return;
    }
    this.pending = text.slice(end + 1);
    const lines = text.slice(0, end).split('\n');
    this.write(lines.map((l) => `${this.prefix}${l}\n`).join(''));
  }

  flush(): void {
    const rest = this.pending + this.decoder.end();
    this.pending = '';
    if (rest.length > 0) this.write(`${this.prefix}${rest}\n`);
  }
}

// "timed out connecting to <host>:<port> after 10 s" (winrm).
function connectTimeoutOf(message: string): string | undefined {
  return /timed out connecting to \S+ after (\d+(?:\.\d+)? m?s)/.exec(message)?.[1];
}

function resultText(code: number, exitCode: number | null, message = ''): string {
  if (code === EXIT.connection) {
    const after = connectTimeoutOf(message);
    if (after) return `connect timeout (${after})`;
  }
  switch (code) {
    case EXIT.ok:
      return 'ok';
    case EXIT.remote:
      return exitCode !== null ? `exit ${exitCode}` : 'remote error';
    case EXIT.auth:
      return 'auth failed';
    case EXIT.connection:
      return 'connection failed';
    case EXIT.usage:
      return 'usage error';
    case EXIT.file:
      return 'file error';
    case EXIT.interrupted:
      return 'interrupted';
    default:
      return 'internal error';
  }
}

function formatDuration(ms: number): string {
  return ms < 10_000 ? `${(ms / 1000).toFixed(1)}s` : `${Math.round(ms / 1000)}s`;
}

export function formatTable(outcomes: HostOutcome[]): string {
  const rows = outcomes.map((o) => [o.label, o.result, o.skipped ? '-' : formatDuration(o.durationMs)]);
  const head = ['HOST', 'RESULT', 'TIME'];
  const widths = head.map((h, i) => Math.max(h.length, ...rows.map((r) => (r[i] as string).length)));
  const line = (cells: string[]) => cells.map((c, i) => (i === cells.length - 1 ? c : c.padEnd(widths[i] as number))).join('  ') + '\n';
  return line(head) + rows.map(line).join('');
}

// Exit code rule: 0 only if every host ran and exited 0;
// otherwise the smallest non-zero per-host code, so the most basic failure
// wins (2 auth before 3 connection before 4 remote). Skipped hosts follow
// an auth failure and add nothing.
export function fleetExitCode(outcomes: HostOutcome[]): number {
  const codes = outcomes.filter((o) => !o.skipped && o.code !== EXIT.ok).map((o) => o.code);
  return codes.length === 0 ? EXIT.ok : Math.min(...codes);
}

// --- The run ----------------------------------------------------------

function wait(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms).unref());
}

export async function runFleet(hosts: FleetHost[], cmd: string, args: string[], opts: FleetOptions): Promise<FleetRun> {
  const now = opts.now ?? Date.now;
  const scrub = opts.redact ?? ((t: string) => t);
  const width = Math.max(...hosts.map((h) => h.label.length));
  const outcomes: Array<HostOutcome | undefined> = new Array(hosts.length);
  const open = new Set<FleetClient>();
  const closeMs = opts.closeTimeoutMs ?? 3000;
  let authFailedOn: string | undefined;

  const runHost = async (h: FleetHost): Promise<HostOutcome> => {
    const start = now();
    const prefix = `${h.label.padEnd(width)} | `;
    const out = new LinePrefixer(prefix, (t) => opts.io.stdout.write(t));
    const err = new LinePrefixer(prefix, (t) => opts.io.stderr.write(t));
    let stdout = '';
    let stderr = '';
    let exitCode: number | null = null;
    const client = opts.connect(h);
    open.add(client);
    try {
      const it = client.runStream(cmd, args, { signal: opts.signal })[Symbol.asyncIterator]();
      for (;;) {
        const r = await it.next();
        if (r.done) {
          const end = r.value as { exitCode?: number | null } | undefined;
          exitCode = typeof end?.exitCode === 'number' ? end.exitCode : null;
          break;
        }
        const chunk = r.value;
        if (chunk.stream === 'stdout') {
          if (opts.json) stdout += chunk.data;
          else out.push(chunk.data);
        } else if (opts.json) stderr += chunk.data;
        else err.push(chunk.data);
      }
      if (exitCode === null) throw new Error('the server sent no exit code');
      const code = exitCode === 0 ? EXIT.ok : EXIT.remote;
      return { host: h.host, label: h.label, exitCode, stdout, stderr, durationMs: now() - start, code, result: resultText(code, exitCode) };
    } catch (e) {
      const code = e instanceof WinRMAbortError ? EXIT.interrupted : exitCodeFor(e);
      const name = e instanceof Error ? e.name : 'Error';
      const message = scrub(e instanceof Error ? e.message : String(e));
      if (code === EXIT.auth && authFailedOn === undefined) authFailedOn = h.label;
      return {
        host: h.host,
        label: h.label,
        exitCode: null,
        stdout,
        stderr,
        durationMs: now() - start,
        error: { name, message, exitCode: code },
        code,
        result: resultText(code, null, message),
      };
    } finally {
      out.flush();
      err.flush();
      await Promise.race([client.close().catch(() => undefined), wait(closeMs)]);
      open.delete(client);
    }
  };

  const report = (o: HostOutcome) => {
    if (opts.json) {
      const line: Record<string, unknown> = {
        host: o.host,
        label: o.label,
        exitCode: o.exitCode,
        stdout: o.stdout,
        stderr: o.stderr,
        durationMs: o.durationMs,
      };
      if (o.error) line.error = o.error;
      opts.io.stdout.write(JSON.stringify(line) + '\n');
    } else if (o.error && !o.skipped && o.code !== EXIT.interrupted) {
      opts.io.stderr.write(`${h(o.label)}winlinux: ${o.error.name}: ${o.error.message}\n`);
    }
  };
  const h = (label: string) => `${label.padEnd(width)} | `;

  let next = 0;
  const worker = async () => {
    while (next < hosts.length && !opts.signal?.aborted) {
      const index = next++;
      const host = hosts[index] as FleetHost;
      // Account-lockout guard: after one auth failure no new host starts,
      // so a wrong password costs one failed sign-in, not one per host.
      if (authFailedOn !== undefined) {
        const o: HostOutcome = {
          host: host.host,
          label: host.label,
          exitCode: null,
          stdout: '',
          stderr: '',
          durationMs: 0,
          code: EXIT.auth,
          result: `skipped (auth failed on ${authFailedOn})`,
          skipped: true,
          error: { name: 'WinLinuxSkipped', message: `not started: auth failed on ${authFailedOn}`, exitCode: EXIT.auth },
        };
        outcomes[index] = o;
        report(o);
        continue;
      }
      const o = await runHost(host);
      outcomes[index] = o;
      report(o);
    }
  };
  const parallel = Math.max(1, Math.min(opts.parallel, hosts.length));
  const all = Promise.all(Array.from({ length: parallel }, worker));
  // Ctrl+C: the abort stops new hosts and cuts the running commands. Every
  // client is closed within closeMs of it, even one stuck in its open.
  const bounded = new Promise<void>((resolve) => {
    if (!opts.signal) return;
    const onAbort = () => void wait(closeMs).then(resolve);
    if (opts.signal.aborted) onAbort();
    else opts.signal.addEventListener('abort', onAbort, { once: true });
  });
  await Promise.race([all, bounded]);
  for (const client of open) void client.close().catch(() => undefined);

  const done = outcomes.filter((o): o is HostOutcome => o !== undefined);
  if (opts.signal?.aborted) {
    const finished = done.filter((o) => o.code !== EXIT.interrupted);
    if (!opts.json && finished.length > 0) opts.io.stderr.write(formatTable(finished));
    return { outcomes: done, exitCode: EXIT.interrupted };
  }
  if (!opts.json) opts.io.stderr.write(formatTable(done));
  return { outcomes: done, exitCode: fleetExitCode(done) };
}
