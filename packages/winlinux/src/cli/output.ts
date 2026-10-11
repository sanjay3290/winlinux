// Human and --json renderers. The human renderers show every
// string with its control characters escaped; --json keeps them raw.
import type { DirEntry, EventRecord, ShareInfo, CommandResult, ServiceInfo, ProcessInfo, FileStat } from '../index.js';
import { terminalSafe } from '../terminal.js';

export interface JsonDirEntry {
  name: string;
  isDirectory: boolean;
  sizeBytes: string;
  mtime: string;
}

// bigint cannot go through JSON.stringify: sizeBytes becomes a decimal string.
export function dirEntriesToJson(entries: DirEntry[]): JsonDirEntry[] {
  return entries.map((e) => ({
    name: e.name,
    isDirectory: e.isDirectory,
    sizeBytes: e.sizeBytes.toString(10),
    mtime: e.mtime.toISOString(),
  }));
}

// stat: one JSON object; sizeBytes is a decimal string like ls.
export interface JsonStat {
  share: string;
  path: string;
  isDirectory: boolean;
  sizeBytes: string;
  mtime: string;
  atime: string;
  readonly: boolean;
}

export function statToJson(share: string, path: string, info: FileStat): JsonStat {
  return {
    share,
    path,
    isDirectory: info.isDirectory,
    sizeBytes: info.sizeBytes.toString(10),
    mtime: info.mtime.toISOString(),
    atime: info.atime.toISOString(),
    readonly: info.readonly,
  };
}

export function formatStat(share: string, path: string, info: FileStat): string {
  return table(
    ['Type', 'Size', 'Modified', 'Accessed', 'ReadOnly', 'Path'],
    [[info.isDirectory ? 'dir' : 'file', info.sizeBytes.toString(10), info.mtime.toISOString(), info.atime.toISOString(), info.readonly ? 'yes' : 'no', `${share}/${path}`]],
  );
}

export function formatLs(entries: DirEntry[]): string {
  return entries
    .map((e) => `${e.isDirectory ? 'd' : '-'} ${e.sizeBytes.toString(10).padStart(12)} ${e.mtime.toISOString()} ${terminalSafe(e.name)}\n`)
    .join('');
}

function table(header: string[], cells: string[][]): string {
  const rows = cells.map((row) => row.map((cell) => terminalSafe(cell)));
  const widths = header.map((h, i) => Math.max(h.length, ...rows.map((r) => (r[i] ?? '').length)));
  const line = (cells: string[]) =>
    cells
      .map((c, i) => (i === cells.length - 1 ? c : c.padEnd(widths[i] ?? 0)))
      .join('  ')
      .trimEnd() + '\n';
  return line(header) + rows.map(line).join('');
}

export function formatEvents(events: EventRecord[]): string {
  return table(
    ['TimeCreated', 'Level', 'Id', 'Provider', 'Message'],
    events.map((e) => [e.timeCreated, e.level, String(e.id), e.provider, (e.message ?? '').split(/\r?\n/)[0] ?? '']),
  );
}

export function formatShares(shares: ShareInfo[]): string {
  return table(
    ['Name', 'Type', 'Comment'],
    shares.map((s) => [s.name, s.type, s.comment]),
  );
}

export function runJson(result: CommandResult): string {
  return JSON.stringify({ stdout: result.stdout, stderr: result.stderr, exitCode: result.exitCode });
}

export function formatServices(services: ServiceInfo[]): string {
  return table(
    ['Name', 'Status', 'StartType', 'DisplayName'],
    services.map((s) => [s.name, s.status, s.startType, s.displayName]),
  );
}

// CPU(s) with two decimals; blank when the server reported none (an exited
// or access-denied process). WS is the working set in bytes.
export function formatProcesses(processes: ProcessInfo[]): string {
  return table(
    ['PID', 'Name', 'CPU(s)', 'WS', 'StartTime'],
    processes.map((p) => [String(p.id), p.name, p.cpuSeconds === null ? '' : p.cpuSeconds.toFixed(2), String(p.workingSetBytes), p.startTime ?? '']),
  );
}

// Client-side filters for `services` and `ps`: no user text reaches
// the remote script. Name matching is a case-insensitive substring test.
export interface ServiceFilter {
  status?: 'running' | 'stopped';
  name?: string;
}

export function filterServices(services: ServiceInfo[], f: ServiceFilter): ServiceInfo[] {
  const name = f.name?.toLowerCase();
  return services.filter(
    (s) =>
      (f.status === undefined || s.status.toLowerCase() === f.status) &&
      (name === undefined || s.name.toLowerCase().includes(name) || s.displayName.toLowerCase().includes(name)),
  );
}

export function filterProcesses(processes: ProcessInfo[], f: { name?: string }): ProcessInfo[] {
  const name = f.name?.toLowerCase();
  return name === undefined ? processes : processes.filter((p) => p.name.toLowerCase().includes(name));
}
