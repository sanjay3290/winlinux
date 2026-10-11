import { XMLParser } from 'fast-xml-parser';
import type { EventRecord, ProcessInfo, ServiceInfo } from './index.js';
import { WinRMProtocolError } from './errors.js';

function parseJsonArray(stdout: string, what: string): Array<Record<string, unknown>> {
  if (stdout.trim() === '') return [];
  let parsed: unknown;
  try {
    parsed = JSON.parse(stdout);
  } catch {
    throw new WinRMProtocolError(`WinRM ${what} query returned invalid JSON`);
  }
  const items = Array.isArray(parsed) ? parsed : [parsed];
  for (const item of items) {
    if (typeof item !== 'object' || item === null) {
      throw new WinRMProtocolError(`WinRM ${what} query returned an unexpected JSON shape`);
    }
  }
  return items as Array<Record<string, unknown>>;
}

function str(value: unknown): string {
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  return '';
}

function num(value: unknown): number {
  const n = typeof value === 'number' ? value : Number(value);
  return Number.isFinite(n) ? n : 0;
}

// ConvertTo-Json on Windows PowerShell 5.1 (the default powershell.exe on
// every Windows Server) writes a DateTime as "\/Date(<ms since epoch>)\/",
// with an optional "+hhmm" offset after the digits for a Local kind;
// PowerShell 7 writes ISO-8601. The ms value is always UTC, so the
// offset only carries the server's zone and does not change the instant.
const JSON_NET_DATE = /^\/Date\((-?\d+)(?:[+-]\d{4})?\)\/$/;

function parseJsonDate(raw: string): Date | null {
  const m = JSON_NET_DATE.exec(raw.trim());
  const parsed = m ? new Date(Number(m[1])) : new Date(raw);
  return Number.isNaN(parsed.getTime()) ? null : parsed;
}

export function mapEventRecords(stdout: string): EventRecord[] {
  return parseJsonArray(stdout, 'event log').map((e) => {
    const raw = str(e['TimeCreated']);
    const parsed = parseJsonDate(raw);
    return {
      timeCreated: parsed === null ? raw : parsed.toISOString(),
      id: num(e['Id']),
      level: str(e['LevelDisplayName']),
      provider: str(e['ProviderName']),
      message: str(e['Message']),
    };
  });
}

// ServiceControllerStatus (System.ServiceProcess) numeric values.
const SERVICE_STATUS: Record<number, string> = {
  1: 'Stopped',
  2: 'StartPending',
  3: 'StopPending',
  4: 'Running',
  5: 'ContinuePending',
  6: 'PausePending',
  7: 'Paused',
};

// ServiceStartMode numeric values.
const SERVICE_START_TYPE: Record<number, string> = {
  0: 'Boot',
  1: 'System',
  2: 'Automatic',
  3: 'Manual',
  4: 'Disabled',
};

function mapEnum(value: unknown, table: Record<number, string>): string {
  if (typeof value === 'string') return value;
  const n = num(value);
  return table[n] ?? String(value);
}

export function mapServices(stdout: string): ServiceInfo[] {
  return parseJsonArray(stdout, 'service').map((s) => ({
    name: str(s['Name']),
    displayName: str(s['DisplayName']),
    status: mapEnum(s['Status'], SERVICE_STATUS),
    startType: mapEnum(s['StartType'], SERVICE_START_TYPE),
  }));
}

// Get-Process StartTime renders in the server locale, e.g. "9/11/2026
// 10:24:35 AM" on US English servers. Parse that shape strictly and keep
// the reported wall time without inventing a zone; anything else falls
// back to the raw string. PowerShell 5.1 sends the "\/Date(ms)\/" form
// instead, which is an exact UTC instant.
const US_DATETIME = /^(\d{1,2})\/(\d{1,2})\/(\d{4}) (\d{1,2}):(\d{2}):(\d{2})(?: (AM|PM))?$/;

function mapStartTime(value: unknown): string | null {
  if (value === null || value === undefined) return null;
  if (typeof value !== 'string') return str(value);
  if (JSON_NET_DATE.test(value.trim())) return parseJsonDate(value)?.toISOString() ?? value;
  const m = US_DATETIME.exec(value.trim());
  if (!m) return value;
  let hour = Number(m[4]);
  const ampm = m[7];
  if (ampm === 'PM' && hour < 12) hour += 12;
  if (ampm === 'AM' && hour === 12) hour = 0;
  const p = (n: number | string) => String(n).padStart(2, '0');
  return `${m[3]}-${p(m[1] as string)}-${p(m[2] as string)}T${p(hour)}:${m[5]}:${m[6]}`;
}

export function mapProcesses(stdout: string): ProcessInfo[] {
  return parseJsonArray(stdout, 'process').map((p) => ({
    id: num(p['Id']),
    name: str(p['ProcessName']),
    cpuSeconds: p['CPU'] === null || p['CPU'] === undefined ? null : num(p['CPU']),
    workingSetBytes: num(p['WS']),
    startTime: mapStartTime(p['StartTime']),
  }));
}

const clixmlParser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: '@',
  textNodeName: '#text',
  parseTagValue: false,
  trimValues: false,
  removeNSPrefix: true,
});

// Failing PowerShell writes CLIXML to stderr. Convert it to readable text
// (same approach as pywinrm); pass anything else through untouched.
export function stripCliXml(stderr: string): string {
  if (!stderr.startsWith('#< CLIXML\r\n')) return stderr;
  try {
    const withoutNamespaces = stderr.slice(11).replace(/xmlns\s*=\s*"[^"]*"/g, '');
    const doc = clixmlParser.parse(withoutNamespaces) as Record<string, unknown>;
    const objs = (doc['Objs'] ?? {}) as Record<string, unknown>;
    const nodes = objs['S'];
    const list = Array.isArray(nodes) ? nodes : [nodes];
    let out = '';
    for (const node of list) {
      const text = typeof node === 'string' ? node : (node as Record<string, unknown>)['#text'];
      if (typeof text === 'string') out += text.replace(/_x000D__x000A_/g, '\n');
    }
    return out === '' ? stderr : out.trim();
  } catch {
    return stderr;
  }
}
