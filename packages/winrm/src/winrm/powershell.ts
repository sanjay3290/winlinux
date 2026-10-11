import type { EventLogQuery } from './index.js';

const EVENT_SELECT = 'Select-Object TimeCreated,Id,LevelDisplayName,ProviderName,Message';

// PowerShell treats the ASCII apostrophe and four Unicode single quotes
// (U+2018, U+2019, U+201A, U+201B) as single-quote characters. Inside a
// single-quoted string each of them is escaped by doubling it.
const PS_SINGLE_QUOTES = /['\u2018\u2019\u201a\u201b]/g;

// A PowerShell single-quoted literal of `value`: no variable expansion,
// no escape sequences, no subexpressions. Every value that goes into a
// PowerShell script goes through this one helper.
export function psQuote(value: string): string {
  return `'${value.replace(PS_SINGLE_QUOTES, '$&$&')}'`;
}

function pad(n: number): string {
  return String(n).padStart(2, '0');
}

// PowerShell parses 'yyyy-MM-ddTHH:mm:ss' unambiguously. Rendered in UTC;
// the server interprets it in server-local time, which matches for UTC
// servers and stays a documented approximation otherwise.
function formatFilterDate(date: Date): string {
  return (
    `${date.getUTCFullYear()}-${pad(date.getUTCMonth() + 1)}-${pad(date.getUTCDate())}` +
    `T${pad(date.getUTCHours())}:${pad(date.getUTCMinutes())}:${pad(date.getUTCSeconds())}`
  );
}

export function buildEventLogScript(q: EventLogQuery): string {
  const maxEvents = q.maxEvents ?? 100;
  let source: string;
  if (q.level === undefined && q.provider === undefined && q.startTime === undefined) {
    source = `Get-WinEvent -LogName ${psQuote(q.logName)} -MaxEvents ${maxEvents}`;
  } else {
    const parts = [`LogName=${psQuote(q.logName)}`];
    if (q.level !== undefined) parts.push(`Level=${q.level}`);
    if (q.provider !== undefined) parts.push(`ProviderName=${psQuote(q.provider)}`);
    if (q.startTime !== undefined) parts.push(`StartTime=${psQuote(formatFilterDate(q.startTime))}`);
    source = `Get-WinEvent -FilterHashtable @{${parts.join('; ')}} -MaxEvents ${maxEvents}`;
  }
  if (q.oldest) source += ' -Oldest';
  return `@(${source} | ${EVENT_SELECT}) | ConvertTo-Json -Compress -Depth 3`;
}

export function buildServicesScript(): string {
  return 'Get-Service | Select-Object Name,DisplayName,Status,StartType | ConvertTo-Json -Compress -Depth 2';
}

export function buildProcessesScript(): string {
  return 'Get-Process | Select-Object Id,ProcessName,CPU,WS,StartTime | ConvertTo-Json -Compress -Depth 2';
}
