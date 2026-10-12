// `winlinux pwsh -c <script>`: one PSRP pipeline, printed
// the way Windows PowerShell prints it, or one JSON value with --json.
import { psValueToJson, type PSErrorRecord, type PSInvocationResult, type PSStreamEvent, type PSValue, type PowerShellSession } from '../index.js';
import { terminalSafe } from '../terminal.js';
import { EXIT } from '../errors.js';
import type { Io } from './app.js';

const RED = '\x1b[31m';
const RESET = '\x1b[0m';
const safe = (text: string) => terminalSafe(text, { newlines: true });

// An error record as Windows PowerShell 5.1 prints a concise error:
// the message, then the category and the id, indented.
export function formatErrorRecord(record: PSErrorRecord): string {
  const lines = [record.message || record.fullyQualifiedErrorId || 'error'];
  if (record.categoryInfo) lines.push(`    + CategoryInfo          : ${record.categoryInfo}`);
  if (record.fullyQualifiedErrorId) lines.push(`    + FullyQualifiedErrorId : ${record.fullyQualifiedErrorId}`);
  return `${lines.map(safe).join('\n')}\n`;
}

export function errorRecordJson(record: PSErrorRecord): Record<string, unknown> {
  return {
    message: record.message,
    fullyQualifiedErrorId: record.fullyQualifiedErrorId,
    category: record.category,
    categoryInfo: record.categoryInfo,
    targetName: record.targetName,
    ...(record.exceptionType !== undefined ? { exceptionType: record.exceptionType } : {}),
    ...(record.scriptStackTrace !== undefined ? { scriptStackTrace: record.scriptStackTrace } : {}),
  };
}

const isRecord = (reason: PSInvocationResult['reason']): reason is PSErrorRecord => reason !== undefined && !(reason instanceof Error);

// The --json value: output objects as toJson gives them, the error records, the
// final state, and the reason of a Failed pipeline.
export function resultJson(result: PSInvocationResult): Record<string, unknown> {
  const out: Record<string, unknown> = {
    output: result.output.map((v) => psValueToJson(v)),
    errors: result.errors.map(errorRecordJson),
    state: result.state,
  };
  if (isRecord(result.reason)) out['reason'] = errorRecordJson(result.reason);
  else if (result.reason instanceof Error) out['reason'] = { message: result.reason.message, name: result.reason.name };
  return out;
}

// Exit code of a pipeline: 0 Completed with no error record,
// 4 Failed or any error record, 130 Stopped.
export function pipelineExitCode(result: PSInvocationResult): number {
  if (result.state === 'Stopped') return EXIT.interrupted;
  if (result.state === 'Failed' || result.errors.length > 0) return EXIT.remote;
  return EXIT.ok;
}

export interface PwshPrinter {
  event(event: PSStreamEvent): void;
  // After the final state: the reason of a Failed pipeline, and a clean
  // line after progress.
  end(result: PSInvocationResult): void;
}

const valueText = (value: PSValue): string => (typeof value === 'string' ? value : value === null ? '' : JSON.stringify(psValueToJson(value)));

// Human output: output lines on stdout, every other stream on stderr with
// its prefix, errors red on a TTY, progress as one redrawn line on a TTY.
export function pwshPrinter(io: Io): PwshPrinter {
  const errTty = (io.stderr as { isTTY?: boolean }).isTTY === true;
  let progressShown = false;
  const clearProgress = () => {
    if (!progressShown) return;
    io.stderr.write('\r\x1b[K');
    progressShown = false;
  };
  const err = (text: string) => {
    clearProgress();
    io.stderr.write(text);
  };
  return {
    event(event) {
      switch (event.stream) {
        case 'output':
          clearProgress();
          io.stdout.write(`${safe(valueText(event.value))}\n`);
          return;
        case 'error': {
          const text = formatErrorRecord(event.record);
          err(errTty ? `${RED}${text.replace(/\n$/, '')}${RESET}\n` : text);
          return;
        }
        case 'warning':
          err(`WARNING: ${safe(event.message)}\n`);
          return;
        case 'verbose':
          err(`VERBOSE: ${safe(event.message)}\n`);
          return;
        case 'debug':
          err(`DEBUG: ${safe(event.message)}\n`);
          return;
        case 'information': {
          // Write-Host text goes to stdout, as the console shows it.
          const data = event.record.messageData;
          const text = typeof data === 'string' ? data : data !== null && typeof data === 'object' && 'adapted' in data ? String(data.adapted.get('Message') ?? data.toStringValue ?? '') : valueText(data);
          clearProgress();
          io.stdout.write(`${safe(text)}\n`);
          return;
        }
        case 'progress': {
          if (!errTty) return;
          const r = event.record;
          const percent = r.percentComplete >= 0 ? ` ${r.percentComplete}%` : '';
          io.stderr.write(`\r\x1b[K${safe(r.activity)}${percent} ${safe(r.statusDescription)}`);
          progressShown = true;
          return;
        }
      }
    },
    end(result) {
      clearProgress();
      if (result.state === 'Failed') {
        if (isRecord(result.reason)) err(errTty ? `${RED}${formatErrorRecord(result.reason).replace(/\n$/, '')}${RESET}\n` : formatErrorRecord(result.reason));
        else err(`winlinux: pipeline failed${result.reason ? `: ${safe(result.reason.message)}` : ''}\n`);
      }
    },
  };
}

// Runs one pipeline in the session and prints it; returns the exit code.
export async function runPwsh(session: PowerShellSession, script: string, io: Io, opts: { json: boolean; signal?: AbortSignal }): Promise<number> {
  const columns = (io.stdout as { isTTY?: boolean; columns?: number }).isTTY === true ? ((io.stdout as { columns?: number }).columns ?? 120) : 120;
  const pipeline = session.invoke(script, { ...(opts.json ? {} : { outString: { width: Math.max(20, columns) } }), ...(opts.signal ? { signal: opts.signal } : {}) });
  if (opts.json) {
    const result = await pipeline.result();
    io.stdout.write(`${JSON.stringify(resultJson(result))}\n`);
    return pipelineExitCode(result);
  }
  const printer = pwshPrinter(io);
  for await (const event of pipeline) printer.event(event);
  const result = await pipeline.result();
  printer.end(result);
  return pipelineExitCode(result);
}
