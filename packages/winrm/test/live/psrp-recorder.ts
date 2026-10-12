// The fixture recorder of the PSRP runners: WINLINUX_PSRP_RECORD=<dir>
// writes every decrypted SOAP request and response and every decoded PSRP
// message of a pool, redacted, as numbered files. Read by the test runners
// only; the CLI never records.
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import type { PsrpTraceEvent } from '../../src/winrm/index.js';
import { messageTypeName } from '../../src/winrm/psrp/messages.js';
import { redactText, type RedactNames } from './redact.js';

export interface Recorder {
  trace(event: PsrpTraceEvent): void;
  files: string[];
}

export function createRecorder(dir: string, label: string, names: RedactNames): Recorder {
  mkdirSync(dir, { recursive: true });
  let n = 0;
  const files: string[] = [];
  const write = (suffix: string, text: string) => {
    const file = join(dir, `${label}-${String(++n).padStart(4, '0')}-${suffix}`);
    writeFileSync(file, redactText(text, names));
    files.push(file);
  };
  return {
    files,
    trace(event) {
      if (event.kind === 'request') write('request.xml', event.soap);
      else if (event.kind === 'response') write('response.xml', event.soap);
      else if (event.kind === 'fault') write('fault.txt', event.error instanceof Error ? `${event.error.name}: ${event.error.message}` : String(event.error));
      else write(`${event.direction}-${messageTypeName(event.message.messageType)}.xml`, event.message.data);
    },
  };
}

export function recorderFromEnv(env: NodeJS.ProcessEnv, label: string): Recorder | undefined {
  const dir = env['WINLINUX_PSRP_RECORD'];
  if (!dir) return undefined;
  return createRecorder(dir, label, { host: env['WINRM_HOST'], domain: env['WINRM_DOMAIN'], user: env['WINRM_USER'] });
}
