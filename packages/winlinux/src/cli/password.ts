// Password sources: -K needs none; then WINLINUX_PASSWORD;
// then a no-echo TTY prompt; otherwise a usage error. Never argv, never a file.
import { WinLinuxUsageError } from '../errors.js';

export const PASSWORD_ENV = 'WINLINUX_PASSWORD';
// The passphrase of an encrypted client key.
export const KEY_PASSPHRASE_ENV = 'WINLINUX_KEY_PASSPHRASE';

export class PromptInterrupted extends Error {
  constructor() {
    super('interrupted');
    this.name = 'PromptInterrupted';
  }
}

export interface PasswordIo {
  env: NodeJS.ProcessEnv;
  stdin: NodeJS.ReadStream;
  stderr: NodeJS.WritableStream;
}

// Reads WINLINUX_PASSWORD once and removes it from the environment, so child
// processes (for example kinit, which gets a copy of process.env) never see it.
export function takeEnvPassword(env: NodeJS.ProcessEnv): string | undefined {
  const value = env[PASSWORD_ENV];
  delete env[PASSWORD_ENV];
  return value || undefined;
}

// Reads WINLINUX_KEY_PASSPHRASE once and removes it from the environment,
// as takeEnvPassword does.
export function takeEnvPassphrase(env: NodeJS.ProcessEnv): string | undefined {
  const value = env[KEY_PASSPHRASE_ENV];
  delete env[KEY_PASSPHRASE_ENV];
  return value || undefined;
}

// A PEM private key that needs a passphrase: PKCS#8 ENCRYPTED PRIVATE KEY,
// or a traditional key with a Proc-Type: 4,ENCRYPTED header.
export function pemKeyIsEncrypted(pem: string): boolean {
  return /-----BEGIN ENCRYPTED PRIVATE KEY-----/.test(pem) || /Proc-Type:\s*4,ENCRYPTED/.test(pem);
}

// The key passphrase: WINLINUX_KEY_PASSPHRASE, else a no-echo prompt,
// else a usage error. Only asked for when the key is encrypted.
export async function resolvePassphrase(fromEnv: string | undefined, io: PasswordIo): Promise<string> {
  if (fromEnv) return fromEnv;
  if (io.stdin.isTTY) return promptPassword(io.stdin, io.stderr, 'Key passphrase: ');
  throw new WinLinuxUsageError(`the client key is encrypted: set ${KEY_PASSPHRASE_ENV} or run in a terminal`);
}

export async function resolvePassword(
  useTicketCache: boolean,
  fromEnv: string | undefined,
  io: PasswordIo,
): Promise<string | undefined> {
  if (useTicketCache) return undefined;
  if (fromEnv) return fromEnv;
  if (io.stdin.isTTY) return promptPassword(io.stdin, io.stderr);
  throw new WinLinuxUsageError(`password required: set ${PASSWORD_ENV}, run in a terminal, or use -K`);
}

// Raw mode: no echo; Enter ends; Backspace deletes; Ctrl+C restores the mode
// and rejects with PromptInterrupted (the caller exits 130).
export function promptPassword(stdin: NodeJS.ReadStream, stderr: NodeJS.WritableStream, label = 'Password: '): Promise<string> {
  return new Promise<string>((resolve, reject) => {
    let value = '';
    const wasRaw = stdin.isRaw;
    // Raw mode (no echo) before the prompt: a key typed as soon as the
    // prompt appears must never be echoed by the terminal.
    stdin.setRawMode(true);
    stderr.write(label);
    stdin.setEncoding('utf8');
    stdin.resume();
    const finish = (err: Error | null) => {
      stdin.removeListener('data', onData);
      stdin.setRawMode(wasRaw);
      stdin.pause();
      stderr.write('\n');
      if (err) reject(err);
      else resolve(value);
    };
    const onData = (chunk: string) => {
      for (const ch of chunk) {
        if (ch === '\r' || ch === '\n') return finish(null);
        if (ch === '\u0003') return finish(new PromptInterrupted());
        if (ch === '\u0004') {
          if (value.length === 0) return finish(new PromptInterrupted());
          continue;
        }
        if (ch === '\u007f' || ch === '\b') {
          value = Array.from(value).slice(0, -1).join('');
          continue;
        }
        if (ch < ' ') continue; // other control keys
        value += ch;
      }
    };
    stdin.on('data', onData);
  });
}
