// Interactive shell.
import { createInterface, type Interface } from 'node:readline/promises';
import { parseArgs } from 'node:util';
import { WinRMAbortError, WinRMFaultError } from '@winlinux/winrm';
import { EXIT, WinLinuxAuthError } from '../errors.js';
import { redact, type RedactSecrets } from '../redact.js';
import type { WinLinuxClient } from '../types.js';
import { COMMANDS, LINE_OPTIONS, SHELL_HELP, closeWithin, execute, printError, type Command, type Io } from './app.js';
import { cdTarget, isCd, resolveCd, sameDirectory } from './cwd.js';
import { PromptInterrupted, promptPassword } from './password.js';
import { tokenize } from './tokenize.js';

export interface ShellOptions {
  verbose: boolean;
  secrets: RedactSecrets;
  // True when stdin is a TTY and a password (not -K) is in use: one re-prompt after an auth failure.
  canReprompt: boolean;
  // Test seams; the defaults use readline and the raw-mode prompt.
  reader?: ShellReader;
  askPassword?: () => Promise<string>;
}

// What the shell loop needs from its line source.
export interface ShellReader {
  next(): Promise<string | null>;
  prompt(): void;
  clearLine(): void;
  suspend<T>(fn: () => Promise<T>): Promise<T>;
  close(): void;
}

type State = 'prompt' | 'run' | 'transfer' | 'busy';

// Queues lines from readline so a line typed (or piped) during an operation is not lost.
// The interface can be closed and reopened around a password prompt.
class LineReader implements ShellReader {
  private rl: Interface | undefined;
  private readonly queue: string[] = [];
  private waiter: ((line: string | null) => void) | undefined;
  private ended = false;
  private suspended = false;

  constructor(
    private readonly io: Io,
    private readonly promptText: string,
    private readonly onSigint: () => void,
  ) {
    this.open();
  }

  private open(): void {
    const rl = createInterface({
      input: this.io.stdin,
      output: this.io.stdout,
      terminal: this.io.stdin.isTTY === true,
      prompt: this.promptText,
    });
    rl.on('line', (line) => this.push(line));
    rl.on('close', () => {
      if (this.suspended) return;
      this.ended = true;
      this.push(null);
    });
    rl.on('SIGINT', this.onSigint);
    this.rl = rl;
  }

  private push(line: string | null): void {
    if (this.waiter) {
      const w = this.waiter;
      this.waiter = undefined;
      w(line);
    } else if (line !== null) {
      this.queue.push(line);
    }
  }

  next(): Promise<string | null> {
    const queued = this.queue.shift();
    if (queued !== undefined) return Promise.resolve(queued);
    if (this.ended) return Promise.resolve(null);
    return new Promise((resolve) => (this.waiter = resolve));
  }

  prompt(): void {
    this.rl?.prompt();
  }

  clearLine(): void {
    this.rl?.write(null, { ctrl: true, name: 'u' });
    this.io.stdout.write('\n');
    this.rl?.prompt();
  }

  async suspend<T>(fn: () => Promise<T>): Promise<T> {
    this.suspended = true;
    this.rl?.close();
    this.suspended = false;
    try {
      return await fn();
    } finally {
      this.open();
    }
  }

  close(): void {
    this.suspended = true;
    this.rl?.close();
  }
}

export async function runShell(client: WinLinuxClient, io: Io, opts: ShellOptions): Promise<number> {
  const passwords = opts.secrets.password ? [opts.secrets.password] : [];
  const redactAll = (text: string) =>
    passwords.reduce((out, password) => redact(out, { username: opts.secrets.username, password }), text);
  let authRetried = false;
  const scripted = io.stdin.isTTY !== true;
  // Non-TTY (scripted) input: exit with the code of the last failing line.
  // A non-zero remote exit counts as 4, like the `run` subcommand.
  let lastFailure: number = EXIT.ok;
  // Set by `cd`; undefined until then (lines run in the WinRS default).
  // Later lines open their shell there (rsp:WorkingDirectory).
  let cwd: string | undefined;
  let state: State = 'prompt';
  let abortRun: (() => void) | undefined;
  let warned = false;
  let quitting = false;
  const exit = io.exit ?? (() => undefined);

  const quit = () => {
    if (quitting) return exit(EXIT.interrupted);
    quitting = true;
    io.stderr.write('interrupted; closing\n');
    void closeWithin(client).then(() => exit(EXIT.interrupted));
  };

  const onSigint = () => {
    switch (state) {
      case 'prompt':
        reader.clearLine();
        return;
      case 'run':
        abortRun?.();
        return;
      case 'transfer':
        if (!warned) {
          warned = true;
          io.stderr.write('file transfers cannot be interrupted; press Ctrl+C again to quit\n');
          return;
        }
        return quit();
      case 'busy':
        return quit();
    }
  };

  const reader: ShellReader = opts.reader ?? new LineReader(io, `winlinux ${client.username}@${client.host}> `, onSigint);
  const askPassword = opts.askPassword ?? (() => promptPassword(io.stdin, io.stderr));
  process.on('SIGINT', onSigint);

  const runStreaming = async (cmd: string, args: string[]) => {
    const iterator = client.runStream(cmd, args, { cwd })[Symbol.asyncIterator]();
    const aborted = new Promise<'abort'>((resolve) => (abortRun = () => resolve('abort')));
    try {
      for (;;) {
        const next = iterator.next();
        next.catch(() => undefined); // may settle after an abort
        const result = await Promise.race([next, aborted]);
        if (result === 'abort') {
          // Stop printing now; Signal and Delete finish in the background.
          iterator.return?.(undefined)?.catch(() => undefined);
          io.stdout.write('\n');
          return;
        }
        if (result.done) return;
        (result.value.stream === 'stderr' ? io.stderr : io.stdout).write(result.value.data);
      }
    } finally {
      abortRun = undefined;
    }
  };

  // Scripted input: `client.run` reports the exit code, which the stream does
  // not, so output appears when the command ends rather than live.
  const runBuffered = async (cmd: string, args: string[]) => {
    const abort = new AbortController();
    abortRun = () => abort.abort();
    try {
      const result = await client.run(cmd, args, { cwd, signal: abort.signal });
      io.stdout.write(result.stdout);
      io.stderr.write(result.stderr);
      if (result.exitCode !== 0) {
        io.stderr.write(`winlinux: remote command exited with code ${result.exitCode}\n`);
        lastFailure = EXIT.remote;
      }
    } catch (err) {
      if (!(err instanceof WinRMAbortError)) throw err;
      io.stdout.write('\n');
    } finally {
      abortRun = undefined;
    }
  };

  // Before any `cd <dir>`, the first `cd` asks the remote for its default
  // directory once and tracks it from then on.
  const currentDirectory = async () => {
    if (cwd !== undefined) return cwd;
    const result = await client.run('cd');
    const dir = result.stdout.trim();
    if (!/^[A-Za-z]:\\/.test(dir)) throw new Error(`cannot read the remote working directory: ${result.stderr || dir}`);
    cwd = dir;
    return dir;
  };

  // `cd` is local: resolve the target (cwd.ts), then open a shell there and
  // let cmd.exe print its directory. A missing directory shows up either as
  // a WinRM fault on Create ("The directory name is invalid") or, if the
  // server fell back to its default, as a different directory in the
  // output; both keep the old one. No cmd syntax is sent, so cmd.exe quoting
  // cannot bite. A bare `cd` prints the tracked directory.
  const changeDirectory = async (args: string[]) => {
    const target = cdTarget(args);
    if (target === undefined) {
      io.stdout.write(`${await currentDirectory()}\n`);
      return;
    }
    const resolved = resolveCd(await currentDirectory(), target);
    let detail = '';
    try {
      const result = await client.run('cmd', ['/c', 'cd'], { cwd: resolved });
      if (result.exitCode === 0 && sameDirectory(result.stdout, resolved)) {
        cwd = resolved;
        return;
      }
      detail = result.stderr.trim();
    } catch (err) {
      if (!(err instanceof WinRMFaultError)) throw err;
      detail = err.reason;
    }
    io.stderr.write(`winlinux: cd: no such directory: ${resolved}${detail ? ` (${detail})` : ''}\n`);
    lastFailure = EXIT.remote;
  };

  const handleLine = async (line: string) => {
    const tokens = tokenize(line);
    const head = tokens[0];
    if (head === undefined) return;
    if ((COMMANDS as readonly string[]).includes(head) && head !== 'run') {
      const { values, positionals } = parseArgs({
        args: tokens.slice(1),
        options: LINE_OPTIONS,
        allowPositionals: true,
        strict: true,
      });
      const command = head as Command;
      state = command === 'get' || command === 'put' ? 'transfer' : 'busy';
      const code = await execute(client, command, positionals, values, io);
      if (code !== EXIT.ok) lastFailure = code;
      return;
    }
    let words = head === 'run' ? tokens.slice(1) : tokens;
    if (words[0] === '--') words = words.slice(1);
    const [cmd, ...args] = words;
    if (cmd === undefined) {
      io.stderr.write('winlinux: run needs a command\n');
      lastFailure = EXIT.usage;
      return;
    }
    state = 'run';
    if (isCd(cmd)) return changeDirectory(args);
    await (scripted ? runBuffered : runStreaming)(cmd, args);
  };

  try {
    for (;;) {
      state = 'prompt';
      warned = false;
      reader.prompt();
      const line = await reader.next();
      if (line === null) break;
      const word = line.trim();
      if (word === 'exit' || word === 'quit') break;
      if (word === 'help') {
        io.stdout.write(SHELL_HELP);
        continue;
      }
      try {
        await handleLine(line);
      } catch (err) {
        lastFailure = printError(err, io, { username: opts.secrets.username }, { json: false, verbose: opts.verbose, redact: redactAll });
        if (err instanceof WinLinuxAuthError) {
          // Never retry the same password: ask once for a new one, else stop.
          if (authRetried || !opts.canReprompt) return EXIT.auth;
          authRetried = true;
          const password = await reader.suspend(askPassword);
          passwords.push(password);
          client.setPassword(password);
        }
      }
    }
    return scripted ? lastFailure : EXIT.ok;
  } catch (err) {
    if (err instanceof PromptInterrupted) return EXIT.interrupted;
    throw err;
  } finally {
    process.removeListener('SIGINT', onSigint);
    reader.close();
    await client.close();
  }
}
