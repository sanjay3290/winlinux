// Runs the built winlinux binary in a real pseudo-terminal, through
// a small Python driver on the standard `pty` module: it forks the
// program on a new pty (a new session with the pty as its controlling
// terminal, 80x24), copies its own stdin to the pty and the pty to its
// stdout, and exits with the program's exit code (128 + n for signal n).
// Bytes written here reach the program as keystrokes; its stdout and stderr
// come back merged, with the terminal's echo, as a user would see them.
//
// Not script(1): BSD script on macOS calls tcgetattr on its stdin, and Node
// gives a child a socket for stdin on macOS, so it exits at once ("Operation
// not supported on socket"). The driver never touches its stdin's terminal
// modes, so a pipe or a socket both work, on Linux and macOS alike. python3
// ships with the Xcode Command Line Tools (which the addon already needs)
// and with every Linux image the check uses. No native module.
import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { CLI, EMPTY_HOME } from './cli.js';

export const PTY_DRIVER = `
import errno, fcntl, os, pty, select, struct, sys, termios
argv = sys.argv[1:]
pid, fd = pty.fork()
if pid == 0:
    try:
        fcntl.ioctl(0, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
    except OSError:
        pass
    try:
        os.execvp(argv[0], argv)
    finally:
        os._exit(127)
out = sys.stdout.buffer
stdin_open = True
while True:
    ready, _, _ = select.select([fd] + ([0] if stdin_open else []), [], [])
    if fd in ready:
        try:
            data = os.read(fd, 65536)
        except OSError as e:
            if e.errno != errno.EIO:
                raise
            data = b""
        if not data:
            break
        out.write(data)
        out.flush()
    if stdin_open and 0 in ready:
        data = os.read(0, 65536)
        if data:
            while data:
                data = data[os.write(fd, data):]
        else:
            stdin_open = False
_, status = os.waitpid(pid, 0)
if os.WIFEXITED(status):
    sys.exit(os.WEXITSTATUS(status))
sys.exit(128 + os.WTERMSIG(status))
`;

// The driver needs python3: a missing one fails the run, it is never a skip.
export function assertPtyAvailable(): void {
  const probe = spawnSync('python3', ['-c', PTY_DRIVER, 'sh', '-c', 'test -t 0 && test -t 1 && exit 7'], { stdio: 'pipe' });
  if (probe.error || probe.status !== 7) {
    throw new Error(
      `python3 is needed for the TTY tests (Xcode Command Line Tools on macOS, python3 on Linux): ${probe.error?.message ?? `driver exit ${probe.status}: ${String(probe.stderr ?? '').trim()}`}`,
    );
  }
}

// Strips ANSI control sequences and carriage returns, so assertions see text.
export function plain(text: string): string {
  return text.replace(/\x1b\[[0-9;?]*[A-Za-z]/g, '').replace(/\x1b[>=]/g, '').replace(/\r/g, '');
}

export class PtyCli {
  raw = '';
  readonly exited: Promise<number | null>;
  private readonly child: ChildProcess;
  private cursor = 0;
  private listeners = new Set<() => void>();

  constructor(args: string[], env: Record<string, string> = {}) {
    const argv = [process.execPath, CLI, ...args];
    this.child = spawn('python3', ['-c', PTY_DRIVER, ...argv], {
      env: { PATH: process.env.PATH ?? '', NODE_NO_WARNINGS: '1', TERM: 'xterm', HOME: EMPTY_HOME, ...env },
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    const onData = (d: Buffer) => {
      this.raw += d.toString('utf8');
      for (const listener of this.listeners) listener();
    };
    this.child.stdout!.on('data', onData);
    this.child.stderr!.on('data', onData);
    this.exited = new Promise((resolve) => this.child.on('close', (code) => resolve(code)));
  }

  // All output so far, as text.
  get text(): string {
    return plain(this.raw);
  }

  // Types bytes at the terminal (\r for Enter, \x03 for Ctrl+C, \x04 for Ctrl+D).
  type(keys: string): void {
    this.child.stdin!.write(keys);
  }

  // Waits until `pattern` appears in the output after the previous match,
  // then moves past it. Rejects with the output so far on timeout.
  waitFor(pattern: string | RegExp, timeoutMs = 10000): Promise<string> {
    return new Promise((resolve, reject) => {
      const check = () => {
        const rest = this.text.slice(this.cursor);
        const match = typeof pattern === 'string' ? (rest.includes(pattern) ? { index: rest.indexOf(pattern), 0: pattern } : null) : pattern.exec(rest);
        if (!match) return false;
        const end = this.cursor + match.index + match[0].length;
        const seen = this.text.slice(this.cursor, end);
        this.cursor = end;
        done();
        resolve(seen);
        return true;
      };
      const timer = setTimeout(() => {
        done();
        reject(new Error(`timed out waiting for ${String(pattern)}; output after the last match:\n${this.text.slice(this.cursor)}`));
      }, timeoutMs);
      const done = () => {
        clearTimeout(timer);
        this.listeners.delete(listener);
      };
      const listener = () => void check();
      this.listeners.add(listener);
      check();
    });
  }

  async exitCode(timeoutMs = 15000): Promise<number | null> {
    let timer: NodeJS.Timeout | undefined;
    const timeout = new Promise<never>((_r, reject) => {
      timer = setTimeout(() => {
        this.kill();
        reject(new Error(`the program did not exit; output:\n${this.text}`));
      }, timeoutMs);
    });
    try {
      return await Promise.race([this.exited, timeout]);
    } finally {
      clearTimeout(timer);
    }
  }

  kill(): void {
    this.child.kill('SIGKILL');
  }
}
