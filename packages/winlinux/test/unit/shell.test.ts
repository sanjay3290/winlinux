import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { PassThrough } from 'node:stream';
import { SmbAuthError, SmbNotFoundError } from '@winlinux/smb2';
import { WinRMFaultError } from '@winlinux/winrm';
import { createClient } from '../../dist/client.js';
import { runShell, type ShellReader } from '../../dist/cli/shell.js';
import type { Io } from '../../dist/cli/app.js';
import { FakeSmb, FakeWinrm, OK, fakeDeps } from '../helpers/fakes.js';

const FIRST = 'shell-first-password';
const TTY = { isTTY: true } as NodeJS.ReadStream;
const SECOND = 'shell-second-password';

class ScriptedReader implements ShellReader {
  prompts = 0;
  suspends = 0;
  constructor(private readonly lines: string[]) {}
  async next() {
    return this.lines.shift() ?? null;
  }
  prompt() {
    this.prompts += 1;
  }
  clearLine() {}
  async suspend<T>(fn: () => Promise<T>) {
    this.suspends += 1;
    return fn();
  }
  close() {}
}

function capture(stdin: NodeJS.ReadStream = process.stdin): { io: Io; out: () => string; err: () => string } {
  const stdout = new PassThrough();
  const stderr = new PassThrough();
  let out = '';
  let err = '';
  stdout.on('data', (d: Buffer) => (out += d.toString()));
  stderr.on('data', (d: Buffer) => (err += d.toString()));
  return { io: { env: {}, stdin, stdout, stderr }, out: () => out, err: () => err };
}

function failingSmbClient() {
  const deps = fakeDeps({
    smb: async () => {
      throw new SmbAuthError('authentication failed during session setup', 0xc000006d);
    },
  });
  const client = createClient('srv', { username: 'alice', password: FIRST, auth: 'ntlm' }, deps);
  return { client, deps };
}

describe('interactive shell', () => {
  it('re-prompts once after an auth failure, then exits 2 on the second', async () => {
    const { client, deps } = failingSmbClient();
    const reader = new ScriptedReader(['ls C$', 'ls C$', 'ls C$']);
    let asked = 0;
    const { io, err } = capture();
    const code = await runShell(client, io, {
      verbose: false,
      secrets: { username: 'alice', password: FIRST },
      canReprompt: true,
      reader,
      askPassword: async () => {
        asked += 1;
        return SECOND;
      },
    });
    assert.equal(code, 2);
    assert.equal(asked, 1, 'one re-prompt only');
    assert.equal(reader.suspends, 1);
    assert.equal(deps.smbOpens.length, 2, 'one logon per password, no silent retry');
    assert.equal(deps.smbOpens[0]?.credentials.password, FIRST);
    assert.equal(deps.smbOpens[1]?.credentials.password, SECOND);
    assert.equal((err().match(/WinLinuxAuthError/g) ?? []).length, 2);
    assert.ok(!err().includes(FIRST) && !err().includes(SECOND));
  });

  it('exits 2 on an auth failure when stdin is not a TTY', async () => {
    const { client, deps } = failingSmbClient();
    let asked = 0;
    const { io, err } = capture();
    const code = await runShell(client, io, {
      verbose: false,
      secrets: { username: 'alice', password: FIRST },
      canReprompt: false,
      reader: new ScriptedReader(['ls C$', 'ls C$']),
      askPassword: async () => {
        asked += 1;
        return SECOND;
      },
    });
    assert.equal(code, 2);
    assert.equal(asked, 0);
    assert.equal(deps.smbOpens.length, 1);
    assert.match(err(), /winlinux: WinLinuxAuthError: smb authentication failed for srv:445/);
  });

  it('runs commands, streams run output, and exits 0 at end of input', async () => {
    const deps = fakeDeps({});
    const client = createClient('srv', { username: 'alice', password: FIRST, auth: 'ntlm' }, deps);
    const { io, out } = capture(TTY);
    const code = await runShell(client, io, {
      verbose: false,
      secrets: { username: 'alice', password: FIRST },
      canReprompt: false,
      reader: new ScriptedReader(['help', 'hostname', 'ls C$ --json', 'exit', 'never-run']),
    });
    assert.equal(code, 0);
    assert.match(out(), /Commands \(no <target>\)/);
    assert.match(out(), /x\[\]\n$/, 'streamed "x" from run, then [] from ls --json');
    assert.equal(deps.winrmOpens.length, 1);
    assert.equal(deps.smbOpens.length, 1);
  });

  it('non-TTY input exits with the code of the last failing line; a TTY exits 0', async () => {
    const lines = () => new ScriptedReader(['ls C$', 'run', 'ls C$ --bogus', 'hostname']);
    const client = () =>
      createClient('srv', { username: 'alice', password: FIRST, auth: 'ntlm' }, fakeDeps({
        smb: async () => {
          const s = new FakeSmb();
          s.listImpl = async () => Promise.reject(new SmbNotFoundError('no such file or directory', 0xc0000034));
          return s;
        },
      }));
    const opts = (reader: ScriptedReader) => ({ verbose: false, secrets: { username: 'alice', password: FIRST }, canReprompt: false, reader });

    // ls fails with exit 5, bare "run" is a usage error (1), then parseArgs rejects --bogus (1), hostname works.
    const piped = capture();
    assert.equal(await runShell(client(), piped.io, opts(lines())), 1);
    assert.match(piped.err(), /SmbNotFoundError/);

    const onlyFile = capture();
    assert.equal(await runShell(client(), onlyFile.io, opts(new ScriptedReader(['ls C$', 'hostname']))), 5);

    const clean = capture();
    assert.equal(await runShell(client(), clean.io, opts(new ScriptedReader(['hostname']))), 0);

    const tty = capture(TTY);
    assert.equal(await runShell(client(), tty.io, opts(lines())), 0, 'interactive exit status is unchanged');
  });

  it('scripted input runs commands buffered, so a non-zero remote exit counts as 4', async () => {
    const winrm = new FakeWinrm();
    winrm.runImpl = async (cmd) => (cmd === 'false' ? { stdout: 'partial', stderr: 'boom\n', exitCode: 3 } : OK);
    const client = () => createClient('srv', { username: 'alice', password: FIRST, auth: 'ntlm' }, fakeDeps({ winrm: async () => winrm }));
    const opts = (lines: string[]) => ({ verbose: false, secrets: { username: 'alice', password: FIRST }, canReprompt: false, reader: new ScriptedReader(lines) });

    const piped = capture();
    assert.equal(await runShell(client(), piped.io, opts(['false', 'hostname'])), 4, 'the failure is not forgotten by a later success');
    assert.equal(piped.out(), 'partialok');
    assert.equal(piped.err(), 'boom\nwinlinux: remote command exited with code 3\n');

    const usage = capture();
    assert.equal(await runShell(client(), usage.io, opts(['false', 'run'])), 1, 'the last failing line wins');

    const tty = capture(TTY);
    assert.equal(await runShell(client(), tty.io, opts(['false'])), 0, 'interactive: streamed, exit code not shown');
    assert.equal(tty.out(), 'x');
  });

  it('cd persists: later lines run in the tracked directory, in both modes', async () => {
    const home = 'C:\\Users\\winlinux';
    const script = ['cd', 'cd C:\\Windows', 'dir /b win.ini', 'cd ..\\Temp', 'cd', 'cd /d D:', 'run echo "a b"'];
    for (const stdin of [undefined, TTY]) {
      const winrm = new FakeWinrm();
      // `cd` prints the directory the shell was opened in (home when none was given).
      winrm.runImpl = async (cmd, args, cwd) => (cmd === 'cd' || args[1] === 'cd' ? { stdout: `${cwd ?? home}\r\n`, stderr: '', exitCode: 0 } : OK);
      const client = createClient('srv', { username: 'alice', password: FIRST, auth: 'ntlm' }, fakeDeps({ winrm: async () => winrm }));
      const { io, out, err } = capture(stdin);
      const code = await runShell(client, io, { verbose: false, secrets: { username: 'alice', password: FIRST }, canReprompt: false, reader: new ScriptedReader([...script]) });
      assert.equal(code, 0, err());
      const mode = stdin === undefined ? 'scripted' : 'tty';
      const expectOut = stdin === undefined ? `${home}\nokC:\\Temp\nok` : `${home}\nxC:\\Temp\nx`;
      assert.equal(out(), expectOut, mode);
      assert.deepEqual(
        winrm.runs,
        [
          { cmd: 'cd', args: [], cwd: undefined }, // bare cd before any cd <dir>: asks the remote once
          { cmd: 'cmd', args: ['/c', 'cd'], cwd: 'C:\\Windows' }, // the existence check opens a shell there
          { cmd: 'dir', args: ['/b', 'win.ini'], cwd: 'C:\\Windows' },
          { cmd: 'cmd', args: ['/c', 'cd'], cwd: 'C:\\Temp' },
          { cmd: 'cmd', args: ['/c', 'cd'], cwd: 'D:\\' },
          { cmd: 'echo', args: ['a b'], cwd: 'D:\\' },
        ],
        mode,
      );
    }
  });

  it('cd to a missing directory keeps the old one and counts as a failure', async () => {
    const winrm = new FakeWinrm();
    const fault = new WinRMFaultError('WinRM SOAP fault', 's:Receiver', 'w:InternalError', 'The directory name is invalid.', 2147942667, 'SRV', '');
    winrm.runImpl = async (cmd, args, cwd) => {
      if (cwd?.includes('fault')) throw fault; // Create refused the WorkingDirectory
      if (cwd?.includes('silent')) return { stdout: 'C:\\Users\\winlinux\r\n', stderr: '', exitCode: 0 }; // fell back to the default
      if (cmd === 'cd' || args[1] === 'cd') return { stdout: `${cwd ?? 'C:\\Users\\winlinux'}\r\n`, stderr: '', exitCode: 0 };
      return OK;
    };
    const client = createClient('srv', { username: 'alice', password: FIRST, auth: 'ntlm' }, fakeDeps({ winrm: async () => winrm }));
    const { io, out, err } = capture();
    const code = await runShell(client, io, {
      verbose: false,
      secrets: { username: 'alice', password: FIRST },
      canReprompt: false,
      reader: new ScriptedReader(['cd C:\\Windows', 'cd fault', 'cd silent', 'cd', 'hostname']),
    });
    assert.equal(code, 4);
    assert.equal(
      err(),
      'winlinux: cd: no such directory: C:\\Windows\\fault (The directory name is invalid.)\nwinlinux: cd: no such directory: C:\\Windows\\silent\n',
    );
    assert.equal(out(), 'C:\\Windows\nok');
    assert.deepEqual(winrm.runs.at(-1), { cmd: 'hostname', args: [], cwd: 'C:\\Windows' });
  });
});
