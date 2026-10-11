// The interactive shell in a real pseudo-terminal: the TTY-only
// paths that piped-stdin tests cannot reach. The built CLI runs under
// a Python pty driver (test/helpers/pty.ts) against the WinRM mock over TLS
// with Basic auth.
import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';
import type { MockServer } from '../../../winrm/dist/test/helpers/mock-server.js';
import { doneReceive, startWinrmMock } from '../helpers/winrm-mock.js';
import { PtyCli, assertPtyAvailable } from '../helpers/pty.js';

const TARGET = 'tester@127.0.0.1';
const PROMPT = `winlinux ${TARGET}> `;
const RIGHT = 'Pty-Right-Pw-73';

const flags = (port: number) => ['--auth', 'basic', '--tls', '--insecure', '--winrm-port', String(port)];
const commandsOf = (mock: MockServer) =>
  mock.requests.map((q) => q.body.toString('utf8')).filter((b) => b.includes('<rsp:Command>'));

async function withMock(opts: Parameters<typeof startWinrmMock>[0], fn: (mock: MockServer) => Promise<void>): Promise<void> {
  const mock = await startWinrmMock(opts);
  try {
    await fn(mock);
  } finally {
    await mock.close();
  }
}

describe('interactive shell in a pty', { timeout: 60000 }, () => {
  before(() => assertPtyAvailable());

  it('the password prompt does not echo, and the password never reaches the screen', async () => {
    await withMock({ password: RIGHT, receive: doneReceive('srv-01\r\n', 0) }, async (mock) => {
      const pty = new PtyCli(['run', ...flags(mock.port), TARGET, 'hostname']);
      await pty.waitFor('Password: ');
      pty.type(`${RIGHT}\r`);
      await pty.waitFor('srv-01');
      assert.equal(await pty.exitCode(), 0, pty.text);
      assert.ok(!pty.raw.includes(RIGHT), `the password was echoed:\n${pty.text}`);
      assert.ok(!pty.raw.includes('*'), 'no mask characters either');
    });
  });

  it('a wrong password re-prompts once, then a second failure exits 2', async () => {
    await withMock({ password: RIGHT }, async (mock) => {
      const pty = new PtyCli(flags(mock.port).concat(TARGET));
      await pty.waitFor('Password: ');
      pty.type('wrong-one\r');
      await pty.waitFor(PROMPT);
      pty.type('hostname\r');
      await pty.waitFor(/WinLinuxAuthError: winrm authentication failed[^\n]*\n/);
      await pty.waitFor('Password: ');
      pty.type('wrong-two\r');
      await pty.waitFor(PROMPT);
      pty.type('hostname\r');
      await pty.waitFor(/WinLinuxAuthError/);
      assert.equal(await pty.exitCode(), 2, pty.text);
      assert.equal(pty.text.split('Password: ').length - 1, 2, 'asked exactly twice');
      for (const pw of ['wrong-one', 'wrong-two']) assert.ok(!pty.raw.includes(pw), `${pw} reached the screen`);
    });
  });

  it('after one wrong password the right one works, and Ctrl+D exits 0', async () => {
    await withMock({ password: RIGHT, receive: doneReceive('srv-02\r\n', 0) }, async (mock) => {
      const pty = new PtyCli(flags(mock.port).concat(TARGET));
      await pty.waitFor('Password: ');
      pty.type('wrong-one\r');
      await pty.waitFor(PROMPT);
      pty.type('hostname\r');
      await pty.waitFor('Password: ');
      pty.type(`${RIGHT}\r`);
      await pty.waitFor(PROMPT);
      pty.type('hostname\r');
      await pty.waitFor('srv-02');
      await pty.waitFor(PROMPT);
      pty.type('\x04');
      assert.equal(await pty.exitCode(), 0, pty.text);
    });
  });

  it('Ctrl+C at the prompt clears the line; the cleared text never runs', async () => {
    await withMock({ password: RIGHT, receive: doneReceive('srv-03\r\n', 0) }, async (mock) => {
      const pty = new PtyCli(flags(mock.port).concat(TARGET), { WINLINUX_PASSWORD: RIGHT });
      await pty.waitFor(PROMPT);
      pty.type('never-run-this');
      await pty.waitFor('never-run-this');
      pty.type('\x03');
      await pty.waitFor(PROMPT);
      pty.type('hostname\r');
      await pty.waitFor('srv-03');
      await pty.waitFor(PROMPT);
      pty.type('\x04');
      assert.equal(await pty.exitCode(), 0, pty.text);
      const commands = commandsOf(mock);
      assert.equal(commands.length, 1, 'only the hostname line ran');
      assert.ok(commands[0]!.includes('<rsp:Command>hostname</rsp:Command>'));
      assert.ok(!pty.text.includes('interrupted'), 'Ctrl+C at the prompt does not quit');
    });
  });

  it('Ctrl+C during a long run stops the output and the prompt returns', async () => {
    await withMock({ password: RIGHT, hangReceive: true }, async (mock) => {
      const pty = new PtyCli(flags(mock.port).concat(TARGET), { WINLINUX_PASSWORD: RIGHT });
      await pty.waitFor(PROMPT);
      pty.type('ping -t localhost\r');
      // Wait until the command is on the server and its Receive is pending.
      const deadline = Date.now() + 10000;
      while (!mock.requests.some((q) => q.body.toString('utf8').includes('/Receive<')) && Date.now() < deadline) {
        await new Promise((r) => setTimeout(r, 20));
      }
      pty.type('\x03');
      await pty.waitFor(PROMPT);
      pty.type('help\r');
      await pty.waitFor('Commands (no <target>):');
      await pty.waitFor(PROMPT);
      pty.type('exit\r');
      assert.equal(await pty.exitCode(), 0, pty.text);
      assert.ok(!pty.text.includes('interrupted; closing'), 'the shell itself did not quit');
    });
  });

  it('help, then cd and a command that runs in the new directory', async () => {
    await withMock(
      {
        password: RIGHT,
        // First a bare `cd` for the default directory, then `cmd /c cd`
        // run in the new directory as the check, then the dir line.
        receive: (command) =>
          command.includes('<rsp:Command>cd</rsp:Command>')
            ? doneReceive('C:\\Users\\tester\r\n', 0)
            : command.includes('<rsp:Arguments>cd</rsp:Arguments>')
              ? doneReceive('C:\\Windows\r\n', 0)
              : doneReceive('win.ini\r\n', 0),
      },
      async (mock) => {
        const pty = new PtyCli(flags(mock.port).concat(TARGET), { WINLINUX_PASSWORD: RIGHT });
        await pty.waitFor(PROMPT);
        pty.type('help\r');
        await pty.waitFor(/cd \[<dir>\]\s+change \(or print\) the working directory/);
        await pty.waitFor(PROMPT);
        pty.type('cd C:\\Windows\r');
        await pty.waitFor(PROMPT);
        pty.type('dir /b win.ini\r');
        await pty.waitFor('win.ini\n');
        await pty.waitFor(PROMPT);
        pty.type('\x04');
        assert.equal(await pty.exitCode(), 0, pty.text);
        const creates = mock.requests
          .map((q) => q.body.toString('utf8'))
          .filter((b) => b.includes('<rsp:Shell'))
          .map((b) => /<rsp:WorkingDirectory>([^<]*)</.exec(b)?.[1]);
        assert.deepEqual(creates, [undefined, 'C:\\Windows', 'C:\\Windows'], 'the check and the dir line run in C:\\Windows');
      },
    );
  });
});
