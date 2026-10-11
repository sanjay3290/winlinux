// The interactive shell against the fake Windows endpoint from @winlinux/winrm
// (packages/winrm/test/helpers/fake-windows.ts): real shell state, every
// Command line through the cmd.exe/argv simulator, and a working
// directory per Create that `cd` and `dir` honour.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { runCli } from '../helpers/cli.js';
import { startFakeWindows } from '../../../winrm/dist/test/helpers/fake-windows.js';

const USER = 'tester';
const PASS = 'Shell-Windows-Pw-7';
const ENV = { WINLINUX_PASSWORD: PASS };

function shell(port: number): string[] {
  return ['--auth', 'basic', '--tls', '--insecure', '--winrm-port', String(port), `${USER}@127.0.0.1`];
}

describe('shell against the fake Windows endpoint', () => {
  it("cd persists, dir runs there, a failing line exits 4", async () => {
    const win = await startFakeWindows({ tls: true, username: USER, password: PASS });
    try {
      // dir in the default directory fails (File Not Found), then succeeds after cd.
      const r = await runCli(shell(win.port), ENV, 'cd\ndir /b win.ini\ncd C:\\Windows\ncd\ndir /b win.ini\ncd ..\ncd\n');
      assert.equal(r.code, 4, r.stderr);
      const out = r.stdout.replaceAll(`winlinux ${USER}@127.0.0.1> `, '');
      assert.equal(out, 'C:\\Users\\tester\nC:\\Windows\nwin.ini\r\nC:\\\n');
      assert.equal(r.stderr, 'File Not Found\r\nwinlinux: remote command exited with code 1\n');
      assert.deepEqual(win.workingDirectories(), [
        undefined, // bare cd: the default-directory query, tracked from then on
        'C:\\Users\\tester', // dir
        'C:\\Windows', // the cd check
        'C:\\Windows', // dir
        'C:\\', // the cd .. check
      ]);
      assert.deepEqual(win.openShells(), [], 'every shell was deleted');
    } finally {
      await win.close();
    }
  });

  it('a missing directory is refused on Create and the old one is kept', async () => {
    const win = await startFakeWindows({ tls: true, username: USER, password: PASS });
    try {
      const r = await runCli(shell(win.port), ENV, 'cd C:\\Windows\ncd nope\ncd "C:\\Temp & Files"\ncd\n');
      assert.equal(r.code, 4, r.stderr);
      assert.equal(r.stderr, 'winlinux: cd: no such directory: C:\\Windows\\nope (The directory name is invalid.)\n');
      assert.equal(r.stdout.replaceAll(`winlinux ${USER}@127.0.0.1> `, ''), 'C:\\Temp & Files\n');
      assert.deepEqual(win.workingDirectories(), [undefined, 'C:\\Windows', 'C:\\Windows\\nope', 'C:\\Temp & Files']);
      assert.deepEqual(win.openShells(), []);
    } finally {
      await win.close();
    }
  });
});
