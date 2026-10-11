// In-process CLI checks: the env password is removed after it is read, and
// the error printer scrubs the password from every part of the cause chain.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { PassThrough } from 'node:stream';
import { printError, runCli, type Io } from '../../dist/cli/app.js';
import { WinLinuxAuthError } from '../../dist/index.js';

const SENTINEL = 'Print-Error-Sentinel-7Hk2';
const USER = 'alice';
const NEEDLES = [
  SENTINEL,
  Buffer.from(SENTINEL, 'utf8').toString('base64'),
  Buffer.from(`${USER}:${SENTINEL}`, 'utf8').toString('base64'),
];

function capture(env: NodeJS.ProcessEnv = {}): { io: Io; out: () => string; err: () => string } {
  const stdout = new PassThrough();
  const stderr = new PassThrough();
  let out = '';
  let err = '';
  stdout.on('data', (d: Buffer) => (out += d.toString()));
  stderr.on('data', (d: Buffer) => (err += d.toString()));
  return { io: { env, stdin: process.stdin, stdout, stderr }, out: () => out, err: () => err };
}

describe('CLI password handling', () => {
  it('removes WINLINUX_PASSWORD from the environment after reading it', async () => {
    const server = net.createServer();
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = (server.address() as net.AddressInfo).port;
    await new Promise<void>((resolve) => server.close(() => resolve()));

    process.env.WINLINUX_PASSWORD = SENTINEL;
    try {
      const { io, err } = capture(process.env);
      const code = await runCli(['run', '-a', 'ntlm', '--winrm-port', String(port), `${USER}@127.0.0.1`, 'hostname'], io);
      assert.equal(code, 3, err());
      assert.equal(process.env.WINLINUX_PASSWORD, undefined, 'child processes such as kinit cannot inherit it');
      assert.equal('WINLINUX_PASSWORD' in process.env, false);
    } finally {
      delete process.env.WINLINUX_PASSWORD;
    }
  });

  it('printError scrubs the message, every cause message and every stack', () => {
    const root = new Error(`socket said ${NEEDLES[0]}`);
    root.stack = `Error: socket said ${NEEDLES[0]}\n    at frame (${NEEDLES[1]}.js:1:1)`;
    const middle = new Error(`provider sent Basic ${NEEDLES[2]}`, { cause: root });
    middle.stack = `Error: provider sent Basic ${NEEDLES[2]}\n    at other (file:///${NEEDLES[0]}/x.js:2:2)`;
    const top = new WinLinuxAuthError(`winrm authentication failed: ${NEEDLES[1]}`, 'winrm', 'basic', { cause: middle });
    for (const opts of [
      { json: false, verbose: true },
      { json: true, verbose: true },
      { json: true, verbose: false },
      { json: false, verbose: false },
    ]) {
      const { io, err } = capture();
      const code = printError(top, io, { username: USER, password: SENTINEL }, opts);
      assert.equal(code, 2);
      const text = err();
      for (const needle of NEEDLES) assert.ok(!text.includes(needle), `${JSON.stringify(opts)} leaks ${needle}:\n${text}`);
      if (opts.verbose) {
        assert.match(text, /winlinux: cause: Error: provider sent Basic \*\*\*/);
        assert.match(text, /winlinux: cause: Error: socket said \*\*\*/);
        assert.match(text, /at frame \(\*\*\*\.js:1:1\)/);
      }
      if (opts.json) {
        const first = JSON.parse(text.split('\n')[0] ?? '') as { error: { name: string; message: string; exitCode: number } };
        assert.deepEqual(first.error, { name: 'WinLinuxAuthError', message: 'winrm authentication failed: ***', exitCode: 2 });
      }
    }
  });
});
