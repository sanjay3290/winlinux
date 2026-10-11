// run --hosts end to end: the built CLI against two WinRM mocks and
// one closed port, with host aliases from a temp HOME.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { chmod, mkdir, mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runCli } from '../helpers/cli.js';
import { doneReceive, startWinrmMock } from '../helpers/winrm-mock.js';

const SENTINEL = 'Cli-Fleet-Sentinel-Pw-29';

async function freePort(): Promise<number> {
  const server = net.createServer();
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = (server.address() as net.AddressInfo).port;
  await new Promise<void>((resolve) => server.close(() => resolve()));
  return port;
}

async function homeWith(config: string): Promise<string> {
  const home = await mkdtemp(join(tmpdir(), 'winlinux-home-'));
  await mkdir(join(home, '.winlinux'));
  await writeFile(join(home, '.winlinux', 'config'), config);
  await chmod(join(home, '.winlinux', 'config'), 0o600);
  return home;
}

function hostBlock(alias: string, port: number): string {
  return [`Host ${alias}`, '    HostName 127.0.0.1', '    User tester', '    Auth basic', '    TLS yes', '    Insecure yes', `    WinRMPort ${port}`, ''].join('\n');
}

describe('cli run --hosts', () => {
  it('two mocks and one closed port: two ok rows, one connection failed, exit 3', async () => {
    const a = await startWinrmMock({ receive: doneReceive('from-a\n', 0), password: SENTINEL });
    const b = await startWinrmMock({ receive: doneReceive('from-b\npartial', 0), password: SENTINEL });
    const closed = await freePort();
    try {
      const home = await homeWith(
        hostBlock('web1', a.port) + hostBlock('web2', b.port) + hostBlock('gone', closed) + 'Group web web1 web2\n',
      );
      const r = await runCli(['run', '--hosts', '@web,gone,web1', '--', 'hostname'], { HOME: home, WINLINUX_PASSWORD: SENTINEL });
      assert.equal(r.code, 3, r.stderr);
      const out = r.stdout.split('\n').filter(Boolean).sort();
      assert.deepEqual(out, ['web1 | from-a', 'web2 | from-b', 'web2 | partial']);
      assert.match(r.stderr, /HOST +RESULT +TIME\n/);
      assert.match(r.stderr, /\nweb1 +ok +\d/);
      assert.match(r.stderr, /\nweb2 +ok +\d/);
      assert.match(r.stderr, /\ngone +connection failed +\d/);
      assert.equal(r.stderr.match(/\nweb1 +ok/g)?.length, 1, 'the duplicate web1 runs once');
      assert.ok(!r.stderr.includes(SENTINEL) && !r.stdout.includes(SENTINEL));
    } finally {
      await a.close();
      await b.close();
    }
  });

  it('--json prints one object per host and no table; a remote exit 2 makes the run exit 4', async () => {
    const a = await startWinrmMock({ receive: doneReceive('x', 2, 'bad') });
    try {
      const home = await homeWith(hostBlock('web1', a.port));
      const r = await runCli(['run', '--json', '--hosts', 'web1', 'cmd'], { HOME: home, WINLINUX_PASSWORD: SENTINEL });
      assert.equal(r.code, 4, r.stderr);
      assert.equal(r.stderr, '');
      const line = JSON.parse(r.stdout) as Record<string, unknown>;
      assert.deepEqual({ ...line, durationMs: 0 }, {
        host: '127.0.0.1',
        label: 'web1',
        exitCode: 2,
        stdout: 'x',
        stderr: 'bad',
        durationMs: 0,
      });
    } finally {
      await a.close();
    }
  });

  it('usage errors come before any host: unknown group, --parallel range, --hosts on another command', async () => {
    const home = await homeWith(hostBlock('web1', 1));
    for (const [argv, message] of [
      [['run', '--hosts', '@nope', 'hostname'], /unknown group @nope/],
      [['run', '--hosts', 'web1', '--parallel', '33', 'hostname'], /--parallel with --hosts must be an integer from 1 to 32/],
      [['ls', '--hosts', 'web1', 'web1', 'C$'], /--hosts applies to run only/],
      [['run', '--parallel', '2', 'tester@web1', 'hostname'], /--parallel with run needs --hosts/],
      [['run', '--hosts', 'web1'], /wrong number of arguments for run/],
    ] as Array<[string[], RegExp]>) {
      const r = await runCli(argv, { HOME: home, WINLINUX_PASSWORD: SENTINEL });
      assert.equal(r.code, 1, `${argv.join(' ')}: ${r.stderr}`);
      assert.match(r.stderr, message);
    }
  });
});
