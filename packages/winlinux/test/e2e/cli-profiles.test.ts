// Host profiles end to end: the built CLI with HOME set to a temp
// directory and the WinRM mock. No real host.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { chmod, mkdir, mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runCli } from '../helpers/cli.js';
import { doneReceive, startWinrmMock } from '../helpers/winrm-mock.js';

const SENTINEL = 'Cli-Profile-Sentinel-Pw-17';

async function homeWith(config: string, mode = 0o600): Promise<string> {
  const home = await mkdtemp(join(tmpdir(), 'winlinux-home-'));
  await mkdir(join(home, '.winlinux'));
  await writeFile(join(home, '.winlinux', 'config'), config);
  await chmod(join(home, '.winlinux', 'config'), mode);
  return home;
}

function basicUser(header: string | string[] | undefined): string | undefined {
  const value = Array.isArray(header) ? header[0] : header;
  if (!value?.startsWith('Basic ')) return undefined;
  const decoded = Buffer.from(value.slice(6), 'base64').toString('utf8');
  return decoded.slice(0, decoded.indexOf(':'));
}

describe('cli host profiles against the winrm mock', () => {
  it('winlinux run web1 -- hostname uses the profile port, TLS and user', async () => {
    const mock = await startWinrmMock({ receive: doneReceive('web1-out\n', 0), password: SENTINEL });
    try {
      const home = await homeWith(
        [
          'Host web1',
          '    HostName 127.0.0.1',
          '    User svc-ops',
          '    Auth basic',
          '    TLS yes',
          '    Insecure yes',
          `    WinRMPort ${mock.port}`,
          '',
        ].join('\n'),
      );
      const r = await runCli(['run', '-v', 'web1', '--', 'hostname'], { HOME: home, WINLINUX_PASSWORD: SENTINEL });
      assert.equal(r.code, 0, r.stderr);
      assert.equal(r.stdout, 'web1-out\n');
      assert.ok(mock.requests.length > 0, 'the mock on the profile port saw the requests (TLS: the mock speaks HTTPS only)');
      assert.ok(mock.requests.every((q) => basicUser(q.headers.authorization) === 'svc-ops'), 'the profile user signs in');
      assert.match(r.stderr, new RegExp(`winlinux: config ${join(home, '.winlinux', 'config').replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`));
      assert.match(r.stderr, /winlinux: config: matched Host web1/);
      assert.match(r.stderr, new RegExp(`winrm open 127\\.0\\.0\\.1:${mock.port} \\(https`));
      assert.ok(!r.stderr.includes(SENTINEL));
    } finally {
      await mock.close();
    }
  });

  it('user@alias overrides User; a flag overrides the profile port', async () => {
    const mock = await startWinrmMock({ receive: doneReceive('ok\n', 0) });
    try {
      const home = await homeWith(
        ['Host web1', '    HostName 127.0.0.1', '    User svc-ops', '    Auth basic', '    TLS yes', '    Insecure yes', '    WinRMPort 1', ''].join('\n'),
      );
      const r = await runCli(['run', '--winrm-port', String(mock.port), 'alice@web1', '--', 'hostname'], {
        HOME: home,
        WINLINUX_PASSWORD: SENTINEL,
      });
      assert.equal(r.code, 0, r.stderr);
      assert.ok(mock.requests.every((q) => basicUser(q.headers.authorization) === 'alice'));
    } finally {
      await mock.close();
    }
  });

  it('an unknown alias, a Password key and a missing -F file exit 1; a 0644 file warns', async () => {
    const home = await homeWith('Host web1\n    User svc-ops\n');
    let r = await runCli(['run', 'db9', '--', 'hostname'], { HOME: home, WINLINUX_PASSWORD: SENTINEL });
    assert.equal(r.code, 1);
    assert.equal(r.stderr, 'winlinux: WinLinuxUsageError: unknown host alias db9\n');

    const bad = await homeWith('Host web1\n    password hunter2\n');
    r = await runCli(['run', 'web1', '--', 'hostname'], { HOME: bad, WINLINUX_PASSWORD: SENTINEL });
    assert.equal(r.code, 1);
    assert.match(r.stderr, /config:2: passwords are never stored in the config file/);
    assert.ok(!r.stderr.includes('hunter2'));

    r = await runCli(['run', '-F', join(home, 'missing'), 'web1', '--', 'hostname'], { HOME: home, WINLINUX_PASSWORD: SENTINEL });
    assert.equal(r.code, 1);
    assert.match(r.stderr, /config file .*missing: no such file/);

    // -F none: the alias is unknown again.
    r = await runCli(['run', '-F', 'none', 'web1', '--', 'hostname'], { HOME: home, WINLINUX_PASSWORD: SENTINEL });
    assert.equal(r.stderr, 'winlinux: WinLinuxUsageError: unknown host alias web1\n');

    const open = await homeWith('Host web1\n    User svc-ops\n', 0o644);
    r = await runCli(['run', 'nope', '--', 'hostname'], { HOME: open, WINLINUX_PASSWORD: SENTINEL });
    const file = join(open, '.winlinux', 'config');
    assert.ok(r.stderr.startsWith(`winlinux: warning: ${file} is accessible by group or others; run chmod 600 ${file}\n`), r.stderr);
  });
});
