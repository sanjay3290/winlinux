// WinRM connect timeout in the facade and the CLI. The stalled peer
// is a local TCP server that accepts and never answers the TLS handshake.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { chmod, mkdir, mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { connect, WinLinuxUsageError } from '../../dist/index.js';
import { createClient } from '../../dist/client.js';
import { HELP, parseConnectTimeout } from '../../dist/cli/app.js';
import { parseConfig } from '../../dist/cli/config.js';
import { fakeDeps } from '../helpers/fakes.js';
import { runCli } from '../helpers/cli.js';

async function silentServer(): Promise<{ port: number; close: () => Promise<void> }> {
  const sockets = new Set<net.Socket>();
  const server = net.createServer((s) => {
    sockets.add(s);
    s.on('error', () => undefined);
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  return {
    port: (server.address() as net.AddressInfo).port,
    close: () =>
      new Promise<void>((resolve) => {
        for (const s of sockets) s.destroy();
        server.close(() => resolve());
      }),
  };
}

describe('connect timeout: options', () => {
  it('winrm.connectTimeoutMs reaches winrm; it is validated', async () => {
    const deps = fakeDeps({});
    const client = createClient('h.example.test', { username: 'u', password: 'p', winrm: { tls: true, connectTimeoutMs: 2500 } }, deps);
    await client.run('x');
    assert.equal(deps.winrmOpens[0]?.connectTimeoutMs, 2500);
    await client.close();
    for (const bad of [0, -1, 1.5, 600_001]) {
      await assert.rejects(connect('h', { username: 'u', password: 'p', winrm: { connectTimeoutMs: bad } }), (e: Error) => e instanceof WinLinuxUsageError && /connectTimeoutMs/.test(e.message));
    }
  });

  it('--connect-timeout takes seconds from 0.1 to 600', () => {
    assert.equal(parseConnectTimeout('10'), 10_000);
    assert.equal(parseConnectTimeout('0.25'), 250);
    assert.equal(parseConnectTimeout('600'), 600_000);
    for (const bad of ['0', '0.05', '601', 'x', '-1', '1e3']) assert.throws(() => parseConnectTimeout(bad), /--connect-timeout must be a number of seconds from 0\.1 to 600/);
    assert.match(HELP, /--connect-timeout <s>/);
  });

  it('the ConnectTimeout profile key takes seconds', () => {
    assert.equal(parseConfig('Host a\n  ConnectTimeout 3\n', '/c').blocks[0]?.settings.connectTimeout, 3000);
    assert.throws(() => parseConfig('Host a\n  ConnectTimeout soon\n', '/c'), /:2: ConnectTimeout must be a number of seconds/);
  });
});

describe('connect timeout: CLI end to end', () => {
  it('run fails after the timeout with a connection error, exit 3', async () => {
    const server = await silentServer();
    try {
      const start = Date.now();
      const r = await runCli(['run', '-a', 'basic', '--tls', '--insecure', '--winrm-port', String(server.port), '--connect-timeout', '0.3', 'u@127.0.0.1', 'hostname'], { WINLINUX_PASSWORD: 'Connect-Timeout-Sentinel-Pw' });
      assert.equal(r.code, 3, r.stderr);
      assert.match(r.stderr, new RegExp(`WinLinuxConnectionError: .*timed out connecting to 127\\.0\\.0\\.1:${server.port} after 300 ms`));
      assert.ok(Date.now() - start < 10_000);
    } finally {
      await server.close();
    }
  });

  it('run --hosts shows the timeout in the RESULT column; the profile key sets it', async () => {
    const server = await silentServer();
    try {
      const home = await mkdtemp(join(tmpdir(), 'winlinux-home-'));
      await mkdir(join(home, '.winlinux'));
      await writeFile(
        join(home, '.winlinux', 'config'),
        `Host dead\n  HostName 127.0.0.1\n  User u\n  Auth basic\n  TLS yes\n  Insecure yes\n  WinRMPort ${server.port}\n  ConnectTimeout 0.3\n`,
      );
      await chmod(join(home, '.winlinux', 'config'), 0o600);
      const r = await runCli(['run', '--hosts', 'dead', '--', 'hostname'], { HOME: home, WINLINUX_PASSWORD: 'Connect-Timeout-Sentinel-Pw' });
      assert.equal(r.code, 3, r.stderr);
      assert.match(r.stderr, /\ndead +connect timeout \(300 ms\) +\d/);
    } finally {
      await server.close();
    }
  });
});
