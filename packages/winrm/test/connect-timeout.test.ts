// WinRM connect timeout: a new connection must finish TCP connect,
// plus the TLS handshake over HTTPS, within connectTimeoutMs (default 10 s).
// The stalled peer is a TCP server that accepts and never says anything, so
// the TLS handshake never completes. No real network.
import { describe, it, mock } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { readFileSync } from 'node:fs';
import { WinRMTransport, DEFAULT_CONNECT_TIMEOUT_MS } from '../src/winrm/transport.js';
import { startMockServer } from './helpers/mock-server.js';

const basic = {
  mechanism: 'basic' as const,
  createContext: () => ({ complete: true, step: async () => ({ output: Buffer.from('dTpw'), complete: true }) }),
};

async function silentServer(): Promise<{ port: number; connections: () => number; close: () => Promise<void> }> {
  const sockets = new Set<net.Socket>();
  let count = 0;
  const server = net.createServer((s) => {
    count += 1;
    sockets.add(s);
    s.on('error', () => undefined);
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  return {
    port: (server.address() as net.AddressInfo).port,
    connections: () => count,
    close: () =>
      new Promise<void>((resolve) => {
        for (const s of sockets) s.destroy();
        server.close(() => resolve());
      }),
  };
}

const transport = (port: number, tls: boolean, connectTimeoutMs?: number) =>
  new WinRMTransport({
    host: '127.0.0.1',
    port,
    tls,
    tlsVerify: false,
    authProvider: basic,
    credentials: { username: 'u', password: 'p' },
    ...(connectTimeoutMs !== undefined ? { connectTimeoutMs } : {}),
  });

describe('WinRM connect timeout', () => {
  it('the default is 10 s', () => {
    assert.equal(DEFAULT_CONNECT_TIMEOUT_MS, 10_000);
  });

  it('a TLS handshake that never completes fails after connectTimeoutMs with ETIMEDOUT', async () => {
    const server = await silentServer();
    try {
      const t = transport(server.port, true, 200);
      const start = Date.now();
      await assert.rejects(t.post('<x/>'), (err: Error & { code?: string; connectTimeout?: boolean }) => {
        assert.equal(err.code, 'ETIMEDOUT');
        assert.equal(err.connectTimeout, true);
        assert.equal(err.message, `timed out connecting to 127.0.0.1:${server.port} after 200 ms`);
        return true;
      });
      assert.ok(Date.now() - start < 5000, 'far below the 90 s request timeout');
      await t.close();
    } finally {
      await server.close();
    }
  });

  it('with the default, the timeout fires at 10 s (fake timers)', async () => {
    const server = await silentServer();
    mock.timers.enable({ apis: ['setTimeout'] });
    try {
      const t = transport(server.port, true);
      const state: { err?: Error } = {};
      const p = t.post('<x/>').catch((err: Error) => (state.err = err));
      for (let i = 0; i < 200 && server.connections() === 0; i++) await new Promise((r) => setImmediate(r));
      assert.equal(server.connections(), 1, 'TCP connected');
      mock.timers.tick(9_999);
      await new Promise((r) => setImmediate(r));
      assert.equal(state.err, undefined, 'still waiting at 9.999 s');
      mock.timers.tick(1);
      await p;
      const err = (state as { err?: Error }).err;
      assert.match(err?.message ?? '', /^timed out connecting to 127\.0\.0\.1:\d+ after 10 s$/);
      await t.close();
    } finally {
      mock.timers.reset();
      await server.close();
    }
  });

  it('a connected HTTPS server that is slow to answer is not cut by the connect timeout', async () => {
    const fixture = (name: string) => readFileSync(new URL(`./fixtures/${name}`, import.meta.url));
    const server = await startMockServer(
      async () => {
        await new Promise((r) => setTimeout(r, 300));
        return { status: 200, headers: { 'Content-Type': 'application/soap+xml;charset=UTF-8' }, body: '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body/></s:Envelope>' };
      },
      { tls: { cert: fixture('tls-test-cert.pem'), key: fixture('tls-test-key.pem') } },
    );
    try {
      const t = transport(server.port, true, 100);
      assert.match(await t.post('<x/>'), /Envelope/);
      await t.close();
    } finally {
      await server.close();
    }
  });
});
