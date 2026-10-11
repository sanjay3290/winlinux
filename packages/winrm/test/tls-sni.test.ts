// TLS Server Name Indication. RFC 6066 3 forbids an IP address as the
// ServerName, and Node warns (DEP0123) when one is set. This file runs in
// its own process, so the once-per-process warning cannot come from an
// earlier test.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import https from 'node:https';
import type { TLSSocket } from 'node:tls';
import { WinRMTransport } from '../src/winrm/transport.js';
import { basicStub, CREDENTIALS } from './helpers/stub-auth.js';

async function sniServer(): Promise<{ port: number; names: Array<string | false>; close: () => Promise<void> }> {
  const names: Array<string | false> = [];
  const server = https.createServer(
    {
      cert: readFileSync(new URL('./fixtures/tls-test-cert.pem', import.meta.url)),
      key: readFileSync(new URL('./fixtures/tls-test-key.pem', import.meta.url)),
    },
    (req, res) => {
      names.push((req.socket as TLSSocket & { servername: string | false }).servername);
      req.resume();
      req.on('end', () => res.end('<ok/>'));
    },
  );
  await new Promise<void>((resolve) => server.listen(0, resolve));
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('no listen address');
  return {
    port: address.port,
    names,
    close: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  };
}

async function postOnce(host: string, port: number): Promise<void> {
  const transport = new WinRMTransport({ host, port, tls: true, tlsVerify: false, authProvider: basicStub(), credentials: CREDENTIALS });
  try {
    assert.equal(await transport.post('<soap/>'), '<ok/>');
  } finally {
    await transport.close();
  }
}

describe('transport TLS SNI', () => {
  it('sends no SNI and prints no DEP0123 for an IP host', async () => {
    const warnings: string[] = [];
    const onWarning = (w: Error & { code?: string }) => warnings.push(w.code ?? w.message);
    process.on('warning', onWarning);
    const server = await sniServer();
    try {
      await postOnce('127.0.0.1', server.port);
      // Warnings are emitted on the next tick.
      await new Promise((resolve) => setImmediate(resolve));
    } finally {
      process.off('warning', onWarning);
      await server.close();
    }
    assert.deepEqual(server.names, [false]);
    assert.ok(!warnings.includes('DEP0123'), `unexpected warnings: ${warnings.join(', ')}`);
  });

  it('sends the host name as SNI for a DNS host', async () => {
    const server = await sniServer();
    try {
      await postOnce('localhost', server.port);
    } finally {
      await server.close();
    }
    assert.deepEqual(server.names, ['localhost']);
  });
});
