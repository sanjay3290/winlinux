// HTTP.sys asks for the client certificate after the TLS handshake
// (a renegotiation in TLS 1.2; post-handshake auth in TLS 1.3, which Node's
// client does not offer). This mock does the same: the handshake asks for
// no certificate; the first request triggers a renegotiation that asks for
// one. Certificate sign-in caps its connection at TLS 1.2, so the
// renegotiation runs; other mechanisms keep TLS 1.3.
// Limit of the mock: Node's server cannot read a client certificate that
// arrives in a renegotiation (getPeerCertificate stays empty, even with
// openssl s_client as the client). So this file checks the protocol and
// the renegotiation, and client-certificate.test.ts checks the certificate
// itself in the handshake. A live check against Windows proves the two
// together.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import https from 'node:https';
import type { TLSSocket } from 'node:tls';
import type { AddressInfo } from 'node:net';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { connect } from '../src/winrm/index.js';
import { CERTIFICATE_AUTH_HEADER } from '../src/winrm/transport.js';
import { actionOf } from './helpers/mock-server.js';

const fixture = (name: string) => readFileSync(fileURLToPath(new URL(`./fixtures/${name}`, import.meta.url)), 'utf8');
const CERT = Buffer.from(fixture('client-cert/client-cert.pem'));
const KEY = Buffer.from(fixture('client-cert/client-key.pem'));
const SIGNAL = '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><rsp:SignalResponse xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell"/></s:Body></s:Envelope>';
const DELETE = '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><x:DeleteResponse xmlns:x="http://schemas.xmlsoap.org/ws/2004/09/transfer"/></s:Body></s:Envelope>';

interface Seen {
  protocols: string[];
  renegotiations: number;
  renegotiationErrors: string[];
  authorization: Array<string | undefined>;
}

// Like HTTP.sys without clientcertnegotiation=enable.
async function lateCertServer(): Promise<{ port: number; seen: Seen; close: () => Promise<void> }> {
  const seen: Seen = { protocols: [], renegotiations: 0, renegotiationErrors: [], authorization: [] };
  const server = https.createServer(
    { cert: fixture('tls-test-cert.pem'), key: fixture('tls-test-key.pem'), ca: fixture('client-cert/ca-cert.pem'), requestCert: false },
    (req, res) => {
      const chunks: Buffer[] = [];
      req.on('data', (c: Buffer) => chunks.push(c));
      req.on('end', () => {
        const socket = req.socket as TLSSocket;
        seen.protocols.push(socket.getProtocol() ?? '');
        seen.authorization.push(req.headers.authorization);
        const answer = () => {
          const action = actionOf(Buffer.concat(chunks));
          const body =
            action === 'Create' ? fixture('create-response.xml') : action === 'Command' ? fixture('command-response.xml') : action === 'Receive' ? fixture('receive-done.xml') : action === 'Signal' ? SIGNAL : DELETE;
          res.writeHead(200, { 'Content-Type': 'application/soap+xml;charset=UTF-8' }).end(body);
        };
        if (socket.getProtocol() === 'TLSv1.2' && seen.renegotiations > 0) return answer();
        // Ask for the certificate now, after the handshake.
        socket.renegotiate({ requestCert: true, rejectUnauthorized: false }, (err) => {
          if (!err) seen.renegotiations += 1;
          if (err) {
            seen.renegotiationErrors.push(err.message);
            res.writeHead(401).end();
            return;
          }
          answer();
        });
      });
    },
  );
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  return {
    port: (server.address() as AddressInfo).port,
    seen,
    close: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  };
}

describe('certificate sign-in when the server asks for the certificate after the handshake', () => {
  it('works: the certificate connection is capped at TLS 1.2 and completes the renegotiation', async () => {
    const server = await lateCertServer();
    try {
      const session = await connect({ host: '127.0.0.1', port: server.port, tls: true, tlsVerify: false, clientCertificate: { cert: CERT, key: KEY } });
      try {
        const result = await session.runCommand('whoami');
        assert.equal(result.exitCode, 3);
      } finally {
        await session.close();
      }
      assert.deepEqual(server.seen.renegotiationErrors, []);
      assert.ok(server.seen.renegotiations >= 1, 'the server asked for the certificate after the handshake');
      assert.ok(server.seen.protocols.every((p) => p === 'TLSv1.2'), server.seen.protocols.join(','));
      assert.ok(server.seen.authorization.every((a) => a === CERTIFICATE_AUTH_HEADER));
    } finally {
      await server.close();
    }
  });

  it('the cause: the same late request over TLS 1.3 cannot get the certificate', async () => {
    const server = await lateCertServer();
    try {
      // A plain HTTPS client with the certificate and Node's default TLS
      // range, as certificate sign-in used to connect.
      const status = await new Promise<number>((resolve, reject) => {
        const req = https.request(
          { host: '127.0.0.1', port: server.port, method: 'POST', path: '/wsman', cert: CERT, key: KEY, rejectUnauthorized: false, headers: { Authorization: CERTIFICATE_AUTH_HEADER } },
          (res) => {
            res.resume();
            res.on('end', () => resolve(res.statusCode ?? 0));
          },
        );
        req.on('error', reject);
        req.end('<x/>');
      });
      assert.equal(status, 401);
      assert.deepEqual(server.seen.protocols, ['TLSv1.3']);
      assert.equal(server.seen.renegotiationErrors.length, 1, 'TLS 1.3 has no renegotiation');
      assert.equal(server.seen.renegotiations, 0);
    } finally {
      await server.close();
    }
  });

  it('other mechanisms keep TLS 1.3', async () => {
    const server = await lateCertServer();
    try {
      const session = await connect({
        host: '127.0.0.1',
        port: server.port,
        tls: true,
        tlsVerify: false,
        authProvider: { mechanism: 'basic', createContext: () => ({ complete: true, step: async () => ({ output: Buffer.from('dTpw'), complete: true }) }) },
        credentials: { username: 'u', password: 'p' },
      });
      try {
        await assert.rejects(session.runCommand('whoami'));
      } finally {
        await session.close();
      }
      assert.ok(server.seen.protocols.length > 0);
      assert.ok(server.seen.protocols.every((p) => p === 'TLSv1.3'), server.seen.protocols.join(','));
    } finally {
      await server.close();
    }
  });
});
