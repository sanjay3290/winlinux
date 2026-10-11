// WinRM certificate sign-in over HTTPS: a local HTTPS mock that
// asks for a client certificate signed by a test CA. No real host.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { connect, WinRMAuthError, WinRMTransportError } from '../src/winrm/index.js';
import { CERTIFICATE_AUTH_HEADER, WinRMTransport } from '../src/winrm/transport.js';
import { actionOf, startMockServer, type MockHandler } from './helpers/mock-server.js';

const fixture = (name: string) => readFileSync(fileURLToPath(new URL(`./fixtures/${name}`, import.meta.url)), 'utf8');
const CA = fixture('client-cert/ca-cert.pem');
const CERT = Buffer.from(fixture('client-cert/client-cert.pem'));
const KEY = Buffer.from(fixture('client-cert/client-key.pem'));
const ENCRYPTED_KEY = Buffer.from(fixture('client-cert/client-key-encrypted.pem'));
const PASSPHRASE = 'Test-Key-Passphrase-Sentinel';
const SERVER_TLS = { cert: fixture('tls-test-cert.pem'), key: fixture('tls-test-key.pem') };

const SOAP = { 'Content-Type': 'application/soap+xml;charset=UTF-8' };
const SIGNAL_RESPONSE =
  '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body>' +
  '<rsp:SignalResponse xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell"/>' +
  '</s:Body></s:Envelope>';
const DELETE_RESPONSE =
  '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body>' +
  '<x:DeleteResponse xmlns:x="http://schemas.xmlsoap.org/ws/2004/09/transfer"/>' +
  '</s:Body></s:Envelope>';

// A WinRM endpoint that runs one command (Create, Command, Receive done,
// Signal, Delete) and answers 401 to a request without the mutual header.
const winrmHandler: MockHandler = (req) => {
  if (req.headers.authorization !== CERTIFICATE_AUTH_HEADER) return { status: 401 };
  const action = actionOf(req.body);
  const body =
    action === 'Create'
      ? fixture('create-response.xml')
      : action === 'Command'
        ? fixture('command-response.xml')
        : action === 'Receive'
          ? fixture('receive-done.xml')
          : action === 'Signal'
            ? SIGNAL_RESPONSE
            : DELETE_RESPONSE;
  return { status: 200, headers: SOAP, body };
};

async function certServer(handler: MockHandler = winrmHandler, requireCert = true) {
  return startMockServer(handler, { tls: { ...SERVER_TLS, requestCert: true, rejectUnauthorized: requireCert, ca: CA } });
}

describe('WinRM certificate sign-in', () => {
  it('runs a command with the client certificate and the mutual-auth header on every request; no Negotiate', async () => {
    const server = await certServer();
    try {
      const session = await connect({
        host: '127.0.0.1',
        port: server.port,
        tls: true,
        tlsVerify: false,
        clientCertificate: { cert: CERT, key: KEY },
      });
      try {
        const result = await session.runCommand('whoami');
        assert.equal(result.exitCode, 3);
        assert.equal(result.stdout, 'world');
      } finally {
        await session.close();
      }
      assert.ok(server.requests.length >= 3);
      for (const r of server.requests) {
        assert.equal(r.headers.authorization, CERTIFICATE_AUTH_HEADER);
        assert.equal(r.clientCertCN, 'test-user');
      }
    } finally {
      await server.close();
    }
  });

  it('an encrypted key works with its passphrase', async () => {
    const server = await certServer();
    try {
      const session = await connect({
        host: '127.0.0.1',
        port: server.port,
        tls: true,
        tlsVerify: false,
        clientCertificate: { cert: CERT, key: ENCRYPTED_KEY, passphrase: PASSPHRASE },
      });
      try {
        assert.equal((await session.runCommand('whoami')).exitCode, 3);
      } finally {
        await session.close();
      }
    } finally {
      await server.close();
    }
  });

  it('a server that requires a certificate refuses a client without one', async () => {
    const server = await certServer();
    try {
      // A Basic client with no certificate: the TLS handshake fails.
      const session = await connect({
        host: '127.0.0.1',
        port: server.port,
        tls: true,
        tlsVerify: false,
        authProvider: {
          mechanism: 'basic',
          createContext: () => ({
            complete: true,
            step: async () => ({ output: Buffer.from('dTpw'), complete: true }),
          }),
        },
        credentials: { username: 'u', password: 'p' },
      });
      try {
        await assert.rejects(session.runCommand('whoami'));
      } finally {
        await session.close();
      }
      assert.equal(server.requests.length, 0, 'no request got through');
    } finally {
      await server.close();
    }
  });

  it('a TLS alert for the certificate is an auth error with the mapping hint', async () => {
    // The server trusts a different CA, so it refuses our certificate.
    const server = await startMockServer(winrmHandler, {
      tls: { ...SERVER_TLS, requestCert: true, rejectUnauthorized: true, ca: SERVER_TLS.cert },
    });
    try {
      const session = await connect({ host: '127.0.0.1', port: server.port, tls: true, tlsVerify: false, clientCertificate: { cert: CERT, key: KEY } });
      try {
        await assert.rejects(session.runCommand('whoami'), (err: Error) => {
          assert.ok(err instanceof WinRMAuthError, `${err.name}: ${err.message}`);
          assert.match(err.message, /WSMan:\\localhost\\ClientCertificate/);
          return true;
        });
      } finally {
        await session.close();
      }
    } finally {
      await server.close();
    }
  });

  it('HTTP 401 with a certificate is an auth error with the mapping hint', async () => {
    const server = await certServer(() => ({ status: 401 }));
    try {
      const session = await connect({ host: '127.0.0.1', port: server.port, tls: true, tlsVerify: false, clientCertificate: { cert: CERT, key: KEY } });
      try {
        await assert.rejects(session.runCommand('whoami'), (err: Error) => {
          assert.ok(err instanceof WinRMAuthError);
          assert.match(err.message, /HTTP 401.*Auth\/Certificate.*ClientCertificate/);
          return true;
        });
      } finally {
        await session.close();
      }
    } finally {
      await server.close();
    }
  });

  it('refuses certificate sign-in without TLS, and with encryption always, before any socket', () => {
    const base = { host: '127.0.0.1', port: 1, clientCertificate: { cert: CERT, key: KEY } };
    assert.throws(() => new WinRMTransport({ ...base, tls: false }), (e: Error) => e instanceof WinRMTransportError && /needs HTTPS/.test(e.message));
    assert.throws(() => new WinRMTransport({ ...base, tls: true, encryption: 'always' }), /no message encryption/);
  });

  it('without a certificate an authProvider and credentials are still required', () => {
    assert.throws(() => new WinRMTransport({ host: '127.0.0.1', port: 1, tls: true }), /authProvider and credentials, or a clientCertificate/);
  });

  it('a key never appears in an error message', async () => {
    const server = await certServer(() => ({ status: 401 }));
    try {
      const session = await connect({ host: '127.0.0.1', port: server.port, tls: true, tlsVerify: false, clientCertificate: { cert: CERT, key: ENCRYPTED_KEY, passphrase: PASSPHRASE } });
      try {
        await assert.rejects(session.runCommand('whoami'), (err: Error) => {
          assert.ok(!err.message.includes(PASSPHRASE));
          assert.ok(!err.message.includes('PRIVATE KEY'));
          return true;
        });
      } finally {
        await session.close();
      }
    } finally {
      await server.close();
    }
  });
});
