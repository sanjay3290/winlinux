// Kerberos sends no channel binding yet, so over HTTPS
// only a verified certificate ties the AP-REQ to the real server. With
// tlsVerify false a Kerberos provider is refused before any socket, and a
// Negotiate context that picks Kerberos is refused before its first token
// goes out. Plain HTTP (sealed messages) and other mechanisms are unchanged.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { WinRMTransport } from '../src/winrm/transport.js';
import { negotiateGate, startMockServer } from './helpers/mock-server.js';
import { CREDENTIALS, challengeStub, kerberosStub } from './helpers/stub-auth.js';

const pem = (name: string) => readFileSync(new URL(`./fixtures/${name}`, import.meta.url));
const tls = () => ({ cert: pem('tls-test-cert.pem'), key: pem('tls-test-key.pem') });
const REFUSED = /Kerberos refuses --insecure \(tlsVerify false\) over HTTPS/;

describe('Kerberos over unverified TLS', () => {
  it('a Kerberos provider with tls and tlsVerify false is refused before any socket', () => {
    assert.throws(
      () => new WinRMTransport({ host: '127.0.0.1', port: 1, tls: true, tlsVerify: false, authProvider: kerberosStub(), credentials: CREDENTIALS }),
      REFUSED,
    );
  });

  it('a Kerberos provider with a verified certificate, or over plain HTTP, is accepted', () => {
    new WinRMTransport({ host: '127.0.0.1', port: 1, tls: true, authProvider: kerberosStub(), credentials: CREDENTIALS });
    new WinRMTransport({ host: '127.0.0.1', port: 1, tls: false, tlsVerify: false, authProvider: kerberosStub(), credentials: CREDENTIALS });
  });

  it('Negotiate that picks Kerberos is refused before its token reaches the server', async () => {
    const gate = negotiateGate();
    const server = await startMockServer((req) => gate.check(req) ?? { status: 200, body: '<ok/>' }, { tls: tls() });
    const transport = new WinRMTransport({
      host: '127.0.0.1',
      port: server.port,
      tls: true,
      tlsVerify: false,
      authProvider: kerberosStub({ mechanism: 'negotiate' }),
      credentials: CREDENTIALS,
    });
    try {
      await assert.rejects(transport.post('<soap/>'), REFUSED);
    } finally {
      await transport.close();
      await server.close();
    }
    assert.deepEqual(
      server.requests.filter((r) => /^Negotiate \S/.test(r.headers.authorization ?? '')),
      [],
      'no Kerberos token was sent',
    );
  });

  it('Negotiate that does not pick Kerberos still signs in over unverified TLS', async () => {
    const gate = negotiateGate();
    const server = await startMockServer((req) => gate.check(req) ?? { status: 200, body: '<ok/>' }, { tls: tls() });
    const transport = new WinRMTransport({
      host: '127.0.0.1',
      port: server.port,
      tls: true,
      tlsVerify: false,
      authProvider: challengeStub({ mechanism: 'negotiate' }),
      credentials: CREDENTIALS,
    });
    try {
      assert.equal(await transport.post('<soap/>'), '<ok/>');
    } finally {
      await transport.close();
      await server.close();
    }
  });
});
