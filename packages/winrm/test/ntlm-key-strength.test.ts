// NTLM key strength over WinRM: a CHALLENGE that drops
// NEGOTIATE_128 (a 40- or 56-bit RC4 sealing key) fails the handshake before
// any AUTHENTICATE goes out. With message encryption on, so does one that
// drops NEGOTIATE_SEAL: the first sealed body is built before the request
// that would carry the AUTHENTICATE.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { NtlmAuthProvider } from '@winlinux/auth';
import { WinRMTransport } from '../src/winrm/transport.js';
import { startMockServer } from './helpers/mock-server.js';
import { challengeWithTimestamp, ntlmsspType } from './helpers/ntlm-wire.js';

const F_SEAL = 0x00000020;
const F_128 = 0x20000000;
const F_56 = 0x80000000;

const pem = (name: string) => readFileSync(new URL(`./fixtures/${name}`, import.meta.url));

// The handshake against a server whose CHALLENGE flags lose `drop`:
// message encryption over HTTP, or none over HTTPS.
async function handshake(drop: number, encryption: 'always' | 'never'): Promise<{ error: unknown; authenticates: number }> {
  const tls = encryption === 'never';
  let authenticates = 0;
  const server = await startMockServer((req) => {
    const m = /^Negotiate (.+)$/.exec(req.headers.authorization ?? '');
    if (!m?.[1]) return { status: 401, headers: { 'WWW-Authenticate': 'Negotiate' } };
    const token = Buffer.from(m[1], 'base64');
    if (ntlmsspType(token) === 1) {
      const challenge = challengeWithTimestamp();
      challenge.writeUInt32LE((challenge.readUInt32LE(20) & ~drop) >>> 0, 20);
      return { status: 401, headers: { 'WWW-Authenticate': `Negotiate ${challenge.toString('base64')}` } };
    }
    authenticates += 1;
    return { status: 200, body: '<ok/>' };
  }, tls ? { tls: { cert: pem('tls-test-cert.pem'), key: pem('tls-test-key.pem') } } : undefined);
  const transport = new WinRMTransport({
    host: '127.0.0.1',
    port: server.port,
    tls,
    tlsVerify: false,
    encryption,
    authProvider: new NtlmAuthProvider(),
    credentials: { username: 'User', password: 'Password', domain: 'Domain' },
  });
  let error: unknown;
  try {
    await transport.post('<soap/>');
  } catch (err) {
    error = err;
  } finally {
    await transport.close();
    await server.close();
  }
  return { error, authenticates };
}

describe('NTLM key strength over WinRM', () => {
  for (const [label, drop] of [
    ['NEGOTIATE_128 (56-bit key)', F_128],
    ['NEGOTIATE_128 and NEGOTIATE_56 (40-bit key)', F_128 | F_56],
  ] as const) {
    for (const encryption of ['always', 'never'] as const) {
      it(`a CHALLENGE without ${label} fails before the AUTHENTICATE (encryption ${encryption})`, async () => {
        const { error, authenticates } = await handshake(drop, encryption);
        assert.match(String(error), /128-bit/);
        assert.equal(authenticates, 0, 'no AUTHENTICATE was sent');
      });
    }
  }

  it('with encryption on, a CHALLENGE without NEGOTIATE_SEAL fails before the AUTHENTICATE', async () => {
    const { error, authenticates } = await handshake(F_SEAL, 'always');
    assert.match(String(error), /SEAL/);
    assert.equal(authenticates, 0, 'no AUTHENTICATE was sent');
  });
});
