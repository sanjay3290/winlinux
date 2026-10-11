// Bare NTLMSSP in the Negotiate header for NTLM: the SPNEGO frame
// is stripped from outgoing NTLM tokens, Kerberos and Negotiate-Kerberos
// keep theirs, and the fake Windows endpoint refuses a sealed body after
// SPNEGO-wrapped NTLM the way Windows does.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { readFileSync } from 'node:fs';
import { NtlmAuthProvider } from '@winlinux/auth';
import { WinRMProtocolError } from '../src/winrm/errors.js';
import { isNtlmssp, rawNtlmToken } from '../src/winrm/ntlmssp.js';
import { WinRMTransport } from '../src/winrm/transport.js';
import { startFakeWindows } from './helpers/fake-windows.js';
import { mimeUnwrap, mimeWrap, mimeWrapIov, negotiateGate, startMockServer, type MockHandler, type MockResponse } from './helpers/mock-server.js';
import { challengeWithTimestamp, NTLM_STUB, ntlmsspOffset, ntlmsspType, spnegoInit, spnegoResp, tlv, type3AvPairs } from './helpers/ntlm-wire.js';
import { CREDENTIALS, FAKE_KRB_IOV, challengeStub, fakeKrbWrapIov, fakeNtlmUnwrap, fakeNtlmWrap, kerberosStub, KerberosStubSecurityContext, ntlmStub, StubAuthProvider } from './helpers/stub-auth.js';

const B64 = (s: string) => Buffer.from(s).toString('base64');
const RESPONSE_SOAP = '<s:Envelope><s:Body>pong</s:Body></s:Envelope>';

function headerToken(authorization: string | undefined): Buffer {
  const m = /^Negotiate ([A-Za-z0-9+/=]+)$/.exec(authorization ?? '');
  if (!m?.[1]) throw new Error(`no Negotiate token in ${String(authorization)}`);
  return Buffer.from(m[1], 'base64');
}

describe('rawNtlmToken', () => {
  it('unwraps a NegTokenInit to its NTLMSSP NEGOTIATE', () => {
    assert.ok(rawNtlmToken(spnegoInit(NTLM_STUB.initial)).equals(NTLM_STUB.initial));
  });

  it('unwraps a NegTokenResp to its NTLMSSP AUTHENTICATE and drops the mechListMIC', () => {
    const framed = spnegoResp(NTLM_STUB.response, { mechListMIC: Buffer.alloc(16, 7) });
    assert.ok(rawNtlmToken(framed).equals(NTLM_STUB.response));
    assert.ok(rawNtlmToken(spnegoResp(NTLM_STUB.response, { negState: 0 })).equals(NTLM_STUB.response));
  });

  it('unwraps a long-form length frame (a real AUTHENTICATE is over 127 bytes)', () => {
    const big = Buffer.concat([NTLM_STUB.response, Buffer.alloc(300, 0xab)]);
    const framed = spnegoResp(big);
    assert.equal(framed[1], 0x82, 'two-byte length');
    assert.ok(rawNtlmToken(framed).equals(big));
  });

  it('passes bare NTLMSSP and non-SPNEGO tokens through unchanged', () => {
    assert.equal(rawNtlmToken(NTLM_STUB.initial), NTLM_STUB.initial);
    const other = Buffer.from('initial-token');
    assert.equal(rawNtlmToken(other), other);
    assert.equal(isNtlmssp(NTLM_STUB.challenge), true);
    assert.equal(isNtlmssp(other), false);
  });

  it('refuses a SPNEGO frame around something that is not NTLMSSP, or with no token', () => {
    assert.throws(() => rawNtlmToken(spnegoInit(Buffer.from('kerberos-ap-req'))), WinRMProtocolError);
    // NegTokenResp with a mechListMIC only.
    const micOnly = tlv(0xa1, tlv(0x30, tlv(0xa3, tlv(0x04, Buffer.alloc(16)))));
    assert.throws(() => rawNtlmToken(micOnly), /SPNEGO token for NTLM carries no NTLMSSP/);
    assert.throws(() => rawNtlmToken(Buffer.from([0x60, 0x05, 0x01])), WinRMProtocolError);
  });
});

// Sealed echo over plain HTTP, gated by the connection-bound Negotiate
// gate (which matches the NTLMSSP stub tokens bare or SPNEGO-framed).
function sealedEcho(gate = negotiateGate()): MockHandler {
  return (req): MockResponse => {
    const denied = gate.check(req);
    if (denied) return denied;
    const soap = mimeUnwrap(req.body, fakeNtlmUnwrap);
    const r = mimeWrap(`<re>${soap}</re>`, fakeNtlmWrap);
    return { status: 200, headers: { 'Content-Type': r.contentType }, body: r.body };
  };
}

describe('transport sends NTLM bare in the Negotiate header', () => {
  it('strips the SPNEGO frame from NEGOTIATE and AUTHENTICATE, then seals and unseals as before', async () => {
    const gate = negotiateGate();
    const server = await startMockServer(sealedEcho(gate));
    const transport = new WinRMTransport({ host: '127.0.0.1', port: server.port, tls: false, authProvider: ntlmStub({ seal: true }), credentials: CREDENTIALS });
    try {
      assert.equal(await transport.post('<soap>one</soap>'), '<re><soap>one</soap></re>');
      assert.equal(await transport.post('<soap>two</soap>'), '<re><soap>two</soap></re>');
    } finally {
      await transport.close();
      await server.close();
    }
    const negotiate = headerToken(server.requests[0]?.headers.authorization);
    const authenticate = headerToken(server.requests[1]?.headers.authorization);
    assert.ok(negotiate.equals(NTLM_STUB.initial), 'NEGOTIATE goes out bare');
    assert.ok(authenticate.equals(NTLM_STUB.response), 'AUTHENTICATE goes out bare, without the mechListMIC');
    assert.equal(ntlmsspOffset(negotiate), 0);
    assert.equal(ntlmsspOffset(authenticate), 0);
    assert.equal(gate.framingOf(0), 'raw');
    assert.equal(server.requests[2]?.headers.authorization, undefined);
    assert.equal(server.requests.length, 3);
  });

  it('leaves the scripted string tokens of challengeStub alone', async () => {
    const server = await startMockServer(sealedEcho());
    const transport = new WinRMTransport({ host: '127.0.0.1', port: server.port, tls: false, authProvider: challengeStub({ seal: true }), credentials: CREDENTIALS });
    try {
      assert.equal(await transport.post('<soap/>'), '<re><soap/></re>');
    } finally {
      await transport.close();
      await server.close();
    }
    assert.equal(server.requests[0]?.headers.authorization, `Negotiate ${B64('initial-token')}`);
  });

  // Over plain HTTP with Kerberos message encryption: Kerberos over HTTPS
  // with an unverified test certificate is refused until it sends a
  // channel binding.
  it('keeps SPNEGO for Kerberos, and for Negotiate when Kerberos won', async () => {
    const apReq = spnegoInit(Buffer.from('fake-ap-req'));
    const apRep = spnegoResp(Buffer.from('fake-ap-rep'), { negState: 0 });
    for (const mechanism of ['kerberos', 'negotiate'] as const) {
      const provider = new StubAuthProvider(
        mechanism,
        () =>
          new KerberosStubSecurityContext(
            [
              { expectInput: null, output: apReq, complete: false },
              { expectInput: apRep, output: null, complete: true },
            ],
            FAKE_KRB_IOV,
          ),
      );
      let authenticated = false;
      const server = await startMockServer((req): MockResponse => {
        if (!authenticated) {
          if (req.headers.authorization !== `Negotiate ${apReq.toString('base64')}`) return { status: 401, headers: { 'WWW-Authenticate': 'Negotiate' } };
          authenticated = true;
          return { status: 200, headers: { 'WWW-Authenticate': `Negotiate ${apRep.toString('base64')}` } };
        }
        const reply = mimeWrapIov('<ok/>', (m) => fakeKrbWrapIov(m));
        return { status: 200, headers: { 'Content-Type': reply.contentType }, body: reply.body };
      });
      const transport = new WinRMTransport({ host: '127.0.0.1', port: server.port, tls: false, authProvider: provider, credentials: CREDENTIALS });
      try {
        assert.equal(await transport.post('<soap/>'), '<ok/>', mechanism);
      } finally {
        await transport.close();
        await server.close();
      }
      assert.ok(headerToken(server.requests[0]?.headers.authorization).equals(apReq), `${mechanism}: the SPNEGO AP-REQ is untouched`);
    }
  });

  it('a Negotiate provider that picked NTLM also sends it bare', async () => {
    const gate = negotiateGate();
    const server = await startMockServer(sealedEcho(gate));
    const inner = ntlmStub({ seal: true });
    // Negotiate whose context reports NTLM as the winner after its first step.
    const provider = new StubAuthProvider('negotiate', () => Object.assign(inner.createContext({ host: 'h', service: 'HTTP' }, CREDENTIALS), { negotiatedMechanism: 'ntlm' as const }) as never);
    const transport = new WinRMTransport({ host: '127.0.0.1', port: server.port, tls: false, authProvider: provider, credentials: CREDENTIALS });
    try {
      assert.equal(await transport.post('<soap/>'), '<re><soap/></re>');
    } finally {
      await transport.close();
      await server.close();
    }
    assert.ok(headerToken(server.requests[0]?.headers.authorization).equals(NTLM_STUB.initial));
    assert.equal(gate.framingOf(0), 'raw');
  });
});

describe('real NTLM provider over the mock', () => {
  it('sends bare NEGOTIATE and AUTHENTICATE with a MIC, and takes a bare CHALLENGE', async () => {
    const seen: Buffer[] = [];
    const server = await startMockServer(
      (req): MockResponse => {
        const token = headerToken(req.headers.authorization);
        seen.push(token);
        if (ntlmsspType(token) === 1) return { status: 401, headers: { 'WWW-Authenticate': `Negotiate ${challengeWithTimestamp().toString('base64')}` } };
        return { status: 200, body: '<ok/>' };
      },
      { tls: { cert: readFileSync(new URL('./fixtures/tls-test-cert.pem', import.meta.url)), key: readFileSync(new URL('./fixtures/tls-test-key.pem', import.meta.url)) } },
    );
    const transport = new WinRMTransport({
      host: '127.0.0.1',
      port: server.port,
      tls: true,
      tlsVerify: false,
      encryption: 'never',
      authProvider: new NtlmAuthProvider(),
      credentials: { username: 'User', password: 'Password', domain: 'Domain' },
    });
    try {
      assert.equal(await transport.post('<soap/>'), '<ok/>');
    } finally {
      await transport.close();
      await server.close();
    }
    assert.equal(seen.length, 2);
    assert.equal(ntlmsspOffset(seen[0]!), 0, 'bare NEGOTIATE');
    assert.equal(ntlmsspType(seen[0]!), 1);
    assert.equal(ntlmsspOffset(seen[1]!), 0, 'bare AUTHENTICATE');
    assert.equal(ntlmsspType(seen[1]!), 3);
    // MS-WSMV 4.5: "Authorization: Negotiate TlRMTVNTUAAD..." is a bare AUTHENTICATE.
    assert.ok(seen[1]!.toString('base64').startsWith('TlRMTVNTUAAD'));
    // The AUTHENTICATE still has the client AV pairs (the server sent a timestamp) and a MIC.
    assert.ok(type3AvPairs(seen[1]!).some((p) => p.id === 9), 'MsvAvTargetName');
    assert.ok(!seen[1]!.subarray(72, 88).equals(Buffer.alloc(16)), 'MIC present');
  });
});

describe('fake Windows refuses a sealed body after SPNEGO-wrapped NTLM', () => {
  // A hand-driven client on one keep-alive connection, so the fake sees
  // what a transport that still wraps NTLM in SPNEGO would send.
  async function drive(port: number, initial: Buffer, response: Buffer): Promise<number[]> {
    const agent = new http.Agent({ keepAlive: true, maxSockets: 1 });
    const statuses: number[] = [];
    const send = (headers: Record<string, string>, body: Buffer) =>
      new Promise<void>((resolve, reject) => {
        const req = http.request({ host: '127.0.0.1', port, path: '/wsman', method: 'POST', agent, headers: { ...headers, 'Content-Length': String(body.length) } }, (res) => {
          statuses.push(res.statusCode ?? 0);
          res.resume();
          res.on('end', resolve);
        });
        req.on('error', reject);
        req.end(body);
      });
    try {
      await send({ Authorization: `Negotiate ${initial.toString('base64')}`, 'Content-Type': 'application/soap+xml;charset=UTF-8' }, Buffer.alloc(0));
      const sealed = mimeWrap('<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body/></s:Envelope>', fakeNtlmWrap);
      await send({ Authorization: `Negotiate ${response.toString('base64')}`, 'Content-Type': sealed.contentType }, sealed.body);
    } finally {
      agent.destroy();
    }
    return statuses;
  }

  it('answers 400 to the sealed body after SPNEGO-wrapped NTLM, 200 (handled) after bare NTLMSSP', async () => {
    const fake = await startFakeWindows({ tls: false, username: 'u', password: 'p' });
    try {
      const wrapped = await drive(fake.port, spnegoInit(NTLM_STUB.initial), spnegoResp(NTLM_STUB.response));
      assert.deepEqual(wrapped, [401, 400]);
      assert.equal(fake.spnegoSealsRefused, 1);
      const bare = await drive(fake.port, NTLM_STUB.initial, NTLM_STUB.response);
      // The fake handles the sealed body: this one carries no WS-Man action,
      // so the fake answers its usual 500, not the 400 refusal.
      assert.equal(bare[0], 401);
      assert.notEqual(bare[1], 400);
      assert.equal(fake.spnegoSealsRefused, 1);
      assert.equal(fake.sealedRequests, 1);
    } finally {
      await fake.close();
    }
  });
});
