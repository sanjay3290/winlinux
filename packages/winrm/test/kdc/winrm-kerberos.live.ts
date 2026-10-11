// Live proof of Kerberos message encryption over plain HTTP with a
// real GSS acceptor: the WinRM transport (real @winlinux/auth Kerberos and
// Negotiate providers on @winlinux/krb-session-key) talks to an HTTP
// server whose auth and sealing are MIT krb5's gss_accept_sec_context,
// gss_unwrap_iov and gss_wrap_iov (the harness in
// packages/krb-session-key/test/kdc), against a throwaway local KDC.
// Linux only: npm run test:kdc -w @winlinux/winrm
import { after, before, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createAuthProvider } from '@winlinux/auth';
import type { AuthProvider, Mechanism } from '../../src/auth-provider.js';
import { WinRMTransport } from '../../src/winrm/transport.js';
import { connect } from '../../src/winrm/index.js';
import { mimeParts, startMockServer, type MockHandler, type MockResponse, type RecordedRequest } from '../helpers/mock-server.js';
import type * as KdcModule from '../../../krb-session-key/dist/test/kdc/kdc.js';
import type { Acceptor, LocalKdc } from '../../../krb-session-key/dist/test/kdc/kdc.js';

// dist/test/kdc -> packages/krb-session-key/dist/test/kdc (built by the root build).
const kdcModule = (): Promise<typeof KdcModule> =>
  import(new URL('../../../../krb-session-key/dist/test/kdc/kdc.js', import.meta.url).href) as Promise<typeof KdcModule>;

// The suite connects to 127.0.0.1. An IP address has no principal, so the
// Kerberos context refuses it unless the SPN is named. The KDC has
// HTTP/127.0.0.1, so name it, as kerberosHostname does in the facade.
function loopbackProvider(mechanism: Mechanism): AuthProvider {
  const inner = createAuthProvider(mechanism);
  return {
    mechanism: inner.mechanism,
    createContext: (target, credentials) => inner.createContext({ ...target, spn: 'HTTP/127.0.0.1' }, credentials),
  };
}

const REQUEST_SOAP = '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body>ping over Kerberos é</s:Body></s:Envelope>';
const RESPONSE_SOAP = '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body>pong</s:Body></s:Envelope>';
const BOUNDARY = '--Encrypted Boundary';
const SPNEGO_PROTOCOL = 'application/HTTP-SPNEGO-session-encrypted';

interface ServerStats {
  seen: string[];
  lengthFields: number[];
  mechs: string[];
}

// An HTTP server that is a GSS acceptor: one acceptor context per TCP
// connection, like HTTP.sys connection-bound Negotiate auth. It takes the
// AP-REQ (inside SPNEGO) from the Authorization header, answers with the
// AP-REP in WWW-Authenticate on the response to that request, unseals
// every later body with gss_unwrap_iov and seals its reply with
// gss_wrap_iov, Length-Field = its header length.
// `reply` picks the acceptor's wrap API for the response: 'iov' is
// gss_wrap_iov HEADER|DATA|PADDING (RRC 28, the layout MIT sends),
// 'plain' is gss_wrap (RRC 0, the trailer at the end), split MS-WSMV style
// with the last OriginalContent Length bytes as the data.
function acceptorHandler(
  kdc: LocalKdc,
  kdcMod: typeof KdcModule,
  stats: ServerStats,
  reply: 'iov' | 'plain' = 'iov',
): { handler: MockHandler; close(): void } {
  const acceptors = new Map<number, { acceptor: Acceptor; complete: boolean }>();
  const handler = async (req: RecordedRequest): Promise<MockResponse> => {
    let conn = acceptors.get(req.socketId);
    if (!conn) {
      conn = { acceptor: await kdcMod.Acceptor.start(kdc), complete: false };
      acceptors.set(req.socketId, conn);
    }
    const headers: Record<string, string> = {};
    // HTTP.sys: a token on an authenticated connection is a new handshake,
    // and a stale AP-REQ is a replay: 401 with a fresh challenge.
    if (conn.complete && req.headers.authorization) return { status: 401, headers: { 'WWW-Authenticate': 'Negotiate' } };
    if (!conn.complete) {
      const m = /^Negotiate\s+([A-Za-z0-9+/=]+)$/.exec(req.headers.authorization ?? '');
      if (!m?.[1]) return { status: 401, headers: { 'WWW-Authenticate': 'Negotiate' } };
      const r = await conn.acceptor.accept(Buffer.from(m[1], 'base64'));
      if (r.token) headers['WWW-Authenticate'] = `Negotiate ${r.token.toString('base64')}`;
      if (!r.complete) return { status: 401, headers };
      conn.complete = true;
      stats.mechs.push(await conn.acceptor.mech());
      if (req.body.length === 0) return { status: 200, headers };
    }
    const [part] = mimeParts(req.body);
    if (!part) return { status: 400, body: 'expected one encrypted part' };
    stats.lengthFields.push(part.lengthField);
    const plain = await conn.acceptor.unwrapIov(part.header, part.data);
    assert.equal(plain.length, part.originalLength);
    stats.seen.push(plain.toString('utf8'));
    const replyBytes = Buffer.from(RESPONSE_SOAP, 'utf8');
    let sealed: { header: Buffer; data: Buffer };
    if (reply === 'plain') {
      const token = await conn.acceptor.wrapPlain(replyBytes);
      sealed = { header: token.subarray(0, token.length - replyBytes.length), data: token.subarray(token.length - replyBytes.length) };
    } else {
      sealed = await conn.acceptor.wrapIov(replyBytes);
    }
    const prefix = Buffer.alloc(4);
    prefix.writeUInt32LE(sealed.header.length, 0);
    const head =
      `${BOUNDARY}\r\n\tContent-Type: ${SPNEGO_PROTOCOL}\r\n` +
      `\tOriginalContent: type=application/soap+xml;charset=UTF-8;Length=${replyBytes.length}\r\n` +
      `${BOUNDARY}\r\n\tContent-Type: application/octet-stream\r\n`;
    return {
      status: 200,
      headers: { ...headers, 'Content-Type': `multipart/encrypted;protocol="${SPNEGO_PROTOCOL}";boundary="Encrypted Boundary"` },
      body: Buffer.concat([Buffer.from(head), prefix, sealed.header, sealed.data, Buffer.from(`${BOUNDARY}--\r\n`)]),
    };
  };
  return {
    handler,
    close: () => {
      for (const c of acceptors.values()) c.acceptor.close();
    },
  };
}

describe('WinRM transport: Kerberos message encryption over HTTP against a real GSS acceptor (local KDC)', () => {
  let kdc: LocalKdc;
  let kdcMod: typeof KdcModule;

  before(async () => {
    kdcMod = await kdcModule();
    kdc = await kdcMod.startLocalKdc();
    // The real providers read the ticket cache the KDC helper filled.
    process.env.KRB5CCNAME = kdc.ccache;
  });

  after(async () => {
    delete process.env.KRB5CCNAME;
    await kdc?.stop();
  });

  for (const mechanism of ['kerberos', 'negotiate'] as Mechanism[]) {
    it(`${mechanism}: the acceptor unwraps our requests and we unwrap its replies (aes256)`, async () => {
      const stats: ServerStats = { seen: [], lengthFields: [], mechs: [] };
      const acceptor = acceptorHandler(kdc, kdcMod, stats);
      const server = await startMockServer(acceptor.handler);
      // host 127.0.0.1 -> SPN HTTP/127.0.0.1, which the keytab holds (aes256).
      const transport = new WinRMTransport({
        host: '127.0.0.1',
        port: server.port,
        tls: false,
        authProvider: loopbackProvider(mechanism),
        credentials: { username: kdcMod.USER, realm: kdcMod.REALM, useTicketCache: true },
      });
      try {
        assert.equal(await transport.post(REQUEST_SOAP), RESPONSE_SOAP);
        assert.equal(await transport.post(REQUEST_SOAP), RESPONSE_SOAP);
        assert.equal(await transport.post(REQUEST_SOAP), RESPONSE_SOAP);
      } finally {
        await transport.close();
        acceptor.close();
        await server.close();
      }
      assert.deepEqual(stats.seen, [REQUEST_SOAP, REQUEST_SOAP, REQUEST_SOAP]);
      assert.deepEqual(stats.lengthFields, [60, 60, 60], 'RFC 4121 header with the rotated trailer');
      assert.deepEqual(stats.mechs, ['{ 1 2 840 113554 1 2 2 }'], 'one context on one connection; SPNEGO reports the krb5 mechanism it negotiated');
      const sealedRequests = server.requests.filter((r) => r.body.length > 0);
      assert.equal(sealedRequests.length, 3);
      for (const r of sealedRequests) {
        assert.equal(r.headers['content-type'], `multipart/encrypted;protocol="${SPNEGO_PROTOCOL}";boundary="Encrypted Boundary"`);
        assert.equal(r.body.includes(REQUEST_SOAP), false, 'no plaintext on the wire');
      }
    });
  }

  it('a reply sealed with gss_wrap (RRC 0, not the MIT IOV layout) is unsealed too', async () => {
    const stats: ServerStats = { seen: [], lengthFields: [], mechs: [] };
    const acceptor = acceptorHandler(kdc, kdcMod, stats, 'plain');
    const server = await startMockServer(acceptor.handler);
    const transport = new WinRMTransport({
      host: '127.0.0.1',
      port: server.port,
      tls: false,
      authProvider: loopbackProvider('kerberos'),
      credentials: { username: kdcMod.USER, realm: kdcMod.REALM, useTicketCache: true },
    });
    try {
      assert.equal(await transport.post(REQUEST_SOAP), RESPONSE_SOAP);
      assert.equal(await transport.post(REQUEST_SOAP), RESPONSE_SOAP);
    } finally {
      await transport.close();
      acceptor.close();
      await server.close();
    }
    assert.deepEqual(stats.seen, [REQUEST_SOAP, REQUEST_SOAP]);
  });

  it('a password Kerberos context (kinit into a private ccache) works the same way', async () => {
    const stats: ServerStats = { seen: [], lengthFields: [], mechs: [] };
    const acceptor = acceptorHandler(kdc, kdcMod, stats);
    const server = await startMockServer(acceptor.handler);
    const session = await connect({
      host: '127.0.0.1',
      port: server.port,
      tls: false,
      authProvider: loopbackProvider('kerberos'),
      credentials: { username: kdcMod.USER, password: kdcMod.PASSWORD, realm: kdcMod.REALM },
    });
    try {
      // The session layer sends a real WS-Man Create; the acceptor
      // answers with our fixed SOAP, which the session cannot parse as a
      // shell: what matters here is that the sealed round trip happened.
      await assert.rejects(session.runCommand('hostname'));
    } finally {
      await session.close();
      acceptor.close();
      await server.close();
    }
    assert.equal(stats.seen.length, 1);
    assert.match(stats.seen[0] ?? '', /wsman\/1\/windows\/shell/);
    assert.deepEqual(stats.lengthFields, [60]);
  });

  it('a keytab Kerberos context (kinit -k -t into a private ccache, no password) works the same way', async () => {
    const keytab = await kdcMod.exportUserKeytab(kdc);
    const stats: ServerStats = { seen: [], lengthFields: [], mechs: [] };
    const acceptor = acceptorHandler(kdc, kdcMod, stats);
    const server = await startMockServer(acceptor.handler);
    // The default ticket cache must not be what signs in: point it at an
    // empty path for this test, so only the keytab can give a TGT.
    const savedCcache = process.env.KRB5CCNAME;
    process.env.KRB5CCNAME = `FILE:${kdc.dir}/no-such-ccache`;
    const session = await connect({
      host: '127.0.0.1',
      port: server.port,
      tls: false,
      authProvider: loopbackProvider('kerberos'),
      credentials: { username: kdcMod.USER, realm: kdcMod.REALM, keytab },
    });
    try {
      await assert.rejects(session.runCommand('hostname'));
    } finally {
      await session.close();
      acceptor.close();
      await server.close();
      process.env.KRB5CCNAME = savedCcache;
    }
    assert.equal(stats.seen.length, 1);
    assert.match(stats.seen[0] ?? '', /wsman\/1\/windows\/shell/);
    assert.deepEqual(stats.mechs.length, 1);
  });

  it('a flipped byte in a sealed response fails with a tamper error, and the next request still works', async () => {
    const stats: ServerStats = { seen: [], lengthFields: [], mechs: [] };
    const acceptor = acceptorHandler(kdc, kdcMod, stats);
    let flipNext = false;
    const server = await startMockServer(async (req) => {
      const res = await acceptor.handler(req, 0);
      if (flipNext && res.body && Buffer.isBuffer(res.body)) {
        flipNext = false;
        const body = Buffer.from(res.body);
        const at = body.indexOf('--Encrypted Boundary--') - 3;
        body[at] = (body[at] as number) ^ 0x01;
        return { ...res, body };
      }
      return res;
    });
    const transport = new WinRMTransport({
      host: '127.0.0.1',
      port: server.port,
      tls: false,
      authProvider: loopbackProvider('kerberos'),
      credentials: { username: kdcMod.USER, realm: kdcMod.REALM, useTicketCache: true },
    });
    try {
      assert.equal(await transport.post(REQUEST_SOAP), RESPONSE_SOAP);
      flipNext = true;
      await assert.rejects(transport.post(REQUEST_SOAP), /tampered/);
    } finally {
      await transport.close();
      acceptor.close();
      await server.close();
    }
  });
});
