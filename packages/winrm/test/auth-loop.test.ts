import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import net from 'node:net';
import { WinRMTransport } from '../src/winrm/transport.js';
import { WinRMAuthError } from '../src/winrm/errors.js';
import { basicStub, challengeStub, CREDENTIALS, StubAuthProvider, StubSecurityContext } from './helpers/stub-auth.js';
import { mimeWrap, negotiateGate, startMockServer, type MockResponse, type RecordedRequest } from './helpers/mock-server.js';
import { fakeNtlmWrap } from './helpers/stub-auth.js';

const B64 = (s: string) => Buffer.from(s).toString('base64');

function tls() {
  return {
    cert: readFileSync(new URL('./fixtures/tls-test-cert.pem', import.meta.url)),
    key: readFileSync(new URL('./fixtures/tls-test-key.pem', import.meta.url)),
  };
}

function transportFor(port: number, authProvider: ReturnType<typeof challengeStub>) {
  return new WinRMTransport({ host: '127.0.0.1', port, tls: true, tlsVerify: false, authProvider, credentials: CREDENTIALS });
}

describe('transport auth loop', () => {
  it('attaches the token and retries the same body on the same socket after a 401', async () => {
    const server = await startMockServer(
      (req) => {
        if (req.headers.authorization === `Negotiate ${B64('initial-token')}`) {
          return { status: 401, headers: { 'WWW-Authenticate': `Negotiate ${B64('server-challenge')}` } };
        }
        return { status: 200, body: '<ok/>' };
      },
      { tls: tls() },
    );
    try {
      const transport = transportFor(server.port, challengeStub());
      try {
        const out = await transport.post('<soap>same-body</soap>');
        assert.equal(out, '<ok/>');
      } finally {
        await transport.close();
      }
      assert.equal(server.requests.length, 2);
      // First POST is an empty-body probe; the retry carries the same body.
      assert.equal(server.requests[0]?.body.length, 0);
      assert.equal(server.requests[0]?.headers['content-length'], '0');
      assert.equal(server.requests[0]?.headers.authorization, `Negotiate ${B64('initial-token')}`);
      assert.equal(server.requests[1]?.body.toString('utf8'), '<soap>same-body</soap>');
      assert.equal(server.requests[1]?.headers.authorization, `Negotiate ${B64('response-token')}`);
      // NTLM binds auth to the TCP connection: one socket for both.
      assert.equal(server.requests[0]?.socketId, server.requests[1]?.socketId);
      assert.equal(server.connectionCount(), 1);
    } finally {
      await server.close();
    }
  });

  it('sends Basic credentials preemptively with the full body', async () => {
    const server = await startMockServer(() => ({ status: 200, body: '<ok/>' }), { tls: tls() });
    try {
      const transport = transportFor(server.port, basicStub('dXNlcjpwYXNz'));
      try {
        await transport.post('<soap>body</soap>');
      } finally {
        await transport.close();
      }
      assert.equal(server.requests.length, 1);
      assert.equal(server.requests[0]?.headers.authorization, 'Basic dXNlcjpwYXNz');
      assert.equal(server.requests[0]?.body.toString('utf8'), '<soap>body</soap>');
    } finally {
      await server.close();
    }
  });

  it('sends no Authorization header once the connection is authenticated', async () => {
    // The gate answers a re-sent AUTHENTICATE token with 401, as HTTP.sys
    // does, so a transport that repeats it re-handshakes on every post.
    const gate = negotiateGate();
    const server = await startMockServer(
      (req) => gate.check(req) ?? { status: 200, body: `<ok>${req.body.toString('utf8')}</ok>` },
      { tls: tls() },
    );
    try {
      const provider = challengeStub();
      const transport = transportFor(server.port, provider);
      try {
        assert.equal(await transport.post('<soap>one</soap>'), '<ok><soap>one</soap></ok>');
        assert.equal(await transport.post('<soap>two</soap>'), '<ok><soap>two</soap></ok>');
        assert.equal(await transport.post('<soap>three</soap>'), '<ok><soap>three</soap></ok>');
      } finally {
        await transport.close();
      }
      // Probe, AUTHENTICATE + body, then two bare requests: one handshake,
      // one context, one socket, no stale token.
      assert.equal(server.requests.length, 4);
      assert.equal(server.requests[1]?.headers.authorization, `Negotiate ${B64('response-token')}`);
      assert.equal(server.requests[2]?.headers.authorization, undefined);
      assert.equal(server.requests[3]?.headers.authorization, undefined);
      assert.equal(server.requests[2]?.body.toString('utf8'), '<soap>two</soap>');
      assert.equal(gate.handshakes, 1);
      assert.equal(gate.staleTokens, 0);
      assert.equal(provider.contexts.length, 1);
      assert.ok(server.requests.every((r) => r.socketId === 0), 'one keep-alive connection');
    } finally {
      await server.close();
    }
  });

  it('keeps sending Basic credentials on every request (RFC 7617)', async () => {
    const server = await startMockServer((req) => (req.headers.authorization ? { status: 200, body: '<ok/>' } : { status: 401 }), { tls: tls() });
    try {
      const transport = transportFor(server.port, basicStub('dXNlcjpwYXNz'));
      try {
        assert.equal(await transport.post('<soap>one</soap>'), '<ok/>');
        assert.equal(await transport.post('<soap>two</soap>'), '<ok/>');
      } finally {
        await transport.close();
      }
      assert.deepEqual(
        server.requests.map((r) => r.headers.authorization),
        ['Basic dXNlcjpwYXNz', 'Basic dXNlcjpwYXNz'],
      );
    } finally {
      await server.close();
    }
  });

  it('the mock gate refuses a stale AUTHENTICATE token and a bare request on a fresh socket', () => {
    const gate = negotiateGate();
    const req = (socketId: number, authorization?: string): RecordedRequest => ({
      method: 'POST',
      url: '/wsman',
      headers: authorization === undefined ? {} : { authorization },
      body: Buffer.alloc(0),
      socketId,
    });
    const initial = `Negotiate ${B64('initial-token')}`;
    const response = `Negotiate ${B64('response-token')}`;
    // A completed token with no handshake before it on this socket.
    assert.deepEqual(gate.check(req(0, response)), { status: 401, headers: { 'WWW-Authenticate': 'Negotiate' } });
    assert.deepEqual(gate.check(req(0)), { status: 401, headers: { 'WWW-Authenticate': 'Negotiate' } });
    assert.deepEqual(gate.check(req(0, initial)), { status: 401, headers: { 'WWW-Authenticate': `Negotiate ${B64('server-challenge')}` } });
    assert.equal(gate.check(req(0, response)), null);
    assert.equal(gate.check(req(0)), null, 'the connection is authenticated');
    assert.equal(gate.handshakes, 1);
    // The old AUTHENTICATE again on the authenticated connection: Windows
    // takes it as a new handshake and refuses it.
    assert.deepEqual(gate.check(req(0, response)), { status: 401, headers: { 'WWW-Authenticate': 'Negotiate' } });
    assert.equal(gate.staleTokens, 1);
    // Another socket starts from nothing.
    assert.deepEqual(gate.check(req(1)), { status: 401, headers: { 'WWW-Authenticate': 'Negotiate' } });
  });

  it('throws WinRMAuthError on a 401 without a challenge token', async () => {
    const server = await startMockServer(() => ({ status: 401, headers: { 'WWW-Authenticate': 'Negotiate' } }), {
      tls: tls(),
    });
    try {
      const transport = transportFor(server.port, challengeStub());
      try {
        await assert.rejects(() => transport.post('<soap/>'), WinRMAuthError);
      } finally {
        await transport.close();
      }
    } finally {
      await server.close();
    }
  });

  it('disposes the old context before a re-auth handshake', async () => {
    const events: string[] = [];
    let made = 0;
    const provider = new StubAuthProvider('ntlm', () => {
      const id = made++;
      events.push(`create ${id}`);
      const ctx = new StubSecurityContext([
        { expectInput: null, output: Buffer.from('initial-token'), complete: false },
        { expectInput: Buffer.from('server-challenge'), output: Buffer.from('response-token'), complete: true },
      ]);
      Object.assign(ctx, { dispose: async () => void events.push(`dispose ${id}`) });
      return ctx;
    });
    const server = await startMockServer(
      (req, index) => {
        if (req.headers.authorization === `Negotiate ${B64('initial-token')}`) {
          return { status: 401, headers: { 'WWW-Authenticate': `Negotiate ${B64('server-challenge')}` } };
        }
        // Request 2 is the second post on the established session: the
        // server has lost the auth state and asks again.
        if (index === 2) return { status: 401, headers: { 'WWW-Authenticate': 'Negotiate' } };
        return { status: 200, body: '<ok/>' };
      },
      { tls: tls() },
    );
    try {
      const transport = transportFor(server.port, provider);
      try {
        assert.equal(await transport.post('<soap>one</soap>'), '<ok/>');
        assert.equal(await transport.post('<soap>two</soap>'), '<ok/>');
        assert.deepEqual(events, ['create 0', 'dispose 0', 'create 1']);
      } finally {
        await transport.close();
      }
      assert.deepEqual(events, ['create 0', 'dispose 0', 'create 1', 'dispose 1']);
    } finally {
      await server.close();
    }
  });

  it('rejects with ETIMEDOUT when the server accepts and never answers', async () => {
    const sockets = new Set<net.Socket>();
    const silent = net.createServer((socket) => {
      sockets.add(socket);
      socket.resume(); // read the request, never write a byte back
    });
    await new Promise<void>((resolve) => silent.listen(0, '127.0.0.1', resolve));
    const port = (silent.address() as net.AddressInfo).port;
    const transport = new WinRMTransport({
      host: '127.0.0.1',
      port,
      tls: false,
      authProvider: challengeStub({ seal: true }),
      credentials: CREDENTIALS,
      requestTimeoutMs: 200,
    });
    const started = Date.now();
    try {
      await assert.rejects(transport.post('<soap/>'), (err: Error & { code?: string }) => {
        assert.equal(err.code, 'ETIMEDOUT');
        assert.match(err.message, /timed out after 200 ms/);
        return true;
      });
      const elapsed = Date.now() - started;
      assert.ok(elapsed >= 150 && elapsed < 2000, `rejected after ${elapsed} ms`);
    } finally {
      await transport.close();
      for (const socket of sockets) socket.destroy();
      await new Promise<void>((resolve) => silent.close(() => resolve()));
    }
  });

  it('starts a fresh handshake after a handshake request times out', async () => {
    const provider = challengeStub({ seal: true });
    const server = await startMockServer((req, index): MockResponse | Promise<MockResponse> => {
      // The first probe never gets an answer: the client times out mid-handshake.
      if (index === 0) return new Promise<MockResponse>(() => undefined);
      if (req.headers.authorization === `Negotiate ${B64('initial-token')}`) {
        return { status: 401, headers: { 'WWW-Authenticate': `Negotiate ${B64('server-challenge')}` } };
      }
      if (req.headers.authorization !== `Negotiate ${B64('response-token')}`) return { status: 400 };
      const wrapped = mimeWrap('<ok/>', fakeNtlmWrap);
      return { status: 200, headers: { 'Content-Type': wrapped.contentType }, body: wrapped.body };
    });
    const transport = new WinRMTransport({
      host: '127.0.0.1',
      port: server.port,
      tls: false,
      authProvider: provider,
      credentials: CREDENTIALS,
      requestTimeoutMs: 200,
    });
    try {
      await assert.rejects(transport.post('<soap>one</soap>'), (err: Error & { code?: string }) => err.code === 'ETIMEDOUT');
      assert.equal(await transport.post('<soap>two</soap>'), '<ok/>');
      // The second post starts over: an empty probe from a new context.
      assert.equal(server.requests[1]?.body.length, 0);
      assert.equal(server.requests[1]?.headers.authorization, `Negotiate ${B64('initial-token')}`);
      assert.equal(provider.contexts.length, 2);
    } finally {
      await transport.close();
      await server.close();
    }
  });

  it('still re-authenticates when disposing the old context throws', async () => {
    const provider = new StubAuthProvider('ntlm', () => {
      const ctx = new StubSecurityContext([
        { expectInput: null, output: Buffer.from('initial-token'), complete: false },
        { expectInput: Buffer.from('server-challenge'), output: Buffer.from('response-token'), complete: true },
      ]);
      Object.assign(ctx, { dispose: async () => { throw new Error('EBUSY: cannot remove the temp ccache'); } });
      return ctx;
    });
    const server = await startMockServer(
      (req, index) => {
        if (req.headers.authorization === `Negotiate ${B64('initial-token')}`) {
          return { status: 401, headers: { 'WWW-Authenticate': `Negotiate ${B64('server-challenge')}` } };
        }
        if (index === 2) return { status: 401, headers: { 'WWW-Authenticate': 'Negotiate' } };
        return { status: 200, body: '<ok/>' };
      },
      { tls: tls() },
    );
    const transport = transportFor(server.port, provider);
    try {
      assert.equal(await transport.post('<soap>one</soap>'), '<ok/>');
      assert.equal(await transport.post('<soap>two</soap>'), '<ok/>');
      assert.equal(provider.contexts.length, 2);
    } finally {
      await transport.close().catch(() => undefined);
      await server.close();
    }
  });

  it('maps KerberosCredentialError from step() to WinRMAuthError and does not retry', async () => {
    const krbErr = Object.assign(new Error('KDC rejected the password'), { name: 'KerberosCredentialError' });
    const events: string[] = [];
    let made = 0;
    const provider = new StubAuthProvider('negotiate', () => {
      const id = made++;
      events.push(`create ${id}`);
      const ctx = new StubSecurityContext([]);
      Object.assign(ctx, {
        step: async () => {
          events.push(`step ${id}`);
          throw krbErr;
        },
        dispose: async () => void events.push(`dispose ${id}`),
      });
      return ctx;
    });
    const server = await startMockServer(() => ({ status: 200, body: '<ok/>' }), { tls: tls() });
    const transport = transportFor(server.port, provider);
    try {
      await assert.rejects(transport.post('<soap>body</soap>'), (err: unknown) => {
        assert.ok(err instanceof WinRMAuthError);
        assert.equal(err.cause, krbErr);
        return true;
      });
      // One step, then the context is reset. No second step (no NTLM or
      // other retry) and no request reaches the server.
      assert.deepEqual(events, ['create 0', 'step 0', 'dispose 0', 'create 1']);
      assert.equal(server.requests.length, 0);
    } finally {
      await transport.close().catch(() => undefined);
      await server.close();
    }
  });
});
