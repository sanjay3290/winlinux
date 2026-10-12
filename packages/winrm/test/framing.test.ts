import { describe, it } from 'node:test';
import { execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import type { SecurityContext } from '../src/auth-provider.js';
import { connect } from '../src/winrm/index.js';
import { WinRMAuthError, WinRMProtocolError, WinRMTransportError } from '../src/winrm/errors.js';
import {
  decryptMessage,
  describeWrapToken,
  ENCRYPTED_PROTOCOLS,
  encryptedContentType,
  encryptMessage,
  SPNEGO_PROTOCOL,
} from '../src/winrm/encryption.js';
import { WinRMTransport } from '../src/winrm/transport.js';
import {
  challengeStub,
  CREDENTIALS,
  FAKE_KRB_HEADER_LENGTH,
  FAKE_KRB_IOV,
  FAKE_NTLM,
  fakeKrbUnwrapIov,
  fakeKrbWrapIov,
  fakeNtlmUnwrap,
  fakeNtlmWrap,
  kerberosStub,
  KerberosStubSecurityContext,
  StubAuthProvider,
  StubSecurityContext,
} from './helpers/stub-auth.js';
import {
  mimeParts,
  mimeUnwrap,
  mimeUnwrapIov,
  mimeWrap,
  mimeWrapIov,
  negotiateGate,
  startMockServer,
  type MockHandler,
  type MockResponse,
} from './helpers/mock-server.js';

const B64 = (s: string) => Buffer.from(s).toString('base64');
const golden = (name: string) => readFileSync(new URL(`./fixtures/golden/${name}`, import.meta.url));

const REQUEST_SOAP = '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body>ping</s:Body></s:Envelope>';
const RESPONSE_SOAP = '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body>pong é</s:Body></s:Envelope>';

// A context that only knows the NTLM layout (signature(16) || sealed).
function ntlmContext(): SecurityContext {
  return {
    complete: true,
    negotiatedMechanism: 'ntlm',
    step: async () => ({ output: null, complete: true }),
    wrap: async (p: Buffer) => fakeNtlmWrap(p),
    unwrap: async (c: Buffer) => fakeNtlmUnwrap(c),
  };
}

// Server: NTLM-style 401 challenge, then decrypt the request with the
// independent oracle and answer with an encrypted response.
function echoHandler(seen: string[], respond: () => { contentType: string; body: Buffer } = () => mimeWrap(RESPONSE_SOAP, fakeNtlmWrap)): MockHandler {
  const gate = negotiateGate();
  return (req): MockResponse => {
    const denied = gate.check(req);
    if (denied) return denied;
    seen.push(mimeUnwrap(req.body, fakeNtlmUnwrap));
    const r = respond();
    return { status: 200, headers: { 'Content-Type': r.contentType }, body: r.body };
  };
}

function transportFor(port: number, authProvider: StubAuthProvider): WinRMTransport {
  return new WinRMTransport({ host: '127.0.0.1', port, tls: false, authProvider, credentials: CREDENTIALS });
}

describe('MS-WSMV encryption framing', () => {
  // Golden source: pywinrm winrm/encryption.py at commit fbb05e8
  // (https://github.com/diyan/pywinrm/blob/fbb05e87dc8c7ad79bc5dc1d334c39f28bc80b73/winrm/encryption.py),
  // reproduced by packages/winrm/scripts/gen-pywinrm-ntlm-golden.py with a
  // fixed-key MS-NLMP NTLMv2 SEAL. The wrap output fixture is what an NTLM
  // SecurityContext.wrap() returns for create-shell.xml.
  it('byte-matches the pywinrm NTLM-encrypted request (golden)', async () => {
    const soap = golden('create-shell.xml');
    const wrapOutput = golden('pywinrm-ntlm-wrap-output.bin');
    const ctx: SecurityContext = {
      complete: true,
      negotiatedMechanism: 'ntlm',
      step: async () => ({ output: null, complete: true }),
      wrap: async (p: Buffer) => {
        assert.ok(p.equals(soap), 'wrap() gets exactly the SOAP plaintext');
        return wrapOutput;
      },
    };
    const body = await encryptMessage(ctx, 'ntlm', soap);
    assert.ok(body.equals(golden('pywinrm-ntlm-encrypted-request.bin')), 'request body equals the pywinrm golden bytes');
    assert.equal(encryptedContentType(), golden('pywinrm-ntlm-content-type.txt').toString('utf8'));
  });

  it('parses the pywinrm golden envelope and gives unwrap() only the sealed blob', async () => {
    const soap = golden('create-shell.xml');
    const wrapOutput = golden('pywinrm-ntlm-wrap-output.bin');
    const inputs: Buffer[] = [];
    const ctx: SecurityContext = {
      complete: true,
      negotiatedMechanism: 'ntlm',
      step: async () => ({ output: null, complete: true }),
      unwrap: async (c: Buffer) => {
        inputs.push(Buffer.from(c));
        return soap;
      },
    };
    const out = await decryptMessage(ctx, 'ntlm', SPNEGO_PROTOCOL, golden('pywinrm-ntlm-encrypted-request.bin'));
    assert.equal(out, soap.toString('utf8'));
    assert.equal(inputs.length, 1);
    assert.ok(inputs[0]?.equals(wrapOutput), 'unwrap() input is signature || sealed data, no prefix, no MIME');
  });

  it('writes the 4-byte LE signature length, the OriginalContent Length and the boundaries', async () => {
    const soap = Buffer.from(RESPONSE_SOAP, 'utf8'); // multi-byte UTF-8: Length counts bytes
    const body = await encryptMessage(ntlmContext(), 'ntlm', soap);
    const head =
      '--Encrypted Boundary\r\n' +
      '\tContent-Type: application/HTTP-SPNEGO-session-encrypted\r\n' +
      `\tOriginalContent: type=application/soap+xml;charset=UTF-8;Length=${soap.length}\r\n` +
      '--Encrypted Boundary\r\n' +
      '\tContent-Type: application/octet-stream\r\n';
    assert.equal(body.subarray(0, head.length).toString('utf8'), head);
    const stream = body.subarray(Buffer.byteLength(head));
    assert.equal(stream.readUInt32LE(0), 16);
    assert.ok(stream.subarray(4, 4 + 16 + soap.length).equals(fakeNtlmWrap(soap)));
    assert.equal(stream.subarray(4 + 16 + soap.length).toString('utf8'), '--Encrypted Boundary--\r\n');
  });

  it('round-trips encrypt then decrypt with an NTLM-layout context', async () => {
    const ctx = ntlmContext();
    const body = await encryptMessage(ctx, 'ntlm', Buffer.from(RESPONSE_SOAP, 'utf8'));
    assert.equal(await decryptMessage(ctx, 'ntlm', SPNEGO_PROTOCOL, body), RESPONSE_SOAP);
  });

  it('raises WinRMTransportError for a flipped payload byte', async () => {
    const ctx = ntlmContext();
    const body = await encryptMessage(ctx, 'ntlm', Buffer.from(RESPONSE_SOAP, 'utf8'));
    const tampered = Buffer.from(body);
    const idx = body.indexOf('--Encrypted Boundary--') - 5; // inside the sealed data
    tampered[idx] = (tampered[idx] as number) ^ 0x01;
    await assert.rejects(decryptMessage(ctx, 'ntlm', SPNEGO_PROTOCOL, tampered), WinRMTransportError);
  });

  it('raises WinRMTransportError for a wrong OriginalContent Length', async () => {
    const ctx = ntlmContext();
    const soap = Buffer.from(RESPONSE_SOAP, 'utf8');
    const body = await encryptMessage(ctx, 'ntlm', soap);
    const wrong = Buffer.from(body.toString('latin1').replace(`Length=${soap.length}`, `Length=${soap.length + 1}`), 'latin1');
    await assert.rejects(decryptMessage(ctx, 'ntlm', SPNEGO_PROTOCOL, wrong), WinRMTransportError);
  });

  it('raises WinRMTransportError for a bad signature length prefix', async () => {
    const ctx = ntlmContext();
    const body = await encryptMessage(ctx, 'ntlm', Buffer.from(RESPONSE_SOAP, 'utf8'));
    const bad = Buffer.from(body);
    const at = body.indexOf('\tContent-Type: application/octet-stream\r\n') + '\tContent-Type: application/octet-stream\r\n'.length;
    bad.writeUInt32LE(20, at);
    await assert.rejects(decryptMessage(ctx, 'ntlm', SPNEGO_PROTOCOL, bad), WinRMTransportError);
  });

  it('rejects a response protocol it did not send', async () => {
    const body = await encryptMessage(ntlmContext(), 'ntlm', Buffer.from(RESPONSE_SOAP, 'utf8'));
    await assert.rejects(
      decryptMessage(ntlmContext(), 'ntlm', 'application/HTTP-CredSSP-session-encrypted', body),
      WinRMTransportError,
    );
    assert.deepEqual([...ENCRYPTED_PROTOCOLS], [SPNEGO_PROTOCOL]);
  });
});

describe('transport encryption over the wire', () => {
  it('wrap()/unwrap() see only the sealed blob: no MIME text, no length prefix', async () => {
    const seen: string[] = [];
    const server = await startMockServer(echoHandler(seen));
    const provider = challengeStub({ seal: FAKE_NTLM });
    const transport = transportFor(server.port, provider);
    try {
      assert.equal(await transport.post(REQUEST_SOAP), RESPONSE_SOAP);
      assert.equal(await transport.post(REQUEST_SOAP), RESPONSE_SOAP);
    } finally {
      await transport.close();
      await server.close();
    }
    assert.deepEqual(seen, [REQUEST_SOAP, REQUEST_SOAP]);
    const ctx = provider.contexts[0] as StubSecurityContext;
    assert.equal(ctx.wrapCalls.length, 2);
    assert.equal(ctx.unwrapCalls.length, 2);
    for (const call of ctx.wrapCalls) {
      assert.equal(call.input.toString('utf8'), REQUEST_SOAP);
      assert.ok(call.output.equals(fakeNtlmWrap(Buffer.from(REQUEST_SOAP))));
    }
    const expectedIn = fakeNtlmWrap(Buffer.from(RESPONSE_SOAP, 'utf8'));
    for (const call of ctx.unwrapCalls) {
      assert.ok(call.input.equals(expectedIn), 'unwrap() input is signature || sealed data');
      assert.equal(call.input.readUInt32LE(0), 1, 'starts with the NTLM signature version, not the length prefix');
      assert.equal(call.input.includes('Encrypted Boundary'), false);
      assert.equal(call.output.toString('utf8'), RESPONSE_SOAP);
    }
    // On the wire, the 4-byte prefix sits right before the wrap() output.
    const req = server.requests.find((r) => r.body.length > 0);
    assert.ok(req);
    assert.equal(req.headers['content-type'], golden('pywinrm-ntlm-content-type.txt').toString('utf8'));
    const out = ctx.wrapCalls[0]?.output as Buffer;
    const at = req.body.indexOf(out);
    assert.ok(at >= 4);
    assert.equal(req.body.readUInt32LE(at - 4), 16);
  });

  it('calls wrap() only after the handshake is complete', async () => {
    const seen: string[] = [];
    const server = await startMockServer(echoHandler(seen));
    let wrapWhileIncomplete = 0;
    const provider = challengeStub({
      seal: {
        wrap: (p) => {
          const ctx = provider.contexts[0] as StubSecurityContext;
          if (!ctx.complete) wrapWhileIncomplete += 1;
          return fakeNtlmWrap(p);
        },
        unwrap: fakeNtlmUnwrap,
      },
    });
    const transport = transportFor(server.port, provider);
    try {
      assert.equal(await transport.post(REQUEST_SOAP), RESPONSE_SOAP);
    } finally {
      await transport.close();
      await server.close();
    }
    assert.equal(wrapWhileIncomplete, 0);
    assert.equal(server.requests[0]?.body.length, 0, 'the first probe carries no body');
  });

  it('raises WinRMTransportError when the server response is tampered with', async () => {
    const seen: string[] = [];
    const server = await startMockServer(
      echoHandler(seen, () => {
        const r = mimeWrap(RESPONSE_SOAP, fakeNtlmWrap);
        const at = r.body.indexOf('--Encrypted Boundary--') - 3;
        r.body[at] = (r.body[at] as number) ^ 0xff;
        return r;
      }),
    );
    const transport = transportFor(server.port, challengeStub({ seal: FAKE_NTLM }));
    try {
      await assert.rejects(transport.post(REQUEST_SOAP), WinRMTransportError);
    } finally {
      await transport.close();
      await server.close();
    }
  });
});

describe('Kerberos over plain HTTP (decision b)', () => {
  it('refuses a Kerberos provider with message encryption', async () => {
    await assert.rejects(
      connect({ host: 'host', authProvider: challengeStub({ seal: true, mechanism: 'kerberos' }), credentials: CREDENTIALS }),
      (err: unknown) => err instanceof WinRMProtocolError && /HTTPS/.test(err.message) && /5986/.test(err.message),
    );
  });

  it('refuses when Negotiate picks Kerberos, before any wrap()', async () => {
    class KerberosWinsContext extends StubSecurityContext {
      readonly negotiatedMechanism = 'kerberos' as const;
    }
    const provider = new StubAuthProvider(
      'negotiate',
      () =>
        new KerberosWinsContext(
          [
            { expectInput: null, output: Buffer.from('initial-token'), complete: false },
            { expectInput: Buffer.from('server-challenge'), output: Buffer.from('response-token'), complete: true },
          ],
          FAKE_NTLM,
        ),
    );
    const seen: string[] = [];
    const server = await startMockServer(echoHandler(seen));
    const transport = transportFor(server.port, provider);
    try {
      await assert.rejects(transport.post(REQUEST_SOAP), (err: unknown) => err instanceof WinRMProtocolError && /5986/.test(err.message));
    } finally {
      await transport.close();
      await server.close();
    }
    assert.equal((provider.contexts[0] as StubSecurityContext).wrapCalls.length, 0);
    assert.equal(server.requests.length, 0);
  });

  it('allows Kerberos over HTTPS without message encryption', async () => {
    const session = await connect({
      host: 'host',
      tls: true,
      authProvider: challengeStub({ seal: true, mechanism: 'kerberos' }),
      credentials: CREDENTIALS,
    });
    await session.close();
  });
});

describe('encrypted session refuses unencrypted responses', () => {
  // Handshake as usual, then answer the authenticated request with `reply`.
  async function postWithReply(reply: MockResponse): Promise<unknown> {
    const server = await startMockServer((req): MockResponse => {
      if (req.headers.authorization !== `Negotiate ${B64('response-token')}`) {
        return { status: 401, headers: { 'WWW-Authenticate': `Negotiate ${B64('server-challenge')}` } };
      }
      return reply;
    });
    const transport = transportFor(server.port, challengeStub({ seal: FAKE_NTLM }));
    try {
      return await transport.post(REQUEST_SOAP).then(
        (v) => ({ resolved: v }),
        (e: unknown) => e,
      );
    } finally {
      await transport.close();
      await server.close();
    }
  }

  const refused = (err: unknown) => err instanceof WinRMTransportError && /unencrypted/.test(err.message);

  it('refuses a plaintext 200 SOAP response', async () => {
    const err = await postWithReply({ status: 200, headers: { 'Content-Type': 'application/soap+xml;charset=UTF-8' }, body: '<FORGED/>' });
    assert.ok(refused(err), `expected a refusal, got ${JSON.stringify(err)}`);
  });

  it('refuses a plaintext 500 SOAP fault', async () => {
    const fault = readFileSync(new URL('./fixtures/fault-500.xml', import.meta.url), 'utf8');
    const err = await postWithReply({ status: 500, headers: { 'Content-Type': 'application/soap+xml;charset=UTF-8' }, body: fault });
    assert.ok(refused(err), `expected a refusal, got ${String(err)}`);
  });

  it('refuses multipart/encrypted with no protocol parameter', async () => {
    const wrapped = mimeWrap(RESPONSE_SOAP, fakeNtlmWrap);
    const err = await postWithReply({
      status: 200,
      headers: { 'Content-Type': 'multipart/encrypted;boundary="Encrypted Boundary"' },
      body: wrapped.body,
    });
    assert.ok(refused(err), `expected a refusal, got ${String(err)}`);
  });

  it('refuses an empty 200 response', async () => {
    const err = await postWithReply({ status: 200 });
    assert.ok(refused(err), `expected a refusal, got ${String(err)}`);
  });
});

describe('transport serializes concurrent requests', () => {
  // Echo server: each response names the request it answers.
  function tagHandler(opts?: { tamper?: string }): MockHandler {
    const gate = negotiateGate();
    return (req): MockResponse => {
      const denied = gate.check(req);
      if (denied) return denied;
      const soap = mimeUnwrap(req.body, fakeNtlmUnwrap);
      const tag = /<s:Body>([^<]*)<\/s:Body>/.exec(soap)?.[1] ?? '?';
      const r = mimeWrap(`<s:Envelope><s:Body>re:${tag}</s:Body></s:Envelope>`, fakeNtlmWrap);
      if (tag === opts?.tamper) {
        const at = r.body.indexOf('--Encrypted Boundary--') - 3;
        r.body[at] = (r.body[at] as number) ^ 0xff;
      }
      return { status: 200, headers: { 'Content-Type': r.contentType }, body: r.body };
    };
  }
  const soapFor = (tag: string) => `<s:Envelope><s:Body>${tag}</s:Body></s:Envelope>`;

  it('runs concurrent posts on a fresh session with exactly one handshake, in order', async () => {
    const server = await startMockServer(tagHandler());
    const provider = challengeStub({ seal: FAKE_NTLM });
    const transport = transportFor(server.port, provider);
    const tags = ['a', 'b', 'c', 'd'];
    try {
      const results = await Promise.all(tags.map((t) => transport.post(soapFor(t))));
      assert.deepEqual(results, tags.map((t) => `<s:Envelope><s:Body>re:${t}</s:Body></s:Envelope>`));
    } finally {
      await transport.close();
      await server.close();
    }
    assert.equal(provider.contexts.length, 1, 'no re-auth context');
    const ctx = provider.contexts[0] as StubSecurityContext;
    assert.equal(ctx.calls, 2, 'one handshake: two step() calls');
    assert.equal(server.requests.filter((r) => r.body.length === 0).length, 1, 'one empty probe');
    assert.deepEqual(ctx.wrapCalls.map((c) => c.input.toString('utf8')), tags.map(soapFor));
    assert.deepEqual(
      ctx.unwrapCalls.map((c) => c.output.toString('utf8')),
      tags.map((t) => `<s:Envelope><s:Body>re:${t}</s:Body></s:Envelope>`),
    );
    // Wire order equals wrap order.
    const wire = server.requests.filter((r) => r.body.length > 0).map((r) => mimeUnwrap(r.body, fakeNtlmUnwrap));
    assert.deepEqual(wire, tags.map(soapFor));
  });

  it('a failing request releases the queue for the next one', async () => {
    const server = await startMockServer(tagHandler({ tamper: 'b' }));
    const transport = transportFor(server.port, challengeStub({ seal: FAKE_NTLM }));
    try {
      const [a, b, c] = await Promise.allSettled(['a', 'b', 'c'].map((t) => transport.post(soapFor(t))));
      assert.equal(a?.status, 'fulfilled');
      assert.equal(b?.status, 'rejected');
      assert.ok(b?.status === 'rejected' && b.reason instanceof WinRMTransportError);
      assert.deepEqual(c, { status: 'fulfilled', value: '<s:Envelope><s:Body>re:c</s:Body></s:Envelope>' });
    } finally {
      await transport.close();
      await server.close();
    }
  });
});

describe('Kerberos with encryption always on HTTPS', () => {
  it('does not tell a TLS caller to use HTTPS', async () => {
    await assert.rejects(
      connect({
        host: 'host',
        tls: true,
        encryption: 'always',
        authProvider: challengeStub({ seal: true, mechanism: 'kerberos' }),
        credentials: CREDENTIALS,
      }),
      (err: unknown) => err instanceof WinRMProtocolError && !/use HTTPS/.test(err.message) && /'auto' or 'never'/.test(err.message),
    );
  });
});

// --- Kerberos over plain HTTP with the gss_wrap_iov split ---------------

describe('MS-WSMV Kerberos framing: Length-Field = header length, data = OriginalContent Length', () => {
  const SOAP = Buffer.from(RESPONSE_SOAP, 'utf8');

  // A completed Kerberos context with the fake split, one step, no server.
  async function completedKrbCtx(): Promise<KerberosStubSecurityContext> {
    const ctx = new KerberosStubSecurityContext([{ expectInput: null, output: Buffer.from('t'), complete: true }], FAKE_KRB_IOV);
    await ctx.step();
    return ctx;
  }

  async function krbContext(): Promise<KerberosStubSecurityContext> {
    const ctx = new KerberosStubSecurityContext(
      [
        { expectInput: null, output: Buffer.from('initial-token'), complete: false },
        { expectInput: Buffer.from('server-challenge'), output: Buffer.from('response-token'), complete: true },
      ],
      FAKE_KRB_IOV,
    );
    await ctx.step();
    await ctx.step(Buffer.from('server-challenge'));
    return ctx;
  }

  it('writes the 60-byte header length, the header, then sealed data of exactly the SOAP length', async () => {
    const ctx = await krbContext();
    const body = await encryptMessage(ctx, 'kerberos', SOAP);
    const head =
      '--Encrypted Boundary\r\n' +
      '\tContent-Type: application/HTTP-SPNEGO-session-encrypted\r\n' +
      `\tOriginalContent: type=application/soap+xml;charset=UTF-8;Length=${SOAP.length}\r\n` +
      '--Encrypted Boundary\r\n' +
      '\tContent-Type: application/octet-stream\r\n';
    assert.equal(body.subarray(0, head.length).toString('utf8'), head);
    const stream = body.subarray(Buffer.byteLength(head));
    assert.equal(stream.readUInt32LE(0), FAKE_KRB_HEADER_LENGTH, 'Length-Field is the encryption header length');
    const call = ctx.wrapWinRMCalls[0]!;
    assert.ok(call.input.equals(SOAP), 'wrapWinRM() gets exactly the SOAP plaintext');
    assert.ok(stream.subarray(4, 4 + 60).equals(call.header), 'the header follows the Length-Field');
    assert.ok(stream.subarray(64, 64 + SOAP.length).equals(call.data), 'then the sealed data');
    assert.equal(stream.subarray(64 + SOAP.length).toString('utf8'), '--Encrypted Boundary--\r\n', 'no padding, no trailer');
    // The independent oracle parses it the same way.
    const [part] = mimeParts(body);
    assert.equal(part?.lengthField, 60);
    assert.equal(part?.data.length, SOAP.length);
    assert.equal(mimeUnwrapIov(body, fakeKrbUnwrapIov), RESPONSE_SOAP);
    assert.equal(ctx.wrapCalls.length, 0, 'the contract wrap() is not used for Kerberos');
  });

  it('round-trips encrypt then decrypt, giving unwrapWinRM() the header and the data separately', async () => {
    const ctx = await krbContext();
    const body = await encryptMessage(ctx, 'kerberos', SOAP);
    assert.equal(await decryptMessage(ctx, 'kerberos', SPNEGO_PROTOCOL, body), RESPONSE_SOAP);
    const call = ctx.unwrapWinRMCalls[0]!;
    assert.equal(call.header.length, 60);
    assert.ok(call.header.equals(ctx.wrapWinRMCalls[0]!.header));
    assert.ok(call.data.equals(ctx.wrapWinRMCalls[0]!.data));
    assert.equal(ctx.unwrapCalls.length, 0, 'the contract unwrap() is not used for Kerberos');
  });

  it('decrypts a response whose header length differs from ours (the acceptor decides it)', async () => {
    // A split whose header is 76 bytes (as if EC were 16): the transport
    // takes the length from the wire, not from a constant.
    const wide = {
      wrapIov: (p: Buffer) => {
        const r = fakeKrbWrapIov(p);
        return { header: Buffer.concat([r.header, Buffer.alloc(16, 0xee)]), data: r.data };
      },
      unwrapIov: (h: Buffer, d: Buffer) => fakeKrbUnwrapIov(h.subarray(0, 60), d),
    };
    const reply = mimeWrapIov(RESPONSE_SOAP, (m) => wide.wrapIov(m));
    assert.equal(reply.body.readUInt32LE(reply.body.indexOf('\tContent-Type: application/octet-stream\r\n') + 41), 76);
    const ctx = new KerberosStubSecurityContext([{ expectInput: null, output: Buffer.from('t'), complete: true }], wide);
    await ctx.step();
    assert.equal(await decryptMessage(ctx, 'kerberos', SPNEGO_PROTOCOL, reply.body), RESPONSE_SOAP);
    assert.equal(ctx.unwrapWinRMCalls[0]?.header.length, 76);
  });

  it('refuses a response whose encrypted data is not OriginalContent Length bytes, before unsealing', async () => {
    const ctx = await krbContext();
    const body = await encryptMessage(ctx, 'kerberos', SOAP);
    const shorter = Buffer.from(body.toString('latin1').replace(`Length=${SOAP.length}`, `Length=${SOAP.length - 1}`), 'latin1');
    await assert.rejects(decryptMessage(ctx, 'kerberos', SPNEGO_PROTOCOL, shorter), (err: unknown) => {
      assert.ok(err instanceof WinRMTransportError);
      assert.match(err.message, /bad Kerberos header length 60/);
      return true;
    });
    assert.equal(ctx.unwrapWinRMCalls.length, 0, 'no crypto on a malformed frame');
  });

  it('refuses a header length shorter than a wrap token', async () => {
    const ctx = await krbContext();
    const body = await encryptMessage(ctx, 'kerberos', SOAP);
    const bad = Buffer.from(body);
    const at = body.indexOf('\tContent-Type: application/octet-stream\r\n') + '\tContent-Type: application/octet-stream\r\n'.length;
    bad.writeUInt32LE(8, at);
    await assert.rejects(decryptMessage(ctx, 'kerberos', SPNEGO_PROTOCOL, bad), WinRMTransportError);
  });

  it('raises WinRMTransportError for a flipped byte in the data or in the header', async () => {
    const ctx = await krbContext();
    const body = await encryptMessage(ctx, 'kerberos', SOAP);
    const at = body.indexOf('\tContent-Type: application/octet-stream\r\n') + '\tContent-Type: application/octet-stream\r\n'.length;
    for (const offset of [4 + 20, 4 + 60 + 5]) {
      const tampered = Buffer.from(body);
      tampered[at + offset] = (tampered[at + offset] as number) ^ 0x01;
      await assert.rejects(decryptMessage(ctx, 'kerberos', SPNEGO_PROTOCOL, tampered), /tampered/);
    }
  });

  it('an unseal failure names the token the server sent: TOK_ID, Flags, EC, RRC, SND_SEQ and the lengths', async () => {
    // A server whose token the GSS layer rejects (what a Windows reply
    // did on macOS): the error carries the fields of the wire header,
    // so the trace says which RFC 4121 layout the server used.
    const foreign = {
      wrapIov: (p: Buffer) => {
        const r = fakeKrbWrapIov(p, 41);
        const header = Buffer.concat([r.header, Buffer.alloc(16, 0xee)]);
        header[2] = 0x03; // SentByAcceptor | Sealed, no subkey
        header.writeUInt16BE(16, 4); // EC 16
        header.writeUInt16BE(44, 6); // RRC 44
        return { header, data: r.data };
      },
      unwrapIov: (): Buffer => {
        throw new Error('gss_unwrap_iov: Miscellaneous failure (see text) (major 0xd0000); unknown mech-code 22 for mech 1 2 840 113554 1 2 2 (minor 22)');
      },
    };
    const reply = mimeWrapIov(RESPONSE_SOAP, (m) => foreign.wrapIov(m));
    const ctx = new KerberosStubSecurityContext([{ expectInput: null, output: Buffer.from('t'), complete: true }], foreign);
    await ctx.step();
    await assert.rejects(decryptMessage(ctx, 'kerberos', SPNEGO_PROTOCOL, reply.body), (err: unknown) => {
      assert.ok(err instanceof WinRMTransportError);
      assert.match(err.message, /^WinRM could not unseal the encrypted response: the message may have been tampered with \(gss_unwrap_iov: .*minor 22\)/);
      assert.match(err.message, /header 76 bytes: TOK_ID 0504, Flags 0x03 \(SentByAcceptor\|Sealed\), Filler ff, EC 16, RRC 44, SND_SEQ 41;/);
      assert.match(err.message, new RegExp(`data ${Buffer.byteLength(RESPONSE_SOAP)} bytes, OriginalContent Length ${Buffer.byteLength(RESPONSE_SOAP)}\\)$`));
      return true;
    });
  });

  it('describeWrapToken reads the RFC 4121 header and flags a non-wrap token', async () => {
    const h = fakeKrbWrapIov(Buffer.from('x'), 7).header;
    assert.equal(describeWrapToken(h), 'TOK_ID 0504, Flags 0x06 (Sealed|AcceptorSubkey), Filler ff, EC 0, RRC 28, SND_SEQ 7');
    assert.equal(describeWrapToken(Buffer.from('040400ff000000000000000000000000', 'hex')), 'TOK_ID 0404 (not a wrap token), Flags 0x00, Filler ff, EC 0, RRC 0, SND_SEQ 0');
    assert.equal(describeWrapToken(Buffer.from('0504', 'hex')), '2 bytes, shorter than a wrap token header');
    // The length check names the token too, before any crypto.
    const at = '\tContent-Type: application/octet-stream\r\n'.length;
    const body = mimeWrapIov(RESPONSE_SOAP, (m) => fakeKrbWrapIov(m, 3)).body;
    const octet = body.indexOf('\tContent-Type: application/octet-stream\r\n') + at;
    const bad = Buffer.from(body);
    bad.writeUInt32LE(61, octet);
    await assert.rejects(
      decryptMessage(await completedKrbCtx(), 'kerberos', SPNEGO_PROTOCOL, bad),
      /bad Kerberos header length 61 .* \(token: TOK_ID 0504, Flags 0x06 \(Sealed\|AcceptorSubkey\), Filler ff, EC 0, RRC 28, SND_SEQ 3\)/,
    );
  });

  it('refuses a split whose data length is not the plaintext length (no padding)', async () => {
    const padded = {
      wrapIov: (p: Buffer) => {
        const r = fakeKrbWrapIov(p);
        return { header: r.header, data: Buffer.concat([r.data, Buffer.alloc(3)]) };
      },
      unwrapIov: fakeKrbUnwrapIov,
    };
    const ctx = new KerberosStubSecurityContext([{ expectInput: null, output: Buffer.from('t'), complete: true }], padded);
    await ctx.step();
    await assert.rejects(encryptMessage(ctx, 'kerberos', SOAP), (err: unknown) => err instanceof WinRMProtocolError && /no padding/.test(err.message));
  });

  it('refuses a Kerberos context without the extension (the kerberos package) and names the addon', async () => {
    const ctx = new KerberosStubSecurityContext([{ expectInput: null, output: Buffer.from('t'), complete: true }]);
    await ctx.step();
    assert.equal(ctx.wrapWinRM, undefined);
    await assert.rejects(encryptMessage(ctx, 'kerberos', SOAP), (err: unknown) => {
      assert.ok(err instanceof WinRMProtocolError);
      assert.match(err.message, /^WinRM message encryption/);
      assert.match(err.message, /@winlinux\/krb-session-key/);
      assert.match(err.message, /HTTPS \(tls:true, port 5986\)/);
      return true;
    });
    const ntlmBody = await encryptMessage(ntlmContext(), 'ntlm', SOAP);
    await assert.rejects(decryptMessage(ctx, 'kerberos', SPNEGO_PROTOCOL, ntlmBody), WinRMProtocolError);
  });

  it('NTLM framing is unchanged: a Kerberos-capable context still frames NTLM with the 16-byte signature', async () => {
    const ctx = await krbContext();
    const body = await encryptMessage(ctx, 'ntlm', SOAP);
    const at = body.indexOf('\tContent-Type: application/octet-stream\r\n') + '\tContent-Type: application/octet-stream\r\n'.length;
    assert.equal(body.readUInt32LE(at), 16);
    assert.equal(ctx.wrapCalls.length, 1);
    assert.equal(ctx.wrapWinRMCalls.length, 0);
    assert.equal(await decryptMessage(ctx, 'ntlm', SPNEGO_PROTOCOL, body), RESPONSE_SOAP);
  });
});

describe('Kerberos over plain HTTP with the IOV split', () => {
  // Server: Negotiate challenge, then unseal the Kerberos frame with the
  // independent oracle and answer with a sealed response.
  function krbEchoHandler(seen: string[], lengthFields: number[]): MockHandler {
    const gate = negotiateGate();
    return (req): MockResponse => {
      const denied = gate.check(req);
      if (denied) return denied;
      for (const part of mimeParts(req.body)) lengthFields.push(part.lengthField);
      seen.push(mimeUnwrapIov(req.body, fakeKrbUnwrapIov));
      const r = mimeWrapIov(RESPONSE_SOAP, (m) => fakeKrbWrapIov(m, 7));
      return { status: 200, headers: { 'Content-Type': r.contentType }, body: r.body };
    };
  }

  it('connect() accepts a Kerberos provider whose context declares the extension', async () => {
    const session = await connect({ host: 'host', authProvider: kerberosStub(), credentials: CREDENTIALS });
    await session.close();
  });

  for (const mechanism of ['kerberos', 'negotiate'] as const) {
    it(`${mechanism}: every request body is sealed with Length-Field 60 and the response is unsealed`, async () => {
      const seen: string[] = [];
      const lengthFields: number[] = [];
      const server = await startMockServer(krbEchoHandler(seen, lengthFields));
      const provider = kerberosStub({ mechanism });
      const transport = transportFor(server.port, provider);
      try {
        assert.equal(await transport.post(REQUEST_SOAP), RESPONSE_SOAP);
        assert.equal(await transport.post(REQUEST_SOAP), RESPONSE_SOAP);
      } finally {
        await transport.close();
        await server.close();
      }
      assert.deepEqual(seen, [REQUEST_SOAP, REQUEST_SOAP]);
      assert.deepEqual(lengthFields, [60, 60]);
      const ctx = provider.contexts[0] as KerberosStubSecurityContext;
      assert.equal(ctx.wrapWinRMCalls.length, 2);
      assert.equal(ctx.unwrapWinRMCalls.length, 2);
      assert.equal(ctx.wrapCalls.length, 0, 'the contract wrap() is never called for Kerberos');
      assert.equal(ctx.unwrapCalls.length, 0);
      for (const call of ctx.unwrapWinRMCalls) {
        assert.equal(call.header.length, 60);
        assert.equal(call.data.length, Buffer.byteLength(RESPONSE_SOAP));
        assert.equal(call.input.toString('utf8'), RESPONSE_SOAP);
      }
      const req = server.requests.find((r) => r.body.length > 0)!;
      assert.equal(req.headers['content-type'], golden('pywinrm-ntlm-content-type.txt').toString('utf8'), 'same SPNEGO protocol string as NTLM');
      assert.equal(server.requests[0]?.body.length, 0, 'the first round is an empty probe');
    });
  }

  it('still refuses, after the first step and before any wrap(), a Kerberos context that never offers the split', async () => {
    const seen: string[] = [];
    const server = await startMockServer(krbEchoHandler(seen, []));
    const provider = kerberosStub({ iov: false });
    const transport = transportFor(server.port, provider);
    try {
      await assert.rejects(transport.post(REQUEST_SOAP), (err: unknown) => {
        assert.ok(err instanceof WinRMProtocolError);
        assert.match(err.message, /^WinRM message encryption over plain HTTP/);
        assert.match(err.message, /@winlinux\/krb-session-key/);
        assert.match(err.message, /HTTPS \(tls:true, port 5986\)/);
        return true;
      });
    } finally {
      await transport.close();
      await server.close();
    }
    const ctx = provider.contexts[0] as KerberosStubSecurityContext;
    assert.equal(ctx.wrapCalls.length, 0);
    assert.equal(ctx.wrapWinRMCalls.length, 0);
    assert.equal(server.requests.length, 0, 'refused before any socket I/O');
  });

  it('still refuses, when Negotiate picks Kerberos without the split, before any wrap()', async () => {
    const server = await startMockServer(krbEchoHandler([], []));
    const provider = kerberosStub({ iov: false, mechanism: 'negotiate' });
    const transport = transportFor(server.port, provider);
    try {
      await assert.rejects(transport.post(REQUEST_SOAP), (err: unknown) => err instanceof WinRMProtocolError && /5986/.test(err.message));
    } finally {
      await transport.close();
      await server.close();
    }
    assert.equal(server.requests.length, 0);
  });

  // Over TLS the transport fetches the server certificate with a probe
  // before the first Kerberos step, so this runs against a mock
  // HTTPS server. A Kerberos provider over unverified TLS is refused, and
  // the test certificate is self-signed, so the check runs in a child
  // process that trusts it through NODE_EXTRA_CA_CERTS.
  it("on HTTPS with encryption 'always', a context without the split gets the TLS wording, after the probe", async () => {
    const here = (name: string) => fileURLToPath(new URL(name, import.meta.url));
    const script = `
      const { readFileSync } = await import('node:fs');
      const [mockServerJs, stubAuthJs, transportJs, certPem, keyPem] = process.argv.slice(1);
      const { startMockServer } = await import(mockServerJs);
      const { kerberosStub, CREDENTIALS } = await import(stubAuthJs);
      const { WinRMTransport } = await import(transportJs);
      const server = await startMockServer(() => ({ status: 401, headers: { 'WWW-Authenticate': 'Negotiate' } }), {
        tls: { cert: readFileSync(certPem), key: readFileSync(keyPem) },
      });
      const transport = new WinRMTransport({ host: '127.0.0.1', port: server.port, tls: true, encryption: 'always', authProvider: kerberosStub({ iov: false }), credentials: CREDENTIALS });
      let out;
      try {
        await transport.post('<x/>');
        out = { ok: true };
      } catch (err) {
        out = { name: err.name, message: err.message };
      }
      out.requests = server.requests.map((r) => r.headers.authorization ?? null);
      await transport.close();
      await server.close();
      console.log(JSON.stringify(out));
    `;
    const { stdout } = await promisify(execFile)(
      process.execPath,
      ['--input-type=module', '-e', script, here('./helpers/mock-server.js'), here('./helpers/stub-auth.js'), here('../src/winrm/transport.js'), here('./fixtures/tls-test-cert.pem'), here('./fixtures/tls-test-key.pem')],
      { env: { ...process.env, NODE_EXTRA_CA_CERTS: here('./fixtures/tls-test-cert.pem') }, timeout: 30_000 },
    );
    const out = JSON.parse(stdout) as { ok?: boolean; name?: string; message?: string; requests: Array<string | null> };
    assert.equal(out.name, 'WinRMProtocolError', out.message);
    assert.doesNotMatch(out.message ?? '', /use HTTPS/);
    assert.match(out.message ?? '', /'auto' or 'never'/);
    assert.deepEqual(out.requests, [null], 'the probe went out; no token did');
  });
});

describe('Kerberos mutual auth: the AP-REP arrives on a non-401 response (RFC 4559 5)', () => {
  // The server accepts the AP-REQ on the empty probe, answers it with a
  // 200 that carries the final token, and takes the real sealed request
  // on the same connection with no further challenge.
  function mutualHandler(seen: string[], statusForProbe: number): MockHandler {
    let authenticated = false;
    return (req): MockResponse => {
      if (!authenticated) {
        if (req.headers.authorization !== `Negotiate ${B64('initial-token')}`) {
          return { status: 401, headers: { 'WWW-Authenticate': 'Negotiate' } };
        }
        authenticated = true;
        if (req.body.length === 0) return { status: statusForProbe, headers: { 'WWW-Authenticate': `Negotiate ${B64('ap-rep')}` } };
      }
      seen.push(mimeUnwrapIov(req.body, fakeKrbUnwrapIov));
      const r = mimeWrapIov(RESPONSE_SOAP, (m) => fakeKrbWrapIov(m, 1));
      return { status: 200, headers: { 'Content-Type': r.contentType }, body: r.body };
    };
  }

  function mutualProvider(): StubAuthProvider {
    return new StubAuthProvider(
      'kerberos',
      () =>
        new KerberosStubSecurityContext(
          [
            { expectInput: null, output: Buffer.from('initial-token'), complete: false },
            { expectInput: Buffer.from('ap-rep'), output: null, complete: true },
          ],
          FAKE_KRB_IOV,
        ),
    );
  }

  for (const status of [200, 500]) {
    it(`consumes the token from an HTTP ${status} probe response, then sends the sealed body on the same socket`, async () => {
      const seen: string[] = [];
      const server = await startMockServer(mutualHandler(seen, status));
      const provider = mutualProvider();
      const transport = transportFor(server.port, provider);
      try {
        assert.equal(await transport.post(REQUEST_SOAP), RESPONSE_SOAP);
        assert.equal(await transport.post(REQUEST_SOAP), RESPONSE_SOAP);
      } finally {
        await transport.close();
        await server.close();
      }
      assert.deepEqual(seen, [REQUEST_SOAP, REQUEST_SOAP]);
      const ctx = provider.contexts[0] as KerberosStubSecurityContext;
      assert.equal(ctx.calls, 2, 'the AP-REP was fed to step()');
      assert.equal(ctx.wrapWinRMCalls.length, 2, 'wrap only after the context completed');
      assert.equal(server.requests.length, 3, 'probe, request, request');
      assert.equal(server.requests[0]?.body.length, 0);
      assert.ok(server.requests.every((r) => r.socketId === 0), 'one keep-alive connection');
      // HTTP.sys treats any Authorization header on
      // an authenticated connection as a new handshake and answers a
      // stale AP-REQ with 401. Only the probe carries a token.
      assert.equal(server.requests[0]?.headers.authorization, `Negotiate ${B64('initial-token')}`);
      assert.equal(server.requests[1]?.headers.authorization, undefined, 'the sealed body after the AP-REP carries no Authorization header');
      assert.equal(server.requests[2]?.headers.authorization, undefined, 'nor does the next request');
    });
  }

  it('a 401 on the sealed request after the AP-REP is an auth error, not a connection error', async () => {
    // The server accepted the AP-REQ (200 with the AP-REP) and then
    // refuses the connection it authenticated: what a replayed or
    // rejected ticket looks like. Exit 2 territory, so WinRMAuthError.
    let authenticated = false;
    const server = await startMockServer((req): MockResponse => {
      if (!authenticated) {
        if (req.headers.authorization !== `Negotiate ${B64('initial-token')}`) return { status: 401, headers: { 'WWW-Authenticate': 'Negotiate' } };
        authenticated = true;
        return { status: 200, headers: { 'WWW-Authenticate': `Negotiate ${B64('ap-rep')}` } };
      }
      return { status: 401, headers: { 'WWW-Authenticate': 'Negotiate' } };
    });
    const provider = mutualProvider();
    const transport = transportFor(server.port, provider);
    try {
      await assert.rejects(transport.post(REQUEST_SOAP), (err: unknown) => {
        assert.ok(err instanceof WinRMAuthError, String(err));
        assert.match(err.message, /HTTP 401 after the handshake had finished/);
        return true;
      });
    } finally {
      await transport.close();
      await server.close();
    }
    assert.equal(server.requests.length, 2, 'probe, then the sealed body');
    assert.equal(server.requests[1]?.headers.authorization, undefined);
  });

  it('refuses a provider that wants another round after the server accepted the request', async () => {
    const provider = new StubAuthProvider(
      'kerberos',
      () =>
        new KerberosStubSecurityContext(
          [
            { expectInput: null, output: Buffer.from('initial-token'), complete: false },
            { expectInput: Buffer.from('ap-rep'), output: Buffer.from('more'), complete: false },
          ],
          FAKE_KRB_IOV,
        ),
    );
    const server = await startMockServer(mutualHandler([], 200));
    const transport = transportFor(server.port, provider);
    try {
      await assert.rejects(transport.post(REQUEST_SOAP), (err: unknown) => err instanceof WinRMProtocolError && /another round/.test(err.message));
    } finally {
      await transport.close();
      await server.close();
    }
  });
});
