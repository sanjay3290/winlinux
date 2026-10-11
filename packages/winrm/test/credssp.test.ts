// CredSSP over WinRM: the "CredSSP" Authorization scheme in the
// transport handshake loop and MS-WSMV CredSSP message encryption, end to
// end through connect() against the in-process CredSSP endpoint
// (helpers/credssp-server.ts: TLS in the header, real NTLMv2 in SPNEGO,
// pubKeyAuth, TSCredentials, encrypted SOAP). Sentinel values only.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { CredSSPAuthProvider, NtlmAuthProvider } from '@winlinux/auth';
import { connect, CREDSSP_HTTP_REASON, CREDSSP_INSECURE_REASON, type Credentials } from '../src/winrm/index.js';
import { WinRMTransportError } from '../src/winrm/errors.js';
import {
  CREDSSP_CHUNK_BYTES,
  CREDSSP_PROTOCOL,
  SPNEGO_PROTOCOL,
  decryptMessage,
  encryptMessage,
  encryptedContentType,
  encryptedProtocolOf,
} from '../src/winrm/encryption.js';
import type { SecurityContext } from '../src/auth-provider.js';
import { actionOf, startMockServer, type MockResponse, type RecordedRequest } from './helpers/mock-server.js';
import { CREDSSP_PASSWORD, credsspEndpoint, type CredSSPEndpoint } from './helpers/credssp-server.js';

const B64 = (s: string) => Buffer.from(s).toString('base64');
const CREDS: Credentials = { username: 'sentinel-user', password: CREDSSP_PASSWORD, domain: 'EXAMPLE' };

function fixture(name: string): string {
  return readFileSync(new URL(`./fixtures/${name}`, import.meta.url), 'utf8');
}

const SIGNAL_RESPONSE =
  '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body>' +
  '<rsp:SignalResponse xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell"/></s:Body></s:Envelope>';
const DELETE_RESPONSE =
  '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body>' +
  '<x:DeleteResponse xmlns:x="http://schemas.xmlsoap.org/ws/2004/09/transfer"/></s:Body></s:Envelope>';

function doneReceive(stdout: string, exitCode = 0): string {
  return (
    '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body>' +
    '<rsp:ReceiveResponse xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell">' +
    `<rsp:Stream Name="stdout" CommandId="COMMAND-ID-1">${B64(stdout)}</rsp:Stream>` +
    '<rsp:CommandState CommandId="COMMAND-ID-1" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done">' +
    `<rsp:ExitCode>${exitCode}</rsp:ExitCode></rsp:CommandState></rsp:ReceiveResponse></s:Body></s:Envelope>`
  );
}

interface Routes {
  [action: string]: string[];
}

// WinRM over the CredSSP endpoint: every SOAP request must be CredSSP
// encrypted, and every response is.
function handler(ep: CredSSPEndpoint, routes: Routes, seen: string[], soaps: string[]) {
  return async (req: RecordedRequest): Promise<MockResponse> => {
    const denied = await ep.check(req);
    if (denied) return denied;
    const soap = await ep.unwrap(req);
    const action = actionOf(Buffer.from(soap));
    seen.push(action);
    soaps.push(soap);
    const next = routes[action]?.shift();
    if (next === undefined) throw new Error(`no scripted response for ${action}`);
    return ep.wrap(req, next);
  };
}

function routes(stdout = 'hello world', exitCode = 0): Routes {
  return {
    Create: [fixture('create-response.xml')],
    Command: [fixture('command-response.xml')],
    Receive: [doneReceive(stdout, exitCode)],
    Signal: [SIGNAL_RESPONSE],
    Delete: [DELETE_RESPONSE],
  };
}

describe('WinRM CredSSP end to end (in-process server)', () => {
  it('signs in with CredSSP over HTTP and runs a command with CredSSP-encrypted bodies', async () => {
    const ep = credsspEndpoint();
    const seen: string[] = [];
    const soaps: string[] = [];
    const server = await startMockServer(handler(ep, routes('hello world', 3), seen, soaps));
    const notices: string[] = [];
    try {
      const session = await connect({
        host: '127.0.0.1',
        port: server.port,
        authProvider: new CredSSPAuthProvider(),
        credentials: CREDS,
        credsspAllowHttp: true,
        onCredSSPDelegation: (host) => notices.push(host),
      });
      try {
        assert.deepEqual(await session.runCommand('echo', ['hello']), { stdout: 'hello world', stderr: '', exitCode: 3 });
      } finally {
        await session.close();
      }
      assert.deepEqual(seen, ['Create', 'Command', 'Receive', 'Signal', 'Delete']);
      assert.match(soaps[1] ?? '', /<rsp:Command>echo<\/rsp:Command>/);
      assert.equal(ep.handshakes, 1, 'one sign-in for the session');
      assert.deepEqual(ep.credentials, [{ domain: 'EXAMPLE', username: 'sentinel-user', password: CREDSSP_PASSWORD }]);
      assert.deepEqual(ep.versions, [6, 6, 6]);
      assert.equal(ep.handshakeBodies, 0, 'every handshake round is an empty probe');
      assert.match(ep.ciphers[0] ?? '', /-GCM-/);
      assert.deepEqual(notices, ['127.0.0.1'], 'one notice per sign-in');
      for (const t of ep.requestContentTypes) assert.equal(t, encryptedContentType(CREDSSP_PROTOCOL));
      // The CredSSP scheme, never Negotiate, and never the password in a header.
      for (const r of server.requests) {
        const auth = r.headers.authorization;
        if (auth !== undefined) assert.match(auth, /^CredSSP [A-Za-z0-9+/=]+$/);
        assert.ok(!JSON.stringify(r.headers).includes(CREDSSP_PASSWORD));
        assert.ok(!r.body.includes(Buffer.from(CREDSSP_PASSWORD, 'utf16le')));
        assert.ok(!r.body.includes(Buffer.from(CREDSSP_PASSWORD, 'utf8')));
      }
    } finally {
      ep.close();
      await server.close();
    }
  });

  it('sends and receives messages over 16 KiB as multi-part (one TLS record per part)', async () => {
    const ep = credsspEndpoint();
    const seen: string[] = [];
    const soaps: string[] = [];
    const big = 'x'.repeat(50_000);
    const server = await startMockServer(handler(ep, routes(big), seen, soaps));
    try {
      const session = await connect({ host: '127.0.0.1', port: server.port, authProvider: new CredSSPAuthProvider(), credentials: CREDS, credsspAllowHttp: true });
      try {
        // A long argument makes the Command request longer than 16 KiB.
        const result = await session.runCommand('echo', ['y'.repeat(20_000)]);
        assert.equal(result.stdout, big);
      } finally {
        await session.close();
      }
      assert.ok(ep.requestContentTypes.includes(encryptedContentType(CREDSSP_PROTOCOL, true)), 'the Command went multi-part');
      assert.ok((soaps[1] ?? '').includes('y'.repeat(20_000)));
    } finally {
      ep.close();
      await server.close();
    }
  });

  it('refuses a server that speaks CredSSP version 5, before any credentials', async () => {
    const ep = credsspEndpoint({ version: 5 });
    const server = await startMockServer(handler(ep, routes(), [], []));
    const notices: string[] = [];
    try {
      const session = await connect({
        host: '127.0.0.1',
        port: server.port,
        authProvider: new CredSSPAuthProvider(),
        credentials: CREDS,
        credsspAllowHttp: true,
        onCredSSPDelegation: (host) => notices.push(host),
      });
      try {
        await assert.rejects(session.runCommand('echo'), /speaks version 5; winlinux needs version 6/);
      } finally {
        await session.close();
      }
      assert.deepEqual(ep.credentials, []);
      assert.deepEqual(notices, [], 'no notice: no password left the client');
    } finally {
      ep.close();
      await server.close();
    }
  });

  it('a wrong password fails at the inner NTLM step; the server gets no credentials', async () => {
    const ep = credsspEndpoint();
    const server = await startMockServer(handler(ep, routes(), [], []));
    try {
      const session = await connect({
        host: '127.0.0.1',
        port: server.port,
        authProvider: new CredSSPAuthProvider(),
        credentials: { ...CREDS, password: 'another-sentinel' },
        credsspAllowHttp: true,
      });
      try {
        // Windows answers a bad password with a TSRequest errorCode.
        await assert.rejects(session.runCommand('echo'), /refused the sign-in \(error 0xc000006d\)/);
      } finally {
        await session.close();
      }
      assert.deepEqual(ep.credentials, []);
    } finally {
      ep.close();
      await server.close();
    }
  });

  // The inner NTLM with the seal state of bare NTLMSSP (pubKeyAuth
  // at seq 0 on a fresh RC4 state) is what Windows dropped: a bare 401
  // Negotiate after the AUTHENTICATE + pubKeyAuth round. The endpoint
  // does the same, so this regression cannot pass the tests again.
  it('the bare NTLMSSP inner NTLM seal state is dropped the way Windows drops it', async () => {
    const ep = credsspEndpoint();
    const server = await startMockServer(handler(ep, routes(), [], []));
    const notices: string[] = [];
    try {
      const session = await connect({
        host: '127.0.0.1',
        port: server.port,
        authProvider: new CredSSPAuthProvider({ inner: (t, c) => new NtlmAuthProvider().createContext(t, c) }),
        credentials: CREDS,
        credsspAllowHttp: true,
        onCredSSPDelegation: (host) => notices.push(host),
      });
      try {
        await assert.rejects(session.runCommand('echo'), /HTTP 401 without a CredSSP challenge after round 4 of the CredSSP exchange/);
      } finally {
        await session.close();
      }
      assert.equal(ep.dropped.length, 1);
      assert.match(ep.dropped[0] ?? '', /NTLM sequence mismatch \(got 0, expected 1\)/);
      assert.deepEqual(ep.credentials, []);
      assert.deepEqual(notices, [], 'no notice: no password left the client');
    } finally {
      ep.close();
      await server.close();
    }
  });
});

describe('WinRM CredSSP refusals', () => {
  const base = { host: 'server.example.test', port: 1, authProvider: new CredSSPAuthProvider(), credentials: CREDS };

  it('refuses plain HTTP unless credsspAllowHttp is set, and names the risk', async () => {
    await assert.rejects(connect({ ...base }), (err: Error) => {
      assert.ok(err instanceof WinRMTransportError);
      assert.equal(err.message, CREDSSP_HTTP_REASON);
      assert.match(err.message, /no certificate check/);
      assert.match(err.message, /delegates your password/);
      assert.match(err.message, /--credssp-allow-http/);
      return true;
    });
    await assert.rejects(connect({ ...base, credsspAllowHttp: false }), /plain HTTP is refused/);
  });

  it('refuses tlsVerify false (--insecure), over HTTPS and HTTP', async () => {
    await assert.rejects(connect({ ...base, tls: true, tlsVerify: false }), (err: Error) => err instanceof WinRMTransportError && err.message === CREDSSP_INSECURE_REASON);
    await assert.rejects(connect({ ...base, tlsVerify: false, credsspAllowHttp: true }), /refuses --insecure/);
  });

  it('accepts HTTPS with a verified certificate without the HTTP flag', async () => {
    const session = await connect({ ...base, tls: true });
    await session.close();
  });
});

// A CredSSP-shaped fake context: wrap() returns header(5) || data || tag(16),
// like one TLS AES-GCM record; unwrap() undoes it.
function fakeCredsspContext(): SecurityContext & { credsspTrailerLength: () => number; wraps: number } {
  const ctx = {
    wraps: 0,
    complete: true,
    negotiatedMechanism: 'credssp' as const,
    credsspTrailerLength: () => 16,
    async step() {
      return { output: null, complete: true };
    },
    async wrap(p: Buffer) {
      ctx.wraps += 1;
      return Buffer.concat([Buffer.from('HDR::'), Buffer.from(p.map((b) => b ^ 0x33)), Buffer.alloc(16, 0xee)]);
    },
    async unwrap(c: Buffer) {
      if (!c.subarray(0, 5).equals(Buffer.from('HDR::'))) throw new Error('fake: bad header');
      return Buffer.from(c.subarray(5, c.length - 16).map((b) => b ^ 0x33));
    },
  };
  return ctx;
}

describe('MS-WSMV CredSSP framing', () => {
  it('writes the CredSSP protocol, the trailer Length-Field and the TLS bytes', async () => {
    const ctx = fakeCredsspContext();
    const soap = Buffer.from('<s:Envelope>sentinel</s:Envelope>');
    const body = await encryptMessage(ctx, 'credssp', soap);
    const text = body.toString('latin1');
    assert.ok(text.startsWith(`--Encrypted Boundary\r\n\tContent-Type: ${CREDSSP_PROTOCOL}\r\n\tOriginalContent: type=application/soap+xml;charset=UTF-8;Length=${soap.length}\r\n--Encrypted Boundary\r\n\tContent-Type: application/octet-stream\r\n`));
    const at = body.indexOf('application/octet-stream\r\n') + 'application/octet-stream\r\n'.length;
    assert.equal(body.readUInt32LE(at), 16, 'Length-Field is the trailer length');
    assert.ok(text.endsWith('--Encrypted Boundary--\r\n'));
    assert.equal(await decryptMessage(ctx, 'credssp', CREDSSP_PROTOCOL, body), soap.toString());
  });

  it('splits a message over 16 KiB into one part per 16 KiB chunk', async () => {
    const ctx = fakeCredsspContext();
    const soap = Buffer.alloc(CREDSSP_CHUNK_BYTES * 2 + 100, 'a');
    const body = await encryptMessage(ctx, 'credssp', soap);
    assert.equal(ctx.wraps, 3);
    const lengths = [...body.toString('latin1').matchAll(/Length=(\d+)/g)].map((m) => Number(m[1]));
    assert.deepEqual(lengths, [CREDSSP_CHUNK_BYTES, CREDSSP_CHUNK_BYTES, 100]);
    assert.equal(await decryptMessage(ctx, 'credssp', CREDSSP_PROTOCOL, body), soap.toString());
    // Exactly 16 KiB stays one part.
    const one = fakeCredsspContext();
    await encryptMessage(one, 'credssp', Buffer.alloc(CREDSSP_CHUNK_BYTES, 'b'));
    assert.equal(one.wraps, 1);
  });

  it('content types: multipart/encrypted and multipart/x-multi-encrypted', () => {
    assert.equal(encryptedContentType(CREDSSP_PROTOCOL), `multipart/encrypted;protocol="${CREDSSP_PROTOCOL}";boundary="Encrypted Boundary"`);
    assert.equal(encryptedContentType(CREDSSP_PROTOCOL, true), `multipart/x-multi-encrypted;protocol="${CREDSSP_PROTOCOL}";boundary="Encrypted Boundary"`);
    assert.equal(encryptedProtocolOf(encryptedContentType(CREDSSP_PROTOCOL, true)), CREDSSP_PROTOCOL);
    assert.equal(encryptedProtocolOf('multipart/mixed;protocol="x"'), null);
  });

  it('refuses a SPNEGO response on a CredSSP session, a bad trailer length, and a context without the extension', async () => {
    const ctx = fakeCredsspContext();
    const body = await encryptMessage(ctx, 'credssp', Buffer.from('<x/>'));
    await assert.rejects(decryptMessage(ctx, 'credssp', SPNEGO_PROTOCOL, body), /protocol 'application\/HTTP-SPNEGO-session-encrypted' on a credssp session/);
    const bad = Buffer.from(body);
    const at = body.indexOf('application/octet-stream\r\n') + 'application/octet-stream\r\n'.length;
    bad.writeUInt32LE(1000, at);
    await assert.rejects(decryptMessage(ctx, 'credssp', CREDSSP_PROTOCOL, bad), /bad CredSSP trailer length 1000/);
    const plain: SecurityContext = { complete: true, step: ctx.step, wrap: ctx.wrap, unwrap: ctx.unwrap };
    await assert.rejects(encryptMessage(plain, 'credssp', Buffer.from('<x/>')), /credsspTrailerLength/);
  });
});
