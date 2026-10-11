// RFC 5929 tls-server-end-point channel binding: the hash picked
// from the certificate's signature algorithm, and the transport binding
// the NTLM AUTHENTICATE to the TLS socket that answered the challenge.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';
import type { AuthProvider, AuthTarget, Credentials, SecurityContext, StepResult } from '../src/auth-provider.js';
import { TLS_SERVER_END_POINT_PREFIX, tlsServerEndPoint, tlsServerEndPointHashName, type ChannelBoundTarget } from '../src/winrm/channel-binding.js';
import { WinRMTransport } from '../src/winrm/transport.js';
import { CREDENTIALS, fakeNtlmUnwrap, fakeNtlmWrap } from './helpers/stub-auth.js';
import { mimeUnwrap, mimeWrap, negotiateGate, startMockServer } from './helpers/mock-server.js';
import { AV_CHANNEL_BINDINGS, challengeWithTimestamp, ntlmsspType, type AvPair, type3AvPairs } from './helpers/ntlm-wire.js';
// The real NTLM provider, for the end-to-end check.
import { channelBindingsHash, NtlmAuthProvider } from '@winlinux/auth';

const B64 = (s: string) => Buffer.from(s).toString('base64');

function pem(name: string): Buffer {
  return readFileSync(new URL(`./fixtures/${name}`, import.meta.url));
}
const der = (name: string) => new X509Certificate(pem(name)).raw;

function tlsOptions() {
  return { cert: pem('tls-test-cert.pem'), key: pem('tls-test-key.pem') };
}

describe('tls-server-end-point hash selection (RFC 5929 4.1)', () => {
  // Expected: the certificate's signature hash, except MD5 and SHA-1 (and
  // an algorithm with no single hash, Ed25519) become SHA-256. Same rule
  // as requests-ntlm _get_certificate_hash, which pywinrm uses.
  for (const [file, expected] of [
    ['cbt/rsa-md5.pem', 'sha256'],
    ['cbt/rsa-sha1.pem', 'sha256'],
    ['tls-test-cert.pem', 'sha256'], // sha256WithRSAEncryption
    ['cbt/rsa-sha384.pem', 'sha384'],
    ['cbt/rsa-pss-sha512.pem', 'sha512'], // hash from the RSASSA-PSS parameters
    ['cbt/ecdsa-sha256.pem', 'sha256'],
    ['cbt/ecdsa-sha384.pem', 'sha384'],
    ['cbt/ed25519.pem', 'sha256'],
  ] as const) {
    it(`${file} -> ${expected}`, () => {
      const raw = der(file);
      assert.equal(tlsServerEndPointHashName(raw), expected);
      const binding = tlsServerEndPoint(raw);
      assert.equal(binding.subarray(0, TLS_SERVER_END_POINT_PREFIX.length).toString('ascii'), TLS_SERVER_END_POINT_PREFIX);
      assert.ok(binding.subarray(TLS_SERVER_END_POINT_PREFIX.length).equals(createHash(expected).update(raw).digest()));
    });
  }

  it('the test certificate binding is "tls-server-end-point:" + its SHA-256 (openssl)', () => {
    // openssl x509 -in tls-test-cert.pem -outform DER | sha256sum
    const sha256 = '76e5bd6ac8b9cd29b12ddf7391b9354faf8a533d43dd2d12f6c323d2a5cfe414';
    assert.equal(tlsServerEndPoint(der('tls-test-cert.pem')).toString('hex'), Buffer.from(TLS_SERVER_END_POINT_PREFIX, 'ascii').toString('hex') + sha256);
  });

  it('rejects bytes that are not a certificate', () => {
    assert.throws(() => tlsServerEndPoint(Buffer.from('not a certificate')), /DER/);
    assert.throws(() => tlsServerEndPoint(Buffer.alloc(0)), /DER/);
  });
});

// A two-step context that snapshots the target's channelBindings at each
// step() call, so the test sees what the provider would have read.
class SnapshotContext implements SecurityContext {
  complete = false;
  readonly bindingsAtStep: Array<Buffer | undefined> = [];
  constructor(private readonly target: ChannelBoundTarget) {}
  // The fake NTLM layout, so the context also serves plain HTTP.
  async wrap(plaintext: Buffer): Promise<Buffer> {
    return fakeNtlmWrap(plaintext);
  }
  async unwrap(ciphertext: Buffer): Promise<Buffer> {
    return fakeNtlmUnwrap(ciphertext);
  }
  async step(inputToken?: Buffer): Promise<StepResult> {
    const b = this.target.channelBindings;
    this.bindingsAtStep.push(b ? Buffer.from(b) : undefined);
    if (inputToken === undefined) return { output: Buffer.from('initial-token'), complete: false };
    this.complete = true;
    return { output: Buffer.from('response-token'), complete: true };
  }
}

class SnapshotProvider implements AuthProvider {
  readonly mechanism = 'ntlm' as const;
  readonly contexts: SnapshotContext[] = [];
  createContext(target: AuthTarget, _credentials: Credentials): SecurityContext {
    const ctx = new SnapshotContext(target as ChannelBoundTarget);
    this.contexts.push(ctx);
    return ctx;
  }
}

describe('transport passes the TLS channel binding to the auth context', () => {
  const expectedBinding = tlsServerEndPoint(der('tls-test-cert.pem'));

  it('sets channelBindings from the peer certificate before the challenge is fed back', async () => {
    const gate = negotiateGate();
    const server = await startMockServer((req) => gate.check(req) ?? { status: 200, body: '<ok/>' }, { tls: tlsOptions() });
    const provider = new SnapshotProvider();
    const transport = new WinRMTransport({ host: '127.0.0.1', port: server.port, tls: true, tlsVerify: false, authProvider: provider, credentials: CREDENTIALS });
    try {
      assert.equal(await transport.post('<soap/>'), '<ok/>');
    } finally {
      await transport.close();
      await server.close();
    }
    const [ctx] = provider.contexts;
    assert.ok(ctx);
    assert.equal(ctx.bindingsAtStep.length, 2);
    assert.equal(ctx.bindingsAtStep[0], undefined, 'no socket yet at the first step');
    assert.ok(ctx.bindingsAtStep[1]?.equals(expectedBinding), 'the challenge step sees the binding of the socket that answered');
  });

  it('sets it again for the fresh context of a re-authentication', async () => {
    const gate = negotiateGate();
    const server = await startMockServer(
      (req, index) => {
        if (index === 2) return { status: 401, headers: { 'WWW-Authenticate': 'Negotiate' } }; // the server forgot us
        return gate.check(req) ?? { status: 200, body: '<ok/>' };
      },
      { tls: tlsOptions() },
    );
    const provider = new SnapshotProvider();
    const transport = new WinRMTransport({ host: '127.0.0.1', port: server.port, tls: true, tlsVerify: false, authProvider: provider, credentials: CREDENTIALS });
    try {
      assert.equal(await transport.post('<soap>one</soap>'), '<ok/>');
      assert.equal(await transport.post('<soap>two</soap>'), '<ok/>');
    } finally {
      await transport.close();
      await server.close();
    }
    assert.equal(provider.contexts.length, 2);
    for (const ctx of provider.contexts) {
      assert.equal(ctx.bindingsAtStep[0], undefined);
      assert.ok(ctx.bindingsAtStep[1]?.equals(expectedBinding));
    }
  });

  it('leaves channelBindings unset over plain HTTP', async () => {
    const gate = negotiateGate();
    const server = await startMockServer((req) => {
      const denied = gate.check(req);
      if (denied) return denied;
      const wrapped = mimeWrap(`<ok>${mimeUnwrap(req.body, fakeNtlmUnwrap)}</ok>`, fakeNtlmWrap);
      return { status: 200, headers: { 'Content-Type': wrapped.contentType }, body: wrapped.body };
    });
    const provider = new SnapshotProvider();
    const transport = new WinRMTransport({ host: '127.0.0.1', port: server.port, tls: false, authProvider: provider, credentials: CREDENTIALS });
    try {
      assert.equal(await transport.post('<soap/>'), '<ok><soap/></ok>');
    } finally {
      await transport.close();
      await server.close();
    }
    const [ctx] = provider.contexts;
    assert.ok(ctx);
    assert.deepEqual(ctx.bindingsAtStep, [undefined, undefined]);
  });
});

describe('real NTLM AUTHENTICATE over the TLS mock', () => {
  // The mock is the server: it answers the NEGOTIATE with a challenge and
  // decodes the AUTHENTICATE it gets back. Over TLS the AV pair must be the
  // MD5 of the gss struct for "tls-server-end-point:" + SHA-256(its own
  // certificate). (No pair at all without a binding: @winlinux/auth
  // channel-bindings.test.ts.)
  async function authenticateOverTls(): Promise<AvPair[]> {
    const tls = true;
    const seen: AvPair[][] = [];
    const server = await startMockServer(
      (req) => {
        const m = /^Negotiate (.+)$/.exec(req.headers.authorization ?? '');
        if (!m?.[1]) return { status: 401, headers: { 'WWW-Authenticate': 'Negotiate' } };
        const token = Buffer.from(m[1], 'base64');
        const type = ntlmsspType(token);
        if (type === null) return { status: 400 };
        // A bare CHALLENGE_MESSAGE, as Windows answers bare NTLMSSP.
        if (type === 1) return { status: 401, headers: { 'WWW-Authenticate': `Negotiate ${challengeWithTimestamp().toString('base64')}` } };
        seen.push(type3AvPairs(token));
        return { status: 200, body: '<ok/>' };
      },
      tls ? { tls: tlsOptions() } : undefined,
    );
    const transport = new WinRMTransport({
      host: '127.0.0.1',
      port: server.port,
      tls,
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
    assert.equal(seen.length, 1);
    return seen[0]!;
  }

  it('over HTTPS carries MsvAvChannelBindings bound to the mock certificate', async () => {
    const pairs = await authenticateOverTls();
    const cbt = pairs.find((p) => p.id === AV_CHANNEL_BINDINGS);
    assert.ok(cbt, 'MsvAvChannelBindings present');
    const expected = channelBindingsHash(tlsServerEndPoint(der('tls-test-cert.pem')));
    assert.equal(cbt.value.toString('hex'), expected.toString('hex'));
    assert.ok(!cbt.value.equals(Buffer.alloc(16)), 'never all zero');
  });
});
