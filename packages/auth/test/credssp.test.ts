// CredSSP: TSRequest DER against hand-built MS-CSSP 2.2.1 fixtures,
// the pubKeyAuth hash (MS-CSSP 3.1.5) against fixed and independently
// computed vectors, the version and nonce rules, and whole handshakes
// against the in-process test server (helpers/credssp-server.ts).
// All values are sentinels; nothing here is a real credential.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes, X509Certificate } from 'node:crypto';
import { CredSSPAuthProvider, CredSSPSecurityContext, credsspCredentialsError, type CredSSPProviderDeps } from '../src/auth/credssp/provider.js';
import { gcmPlaintextLength } from '../src/auth/credssp/tls.js';
import { integer, readInteger, readOne, subjectPublicKey } from '../src/auth/credssp/der.js';
import {
  checkServerVersion,
  decodeTSCredentials,
  decodeTSRequest,
  encodeTSCredentials,
  encodeTSRequest,
  formatErrorCode,
  pubKeyAuthHash,
} from '../src/auth/credssp/tsrequest.js';
import { createAuthProvider } from '../src/auth/index.js';
import type { GssClient } from '../src/auth/kerberos.js';
import { NegState, OID_KRB5, frameNegTokenResp, unframeSpnego } from '../src/auth/spnego.js';
import type { AuthTarget, Credentials, SecurityContext, StepResult } from '../src/auth/types.js';
import {
  CLIENT_MAGIC,
  CredSSPTestServer,
  FAKE_INNER,
  SERVER_MAGIC,
  TEST_CERT,
  TEST_SUBJECT_PUBLIC_KEY_HEX,
  fakeAcceptor,
  fakeSeal,
  fakeUnseal,
  ntlmAcceptor,
  specHash,
  type InnerAcceptor,
  type NtlmAcceptorResult,
  type ServerFaults,
} from './helpers/credssp-server.js';

const TARGET: AuthTarget = { host: 'server.example.test', service: 'HTTP' };
const PASSWORD = 'sentinel-password-126';
const CREDS: Credentials = { username: 'sentinel-user', password: PASSWORD, domain: 'EXAMPLE' };
const hex = (s: string) => Buffer.from(s.replace(/\s+/g, ''), 'hex');

// The client half of the fake inner mechanism (helpers FAKE_INNER).
class FakeInner implements SecurityContext {
  complete = false;
  private round = 0;
  async step(input?: Buffer): Promise<StepResult> {
    this.round += 1;
    if (this.round === 1) return { output: FAKE_INNER.clientFirst, complete: false };
    if (!input?.equals(FAKE_INNER.serverChallenge)) throw new Error('fake inner: unexpected challenge');
    this.complete = true;
    return { output: FAKE_INNER.clientResponse, complete: true };
  }
  async wrap(data: Buffer): Promise<Buffer> {
    return fakeSeal(data);
  }
  async unwrap(data: Buffer): Promise<Buffer> {
    return fakeUnseal(data);
  }
}

const fakeDeps = { inner: () => new FakeInner() };

// Runs the client against the test server until the client completes or
// throws. Returns the client context.
async function handshake(
  ctx: SecurityContext,
  server: CredSSPTestServer,
): Promise<void> {
  let res = await ctx.step();
  for (let i = 0; i < 10; i++) {
    const reply = await server.respond(res.output as Buffer);
    if (reply === null) {
      assert.equal(res.complete, true, 'the server took the credentials only after the client completed');
      return;
    }
    res = await ctx.step(reply);
  }
  throw new Error('handshake did not finish in 10 rounds');
}

async function run(inner: InnerAcceptor, faults: ServerFaults = {}, creds: Credentials = CREDS, deps: CredSSPProviderDeps = fakeDeps) {
  const server = new CredSSPTestServer(inner, faults);
  const ctx = new CredSSPAuthProvider(deps).createContext(TARGET, creds);
  return { server, ctx, done: handshake(ctx, server) };
}

describe('CredSSP TSRequest DER (MS-CSSP 2.2.1)', () => {
  // TSRequest { version [0] 6, negoTokens [1] { { negoToken [0] "NTLMSSP\0" 01000000 } } }
  const NEGO_FIXTURE = hex('301b a003020106 a114 3012 3010 a00e 040c 4e544c4d5353500001000000');
  const SENTINEL_TOKEN = hex('4e544c4d5353500001000000');

  it('encodes and decodes a negoTokens request', () => {
    assert.equal(encodeTSRequest({ version: 6, negoTokens: [SENTINEL_TOKEN] }).toString('hex'), NEGO_FIXTURE.toString('hex'));
    assert.deepEqual(decodeTSRequest(NEGO_FIXTURE), { version: 6, negoTokens: [SENTINEL_TOKEN] });
  });

  // TSRequest { version 6, pubKeyAuth [3] "PKA1", clientNonce [5] 32 x 0x11 }
  const PUBKEY_FIXTURE = hex(`3031 a003020106 a306 0404 504b4131 a522 0420 ${'11'.repeat(32)}`);

  it('encodes and decodes pubKeyAuth with a clientNonce', () => {
    const req = { version: 6, pubKeyAuth: Buffer.from('PKA1'), clientNonce: Buffer.alloc(32, 0x11) };
    assert.equal(encodeTSRequest(req).toString('hex'), PUBKEY_FIXTURE.toString('hex'));
    assert.deepEqual(decodeTSRequest(PUBKEY_FIXTURE), req);
  });

  it('encodes and decodes authInfo and an NTSTATUS errorCode, signed or unsigned', () => {
    // errorCode as Windows sends STATUS_LOGON_FAILURE: a negative INTEGER.
    const signed = hex('3013 a003020106 a204 04024149 a406 0204c000006d');
    const decoded = decodeTSRequest(signed);
    assert.deepEqual(decoded.authInfo, Buffer.from('AI'));
    assert.equal(formatErrorCode(decoded.errorCode as number), '0xc000006d');
    assert.equal(encodeTSRequest(decoded).toString('hex'), signed.toString('hex'));
    // The same value written as a positive INTEGER (a leading zero octet).
    const unsigned = hex('3014 a003020106 a204 04024149 a407 020500c000006d');
    assert.equal(formatErrorCode(decodeTSRequest(unsigned).errorCode as number), '0xc000006d');
    assert.equal(encodeTSRequest({ version: 6, authInfo: Buffer.from('AI'), errorCode: 0xc000006d }).toString('hex'), unsigned.toString('hex'));
  });

  it('DER INTEGER is minimal two-s complement', () => {
    for (const [n, h] of [[0, '020100'], [6, '020106'], [127, '02017f'], [128, '02020080'], [-1, '0201ff'], [-129, '0202ff7f']] as const) {
      assert.equal(integer(n).toString('hex'), h);
      assert.equal(readInteger(readOne(Buffer.from(h, 'hex'), 'int'), 'int'), n);
    }
    assert.throws(() => readInteger(readOne(hex('02020006'), 'int'), 'int'), /not minimal/);
  });

  it('refuses malformed requests', () => {
    const bad: Array<[string, RegExp]> = [
      ['3000', /no version/],
      ['3009 a3020400 a003020106', /out of order/],
      ['300a a003020106 a603020101', /unknown TSRequest field/],
      ['3005 a003020106 00', /trailing bytes/],
      ['3080 a003020106 0000', /indefinite length/],
      ['3009 a003020106 a1023000', /negoTokens is empty/],
      [`3026 a003020106 a51f 041d ${'11'.repeat(29)}`, /clientNonce is 29 bytes, not 32/],
      ['3005 a0030201ff', /version -1 is not valid/],
      ['3006 a003020106', /truncated/],
    ];
    for (const [h, re] of bad) assert.throws(() => decodeTSRequest(hex(h)), re, h);
  });

  // TSCredentials { credType [0] 1, credentials [1] TSPasswordCreds { "D", "U", "P" } } (UTF-16LE)
  const CREDS_FIXTURE = hex('301d a003020101 a116 0414 3012 a00404024400 a10404025500 a20404025000');

  it('encodes TSCredentials with TSPasswordCreds in UTF-16LE', () => {
    assert.equal(encodeTSCredentials({ domain: 'D', username: 'U', password: 'P' }).toString('hex'), CREDS_FIXTURE.toString('hex'));
    const back = decodeTSCredentials(CREDS_FIXTURE);
    assert.deepEqual([back.credType, back.domain.toString('utf16le'), back.username.toString('utf16le'), back.password.toString('utf16le')], [1, 'D', 'U', 'P']);
    // Long values take the long length form.
    const long = encodeTSCredentials({ domain: 'example.test', username: 'u'.repeat(100), password: 'p'.repeat(200) });
    assert.equal(decodeTSCredentials(long).password.toString('utf16le'), 'p'.repeat(200));
    assert.throws(() => decodeTSCredentials(hex('300a a003020102 a1030401 00')), /credType 2 is not a password/);
  });
});

describe('CredSSP pubKeyAuth hash (MS-CSSP 3.1.5, CVE-2018-0886)', () => {
  const NONCE = Buffer.from(Array.from({ length: 32 }, (_, i) => i));
  const KEY = Buffer.from(TEST_SUBJECT_PUBLIC_KEY_HEX, 'hex');

  it('matches fixed vectors (computed with Python hashlib)', () => {
    assert.equal(pubKeyAuthHash('client-to-server', NONCE, KEY).toString('hex'), '169da0bffdd5569c922ee327d77d1b7eaa5fbe2ca480166e7b38ca6242b64cd2');
    assert.equal(pubKeyAuthHash('server-to-client', NONCE, KEY).toString('hex'), '8867adeabb095d1215031c01ed9c1b13d3a4539b4e9befd3cff3dc0ed04af213');
  });

  it('matches the spec formula computed with node:crypto', () => {
    for (let i = 0; i < 5; i++) {
      const nonce = randomBytes(32);
      const key = randomBytes(64 + i);
      const client = createHash('sha256').update(Buffer.concat([Buffer.from('CredSSP Client-To-Server Binding Hash\0'), nonce, key])).digest();
      const server = createHash('sha256').update(Buffer.concat([Buffer.from('CredSSP Server-To-Client Binding Hash\0'), nonce, key])).digest();
      assert.deepEqual(pubKeyAuthHash('client-to-server', nonce, key), client);
      assert.deepEqual(pubKeyAuthHash('server-to-client', nonce, key), server);
      assert.notDeepEqual(client, server);
    }
  });

  it('refuses a missing or short nonce, and an empty key', () => {
    assert.throws(() => pubKeyAuthHash('client-to-server', undefined, KEY), /no clientNonce/);
    assert.throws(() => pubKeyAuthHash('client-to-server', Buffer.alloc(16), KEY), /16 bytes, not 32/);
    assert.throws(() => pubKeyAuthHash('client-to-server', NONCE, Buffer.alloc(0)), /no public key/);
  });

  it('takes SubjectPublicKey from the certificate (openssl agrees)', () => {
    const spki = new X509Certificate(TEST_CERT).publicKey.export({ type: 'spki', format: 'der' });
    assert.equal(subjectPublicKey(spki).toString('hex'), TEST_SUBJECT_PUBLIC_KEY_HEX);
  });

  it('refuses servers older than version 6', () => {
    for (const v of [0, 2, 3, 4, 5]) assert.throws(() => checkServerVersion(v), new RegExp(`speaks version ${v}; winlinux needs version 6 or later`));
    checkServerVersion(6);
    checkServerVersion(7);
  });
});

describe('CredSSP handshake against the in-process server', () => {
  it('runs TLS, the inner exchange, pubKeyAuth both ways and the TSCredentials', async () => {
    const nonce = Buffer.alloc(32, 0x7e);
    const { server, ctx, done } = await run(fakeAcceptor(), {}, CREDS, { ...fakeDeps, nonce: () => nonce });
    try {
      await done;
      assert.equal(ctx.complete, true);
      assert.equal(ctx.negotiatedMechanism, 'credssp');
      assert.equal(ctx.sessionKey, undefined, 'CredSSP has no sessionKey');
      assert.deepEqual(server.versions, [6, 6, 6]);
      assert.deepEqual(server.clientNonce, nonce);
      assert.equal(server.clientHashOk, true);
      assert.deepEqual(server.credentials, { domain: 'EXAMPLE', username: 'sentinel-user', password: PASSWORD });
      assert.match(server.tls.cipherName(), /-GCM-/);
      assert.equal((ctx as CredSSPSecurityContext).credsspTrailerLength?.(), 16);
      // wrap/unwrap go through the inner TLS session, both ways.
      const soap = Buffer.from('<s:Envelope>sentinel</s:Envelope>');
      const sealed = await ctx.wrap!(soap);
      assert.equal(sealed.length, soap.length + 5 + 8 + 16, 'one TLS 1.2 AES-GCM record');
      assert.equal(gcmPlaintextLength(sealed), soap.length);
      assert.deepEqual((await server.tls.feed(sealed)).plain, soap);
      const reply = await server.tls.write(Buffer.from('<reply/>'));
      assert.deepEqual(await ctx.unwrap!(reply), Buffer.from('<reply/>'));
      // A large message spans several records.
      const big = randomBytes(40000);
      const bigSealed = await ctx.wrap!(big);
      assert.equal(gcmPlaintextLength(bigSealed), big.length);
      assert.deepEqual((await server.tls.feed(bigSealed)).plain, big);
      assert.deepEqual(await ctx.unwrap!(await server.tls.write(big)), big);
      await assert.rejects(ctx.step(Buffer.from('x')), /already complete/);
    } finally {
      await ctx.dispose?.();
      server.close();
    }
  });

  it('runs real NTLM inside SPNEGO, with both mechListMICs', async () => {
    const result: NtlmAcceptorResult = { verified: false };
    const { server, ctx, done } = await run(ntlmAcceptor(PASSWORD, result), {}, CREDS, {});
    try {
      await done;
      assert.equal(result.verified, true);
      assert.deepEqual([result.user, result.domain], ['sentinel-user', 'EXAMPLE']);
      assert.deepEqual(server.credentials, { domain: 'EXAMPLE', username: 'sentinel-user', password: PASSWORD });
      const soap = Buffer.from('<s:Envelope>ntlm</s:Envelope>');
      assert.deepEqual((await server.tls.feed(await ctx.wrap!(soap))).plain, soap);
    } finally {
      await ctx.dispose?.();
      server.close();
    }
  });

  it('sends a UPN user name with an empty domain', async () => {
    const creds: Credentials = { username: 'sentinel-user@example.test', password: PASSWORD, domain: 'EXAMPLE' };
    const { server, ctx, done } = await run(fakeAcceptor(), {}, creds);
    try {
      await done;
      assert.deepEqual(server.credentials, { domain: '', username: 'sentinel-user@example.test', password: PASSWORD });
    } finally {
      await ctx.dispose?.();
      server.close();
    }
  });

  it('a wrong password fails at the server, before any credentials are sent', async () => {
    const { server, ctx, done } = await run(ntlmAcceptor('another-sentinel'), {}, CREDS, {});
    try {
      await assert.rejects(done, /wrong password/);
      assert.equal(server.credentials, undefined);
    } finally {
      await ctx.dispose?.();
      server.close();
    }
  });

  it('runs Kerberos as the inner mechanism when a realm is set', async () => {
    const kinits: string[][] = [];
    const services: string[] = [];
    const gss: GssClient = {
      contextComplete: false,
      async step(challenge: string) {
        if (challenge === '') return Buffer.from('SENTINEL-AP-REQ').toString('base64');
        assert.equal(Buffer.from(challenge, 'base64').toString(), 'SENTINEL-AP-REP');
        (this as { contextComplete: boolean }).contextComplete = true;
        return '';
      },
      async wrap(data: string) {
        return fakeSeal(Buffer.from(data, 'base64')).toString('base64');
      },
      async unwrap(data: string) {
        return fakeUnseal(Buffer.from(data, 'base64')).toString('base64');
      },
    };
    const krbAcceptor: InnerAcceptor = {
      async accept(token) {
        const framed = unframeSpnego(token);
        assert.equal(framed.kind, 'init');
        assert.deepEqual(framed.kind === 'init' && framed.mechTypes, [OID_KRB5]);
        return { output: frameNegTokenResp({ negState: NegState.acceptCompleted, responseToken: Buffer.from('SENTINEL-AP-REP') }), complete: false };
      },
      wrap: fakeSeal,
      unwrap: fakeUnseal,
    };
    // The test server finishes its side once the client sends pubKeyAuth.
    let accepted = 0;
    const acceptor: InnerAcceptor = {
      ...krbAcceptor,
      async accept(token) {
        accepted += 1;
        if (accepted > 1) throw new Error('one Kerberos round only');
        return krbAcceptor.accept(token);
      },
    };
    const creds: Credentials = { username: 'sentinel-user', password: PASSWORD, realm: 'EXAMPLE.TEST' };
    const deps = {
      kerberos: {
        kinit: async (args: string[], password: string | undefined) => {
          assert.equal(password, PASSWORD);
          kinits.push(args);
        },
        gss: async (service: string) => {
          services.push(service);
          return gss;
        },
      },
    };
    const { server, ctx, done } = await run(acceptor, {}, creds, deps);
    try {
      await done;
      assert.deepEqual(kinits, [['sentinel-user@EXAMPLE.TEST']]);
      assert.deepEqual(services, ['HTTP@server.example.test']);
      assert.deepEqual(server.credentials, { domain: 'EXAMPLE.TEST', username: 'sentinel-user', password: PASSWORD });
    } finally {
      await ctx.dispose?.();
      server.close();
    }
  });
});

describe('CredSSP refusals', () => {
  async function refused(faults: ServerFaults, re: RegExp) {
    const { server, ctx, done } = await run(fakeAcceptor(), faults);
    try {
      const err = await done.then(() => null, (e: Error) => e);
      assert.ok(err, 'the handshake must fail');
      assert.match(err.message, re);
      assert.ok(!err.message.includes(PASSWORD), 'no password in errors');
      assert.equal(server.credentials, undefined, 'no credentials reach the server');
    } finally {
      await ctx.dispose?.();
      server.close();
    }
  }

  it('refuses a server that speaks version 5 or older', async () => {
    await refused({ version: 5 }, /speaks version 5; winlinux needs version 6/);
    await refused({ version: 2 }, /speaks version 2/);
  });

  it('refuses a server pubKeyAuth over another key (a man in the middle)', async () => {
    await refused({ wrongPubKey: true }, /pubKeyAuth does not match the inner TLS key/);
  });

  it('refuses a reply without pubKeyAuth', async () => {
    await refused({ noPubKeyAuth: true }, /no pubKeyAuth/);
  });

  it('refuses a reply that echoes another nonce', async () => {
    await refused({ echoNonce: Buffer.alloc(32, 0x01) }, /different clientNonce/);
  });

  it('reports a server errorCode in hex', async () => {
    await refused({ errorCode: -1073741715 }, /error 0xc000006d/);
  });

  it('needs a password, and refuses a keytab and the ticket cache', async () => {
    const cases: Array<[Credentials, RegExp]> = [
      [{ username: 'u' }, /needs a password/],
      [{ username: 'u', password: '' }, /needs a password/],
      [{ username: 'u', password: PASSWORD, useTicketCache: true }, /ticket cache/],
      [{ username: 'u', keytab: '/tmp/sentinel.keytab', realm: 'EXAMPLE.TEST' }, /keytab/],
      [{ username: '', password: PASSWORD }, /username/],
    ];
    for (const [creds, re] of cases) {
      assert.match(credsspCredentialsError(creds)?.message ?? '', re);
      const ctx = new CredSSPAuthProvider().createContext(TARGET, creds);
      await assert.rejects(ctx.step(), re);
    }
    assert.equal(credsspCredentialsError(CREDS), undefined);
  });

  it('wrap and unwrap need a complete context', async () => {
    const ctx = new CredSSPAuthProvider().createContext(TARGET, CREDS);
    await assert.rejects(ctx.wrap!(Buffer.from('x')), /not established/);
    await assert.rejects(ctx.unwrap!(Buffer.from('x')), /not established/);
    await assert.rejects(ctx.step(Buffer.from('x')), /first step takes no input/);
  });

  it('refuses TLS records that are not application data', () => {
    assert.throws(() => gcmPlaintextLength(hex('1503030002 0228')), /TLS alert/);
    assert.throws(() => gcmPlaintextLength(hex('1603030004 00000000')), /renegotiation/);
    assert.throws(() => gcmPlaintextLength(hex('17030300')), /truncated/);
    assert.equal(gcmPlaintextLength(Buffer.concat([hex('1703030019'), Buffer.alloc(25)])), 1);
  });

  it('the factory makes CredSSP only on request', () => {
    assert.equal(createAuthProvider('credssp').mechanism, 'credssp');
    assert.ok(createAuthProvider('credssp') instanceof CredSSPAuthProvider);
    // Negotiate is Kerberos with an NTLM fallback; it never runs CredSSP.
    assert.equal(createAuthProvider('negotiate').createContext(TARGET, CREDS).negotiatedMechanism, undefined);
  });
});

// Keeps the helpers' magic strings in step with the module's.
describe('CredSSP test helper', () => {
  it('uses the spec magic strings', () => {
    const nonce = randomBytes(32);
    const key = randomBytes(10);
    assert.deepEqual(specHash(CLIENT_MAGIC, nonce, key), pubKeyAuthHash('client-to-server', nonce, key));
    assert.deepEqual(specHash(SERVER_MAGIC, nonce, key), pubKeyAuthHash('server-to-client', nonce, key));
  });
});
