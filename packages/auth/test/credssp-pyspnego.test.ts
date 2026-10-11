// CredSSP against golden vectors from pyspnego, the library under
// requests-credssp and pywinrm, which Windows accepts. The vectors
// (helpers/credssp-pyspnego-vectors.ts) are a whole pyspnego CredSSP
// exchange with a fixed key. Each test rebuilds one piece with this
// module and compares bytes: the SubjectPublicKey, the TSRequest DER, the
// NTLM seal state after the SPNEGO mechListMIC (a past bug), the server
// half, and the sealed TSCredentials. Sentinel values only.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { X509Certificate } from 'node:crypto';
import { certificateSubjectPublicKey } from '../src/auth/credssp/der.js';
import { decodeTSRequest, encodeTSCredentials, encodeTSRequest, pubKeyAuthHash } from '../src/auth/credssp/tsrequest.js';
import { NtlmSealSession } from '../src/auth/ntlm/seal.js';
import { NegState, OID_NTLMSSP, encodeMechTypeList, unframeSpnego } from '../src/auth/spnego.js';
import { PYSPNEGO_CREDSSP as V } from './helpers/credssp-pyspnego-vectors.js';
import { TEST_CERT, TEST_SUBJECT_PUBLIC_KEY_HEX } from './helpers/credssp-server.js';

const hex = (s: string) => Buffer.from(s, 'hex');
const MECH_LIST = encodeMechTypeList([OID_NTLMSSP]);

function session(): NtlmSealSession {
  return new NtlmSealSession({ exportedSessionKey: hex(V.exportedSessionKey), negotiatedFlags: V.flags, keyExchange: true });
}

const clientAuth = decodeTSRequest(hex(V.clientAuthenticate));
const serverAuth = decodeTSRequest(hex(V.serverPubKeyAuth));

describe('CredSSP vs pyspnego: SubjectPublicKey (MS-CSSP 3.1.5)', () => {
  it('is the BIT STRING value of the certificate SubjectPublicKeyInfo (RSA: PKCS#1 RSAPublicKey)', () => {
    const spk = certificateSubjectPublicKey(hex(V.certificate));
    assert.equal(spk.toString('hex'), V.subjectPublicKey);
    assert.equal(spk[0], 0x30, 'an RSAPublicKey SEQUENCE, no unused-bits octet');
    const spki = new X509Certificate(hex(V.certificate)).publicKey.export({ type: 'spki', format: 'der' });
    assert.notEqual(spk.length, spki.length, 'not the whole SubjectPublicKeyInfo');
  });

  it('takes the EC point of an EC certificate (openssl agrees)', () => {
    assert.equal(certificateSubjectPublicKey(new X509Certificate(TEST_CERT).raw).toString('hex'), TEST_SUBJECT_PUBLIC_KEY_HEX);
  });

  it('refuses bytes that are not a certificate', () => {
    assert.throws(() => certificateSubjectPublicKey(hex('300302010a')), /Certificate/);
  });
});

describe('CredSSP vs pyspnego: TSRequest DER (MS-CSSP 2.2.1)', () => {
  it('re-encodes every TSRequest of the exchange byte for byte', () => {
    for (const name of ['clientNegotiate', 'serverChallenge', 'clientAuthenticate', 'serverPubKeyAuth', 'clientAuthInfo'] as const) {
      assert.equal(encodeTSRequest(decodeTSRequest(hex(V[name]))).toString('hex'), V[name], name);
    }
  });

  it('sends the NTLM AUTHENTICATE, pubKeyAuth and clientNonce in one version 6 TSRequest', () => {
    assert.equal(clientAuth.version, 6);
    assert.equal(clientAuth.negoTokens?.length, 1);
    assert.ok(clientAuth.pubKeyAuth);
    assert.equal(clientAuth.clientNonce?.length, 32);
    assert.equal(clientAuth.authInfo, undefined);
    const framed = unframeSpnego(clientAuth.negoTokens![0]!);
    assert.equal(framed.kind, 'resp');
    assert.ok(framed.kind === 'resp' && framed.responseToken?.subarray(0, 12).equals(Buffer.from('NTLMSSP\0\x03\0\0\0', 'latin1')));
  });

  it('negotiates with the same SPNEGO mechTypes { NTLMSSP } the mechListMIC covers', () => {
    const init = unframeSpnego(decodeTSRequest(hex(V.clientNegotiate)).negoTokens![0]!);
    assert.equal(init.kind, 'init');
    assert.deepEqual(init.kind === 'init' && init.mechTypes, [OID_NTLMSSP]);
  });
});

describe('CredSSP vs pyspnego: NTLM seal state after the SPNEGO mechListMIC (MS-SPNG 3.3.5.1)', () => {
  it('client: mechListMIC at seq 0, then pubKeyAuth at seq 1 with the RC4 state reset', () => {
    const s = session();
    const framed = unframeSpnego(clientAuth.negoTokens![0]!);
    assert.equal(framed.kind, 'resp');
    const mic = framed.kind === 'resp' ? framed.mechListMIC : undefined;
    assert.equal(s.sign(MECH_LIST).toString('hex'), mic?.toString('hex'), 'mechListMIC');
    s.resetRc4('client');
    const hash = pubKeyAuthHash('client-to-server', clientAuth.clientNonce, certificateSubjectPublicKey(hex(V.certificate)));
    const sealed = s.seal(hash);
    assert.equal(sealed.readUInt32LE(12), 1, 'pubKeyAuth carries seq 1');
    assert.equal(sealed.toString('hex'), clientAuth.pubKeyAuth!.toString('hex'), 'pubKeyAuth');
  });

  it('the bare NTLMSSP state (fresh seal state at seq 0) does not match what Windows expects', () => {
    const hash = pubKeyAuthHash('client-to-server', clientAuth.clientNonce, hex(V.subjectPublicKey));
    assert.notEqual(session().seal(hash).toString('hex'), clientAuth.pubKeyAuth!.toString('hex'));
    // Nor a running RC4 stream after the MIC.
    const s = session();
    s.sign(MECH_LIST);
    assert.notEqual(s.seal(hash).toString('hex'), clientAuth.pubKeyAuth!.toString('hex'));
  });

  it('server: its mechListMIC at seq 0, then its pubKeyAuth at seq 1 with the RC4 state reset', () => {
    const s = session();
    const final = unframeSpnego(serverAuth.negoTokens![0]!);
    assert.equal(final.kind, 'resp');
    assert.equal(final.kind === 'resp' && final.negState, NegState.acceptCompleted);
    assert.equal(s.verify(MECH_LIST, final.kind === 'resp' ? final.mechListMIC! : Buffer.alloc(0)), true, 'server mechListMIC');
    s.resetRc4('server');
    const expected = pubKeyAuthHash('server-to-client', clientAuth.clientNonce, hex(V.subjectPublicKey));
    assert.deepEqual(s.unseal(serverAuth.pubKeyAuth!), expected);
  });

  it('client: the TSCredentials go out at seq 2 and match byte for byte', () => {
    const s = session();
    s.sign(MECH_LIST);
    s.resetRc4('client');
    s.seal(pubKeyAuthHash('client-to-server', clientAuth.clientNonce, hex(V.subjectPublicKey)));
    const creds = encodeTSCredentials({ domain: V.domain, username: V.username, password: V.password });
    const authInfo = s.seal(creds);
    assert.equal(authInfo.readUInt32LE(12), 2);
    assert.equal(encodeTSRequest({ version: 6, authInfo }).toString('hex'), V.clientAuthInfo);
  });
});
