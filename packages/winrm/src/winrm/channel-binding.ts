import { createHash } from 'node:crypto';
import type { AuthTarget } from '../auth-provider.js';
import { children, decodeOid, readTlv, type Tlv } from './der.js';

// RFC 5929 tls-server-end-point channel binding for NTLM over HTTPS.
// Windows with the default CbtHardeningLevel=Relaxed refuses an NTLM
// AUTHENTICATE whose MsvAvChannelBindings does not match the TLS server
// certificate, and Strict demands one. The transport computes the binding
// from the peer certificate of its TLS socket and hands it to the auth
// context as the application data of a GSS channel-binding structure:
// "tls-server-end-point:" + hash(DER certificate), hashed as pywinrm's
// requests-ntlm does it (RFC 5929 4.1): with the hash of the certificate's
// signature algorithm, except MD5 and SHA-1 become SHA-256, and SHA-256
// when the algorithm is not known.
//
// Additive to the LOCKED contract (the auth-provider.ts mirror is not
// changed): the target object given to createContext() MAY carry
// `channelBindings`, set once the connection exists and before the first
// server challenge is fed back. Mirrors @winlinux/auth channel-bindings.ts.
export interface ChannelBoundTarget extends AuthTarget {
  channelBindings?: Buffer;
}

export const TLS_SERVER_END_POINT_PREFIX = 'tls-server-end-point:';

// Signature algorithm OID -> node hash name. MD5 and SHA-1 signatures map
// to sha256 (RFC 5929 4.1). RSASSA-PSS carries its hash in the parameters.
const OID_RSASSA_PSS = '1.2.840.113549.1.1.10';
const SIGNATURE_HASH: Record<string, string> = {
  '1.2.840.113549.1.1.4': 'sha256', // md5WithRSAEncryption
  '1.2.840.113549.1.1.5': 'sha256', // sha1WithRSAEncryption
  '1.2.840.113549.1.1.14': 'sha224', // sha224WithRSAEncryption
  '1.2.840.113549.1.1.11': 'sha256', // sha256WithRSAEncryption
  '1.2.840.113549.1.1.12': 'sha384', // sha384WithRSAEncryption
  '1.2.840.113549.1.1.13': 'sha512', // sha512WithRSAEncryption
  '1.2.840.10045.4.1': 'sha256', // ecdsa-with-SHA1
  '1.2.840.10045.4.3.1': 'sha224', // ecdsa-with-SHA224
  '1.2.840.10045.4.3.2': 'sha256', // ecdsa-with-SHA256
  '1.2.840.10045.4.3.3': 'sha384', // ecdsa-with-SHA384
  '1.2.840.10045.4.3.4': 'sha512', // ecdsa-with-SHA512
  '1.2.840.10040.4.3': 'sha256', // dsa-with-sha1
  '2.16.840.1.101.3.4.3.2': 'sha256', // dsa-with-sha256
};
// Hash algorithm OIDs (RSASSA-PSS hashAlgorithm parameter).
const HASH_OID: Record<string, string> = {
  '1.2.840.113549.2.5': 'sha256', // md5
  '1.3.14.3.2.26': 'sha256', // sha1
  '2.16.840.1.101.3.4.2.4': 'sha224',
  '2.16.840.1.101.3.4.2.1': 'sha256',
  '2.16.840.1.101.3.4.2.2': 'sha384',
  '2.16.840.1.101.3.4.2.3': 'sha512',
};
const FALLBACK_HASH = 'sha256';

// The AlgorithmIdentifier of Certificate.signatureAlgorithm (RFC 5280
// 4.1.1.2): the OID, and the parameters TLV when there is one.
function signatureAlgorithm(der: Buffer): { oid: string; params?: Tlv } {
  const cert = readTlv(der, 0);
  if (cert.tag !== 0x30 || cert.total !== der.length) throw new Error('DER: not a Certificate SEQUENCE');
  const [tbs, algorithm, signature] = children(cert.content);
  if (!tbs || !algorithm || !signature || algorithm.tag !== 0x30) throw new Error('DER: Certificate has no signatureAlgorithm');
  const [oid, params] = children(algorithm.content);
  if (!oid || oid.tag !== 0x06) throw new Error('DER: signatureAlgorithm has no OID');
  return { oid: decodeOid(oid.content), params };
}

// RSASSA-PSS-params ::= SEQUENCE { hashAlgorithm [0] AlgorithmIdentifier
// DEFAULT sha1, ... } (RFC 4055 3.1).
function pssHash(params: Tlv | undefined): string {
  if (!params || params.tag !== 0x30) return FALLBACK_HASH;
  const hashField = children(params.content).find((f) => f.tag === 0xa0);
  if (!hashField) return FALLBACK_HASH; // DEFAULT sha1 -> sha256
  const [algorithm] = children(hashField.content);
  if (!algorithm || algorithm.tag !== 0x30) return FALLBACK_HASH;
  const [oid] = children(algorithm.content);
  if (!oid || oid.tag !== 0x06) return FALLBACK_HASH;
  return HASH_OID[decodeOid(oid.content)] ?? FALLBACK_HASH;
}

// The node hash name RFC 5929 4.1 picks for this DER certificate.
export function tlsServerEndPointHashName(der: Buffer): string {
  const { oid, params } = signatureAlgorithm(der);
  if (oid === OID_RSASSA_PSS) return pssHash(params);
  return SIGNATURE_HASH[oid] ?? FALLBACK_HASH;
}

// "tls-server-end-point:" + hash(DER certificate): the GSS channel-binding
// application data for this TLS connection.
export function tlsServerEndPoint(der: Buffer): Buffer {
  const hash = createHash(tlsServerEndPointHashName(der)).update(der).digest();
  return Buffer.concat([Buffer.from(TLS_SERVER_END_POINT_PREFIX, 'ascii'), hash]);
}
