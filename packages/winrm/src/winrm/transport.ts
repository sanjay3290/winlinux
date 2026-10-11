import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import type { TLSSocket } from 'node:tls';
import type { AuthProvider, Credentials, Mechanism, SecurityContext } from '../auth-provider.js';
import { tlsServerEndPoint, type ChannelBoundTarget } from './channel-binding.js';
import {
  declaresWinRMMessageProtection,
  decryptMessage,
  encryptedContentType,
  encryptedProtocolOf,
  encryptMessage,
  hasWinRMMessageProtection,
  isMultiPart,
  kerberosNeedsIov,
  protocolFor,
} from './encryption.js';
import { WinRMAuthError, WinRMProtocolError, WinRMTransportError } from './errors.js';
import { rawNtlmToken } from './ntlmssp.js';
import { parseSoapFault } from './parse.js';

export type WinRMEncryption = 'auto' | 'always' | 'never';

export interface WinRMTransportOptions {
  host: string;
  port: number;
  path?: string;
  tls: boolean;
  tlsVerify?: boolean;
  // Required unless clientCertificate is set.
  authProvider?: AuthProvider;
  credentials?: Credentials;
  // Certificate sign-in: the TLS client certificate is the
  // credential. HTTPS only; no AuthProvider is used.
  clientCertificate?: ClientCertificate;
  encryption?: WinRMEncryption;
  // Longest wait for a new connection: TCP connect, plus the TLS handshake
  // over HTTPS. Default 10 s. A host that drops packets otherwise
  // takes the OS TCP timeout (75 s on macOS).
  connectTimeoutMs?: number;
  // Longest wait for a response with no bytes on the socket. It must be
  // longer than the WS-Man OperationTimeout, or a quiet Receive fails.
  requestTimeoutMs?: number;
  // CredSSP over plain HTTP. Refused unless this is true: the outer
  // channel has no certificate check, and CredSSP delegates the password.
  credsspAllowHttp?: boolean;
  // Called on every CredSSP sign-in, just before the request that carries
  // the encrypted credentials goes out. The library never prints; a CLI
  // prints the notice.
  onCredSSPDelegation?: (host: string) => void;
}

export interface ClientCertificate {
  cert: Buffer; // PEM
  key: Buffer; // PEM, encrypted or not
  passphrase?: string;
}

// The Authorization value for WinRM certificate sign-in (DSP0226 security
// profile wsman:secprofile/https/mutual). The TLS client certificate
// carries the identity; the header only names the profile.
export const CERTIFICATE_AUTH_HEADER = 'http://schemas.dmtf.org/wbem/wsman/1/wsman/secprofile/https/mutual';

export const CERTIFICATE_REFUSED_HINT =
  'the server refused the client certificate; check that WinRM allows certificate sign-in (Auth/Certificate) ' +
  'and that the certificate is mapped to a local account (WSMan:\\localhost\\ClientCertificate)';

// A one-step context for certificate sign-in: no token, no wrap. The
// transport sends CERTIFICATE_AUTH_HEADER instead of a token.
function certificateContext(): SecurityContext {
  let done = false;
  return {
    step: async () => {
      done = true;
      return { output: Buffer.from(CERTIFICATE_AUTH_HEADER, 'ascii'), complete: true };
    },
    get complete() {
      return done;
    },
  };
}

// A TLS alert from the server during the handshake (bad_certificate,
// certificate_required, handshake_failure, access_denied, ...). With a
// client certificate this means the server refused it. Errors about the
// server's own certificate (UNABLE_TO_VERIFY_*, CERT_HAS_EXPIRED, ...) are
// not alerts and stay connection errors.
function isTlsAlert(err: unknown): boolean {
  const code = (err as { code?: unknown })?.code;
  return typeof code === 'string' && /^ERR_SSL_.*ALERT/.test(code);
}

export const SOAP_CONTENT_TYPE = 'application/soap+xml;charset=UTF-8';
const MAX_HANDSHAKE_ROUNDS = 5;
// CredSSP runs a TLS handshake (two rounds), the inner exchange (one or
// two), pubKeyAuth and the credentials through the same header loop.
const MAX_CREDSSP_HANDSHAKE_ROUNDS = 10;

export const CREDSSP_INSECURE_REASON =
  'CredSSP refuses --insecure (tlsVerify false): CredSSP delegates your password to the server, ' +
  "so the server's TLS certificate must be verified";
// Kerberos sends no channel binding yet: over TLS only a verified
// certificate ties the AP-REQ to the real server, so a man in the middle
// with any certificate could pass the ticket on.
export const KERBEROS_INSECURE_REASON =
  'Kerberos refuses --insecure (tlsVerify false) over HTTPS: this client sends no Kerberos channel binding yet, so ' +
  "only the server's verified TLS certificate ties the ticket to the real server. Drop --insecure, or use another sign-in method";
export const CREDSSP_HTTP_REASON =
  'CredSSP over plain HTTP is refused: the outer HTTP channel has no certificate check, and CredSSP ' +
  'delegates your password to the server. Use --tls (HTTPS, port 5986), or pass --credssp-allow-http to accept the risk';
const DEFAULT_REQUEST_TIMEOUT_MS = 90_000;
export const DEFAULT_CONNECT_TIMEOUT_MS = 10_000;

interface RawResponse {
  status: number;
  headers: http.IncomingHttpHeaders;
  body: Buffer;
  // DER certificate of the TLS peer that answered, when the socket is TLS.
  peerCertificate?: Buffer;
}

const NEGOTIATE_CHALLENGE = /(?:negotiate|ntlm)\s+([A-Za-z0-9+/=]+)/i;
const CREDSSP_CHALLENGE = /(?:^|[\s,])credssp\s+([A-Za-z0-9+/=]+)/i;

// The token of the scheme in use: CredSSP for a CredSSP context, else
// Negotiate or NTLM.
function challengeToken(headers: http.IncomingHttpHeaders, credssp = false): Buffer | null {
  const wwwAuth = headers['www-authenticate'];
  if (!wwwAuth) return null;
  const values = Array.isArray(wwwAuth) ? wwwAuth : [wwwAuth];
  for (const value of values) {
    const m = (credssp ? CREDSSP_CHALLENGE : NEGOTIATE_CHALLENGE).exec(value);
    if (m?.[1]) return Buffer.from(m[1], 'base64');
  }
  return null;
}

// One transport per session. NTLM binds authentication to the TCP
// connection, so every request shares one keep-alive agent pinned to a
// single socket, and one SecurityContext drives the handshake.
export class WinRMTransport {
  private readonly agent: http.Agent;
  private readonly httpModule: typeof http | typeof https;
  private readonly opts: WinRMTransportOptions & {
    path: string;
    tlsVerify: boolean;
    encryption: WinRMEncryption;
    requestTimeoutMs: number;
    connectTimeoutMs: number;
  };
  // The target every context gets. Over TLS the transport sets its
  // channelBindings (RFC 5929 tls-server-end-point, channel-binding.ts)
  // once a socket exists and before it feeds the first server challenge,
  // so the NTLM AUTHENTICATE binds to this connection.
  private readonly target: ChannelBoundTarget;
  private ctx: SecurityContext;
  // True once a handshake got a non-401 answer: the connection (pinned
  // agent, one socket) is authenticated.
  private authenticated = false;
  // Basic authenticates each request (RFC 7617), so its credentials go on
  // every one. The Negotiate family authenticates the connection: once the
  // context is complete, HTTP.sys treats any Authorization header as a new
  // handshake and answers a stale AUTHENTICATE token with 401, so no
  // header is sent until the server asks again.
  private repeatHeader: string | null = null;
  private readonly encrypted: boolean;
  private readonly certificate: boolean;

  constructor(opts: WinRMTransportOptions) {
    this.opts = { path: '/wsman', tlsVerify: true, encryption: 'auto', requestTimeoutMs: DEFAULT_REQUEST_TIMEOUT_MS, connectTimeoutMs: DEFAULT_CONNECT_TIMEOUT_MS, ...opts };
    // CredSSP hands the password to the server: a verified server
    // only. Refused before any context or socket exists.
    if (this.opts.authProvider?.mechanism === 'credssp') {
      if (!this.opts.tlsVerify) throw new WinRMTransportError(CREDSSP_INSECURE_REASON);
      if (!this.opts.tls && this.opts.credsspAllowHttp !== true) throw new WinRMTransportError(CREDSSP_HTTP_REASON);
    }
    if (this.opts.authProvider?.mechanism === 'kerberos' && this.opts.tls && !this.opts.tlsVerify) {
      throw new WinRMTransportError(KERBEROS_INSECURE_REASON);
    }
    this.target = { host: this.opts.host, service: 'HTTP' };
    this.certificate = this.opts.clientCertificate !== undefined;
    if (this.certificate) {
      // Never send the client certificate over plain HTTP.
      if (!this.opts.tls) {
        throw new WinRMTransportError('WinRM certificate sign-in needs HTTPS (tls: true, port 5986); it never runs over plain HTTP');
      }
      if (this.opts.encryption === 'always') {
        throw new WinRMTransportError("WinRM certificate sign-in has no message encryption; use encryption 'auto' over HTTPS");
      }
    } else if (!this.opts.authProvider || !this.opts.credentials) {
      throw new WinRMTransportError('WinRM needs an authProvider and credentials, or a clientCertificate');
    }
    this.ctx = this.newContext();
    const hasWrap = typeof this.ctx.wrap === 'function' && typeof this.ctx.unwrap === 'function';
    const wantEncryption = !this.certificate && (this.opts.encryption === 'always' || (this.opts.encryption === 'auto' && !this.opts.tls));

    if (!this.opts.tls && !wantEncryption) {
      throw new WinRMTransportError(
        "WinRM refuses plain HTTP with encryption 'never': SOAP bodies and credentials would travel " +
          'unencrypted. Use HTTPS (tls:true, port 5986) or allow message encryption.',
      );
    }
    if (wantEncryption && !hasWrap) {
      throw new WinRMTransportError(
        `WinRM refuses ${this.opts.tls ? 'this connection' : 'plain HTTP without message encryption'}: the SecurityContext for mechanism ` +
          `'${this.providerMechanism()}' exposes no wrap/unwrap. ` +
          `${this.opts.tls ? 'Pick an AuthProvider with message protection.' : 'Use HTTPS (tls:true, port 5986) or an AuthProvider with message protection (NTLM/Kerberos).'}`,
      );
    }
    // Kerberos wrap() returns one RFC 4121 token; MS-WSMV 2.2.9.1.1.2.2
    // needs the gss_wrap_iov split instead (encryption.ts). A context
    // type that does not declare the extension can never offer it:
    // refuse before any socket opens. One that declares it is checked
    // again after each handshake step (checkEncryptionMechanism), once
    // its GSS layer exists.
    if (wantEncryption && this.providerMechanism() === 'kerberos' && !declaresWinRMMessageProtection(this.ctx)) {
      throw kerberosNeedsIov(this.opts.tls);
    }
    this.encrypted = wantEncryption;

    const agentOpts: http.AgentOptions = { keepAlive: true, maxSockets: 1 };
    if (opts.tls) {
      this.httpModule = https;
      const cert = this.opts.clientCertificate;
      this.agent = new https.Agent({
        ...agentOpts,
        rejectUnauthorized: opts.tlsVerify,
        // Certificate sign-in is capped at TLS 1.2. HTTP.sys asks for
        // the client certificate after the handshake unless the SSL binding
        // has clientcertnegotiation=enable. In TLS 1.2 that is a
        // renegotiation, which Node's client answers. In TLS 1.3 it is
        // post-handshake authentication, which Node's client does not offer,
        // so the server never gets the certificate. Every other mechanism
        // keeps the default (TLS 1.3 when the server offers it).
        ...(cert
          ? { cert: cert.cert, key: cert.key, maxVersion: 'TLSv1.2' as const, ...(cert.passphrase !== undefined ? { passphrase: cert.passphrase } : {}) }
          : {}),
      });
    } else {
      this.httpModule = http;
      this.agent = new http.Agent(agentOpts);
    }
  }

  private newContext(): SecurityContext {
    if (this.certificate) return certificateContext();
    return (this.opts.authProvider as AuthProvider).createContext(this.target, this.opts.credentials as Credentials);
  }

  // Certificate sign-in has no provider; 'basic' stands for "one step, no
  // wrap" wherever the transport asks for a mechanism.
  private providerMechanism(): Mechanism {
    return this.opts.authProvider?.mechanism ?? 'basic';
  }

  private scheme(): string {
    const mechanism = this.providerMechanism();
    return mechanism === 'basic' ? 'Basic' : mechanism === 'credssp' ? 'CredSSP' : 'Negotiate';
  }

  private credssp(): boolean {
    return this.providerMechanism() === 'credssp';
  }

  // The content type of an encrypted body for this session (CredSSP
  // has its own protocol, and a long CredSSP message is multi-part).
  private encryptedType(length: number): string {
    const mechanism = this.credssp() ? 'credssp' : this.mechanism();
    return encryptedContentType(protocolFor(mechanism), isMultiPart(mechanism, length));
  }

  private requestOnce(body: Buffer, headers: Record<string, string>, signal?: AbortSignal): Promise<RawResponse> {
    const { host, port, path, tlsVerify, tls, requestTimeoutMs } = this.opts;
    return new Promise<RawResponse>((resolve, reject) => {
      const req = this.httpModule.request(
        {
          host,
          port,
          path,
          method: 'POST',
          headers: { Connection: 'keep-alive', ...headers },
          agent: this.agent,
          // An abort destroys the request (and its socket) with an AbortError.
          signal,
          // RFC 6066 3: SNI carries a DNS name only, never an IP address.
          ...(this.httpModule === https ? { rejectUnauthorized: tlsVerify, servername: tls && net.isIP(host) === 0 ? host : undefined } : {}),
        },
        (res) => {
          const chunks: Buffer[] = [];
          // getPeerCertificate exists on a TLSSocket only; raw is the DER.
          const peerCertificate = (res.socket as Partial<TLSSocket>).getPeerCertificate?.()?.raw;
          res.on('data', (c: Buffer) => chunks.push(c));
          res.on('end', () =>
            resolve({
              status: res.statusCode ?? 0,
              headers: res.headers,
              body: Buffer.concat(chunks),
              ...(peerCertificate && peerCertificate.length > 0 ? { peerCertificate } : {}),
            }),
          );
        },
      );
      // With a client certificate, a refusal is an auth error, not a network
      // one: a TLS alert from the server, or a reset on a new
      // connection after TCP connected: during the TLS handshake (a server
      // that checks the certificate in the handshake and drops the
      // connection) or after it (a late check) with no response yet.
      // Only for a certificate, and only on a new socket, where the
      // listeners fire once: a listener left on a reused keep-alive socket
      // would pile up and keep each request's body alive.
      let tcpConnected = false;
      if (this.certificate) {
        req.on('socket', (socket) => {
          if (!req.reusedSocket) socket.once('connect', () => (tcpConnected = true));
        });
      }
      req.on('error', (err) => {
        const code = (err as { code?: unknown }).code;
        const refused = tcpConnected && (code === 'ECONNRESET' || /socket disconnected before secure TLS connection/.test(err.message));
        reject(
          this.certificate && (isTlsAlert(err) || refused)
            ? new WinRMAuthError(`WinRM certificate sign-in failed: ${CERTIFICATE_REFUSED_HINT}`, { cause: err })
            : err,
        );
      });
      // Connect timeout, on a new socket only: TCP connect over
      // HTTP, TCP connect and the TLS handshake over HTTPS. A reused
      // keep-alive socket is already connected.
      req.on('socket', (socket) => {
        if (req.reusedSocket) return;
        const { connectTimeoutMs } = this.opts;
        const timer = setTimeout(() => {
          const seconds = connectTimeoutMs % 1000 === 0 ? `${connectTimeoutMs / 1000} s` : `${connectTimeoutMs} ms`;
          const err = new Error(`timed out connecting to ${host}:${port} after ${seconds}`) as Error & { code: string; connectTimeout: boolean };
          err.code = 'ETIMEDOUT';
          err.connectTimeout = true;
          req.destroy(err);
        }, connectTimeoutMs);
        const done = () => clearTimeout(timer);
        socket.once(tls ? 'secureConnect' : 'connect', done);
        socket.once('close', done);
      });
      // A host that drops packets would otherwise hang until the OS TCP
      // timeout. destroy() fails the request with this error.
      req.setTimeout(requestTimeoutMs, () => {
        const err = new Error(`WinRM request to ${host}:${port} timed out after ${requestTimeoutMs} ms`) as Error & { code: string };
        err.code = 'ETIMEDOUT';
        req.destroy(err);
      });
      if (body.length > 0) req.write(body);
      req.end();
    });
  }

  // The mechanism that seals messages: the one SPNEGO picked, else the
  // provider's own.
  private mechanism(): Mechanism {
    return this.ctx.negotiatedMechanism ?? this.providerMechanism();
  }

  // Negotiate can pick Kerberos at run time, and a Kerberos context only
  // knows after its first step whether its GSS layer has the IOV split
  // (@winlinux/krb-session-key) or not (the `kerberos` package). Refuse
  // before any wrap().
  private checkEncryptionMechanism(): void {
    // Negotiate picks Kerberos at run time; refuse it over unverified TLS
    // before its first token leaves.
    if (this.opts.tls && !this.opts.tlsVerify && this.mechanism() === 'kerberos') {
      throw new WinRMTransportError(KERBEROS_INSECURE_REASON);
    }
    if (this.encrypted && this.mechanism() === 'kerberos' && !hasWinRMMessageProtection(this.ctx)) {
      throw kerberosNeedsIov(this.opts.tls);
    }
  }

  // MS-WSMV 2.2.9.1 framing lives in ./encryption.ts. wrap() is only
  // called once the handshake is complete, so a real provider has keys.
  private async requestBody(soap: Buffer): Promise<Buffer> {
    return this.encrypted ? encryptMessage(this.ctx, this.mechanism(), soap) : soap;
  }

  // With message encryption on, every 2xx and 500 response MUST be
  // multipart/encrypted (MS-WSMV 2.2.9.1: the service MUST use the
  // encrypted message when it responds). A plaintext answer, or one with
  // no protocol, is refused: accepting it would let anyone on the path
  // forge a response. An empty body is refused too. Every WS-Man
  // response carries a SOAP envelope, so an empty one is never valid,
  // and accepting it would let an attacker drop a real response.
  private async decryptResponse(res: RawResponse): Promise<string> {
    const protocol = encryptedProtocolOf(res.headers['content-type'] ?? '');
    if (!this.encrypted && protocol === null) return res.body.toString('utf8');
    if (protocol === null) {
      throw new WinRMTransportError(
        `WinRM refuses an unencrypted HTTP ${res.status} response on an encrypted session ` +
          `(Content-Type '${res.headers['content-type'] ?? ''}', ${res.body.length} bytes)`,
      );
    }
    return decryptMessage(this.ctx, this.mechanism(), protocol, res.body);
  }

  private tokenHeader(token: Buffer): string {
    // Certificate sign-in: the profile URI on every request, like Basic.
    if (this.certificate) {
      this.repeatHeader = CERTIFICATE_AUTH_HEADER;
      return CERTIFICATE_AUTH_HEADER;
    }
    // Basic step() output is already base64 user:pass per the contract;
    // Negotiate-family tokens are raw bytes that need base64 for HTTP.
    // NTLM goes out bare, without its SPNEGO frame (ntlmssp.ts);
    // Kerberos, and Negotiate until it has picked NTLM, keep SPNEGO.
    const wire = this.mechanism() === 'ntlm' ? rawNtlmToken(token) : token;
    const text = this.providerMechanism() === 'basic' ? wire.toString('utf8') : wire.toString('base64');
    const header = `${this.scheme()} ${text}`;
    if (this.providerMechanism() === 'basic') this.repeatHeader = header;
    return header;
  }

  // Headers for a request on an authenticated connection: Basic repeats
  // its credentials, the Negotiate family sends nothing.
  private sessionHeaders(): Record<string, string> {
    return this.repeatHeader === null ? {} : { Authorization: this.repeatHeader };
  }

  // Binds the handshake to the TLS connection that answered: the target
  // carries the tls-server-end-point application data of its certificate
  // from now on (the provider reads it when it builds the AUTHENTICATE).
  // Over plain HTTP there is no certificate and no binding.
  private bindChannel(res: RawResponse): void {
    if (res.peerCertificate) this.target.channelBindings = tlsServerEndPoint(res.peerCertificate);
  }

  // Runs the auth loop and returns the first non-401 response.
  private async handshake(body: () => Promise<Buffer>, contentType: string, signal?: AbortSignal): Promise<RawResponse> {
    // Prime the handshake. Multi-step mechanisms probe with an empty
    // body first; single-step ones (Basic) send the body at once.
    const first = await this.ctx.step();
    if (!first.output) throw new WinRMProtocolError('Auth provider returned no initial token');
    this.checkEncryptionMechanism();
    let bodySent = first.complete;
    const firstBody = first.complete ? await body() : Buffer.alloc(0);
    let res = await this.requestOnce(firstBody, {
      Authorization: this.tokenHeader(first.output),
      'Content-Type': first.complete ? contentType : SOAP_CONTENT_TYPE,
      'Content-Length': String(firstBody.length),
    }, signal);
    let rounds = 0;
    const credssp = this.credssp();
    const maxRounds = credssp ? MAX_CREDSSP_HANDSHAKE_ROUNDS : MAX_HANDSHAKE_ROUNDS;
    while (res.status === 401 && rounds < maxRounds) {
      if (this.certificate) throw new WinRMAuthError(`WinRM certificate sign-in failed (HTTP 401): ${CERTIFICATE_REFUSED_HINT}`);
      const challenge = challengeToken(res.headers, credssp);
      if (!challenge) {
        // Windows reports a bad password inside CredSSP (a TSRequest
        // errorCode), but drops CredSSP with a bare 401 when a later step
        // fails, such as a client pubKeyAuth it cannot verify.
        if (credssp && rounds > 0) {
          throw new WinRMAuthError(
            `WinRM credentials were rejected by the server (HTTP 401 without a CredSSP challenge after round ${rounds + 1} ` +
              'of the CredSSP exchange: the server ended CredSSP without an error code)',
          );
        }
        throw new WinRMAuthError(`WinRM credentials were rejected by the server (HTTP 401 without a ${credssp ? 'CredSSP' : 'Negotiate'} challenge)`);
      }
      this.bindChannel(res);
      const out = await this.ctx.step(challenge);
      if (!out.output) throw new WinRMProtocolError('Auth provider returned no token for the server challenge');
      this.checkEncryptionMechanism();
      // The next request carries the encrypted password.
      if (credssp && out.complete) this.opts.onCredSSPDelegation?.(this.opts.host);
      // Retry the SAME request on the SAME socket (pinned agent). An
      // encrypted body needs the finished context, so a round that is
      // still negotiating sends an empty probe instead. CredSSP sends
      // every handshake round with an empty body, the credentials round
      // too (as pywinrm does), and the body once the server accepted.
      const ready = !credssp && (!this.encrypted || out.complete);
      bodySent = ready;
      const retryBody = ready ? await body() : Buffer.alloc(0);
      res = await this.requestOnce(retryBody, {
        Authorization: this.tokenHeader(out.output),
        'Content-Type': ready ? contentType : SOAP_CONTENT_TYPE,
        'Content-Length': String(retryBody.length),
      }, signal);
      rounds += 1;
    }
    if (res.status === 401) throw new WinRMAuthError('WinRM authentication failed: the handshake did not finish');
    // Any other status means the server accepted the credentials for
    // this connection (a 500 is a SOAP fault, a 400 a rejected body).
    this.authenticated = true;
    return this.finishMutualAuth(res, bodySent, body, contentType, signal);
  }

  // Kerberos mutual authentication (RFC 4559 5): the server accepts the
  // AP-REQ and returns the AP-REP in the WWW-Authenticate header of a
  // non-401 response. The context completes only once it has consumed
  // that token. When the request that carried the AP-REQ was the empty
  // probe (a multi-step mechanism sends the body once its context is
  // complete), the real body goes out now, on the same authenticated
  // connection and with no Authorization header, and that response is
  // the result.
  private async finishMutualAuth(
    res: RawResponse,
    bodySent: boolean,
    body: () => Promise<Buffer>,
    contentType: string,
    signal?: AbortSignal,
  ): Promise<RawResponse> {
    if (this.ctx.complete) {
      if (bodySent) return res;
      // CredSSP: the handshake ran on empty probes; send the body now.
      const fullBody = await body();
      return this.requestOnce(fullBody, {
        ...this.sessionHeaders(),
        'Content-Type': contentType,
        'Content-Length': String(fullBody.length),
      }, signal);
    }
    const token = challengeToken(res.headers);
    if (!token) return res;
    const out = await this.ctx.step(token);
    if (out.output && out.output.length > 0) {
      throw new WinRMProtocolError(`WinRM: the server accepted the request (HTTP ${res.status}) but the auth provider wants another round`);
    }
    if (!out.complete) throw new WinRMProtocolError(`WinRM: the handshake did not finish on the HTTP ${res.status} response`);
    this.checkEncryptionMechanism();
    if (bodySent) return res;
    const fullBody = await body();
    return this.requestOnce(fullBody, {
      ...this.sessionHeaders(),
      'Content-Type': contentType,
      'Content-Length': String(fullBody.length),
    }, signal);
  }

  // Disposes the context (best effort) and starts a new one.
  private async resetContext(): Promise<void> {
    await Promise.resolve(this.ctx.dispose?.()).catch(() => undefined);
    // A new socket may show a new certificate: the binding is set again
    // on its first challenge.
    delete this.target.channelBindings;
    this.ctx = this.newContext();
    this.authenticated = false;
    this.repeatHeader = null;
  }

  private async postOnce(soap: string, reauthed: boolean, signal?: AbortSignal): Promise<string> {
    const plain = Buffer.from(soap, 'utf8');
    const contentType = this.encrypted ? this.encryptedType(plain.length) : SOAP_CONTENT_TYPE;
    // Build the body at most once per request: every wrap() advances the
    // provider's sequence number.
    let built: Buffer | null = null;
    const body = async (): Promise<Buffer> => (built ??= await this.requestBody(plain));

    if (!this.authenticated) {
      let res: RawResponse;
      try {
        res = await this.handshake(body, contentType, signal);
      } catch (err) {
        // An abort, timeout, or error mid-handshake leaves the context half
        // negotiated. Start over on the next post instead of wrapping with it.
        await this.resetContext();
        // Negotiate throws KerberosCredentialError when the KDC rejects the
        // password; it does not fall back to NTLM (lockout). Match by name
        // so winrm does not depend on @winlinux/auth.
        if (err instanceof Error && err.name === 'KerberosCredentialError') {
          throw new WinRMAuthError(`WinRM credentials were rejected: ${err.message}`, { cause: err });
        }
        throw err;
      }
      return this.handleResult(res);
    }

    const fullBody = await body();
    const res = await this.requestOnce(fullBody, {
      ...this.sessionHeaders(),
      'Content-Type': contentType,
      'Content-Length': String(fullBody.length),
    }, signal);
    if (res.status === 401 && !reauthed) {
      // The socket lost its auth state (reconnect), or the server asks
      // again (RFC 4559 5: the only time a token goes out on an
      // established session). One fresh handshake.
      // Dispose the old context first: a Kerberos password context holds
      // a temp ccache directory on disk. A failed dispose must not block
      // the re-auth, so resetContext() ignores it.
      await this.resetContext();
      return this.postOnce(soap, true, signal);
    }
    if (res.status === 401) throw new WinRMAuthError('WinRM authentication failed on an established session');
    return this.handleResult(res);
  }

  private async handleResult(res: RawResponse): Promise<string> {
    if (res.status === 500) {
      const text = await this.decryptResponse(res);
      const fault = parseSoapFault(text);
      if (fault) throw fault;
      throw new WinRMTransportError(`WinRM request failed with HTTP 500 and no SOAP fault: ${text.slice(0, 200)}`);
    }
    // A 401 here answers the first sealed request after a finished
    // handshake (the body that follows a mutual-auth probe,
    // finishMutualAuth): the server accepted the AP-REQ and then refused
    // the connection it authenticated. Credentials, SPN or a replayed
    // token are the causes, not the network: an auth error, which
    // the facade maps to exit 2, never a connection error.
    if (res.status === 401) {
      throw new WinRMAuthError('WinRM authentication failed: the server answered HTTP 401 after the handshake had finished');
    }
    if (res.status < 200 || res.status >= 300) {
      throw new WinRMTransportError(`WinRM request failed with HTTP ${res.status}`);
    }
    return this.decryptResponse(res);
  }

  // One request at a time. The handshake, wrap -> send -> receive ->
  // unwrap, and the re-auth path share one SecurityContext whose NTLM
  // sequence numbers must match the order on the wire, so concurrent
  // callers queue here. A failed request still releases the queue.
  private queue: Promise<unknown> = Promise.resolve();

  // An aborted request drops its socket, so the next request starts on a
  // new connection and re-authenticates once.
  post(soap: string, signal?: AbortSignal): Promise<string> {
    const run = this.queue.then(() => this.postOnce(soap, false, signal));
    this.queue = run.catch(() => undefined);
    return run;
  }

  async close(): Promise<void> {
    this.agent.destroy();
    await this.ctx.dispose?.();
  }
}
