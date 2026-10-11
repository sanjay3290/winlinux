// connect() validation. Rejects with WinLinuxUsageError and opens nothing.
import { isIP } from 'node:net';
import type { Credentials, Mechanism } from '@winlinux/auth';
import { CREDSSP_HTTP_REASON, CREDSSP_INSECURE_REASON } from '@winlinux/winrm';
import type { AuthMechanism } from './types.js';
import { WinLinuxUsageError } from './errors.js';
import type { ConnectOptions } from './types.js';

const MECHANISMS: readonly AuthMechanism[] = ['basic', 'ntlm', 'kerberos', 'negotiate', 'credssp', 'certificate'];

function checkPort(name: string, port: number | undefined): void {
  if (port === undefined) return;
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new WinLinuxUsageError(`${name} must be an integer from 1 to 65535`);
  }
}

const VIAS: readonly string[] = ['smb', 'winrm', 'auto'];

export function checkVia(name: string, via: unknown): void {
  if (via !== undefined && !VIAS.includes(via as string)) throw new WinLinuxUsageError(`${name} must be smb, winrm or auto`);
}

export interface ValidatedOptions {
  auth: AuthMechanism;
  credentials: Readonly<Credentials>;
  kerberosHostname?: string;
}

// The mechanisms under which Kerberos is the only thing that can run: an IP
// address as host then fails at the KDC ("Server not found in Kerberos
// database") after a kinit. `negotiate` with a password falls back to NTLM
// and is left alone.
// CredSSP runs Kerberos inside when a realm is set.
function kerberosOnly(auth: AuthMechanism, hasPassword: boolean, hasRealm: boolean): boolean {
  return auth === 'kerberos' || (auth === 'negotiate' && !hasPassword) || (auth === 'credssp' && hasRealm);
}

// CredSSP delegates the password to the server: explicit opt-in,
// a password, and a verified server. Checked before anything else, so the
// refusal names CredSSP.
function checkCredssp(options: ConnectOptions, hasPassword: boolean): void {
  if (options.keytab !== undefined) {
    throw new WinLinuxUsageError("auth 'credssp' cannot use a keytab: CredSSP delegates a password to the server");
  }
  if (options.useTicketCache === true) {
    throw new WinLinuxUsageError("auth 'credssp' cannot use the ticket cache (-K): CredSSP delegates a password to the server");
  }
  if (!hasPassword) throw new WinLinuxUsageError("auth 'credssp' needs a password");
  if (options.winrm?.tlsVerify === false) throw new WinLinuxUsageError(CREDSSP_INSECURE_REASON);
  if (options.winrm?.tls !== true && options.winrm?.credsspAllowHttp !== true) throw new WinLinuxUsageError(CREDSSP_HTTP_REASON);
}

export function validateConnect(host: string, options: ConnectOptions): ValidatedOptions {
  if (typeof host !== 'string' || host.length === 0) throw new WinLinuxUsageError('host must not be empty');
  if (!options || typeof options.username !== 'string' || options.username.length === 0) {
    throw new WinLinuxUsageError('username must not be empty');
  }
  const auth = options.auth ?? 'negotiate';
  if (!MECHANISMS.includes(auth)) {
    throw new WinLinuxUsageError(`auth must be one of ${MECHANISMS.join(', ')}`);
  }
  const hasPassword = typeof options.password === 'string' && options.password.length > 0;
  // Certificate sign-in: the certificate is the credential. HTTPS
  // only, checked here so no socket opens over plain HTTP.
  if (auth === 'certificate') {
    if (typeof options.clientCert !== 'string' || options.clientCert.length === 0 || typeof options.clientKey !== 'string' || options.clientKey.length === 0) {
      throw new WinLinuxUsageError("auth 'certificate' needs clientCert and clientKey (--cert <file> --key <file>)");
    }
    if (options.password !== undefined || options.useTicketCache === true || options.keytab !== undefined) {
      throw new WinLinuxUsageError("auth 'certificate' takes no password, ticket cache or keytab");
    }
    if (options.winrm?.tls !== true) throw new WinLinuxUsageError('certificate sign-in needs HTTPS: use --tls (winrm.tls)');
    if (options.winrm?.encryption === 'always') throw new WinLinuxUsageError("certificate sign-in has no message encryption; leave winrm.encryption at 'auto'");
  } else if (options.clientCert !== undefined || options.clientKey !== undefined || options.clientKeyPassphrase !== undefined) {
    throw new WinLinuxUsageError("clientCert, clientKey and the key passphrase need auth 'certificate' (-a certificate)");
  }
  if (auth === 'credssp') checkCredssp(options, hasPassword);
  const keytab = options.keytab;
  if (keytab !== undefined) {
    // A keytab is a Kerberos key: no password, no ticket cache, no
    // NTLM or Basic, and a realm to build the client principal from.
    if (typeof keytab !== 'string' || keytab.length === 0) throw new WinLinuxUsageError('keytab must be a file path');
    if (options.password !== undefined) throw new WinLinuxUsageError('a keytab and a password cannot be used together');
    if (options.useTicketCache === true) throw new WinLinuxUsageError('a keytab and the ticket cache (-K) cannot be used together');
    if (auth === 'basic' || auth === 'ntlm') {
      throw new WinLinuxUsageError(`auth '${auth}' cannot use a keytab; a keytab works with kerberos or negotiate`);
    }
    if (!options.username.includes('@') && !options.realm && !options.domain) {
      throw new WinLinuxUsageError('a keytab needs a realm: use --realm <REALM>, a DOMAIN\\ prefix, or user@REALM');
    }
  }
  if ((auth === 'basic' || auth === 'ntlm') && !hasPassword) {
    throw new WinLinuxUsageError(`auth '${auth}' needs a password`);
  }
  if ((auth === 'kerberos' || auth === 'negotiate') && !hasPassword && options.useTicketCache !== true && keytab === undefined) {
    throw new WinLinuxUsageError(`auth '${auth}' needs a password unless useTicketCache is true or a keytab is set`);
  }
  checkVia('transfer.via', options.transfer?.via);
  checkPort('winrm.port', options.winrm?.port);
  checkPort('smb.port', options.smb?.port);
  const connectTimeoutMs = options.winrm?.connectTimeoutMs;
  if (connectTimeoutMs !== undefined && (!Number.isInteger(connectTimeoutMs) || connectTimeoutMs < 1 || connectTimeoutMs > 600_000)) {
    throw new WinLinuxUsageError('winrm.connectTimeoutMs must be an integer from 1 to 600000');
  }

  const kerberosHostname = options.kerberosHostname;
  if (kerberosHostname !== undefined) {
    if (typeof kerberosHostname !== 'string' || kerberosHostname.length === 0) {
      throw new WinLinuxUsageError('kerberosHostname must not be empty');
    }
    if (isIP(kerberosHostname) || /[\s/\\@]/.test(kerberosHostname)) {
      throw new WinLinuxUsageError(`kerberosHostname must be the server's DNS name, not ${kerberosHostname}`);
    }
  }
  const hasRealm = typeof options.realm === 'string' && options.realm.length > 0;
  if (kerberosHostname === undefined && kerberosOnly(auth, hasPassword, hasRealm) && isIP(host)) {
    throw new WinLinuxUsageError(
      `Kerberos needs the server's DNS name, not an IP address (${host}); use the FQDN, --krb-hostname <fqdn>, or -a ntlm`,
    );
  }

  const credentials: Credentials = { username: options.username };
  if (hasPassword) credentials.password = options.password;
  if (options.domain !== undefined) credentials.domain = options.domain;
  if (options.realm !== undefined) credentials.realm = options.realm;
  if (options.useTicketCache !== undefined) credentials.useTicketCache = options.useTicketCache;
  if (keytab !== undefined) credentials.keytab = keytab;
  const validated: ValidatedOptions = { auth, credentials: Object.freeze(credentials) };
  if (kerberosHostname !== undefined) validated.kerberosHostname = kerberosHostname;
  return validated;
}

// Path rule: the library never splits paths.
export function checkShare(share: string): void {
  if (typeof share !== 'string' || share.length === 0) throw new WinLinuxUsageError('share must not be empty');
  if (share.includes('/') || share.includes('\\')) {
    throw new WinLinuxUsageError(`share must be a share name without '/' or '\\': ${share}`);
  }
}

// A remote path for the file operations: share-relative, non-empty.
export function checkPath(what: string, remotePath: string): void {
  if (typeof remotePath !== 'string' || remotePath.length === 0) throw new WinLinuxUsageError(`${what} must not be empty`);
}

export function validatePassword(password: string): void {
  if (typeof password !== 'string' || password.length === 0) {
    throw new WinLinuxUsageError('password must be a non-empty string');
  }
}
