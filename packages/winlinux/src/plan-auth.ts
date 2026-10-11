// Mechanism per protocol. Pure function.
//
// SMB signing needs a session key. NTLM always has one; Kerberos has one only
// when @winlinux/krb-session-key is installed. So `negotiate` with a
// password uses NTLM for SMB, unless a realm is set and the addon loads: then
// it uses Negotiate (Kerberos first, NTLM fallback on a client-side Kerberos
// failure). WinRM with message encryption (E: plain HTTP by default) seals
// Kerberos bodies with the gss_wrap_iov split, which the same addon
// provides. Without the addon, winrm refuses Kerberos over HTTP, so under
// negotiate this plan uses NTLM, and Kerberos-only setups are refused before
// any socket opens. With the addon, Kerberos and Negotiate are allowed.
import type { Credentials, Mechanism } from '@winlinux/auth';
import type { AuthMechanism, WinRMOptions } from './types.js';

export type ProtocolPlan =
  | { refused: false; mechanism: AuthMechanism }
  | { refused: true; mechanism: AuthMechanism; reason: string };

export interface AuthPlan {
  winrm: ProtocolPlan;
  smb: ProtocolPlan;
}

export const KERBEROS_OVER_HTTP_REASON = 'Kerberos over plain HTTP is not supported; use --tls';
export const CERTIFICATE_OVER_SMB_REASON = 'certificate sign-in is WinRM-only; use --via winrm for files';
export const BASIC_OVER_SMB_REASON = 'Basic authentication is HTTP-only; use ntlm or negotiate for files';
export const CREDSSP_OVER_SMB_REASON = 'CredSSP is WinRM-only; use another mechanism for files';

const ok = (mechanism: AuthMechanism): ProtocolPlan => ({ refused: false, mechanism });
const refuse = (mechanism: AuthMechanism, reason: string): ProtocolPlan => ({ refused: true, mechanism, reason });

// E is on when encryption is 'always', or 'auto' (default) without TLS (winrm transport.ts:61).
export function winrmEncrypted(opts: WinRMOptions | undefined): boolean {
  const encryption = opts?.encryption ?? 'auto';
  return encryption === 'always' || (encryption === 'auto' && opts?.tls !== true);
}

// kerberosSessionKey: @winlinux/krb-session-key loads on this host, so a
// Kerberos context can sign SMB2 and seal WinRM bodies over plain HTTP.
export function planAuth(
  auth: AuthMechanism,
  credentials: Pick<Credentials, 'password' | 'useTicketCache' | 'realm' | 'keytab'>,
  winrmEncrypted: boolean,
  kerberosSessionKey = false,
): AuthPlan {
  const hasPassword = typeof credentials.password === 'string' && credentials.password.length > 0;
  const hasRealm = typeof credentials.realm === 'string' && credentials.realm.length > 0;
  // Kerberos over plain HTTP needs the addon's gss_wrap_iov split.
  const kerberosWinrm = !winrmEncrypted || kerberosSessionKey;
  switch (auth) {
    case 'negotiate':
      // A keytab has no password, so there is no NTLM fallback: it
      // plans Kerberos for both protocols, like the ticket cache.
      if (hasPassword && credentials.keytab === undefined) {
        const smb: Mechanism = hasRealm && kerberosSessionKey ? 'negotiate' : 'ntlm';
        return { winrm: ok(kerberosWinrm ? 'negotiate' : 'ntlm'), smb: ok(smb) };
      }
      return {
        winrm: kerberosWinrm ? ok('kerberos') : refuse('kerberos', KERBEROS_OVER_HTTP_REASON),
        smb: ok('kerberos'),
      };
    case 'ntlm':
      return { winrm: ok('ntlm'), smb: ok('ntlm') };
    case 'kerberos':
      return {
        winrm: kerberosWinrm ? ok('kerberos') : refuse('kerberos', KERBEROS_OVER_HTTP_REASON),
        smb: ok('kerberos'),
      };
    case 'certificate':
      // A TLS client certificate on WinRM. SMB has no certificate sign-in.
      return { winrm: ok('certificate'), smb: refuse('certificate', CERTIFICATE_OVER_SMB_REASON) };
    case 'basic':
      // Over HTTP winrm itself refuses Basic at open (usage error).
      return { winrm: ok('basic'), smb: refuse('basic', BASIC_OVER_SMB_REASON) };
    case 'credssp':
      // Explicit opt-in only: no other case ever plans credssp.
      // validateConnect already refused it without a password, with -K, a
      // keytab, tlsVerify false, or plain HTTP without credsspAllowHttp.
      return { winrm: ok('credssp'), smb: refuse('credssp', CREDSSP_OVER_SMB_REASON) };
  }
}
