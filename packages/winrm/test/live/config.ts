// Environment for the live WinRM runner. Pure: takes an env object, returns
// a config or the list of problems. run-live.ts turns problems into exit 2.
import type { Credentials, Mechanism } from '../../src/auth-provider.js';

export interface LiveConfig {
  host: string;
  // Ports of the two listeners the scenarios use.
  httpPort: number;
  httpsPort: number;
  tlsVerify: boolean;
  credentials: Credentials;
  // Transport for the scenarios that do not pin one (streaming,
  // PowerShell, event log, abort).
  tls: boolean;
  mechanism: Mechanism;
  // Kerberos: the realm is in credentials.realm; a KDC host, when
  // given, goes into a krb5.conf the runner writes (see krb5Conf).
  kdc?: string;
}

export type LiveConfigResult = { ok: true; config: LiveConfig } | { ok: false; problems: string[] };

const MECHANISMS: readonly Mechanism[] = ['basic', 'ntlm', 'kerberos', 'negotiate'];

export const LIVE_ENV_HELP = [
  'The live WinRM runner needs a Windows Server with WinRM listeners on HTTP and HTTPS.',
  'Required:',
  '  WINRM_HOST        host name or IP of the Windows server',
  '  WINRM_USER        local admin test account',
  '  WINRM_PASS        its password',
  'Optional:',
  '  WINRM_DOMAIN      NTLM domain (default: empty, for a local account)',
  '  WINRM_REALM       Kerberos realm for the Kerberos scenario (default: WINRM_DOMAIN upper-cased; empty on a workgroup VM)',
  '  WINRM_KDC         KDC host for that realm; the runner then writes a krb5.conf and sets KRB5_CONFIG',
  '                    (default: none, the client\'s own krb5.conf or DNS must name the KDC)',
  '  WINRM_MECHANISM   basic|ntlm|kerberos|negotiate for the general scenarios (default: ntlm)',
  '  WINRM_TLS         1 = general scenarios use HTTPS, 0 = HTTP (default: 1)',
  '  WINRM_PORT        port of the listener WINRM_TLS selects (default: 5986 for HTTPS, 5985 for HTTP)',
  '  WINRM_TLS_VERIFY  1 = verify the HTTPS certificate, 0 = accept self-signed (default: 1)',
  'See packages/winrm/test/live/README.md for the VM setup.',
].join('\n');

function flag(value: string | undefined, name: string, fallback: boolean, problems: string[]): boolean {
  if (value === undefined || value === '') return fallback;
  if (value === '1') return true;
  if (value === '0') return false;
  problems.push(`${name} must be 1 or 0, got '${value}'`);
  return fallback;
}

export function liveConfigFromEnv(env: NodeJS.ProcessEnv): LiveConfigResult {
  const problems: string[] = [];
  const host = env['WINRM_HOST'];
  const username = env['WINRM_USER'];
  const password = env['WINRM_PASS'];
  if (!host) problems.push('WINRM_HOST is not set');
  if (!username) problems.push('WINRM_USER is not set');
  if (!password) problems.push('WINRM_PASS is not set');

  const mechanism = (env['WINRM_MECHANISM'] || 'ntlm') as Mechanism;
  if (!MECHANISMS.includes(mechanism)) {
    problems.push(`WINRM_MECHANISM must be one of ${MECHANISMS.join('|')}, got '${mechanism}'`);
  }
  const tls = flag(env['WINRM_TLS'], 'WINRM_TLS', true, problems);
  const tlsVerify = flag(env['WINRM_TLS_VERIFY'], 'WINRM_TLS_VERIFY', true, problems);

  let httpPort = 5985;
  let httpsPort = 5986;
  const portText = env['WINRM_PORT'];
  if (portText) {
    const port = Number(portText);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      problems.push(`WINRM_PORT must be a TCP port, got '${portText}'`);
    } else if (tls) {
      httpsPort = port;
    } else {
      httpPort = port;
    }
  }

  const kdc = env['WINRM_KDC'] || undefined;
  const realm = env['WINRM_REALM'] || env['WINRM_DOMAIN']?.toUpperCase() || undefined;
  if (kdc && !realm) problems.push('WINRM_KDC needs WINRM_REALM (or WINRM_DOMAIN)');

  if (problems.length > 0) return { ok: false, problems };
  const credentials: Credentials = { username: username as string, password };
  if (env['WINRM_DOMAIN']) credentials.domain = env['WINRM_DOMAIN'];
  if (realm) credentials.realm = realm;
  const config: LiveConfig = { host: host as string, httpPort, httpsPort, tlsVerify, credentials, tls, mechanism };
  if (kdc) config.kdc = kdc;
  return { ok: true, config };
}

// What the Kerberos scenario needs on top of the required variables. A
// workgroup VM has no realm and no KDC, so the runner reports these as env
// incomplete (exit 2) instead of failing the scenario.
export function kerberosProblems(cfg: LiveConfig): string[] {
  if (cfg.credentials.realm) return [];
  return [
    'WINRM_REALM (or WINRM_DOMAIN) is not set: the Kerberos scenario needs the realm of ' +
      `${cfg.credentials.username} and a KDC for it (WINRM_KDC, or a [realms] entry in krb5.conf / KRB5_CONFIG, ` +
      'or DNS SRV records); a workgroup VM has neither',
  ];
}

// A krb5.conf for WINRM_KDC: the realm, its KDC, and the target host mapped
// to the realm so the HTTP/<host> ticket request goes to that KDC.
export function krb5Conf(realm: string, kdc: string, host: string): string {
  const lines = [
    '[libdefaults]',
    `    default_realm = ${realm}`,
    '    dns_lookup_kdc = false',
    '',
    '[realms]',
    `    ${realm} = {`,
    `        kdc = ${kdc}`,
    '    }',
    '',
    '[domain_realm]',
    `    ${host.toLowerCase()} = ${realm}`,
  ];
  const dot = host.indexOf('.');
  if (dot > 0 && !/^[\d.]+$/.test(host)) lines.push(`    ${host.slice(dot).toLowerCase()} = ${realm}`);
  return `${lines.join('\n')}\n`;
}
