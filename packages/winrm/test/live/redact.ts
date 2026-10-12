// Redaction for recorded PSRP fixtures: the recorder's host, domain
// and user names, SIDs, IPv4 and IPv6 addresses and user profile paths
// become fixed sentinels before anything is written. A fixture that still
// matches the deny list fails test/psrp/fixtures-redacted.test.ts.
export interface RedactNames {
  host?: string;
  domain?: string;
  user?: string;
}

export const SENTINELS = { host: '<host>', domain: 'example.test', user: '<user>', sid: 'S-1-5-21-0-0-0', ipv4: '0.0.0.0', ipv6: '::' } as const;

const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const IPV4 = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
// IPv6: a run of hex groups and colons with a double colon or at least
// four groups, so a clock time (12:34:56) or a Windows drive stays.
const IPV6_RUN = /(?<![\w:])[0-9a-f:]*:[0-9a-f:]*(?![\w:])/gi;
const isIpv6 = (m: string) => m.length >= 3 && /[0-9a-f]/i.test(m) && (m.includes('::') || m.split(':').length >= 4) && m !== '::1';
const SID = /S-1-5-21-\d+-\d+-\d+(?:-\d+)?/g;
const PROFILE = /([A-Za-z]:\\Users\\)[^\\<>"'\s]+/g;

export function redactText(text: string, names: RedactNames = {}): string {
  let out = text;
  for (const [key, value] of [
    ['host', names.host],
    ['domain', names.domain],
    ['user', names.user],
  ] as const) {
    if (!value || value.length < 2) continue;
    out = out.replace(new RegExp(escapeRe(value), 'gi'), SENTINELS[key]);
  }
  out = out.replace(SID, SENTINELS.sid);
  out = out.replace(PROFILE, `$1${SENTINELS.user}`);
  out = out.replace(IPV4, (m) => (m === '127.0.0.1' ? m : SENTINELS.ipv4));
  out = out.replace(IPV6_RUN, (m) => (isIpv6(m) ? SENTINELS.ipv6 : m));
  return out;
}

// What a committed fixture must not contain. The recorder's own names
// come from the env of the test run (WINRM_HOST, WINRM_DOMAIN, WINRM_USER)
// and are never written to a file.
export function denyList(env: NodeJS.ProcessEnv): Array<{ name: string; test: (text: string) => boolean }> {
  const list: Array<{ name: string; test: (text: string) => boolean }> = [
    { name: 'IPv4 address other than loopback', test: (t) => [...t.matchAll(IPV4)].some((m) => m[0] !== '127.0.0.1' && m[0] !== SENTINELS.ipv4) },
    { name: 'IPv6 address other than loopback', test: (t) => [...t.matchAll(IPV6_RUN)].some((m) => isIpv6(m[0]) && m[0] !== SENTINELS.ipv6) },
    { name: 'domain SID (S-1-5-21-...)', test: (t) => [...t.matchAll(SID)].some((m) => m[0] !== SENTINELS.sid) },
    { name: 'user profile path', test: (t) => [...t.matchAll(PROFILE)].some((m) => !m[0].endsWith(SENTINELS.user)) },
  ];
  for (const [label, key] of [
    ['WINRM_HOST', 'WINRM_HOST'],
    ['WINRM_DOMAIN', 'WINRM_DOMAIN'],
    ['WINRM_USER', 'WINRM_USER'],
  ] as const) {
    const value = env[key];
    if (value && value.length >= 2) list.push({ name: `the recorder's ${label}`, test: (t) => t.toLowerCase().includes(value.toLowerCase()) });
  }
  return list;
}
