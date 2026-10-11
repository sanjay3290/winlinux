// Host profiles in ~/.winlinux/config, in ~/.ssh/config line syntax:
// `Host` blocks of `Key value` lines. Pure functions here; app.ts reads the
// file. No key can hold a secret.
import { isIP } from 'node:net';
import { WinLinuxUsageError } from '../errors.js';
import { parseTarget, type Target } from './target.js';

// `credssp` is not a profile mechanism: CredSSP delegates the
// password, so only `-a credssp` on the command line selects it.
export const PROFILE_MECHANISMS = ['negotiate', 'ntlm', 'kerberos', 'basic', 'certificate'] as const;
export const CREDSSP_PROFILE_REFUSAL = 'CredSSP delegates your password, so a profile cannot select it; use -a credssp per command';
export type ProfileMechanism = (typeof PROFILE_MECHANISMS)[number];

export interface ProfileSettings {
  hostName?: string;
  user?: string;
  domain?: string;
  realm?: string;
  auth?: ProfileMechanism;
  tls?: boolean;
  insecure?: boolean;
  winrmPort?: number;
  smbPort?: number;
  krbHostname?: string;
  connectTimeout?: number; // milliseconds
  useTicketCache?: boolean;
  keytab?: string;
  via?: 'auto' | 'smb' | 'winrm';
  certFile?: string;
  keyFile?: string;
}

export interface HostBlock {
  patterns: string[];
  line: number; // 0 for the implicit block before the first `Host` line
  settings: ProfileSettings;
}

export interface HostConfig {
  file: string;
  blocks: HostBlock[];
  // `Group <name> <member>...` lines: name -> members, as written.
  groups: Map<string, string[]>;
}

export interface ResolvedProfile {
  settings: ProfileSettings;
  // The `Host` lines that matched, in file order, as written.
  matched: string[];
}

type Parser = (value: string, where: string) => ProfileSettings[keyof ProfileSettings];

const word = (what: string) => (value: string, where: string): string => {
  if (/\s/.test(value)) throw new WinLinuxUsageError(`${where}: ${what} must not contain spaces: ${value}`);
  return value;
};

const yesNo: Parser = (value, where) => {
  const v = value.toLowerCase();
  if (v === 'yes') return true;
  if (v === 'no') return false;
  throw new WinLinuxUsageError(`${where}: expected yes or no, got ${value}`);
};

const port: Parser = (value, where) => {
  const n = Number(value);
  if (!/^\d+$/.test(value) || n < 1 || n > 65535) {
    throw new WinLinuxUsageError(`${where}: port must be an integer from 1 to 65535, got ${value}`);
  }
  return n;
};

// Keys are case-insensitive. Each maps to one setting and its parser.
const KEYS: Record<string, { name: keyof ProfileSettings; parse: Parser }> = {
  hostname: { name: 'hostName', parse: word('HostName') },
  user: {
    name: 'user',
    parse: (value, where) => {
      word('User')(value, where);
      if (value.includes('\\')) throw new WinLinuxUsageError(`${where}: User takes no DOMAIN\\ prefix; use the Domain key`);
      return value;
    },
  },
  domain: { name: 'domain', parse: word('Domain') },
  realm: { name: 'realm', parse: word('Realm') },
  auth: {
    name: 'auth',
    parse: (value, where) => {
      const v = value.toLowerCase();
      if (!(PROFILE_MECHANISMS as readonly string[]).includes(v)) {
        const why = v === 'credssp' ? ` (${CREDSSP_PROFILE_REFUSAL})` : '';
        throw new WinLinuxUsageError(`${where}: Auth must be one of ${PROFILE_MECHANISMS.join(', ')}, got ${value}${why}`);
      }
      return v as ProfileMechanism;
    },
  },
  tls: { name: 'tls', parse: yesNo },
  insecure: { name: 'insecure', parse: yesNo },
  winrmport: { name: 'winrmPort', parse: port },
  smbport: { name: 'smbPort', parse: port },
  connecttimeout: {
    name: 'connectTimeout',
    parse: (value, where) => {
      const seconds = Number(value);
      if (!/^\d+(\.\d+)?$/.test(value) || seconds < 0.1 || seconds > 600) {
        throw new WinLinuxUsageError(`${where}: ConnectTimeout must be a number of seconds from 0.1 to 600, got ${value}`);
      }
      return Math.round(seconds * 1000);
    },
  },
  krbhostname: {
    name: 'krbHostname',
    parse: (value, where) => {
      if (isIP(value) || /[\s/\\@]/.test(value)) {
        throw new WinLinuxUsageError(`${where}: KrbHostname must be the server's DNS name, not ${value}`);
      }
      return value;
    },
  },
  useticketcache: { name: 'useTicketCache', parse: yesNo },
  keytab: { name: 'keytab', parse: (value) => value },
  via: {
    name: 'via',
    parse: (value, where) => {
      const v = value.toLowerCase();
      if (v !== 'auto' && v !== 'smb' && v !== 'winrm') throw new WinLinuxUsageError(`${where}: Via must be auto, smb or winrm, got ${value}`);
      return v;
    },
  },
  certfile: { name: 'certFile', parse: (value) => value },
  keyfile: { name: 'keyFile', parse: (value) => value },
};

export const PASSWORD_REFUSAL =
  'passwords are never stored in the config file; use WINLINUX_PASSWORD, the prompt, -K or a keytab';

// `Key value`, `Key=value` or `Key = value`; a value may be in double quotes.
// Returns null for a blank or comment line.
function splitLine(raw: string, where: string): { key: string; args: string[] } | null {
  const line = raw.trim();
  if (line.length === 0 || line.startsWith('#')) return null;
  const m = /^([A-Za-z][A-Za-z0-9]*)\s*(?:=\s*|\s+)(.*)$/.exec(line) ?? /^([A-Za-z][A-Za-z0-9]*)$/.exec(line);
  if (!m?.[1]) throw new WinLinuxUsageError(`${where}: expected Key value, got ${line}`);
  const key = m[1];
  const rest = (m[2] ?? '').trim();
  const args: string[] = [];
  let i = 0;
  while (i < rest.length) {
    if (rest[i] === ' ' || rest[i] === '\t') {
      i += 1;
      continue;
    }
    if (rest[i] === '"') {
      const end = rest.indexOf('"', i + 1);
      if (end === -1) throw new WinLinuxUsageError(`${where}: unclosed double quote`);
      args.push(rest.slice(i + 1, end));
      i = end + 1;
      continue;
    }
    let j = i;
    while (j < rest.length && rest[j] !== ' ' && rest[j] !== '\t') j += 1;
    const token = rest.slice(i, j);
    if (token.includes('"')) throw new WinLinuxUsageError(`${where}: a double quote must enclose the whole value`);
    args.push(token);
    i = j;
  }
  return { key, args };
}

// Text in, profiles out. Throws WinLinuxUsageError naming `file:line`.
// Lines before the first `Host` apply to every host, as in ssh_config.
export function parseConfig(text: string, file: string): HostConfig {
  const blocks: HostBlock[] = [{ patterns: ['*'], line: 0, settings: {} }];
  const groups = new Map<string, string[]>();
  const lines = text.split(/\r?\n/);
  for (let index = 0; index < lines.length; index += 1) {
    const where = `${file}:${index + 1}`;
    const parsed = splitLine(lines[index] ?? '', where);
    if (!parsed) continue;
    const lower = parsed.key.toLowerCase();
    if (lower === 'password') throw new WinLinuxUsageError(`${where}: ${PASSWORD_REFUSAL}`);
    if (lower === 'group') {
      // A Group line is not part of the Host block above it.
      const [name, ...members] = parsed.args;
      if (!name || members.length === 0) throw new WinLinuxUsageError(`${where}: Group needs a name and at least one member`);
      if (!/^[A-Za-z0-9._-]+$/.test(name)) throw new WinLinuxUsageError(`${where}: bad group name ${name}`);
      if (groups.has(name.toLowerCase())) throw new WinLinuxUsageError(`${where}: group ${name} is defined twice`);
      for (const m of members) {
        if (m.startsWith('@')) throw new WinLinuxUsageError(`${where}: groups do not nest: ${m}`);
        if (m.includes(',')) throw new WinLinuxUsageError(`${where}: separate group members with spaces, not commas`);
      }
      groups.set(name.toLowerCase(), members);
      continue;
    }
    if (lower === 'host') {
      if (parsed.args.length === 0) throw new WinLinuxUsageError(`${where}: Host needs at least one pattern`);
      for (const p of parsed.args) {
        if (p.startsWith('!')) throw new WinLinuxUsageError(`${where}: negated Host patterns (!pattern) are not supported`);
      }
      blocks.push({ patterns: parsed.args, line: index + 1, settings: {} });
      continue;
    }
    const spec = KEYS[lower];
    if (!spec) throw new WinLinuxUsageError(`${where}: unknown key ${parsed.key}`);
    if (parsed.args.length !== 1 || parsed.args[0] === '') {
      throw new WinLinuxUsageError(`${where}: ${parsed.key} takes exactly one value`);
    }
    const block = blocks[blocks.length - 1] as HostBlock;
    // Within one block the first line for a key wins, as across blocks.
    if (block.settings[spec.name] === undefined) {
      (block.settings as Record<string, unknown>)[spec.name] = spec.parse(parsed.args[0] as string, where);
    }
  }
  return { file, blocks: blocks.filter((b) => b.line > 0 || Object.keys(b.settings).length > 0), groups };
}

// ssh_config glob: `*` any run of characters, `?` one character, case-insensitive.
export function matchHostPattern(pattern: string, name: string): boolean {
  const source = pattern
    .split('')
    .map((ch) => (ch === '*' ? '.*' : ch === '?' ? '.' : ch.replace(/[.+^${}()|[\]\\]/g, '\\$&')))
    .join('');
  return new RegExp(`^${source}$`, 'i').test(name);
}

// For each key, the first matching block that sets it wins.
export function resolveProfile(config: HostConfig, name: string): ResolvedProfile | null {
  const settings: ProfileSettings = {};
  const matched: string[] = [];
  for (const block of config.blocks) {
    if (!block.patterns.some((p) => matchHostPattern(p, name))) continue;
    matched.push(block.line === 0 ? '(before the first Host line)' : `Host ${block.patterns.join(' ')}`);
    for (const [key, value] of Object.entries(block.settings)) {
      if ((settings as Record<string, unknown>)[key] === undefined) (settings as Record<string, unknown>)[key] = value;
    }
  }
  return matched.length === 0 ? null : { settings, matched };
}

export interface ResolvedTarget {
  target: Target;
  profile: ProfileSettings;
  matched: string[];
}

// Target forms: `alias`, `user@alias`, `DOMAIN\user@alias`, and
// `[DOMAIN\]user@host`. The text after the last `@`, or the whole text
// without one, is matched against the `Host` patterns. The target text beats
// the profile: its user and domain win over User and Domain.
export function resolveTarget(text: string, flagDomain: string | undefined, config: HostConfig | undefined): ResolvedTarget {
  if (!text.includes('@')) {
    if (text.length === 0 || /[\s\\]/.test(text)) throw new WinLinuxUsageError(`target must be [DOMAIN\\]user@host or a host alias: ${text}`);
    const found = config ? resolveProfile(config, text) : null;
    if (!found || !config) throw new WinLinuxUsageError(`unknown host alias ${text}`);
    const { settings } = found;
    if (settings.user === undefined) {
      throw new WinLinuxUsageError(`no user for host alias ${text}; use user@${text} or set User in ${config.file}`);
    }
    const domain = flagDomain ?? settings.domain;
    const target: Target = { username: settings.user, host: settings.hostName ?? text };
    if (domain !== undefined) target.domain = domain;
    return { target, profile: settings, matched: found.matched };
  }
  const parsed = parseTarget(text, flagDomain);
  const found = config ? resolveProfile(config, parsed.host) : null;
  const settings = found?.settings ?? {};
  const target: Target = { username: parsed.username, host: settings.hostName ?? parsed.host };
  const domain = parsed.domain ?? settings.domain;
  if (domain !== undefined) target.domain = domain;
  return { target, profile: settings, matched: found?.matched ?? [] };
}
