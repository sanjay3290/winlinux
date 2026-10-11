// Host profiles: the parser, pattern matching, target forms, the
// precedence matrix, -F and the permission warning. No network.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { chmod, mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { WinLinuxUsageError } from '../../dist/errors.js';
import {
  PASSWORD_REFUSAL,
  matchHostPattern,
  parseConfig,
  resolveProfile,
  resolveTarget,
} from '../../dist/cli/config.js';
import { HELP, buildConnectOptions, credentialSource, loadHostConfig } from '../../dist/cli/app.js';

const FILE = '/home/u/.winlinux/config';

const SAMPLE = `# ~/.winlinux/config
Host web1 web1.example.test
    HostName web1.example.test
    User svc-ops
    Auth kerberos
    Realm EXAMPLE.TEST
    TLS yes
    WinRMPort 5986

Host *.example.test
    Domain EXAMPLE
    UseTicketCache yes
    # a comment inside a block
    WinRMPort 15986
`;

function usage(fn: () => unknown, pattern: RegExp): void {
  assert.throws(fn, (err: unknown) => {
    assert.ok(err instanceof WinLinuxUsageError, `expected WinLinuxUsageError, got ${String(err)}`);
    assert.match((err as Error).message, pattern);
    return true;
  });
}

describe('parseConfig', () => {
  it('reads Host blocks, comments, blank lines and several patterns per Host', () => {
    const config = parseConfig(SAMPLE, FILE);
    assert.equal(config.blocks.length, 2);
    assert.deepEqual(config.blocks[0]?.patterns, ['web1', 'web1.example.test']);
    assert.equal(config.blocks[0]?.line, 2);
    assert.deepEqual(config.blocks[0]?.settings, {
      hostName: 'web1.example.test',
      user: 'svc-ops',
      auth: 'kerberos',
      realm: 'EXAMPLE.TEST',
      tls: true,
      winrmPort: 5986,
    });
    assert.deepEqual(config.blocks[1]?.settings, { domain: 'EXAMPLE', useTicketCache: true, winrmPort: 15986 });
  });

  it('keys are case-insensitive; values may be in double quotes; Key=value works', () => {
    const config = parseConfig(
      'host a\n  HOSTNAME "a.example.test"\n  tls=No\n  krbhostname = a.example.test\n  keytab "/k/my keys/svc.keytab"\n  insecure YES\n  smbport 1445\n',
      FILE,
    );
    assert.deepEqual(config.blocks[0]?.settings, {
      hostName: 'a.example.test',
      tls: false,
      krbHostname: 'a.example.test',
      keytab: '/k/my keys/svc.keytab',
      insecure: true,
      smbPort: 1445,
    });
  });

  it('Via: auto, smb or winrm, case-insensitive; anything else is a usage error', () => {
    assert.equal(parseConfig('Host a\n  Via WinRM\n', FILE).blocks[0]?.settings.via, 'winrm');
    assert.equal(parseConfig('Host a\n  via auto\n', FILE).blocks[0]?.settings.via, 'auto');
    usage(() => parseConfig('Host a\n  Via ftp\n', FILE), /:2: Via must be auto, smb or winrm, got ftp/);
  });

  it('lines before the first Host apply to every host', () => {
    const config = parseConfig('Realm EXAMPLE.TEST\nHost a\n  User u\n', FILE);
    assert.deepEqual(resolveProfile(config, 'zzz')?.settings, { realm: 'EXAMPLE.TEST' });
    assert.deepEqual(resolveProfile(config, 'a')?.settings, { realm: 'EXAMPLE.TEST', user: 'u' });
  });

  it('an unknown key is a usage error with the file and line number', () => {
    usage(() => parseConfig('Host a\n  User u\n  IdentityFile x\n', FILE), /^\/home\/u\/\.winlinux\/config:3: unknown key IdentityFile$/);
  });

  it('refuses Password in any case, naming the line', () => {
    for (const key of ['Password', 'password', 'PASSWORD', 'PassWord']) {
      usage(() => parseConfig(`Host a\n  ${key} hunter2\n`, FILE), new RegExp(`^${FILE.replace(/\./g, '\\.')}:2: ${PASSWORD_REFUSAL}$`));
    }
    usage(() => parseConfig('Password x\n', FILE), /:1: passwords are never stored in the config file; use WINLINUX_PASSWORD, the prompt, -K or a keytab/);
  });

  it('refuses a bad port, a bad yes/no, a bad Auth and a bad KrbHostname', () => {
    usage(() => parseConfig('Host a\n  WinRMPort 0\n', FILE), /:2: port must be an integer from 1 to 65535, got 0/);
    usage(() => parseConfig('Host a\n  SMBPort 65536\n', FILE), /:2: port must be/);
    usage(() => parseConfig('Host a\n  WinRMPort 59x\n', FILE), /:2: port must be/);
    usage(() => parseConfig('Host a\n  TLS true\n', FILE), /:2: expected yes or no, got true/);
    usage(() => parseConfig('Host a\n  UseTicketCache 1\n', FILE), /:2: expected yes or no/);
    usage(() => parseConfig('Host a\n  Auth credssp\n', FILE), /:2: Auth must be one of negotiate, ntlm, kerberos, basic/);
    usage(() => parseConfig('Host a\n  KrbHostname 192.0.2.1\n', FILE), /:2: KrbHostname must be the server's DNS name/);
  });

  it('refuses malformed lines', () => {
    usage(() => parseConfig('Host\n', FILE), /:1: Host needs at least one pattern/);
    usage(() => parseConfig('Host !bad\n', FILE), /:1: negated Host patterns/);
    usage(() => parseConfig('Host a\n  User a b\n', FILE), /:2: User takes exactly one value/);
    usage(() => parseConfig('Host a\n  User\n', FILE), /:2: User takes exactly one value/);
    usage(() => parseConfig('Host a\n  User "u\n', FILE), /:2: unclosed double quote/);
    usage(() => parseConfig('Host a\n  User CORP\\u\n', FILE), /:2: User takes no DOMAIN\\ prefix/);
    usage(() => parseConfig('Host a\n  = x\n', FILE), /:2: expected Key value/);
  });
});

describe('Host pattern matching', () => {
  it('* and ? glob, case-insensitive, whole name only', () => {
    assert.ok(matchHostPattern('*.example.test', 'web1.example.test'));
    assert.ok(matchHostPattern('web?', 'WEB1'));
    assert.ok(!matchHostPattern('web?', 'web10'));
    assert.ok(!matchHostPattern('*.example.test', 'example.test'));
    assert.ok(matchHostPattern('*', 'anything'));
    assert.ok(!matchHostPattern('web1.example.test', 'web1xexample.test'), 'a dot is literal');
  });

  it('first matching block that sets a key wins', () => {
    const config = parseConfig(SAMPLE, FILE);
    const found = resolveProfile(config, 'web1');
    assert.equal(found?.settings.winrmPort, 5986, 'first block wins');
    assert.equal(found?.settings.domain, undefined, '*.example.test does not match the bare alias web1');
    const full = resolveProfile(config, 'web1.example.test');
    assert.equal(full?.settings.winrmPort, 5986);
    assert.equal(full?.settings.domain, 'EXAMPLE', 'the second block fills keys the first left unset');
    assert.deepEqual(full?.matched, ['Host web1 web1.example.test', 'Host *.example.test']);
    assert.equal(resolveProfile(config, 'db1.other.test'), null);
  });
});

describe('target forms', () => {
  const config = parseConfig(SAMPLE + '\nHost bare\n  HostName bare.example.test\n', FILE);

  it('alias: the profile gives the user and the host', () => {
    const r = resolveTarget('web1', undefined, config);
    assert.deepEqual(r.target, { username: 'svc-ops', host: 'web1.example.test' });
    assert.equal(r.profile.tls, true);
  });

  it('user@alias and DOMAIN\\user@alias: the target text beats User and Domain', () => {
    assert.deepEqual(resolveTarget('alice@web1', undefined, config).target, { username: 'alice', host: 'web1.example.test' });
    assert.deepEqual(resolveTarget('OTHER\\alice@web1.example.test', undefined, config).target, {
      username: 'alice',
      domain: 'OTHER',
      host: 'web1.example.test',
    });
    assert.deepEqual(resolveTarget('alice@web1.example.test', undefined, config).target, {
      username: 'alice',
      domain: 'EXAMPLE',
      host: 'web1.example.test',
    });
  });

  it('user@host with no matching block works as before, with no profile', () => {
    const r = resolveTarget('alice@server.other.test', undefined, config);
    assert.deepEqual(r.target, { username: 'alice', host: 'server.other.test' });
    assert.deepEqual(r.profile, {});
    assert.deepEqual(resolveTarget('alice@server', 'CORP', undefined).target, { username: 'alice', domain: 'CORP', host: 'server' });
  });

  it('-d beats the profile Domain', () => {
    assert.equal(resolveTarget('alice@web1.example.test', 'CORP', config).target.domain, 'CORP');
  });

  it('an alias with no matching block, or with no config, is "unknown host alias"', () => {
    usage(() => resolveTarget('db9', undefined, config), /^unknown host alias db9$/);
    usage(() => resolveTarget('web1', undefined, undefined), /^unknown host alias web1$/);
  });

  it('an alias whose profile has no User asks for user@alias', () => {
    usage(() => resolveTarget('bare', undefined, config), new RegExp(`^no user for host alias bare; use user@bare or set User in ${FILE.replace(/\./g, '\\.')}$`));
    assert.deepEqual(resolveTarget('u@bare', undefined, config).target, { username: 'u', host: 'bare.example.test' });
  });
});

describe('precedence: flag, then target, then profile, then default', () => {
  const profile = {
    hostName: 'web1.example.test',
    user: 'svc-ops',
    auth: 'kerberos' as const,
    realm: 'PROFILE.TEST',
    tls: true,
    winrmPort: 5986,
    smbPort: 1445,
    krbHostname: 'spn.example.test',
  };
  const target = { username: 'svc-ops', host: 'web1.example.test' };
  const none = { useTicketCache: false };

  it('the profile beats the defaults', () => {
    const o = buildConnectOptions({}, { target, profile }, none, 'pw');
    assert.equal(o.auth, 'kerberos');
    assert.equal(o.realm, 'PROFILE.TEST');
    assert.deepEqual(o.winrm, { tls: true, tlsVerify: true, port: 5986 });
    assert.deepEqual(o.smb, { port: 1445 });
    assert.equal(o.kerberosHostname, 'spn.example.test');
  });

  it('flags beat the profile', () => {
    const o = buildConnectOptions(
      { auth: 'ntlm', realm: 'FLAG.TEST', 'winrm-port': '7000', 'smb-port': '7001', 'krb-hostname': 'flag.example.test', insecure: true },
      { target, profile },
      none,
      'pw',
    );
    assert.equal(o.auth, 'ntlm');
    assert.equal(o.realm, 'FLAG.TEST');
    assert.deepEqual(o.winrm, { tls: true, tlsVerify: false, port: 7000 });
    assert.deepEqual(o.smb, { port: 7001 });
    assert.equal(o.kerberosHostname, 'flag.example.test');
  });

  it('defaults apply with no flag and no profile', () => {
    const o = buildConnectOptions({}, { target, profile: {} }, none, 'pw');
    assert.equal(o.auth, 'negotiate');
    assert.deepEqual(o.winrm, { tls: false, tlsVerify: true, port: undefined });
    assert.equal(o.realm, undefined);
  });

  it('the target domain reaches the options', () => {
    assert.equal(buildConnectOptions({}, { target: { ...target, domain: 'CORP' }, profile }, none, 'pw').domain, 'CORP');
  });

  it('-K or --keytab replaces the profile credential keys; ~/ in Keytab means $HOME', () => {
    const env = { HOME: '/home/u' };
    const p = { keytab: '~/.winlinux/svc.keytab' };
    assert.deepEqual(credentialSource({}, p, env), { useTicketCache: false, keytab: '/home/u/.winlinux/svc.keytab' });
    assert.deepEqual(credentialSource({ 'use-ticket-cache': true }, p, env), { useTicketCache: true });
    assert.deepEqual(credentialSource({ keytab: '/k/f' }, { useTicketCache: true }, env), { useTicketCache: false, keytab: '/k/f' });
    assert.deepEqual(credentialSource({}, { useTicketCache: true }, env), { useTicketCache: true });
    assert.deepEqual(credentialSource({}, {}, env), { useTicketCache: false });
    usage(() => credentialSource({ keytab: '/k/f', 'use-ticket-cache': true }, {}, env), /--keytab and -K/);
  });
});

describe('loading the config file', () => {
  async function home(text?: string, mode = 0o600): Promise<string> {
    const dir = await mkdtemp(join(tmpdir(), 'winlinux-home-'));
    if (text !== undefined) {
      await mkdir(join(dir, '.winlinux'));
      await writeFile(join(dir, '.winlinux', 'config'), text);
      await chmod(join(dir, '.winlinux', 'config'), mode);
    }
    return dir;
  }
  function sink(): { stderr: NodeJS.WritableStream; text: () => string } {
    let out = '';
    return { stderr: { write: (s: string) => ((out += s), true) } as unknown as NodeJS.WritableStream, text: () => out };
  }

  it('a missing default file is fine', async () => {
    const err = sink();
    assert.equal(await loadHostConfig(undefined, { env: { HOME: await home() }, stderr: err.stderr }), undefined);
    assert.equal(err.text(), '');
  });

  it('reads ~/.winlinux/config; 0600 does not warn, 0644 warns once and continues', async () => {
    const quiet = sink();
    const h1 = await home('Host a\n  User u\n', 0o600);
    assert.equal((await loadHostConfig(undefined, { env: { HOME: h1 }, stderr: quiet.stderr }))?.blocks.length, 1);
    assert.equal(quiet.text(), '');

    const loud = sink();
    const h2 = await home('Host a\n  User u\n', 0o644);
    const file = join(h2, '.winlinux', 'config');
    assert.equal((await loadHostConfig(undefined, { env: { HOME: h2 }, stderr: loud.stderr }))?.blocks.length, 1);
    assert.equal(loud.text(), `winlinux: warning: ${file} is accessible by group or others; run chmod 600 ${file}\n`);
  });

  it('-F picks another file; a missing -F file is a usage error; -F none ignores profiles', async () => {
    const h = await home('Host a\n  User from-home\n');
    const other = join(await mkdtemp(join(tmpdir(), 'winlinux-cfg-')), 'cfg');
    await writeFile(other, 'Host a\n  User from-flag\n', { mode: 0o600 });
    const err = sink();
    const fromFlag = await loadHostConfig(other, { env: { HOME: h }, stderr: err.stderr });
    assert.equal(fromFlag?.blocks[0]?.settings.user, 'from-flag');
    await assert.rejects(loadHostConfig(join(h, 'nope'), { env: { HOME: h }, stderr: err.stderr }), /config file .*nope: no such file/);
    assert.equal(await loadHostConfig('none', { env: { HOME: h }, stderr: err.stderr }), undefined);
  });

  it('a parse error names the file and line', async () => {
    const h = await home('Host a\n  Password x\n');
    await assert.rejects(loadHostConfig(undefined, { env: { HOME: h }, stderr: sink().stderr }), (err: Error) => {
      assert.ok(err instanceof WinLinuxUsageError);
      assert.equal(err.message, `${join(h, '.winlinux', 'config')}:2: ${PASSWORD_REFUSAL}`);
      return true;
    });
  });

  it('--help documents -F and host aliases', () => {
    assert.match(HELP, /-F, --config <file\|none>/);
    assert.match(HELP, /host alias from ~\/\.winlinux\/config/);
  });
});
