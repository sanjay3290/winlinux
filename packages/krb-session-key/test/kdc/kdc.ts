// A throwaway MIT KDC for the live tests, plus the GSS acceptor harness
// (test/kdc/acceptor.c). Everything lives in one temp directory with its
// own krb5.conf and kdc.conf on free localhost ports: no root, no changes
// to /etc. Linux with krb5-kdc, krb5-admin-server (kadmin.local) and
// krb5-user (kinit) installed, plus a C compiler and libkrb5-dev for the
// harness. `requireKdcTools()` names what is missing.
//
// Realm WINLINUX.TEST, with these principals in the keytab:
//   HTTP/aes128.winlinux.test  aes128-cts only (session key aes128)
//   HTTP/aes256.winlinux.test  aes256-cts only (session key aes256)
//   HTTP/127.0.0.1             aes256-cts (what the WinRM transport asks for
//                              when it connects to 127.0.0.1)
// and the user alice (password `alice-pw`).
import { execFile, spawn, type ChildProcess } from 'node:child_process';
import { accessSync, constants } from 'node:fs';
import { chmod, mkdtemp, rm, writeFile } from 'node:fs/promises';
import net from 'node:net';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { createInterface } from 'node:readline';

const execFileAsync = promisify(execFile);

export const REALM = 'WINLINUX.TEST';
export const USER = 'alice';
export const PASSWORD = 'alice-pw'; // test-only value
export const SERVICES = {
  aes128: 'HTTP/aes128.winlinux.test',
  aes256: 'HTTP/aes256.winlinux.test',
  loopback: 'HTTP/127.0.0.1',
} as const;

const TOOLS = ['krb5kdc', 'kdb5_util', 'kadmin.local', 'kinit', 'cc'] as const;
const EXTRA_PATH = ['/usr/sbin', '/sbin', '/usr/local/sbin'];

function findTool(name: string): string | null {
  const dirs = [...(process.env.PATH ?? '').split(':'), ...EXTRA_PATH];
  for (const dir of dirs) {
    if (!dir) continue;
    const p = join(dir, name);
    try {
      accessSync(p, constants.X_OK);
      return p;
    } catch {
      // keep looking
    }
  }
  return null;
}

// Throws a message naming the missing packages (Debian/Ubuntu names).
export function requireKdcTools(): Record<(typeof TOOLS)[number], string> {
  const found: Partial<Record<(typeof TOOLS)[number], string>> = {};
  const missing: string[] = [];
  for (const t of TOOLS) {
    const p = findTool(t);
    if (p) found[t] = p;
    else missing.push(t);
  }
  if (process.platform !== 'linux') missing.push(`(platform ${process.platform}: the harness links MIT libgssapi_krb5)`);
  if (missing.length) {
    throw new Error(
      `local KDC tests need ${missing.join(', ')}: apt-get install krb5-kdc krb5-admin-server krb5-user build-essential libkrb5-dev`,
    );
  }
  return found as Record<(typeof TOOLS)[number], string>;
}

async function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.on('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const addr = srv.address() as net.AddressInfo;
      srv.close(() => resolve(addr.port));
    });
  });
}

function waitForPort(port: number, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  return new Promise((resolve, reject) => {
    const attempt = () => {
      const s = net.connect(port, '127.0.0.1');
      s.once('connect', () => {
        s.destroy();
        resolve();
      });
      s.once('error', () => {
        s.destroy();
        if (Date.now() > deadline) reject(new Error(`KDC did not listen on ${port} within ${timeoutMs} ms`));
        else setTimeout(attempt, 100);
      });
    };
    attempt();
  });
}

export interface LocalKdc {
  readonly dir: string;
  readonly port: number;
  readonly keytab: string;
  // FILE: ccache holding alice's TGT.
  readonly ccache: string;
  // Environment for every krb5 client in this process and its children.
  readonly env: { KRB5_CONFIG: string; KRB5_KDC_PROFILE: string };
  // A krb5.conf that permits aes128-cts only, for an acceptor whose
  // context must use an aes128 subkey.
  readonly krb5ConfAes128: string;
  stop(): Promise<void>;
}

// Starts the KDC, creates the principals, exports the keytab and runs
// kinit for alice. Sets process.env.KRB5_CONFIG for this process (libkrb5
// reads it on first use), which is why this runs before any GSS call.
export async function startLocalKdc(): Promise<LocalKdc> {
  const tools = requireKdcTools();
  const dir = await mkdtemp(join(tmpdir(), 'winlinux-kdc-'));
  const port = await freePort();
  const krb5Conf = join(dir, 'krb5.conf');
  const krb5ConfAes128 = join(dir, 'krb5-aes128.conf');
  const kdcConf = join(dir, 'kdc.conf');
  const keytab = join(dir, 'http.keytab');
  const ccache = `FILE:${join(dir, 'ccache')}`;
  const libdefaults = [
      '[libdefaults]',
      `    default_realm = ${REALM}`,
      '    dns_lookup_realm = false',
      '    dns_lookup_kdc = false',
      '    dns_canonicalize_hostname = false',
      '    rdns = false',
      `    default_keytab_name = FILE:${keytab}`,
  ];
  const rest = [
      '[realms]',
      `    ${REALM} = {`,
      `        kdc = 127.0.0.1:${port}`,
      `        admin_server = 127.0.0.1:${port}`,
      '    }',
      '[domain_realm]',
      `    .winlinux.test = ${REALM}`,
      `    winlinux.test = ${REALM}`,
      '',
  ];
  await writeFile(krb5Conf, [...libdefaults, ...rest].join('\n'));
  // For the aes128 acceptor: RFC 4537 enctype negotiation in the AP-REQ
  // would otherwise give an aes256 acceptor subkey (the client offers it
  // and the server permits it), whatever the ticket session key is.
  await writeFile(
    krb5ConfAes128,
    [...libdefaults, '    permitted_enctypes = aes128-cts-hmac-sha1-96', ...rest].join('\n'),
  );
  await writeFile(
    kdcConf,
    [
      '[kdcdefaults]',
      `    kdc_listen = 127.0.0.1:${port}`,
      `    kdc_tcp_listen = 127.0.0.1:${port}`,
      '[realms]',
      `    ${REALM} = {`,
      `        database_name = ${join(dir, 'principal')}`,
      `        acl_file = ${join(dir, 'kadm5.acl')}`,
      `        key_stash_file = ${join(dir, 'stash')}`,
      '        max_life = 10h 0m 0s',
      '        master_key_type = aes256-cts',
      '        supported_enctypes = aes256-cts:normal aes128-cts:normal',
      '    }',
      '[logging]',
      `    kdc = FILE:${join(dir, 'kdc.log')}`,
      `    admin_server = FILE:${join(dir, 'kadmin.log')}`,
      `    default = FILE:${join(dir, 'krb5lib.log')}`,
      '',
    ].join('\n'),
  );
  await writeFile(join(dir, 'kadm5.acl'), '*/admin@WINLINUX.TEST *\n');
  const env = { KRB5_CONFIG: krb5Conf, KRB5_KDC_PROFILE: kdcConf };
  const childEnv = { ...process.env, ...env };
  const run = async (cmd: string, args: string[]) => {
    try {
      return await execFileAsync(cmd, args, { env: childEnv, encoding: 'utf8' });
    } catch (err) {
      const e = err as { stderr?: string; message: string };
      throw new Error(`${cmd} ${args.join(' ')}: ${(e.stderr || e.message).trim()}`);
    }
  };

  await run(tools.kdb5_util, ['-r', REALM, 'create', '-s', '-P', 'master-pw']);
  const kadmin = (q: string) => run(tools['kadmin.local'], ['-r', REALM, '-q', q]);
  await kadmin(`addprinc -pw ${PASSWORD} ${USER}`);
  await kadmin(`addprinc -randkey -e aes128-cts:normal ${SERVICES.aes128}`);
  // The KDC assumes every service supports aes256 unless told otherwise
  // (MIT dbentry_supports_enctype), so pin the ticket session key too.
  await kadmin(`setstr ${SERVICES.aes128} session_enctypes aes128-cts-hmac-sha1-96`);
  await kadmin(`addprinc -randkey -e aes256-cts:normal ${SERVICES.aes256}`);
  await kadmin(`addprinc -randkey -e aes256-cts:normal ${SERVICES.loopback}`);
  await kadmin(`ktadd -k ${keytab} -norandkey ${SERVICES.aes128} ${SERVICES.aes256} ${SERVICES.loopback}`);

  const kdc = spawn(tools.krb5kdc, ['-n', '-r', REALM], { env: childEnv, stdio: ['ignore', 'pipe', 'pipe'] });
  const kdcOutput: string[] = [];
  kdc.stdout?.on('data', (c: Buffer) => kdcOutput.push(c.toString()));
  kdc.stderr?.on('data', (c: Buffer) => kdcOutput.push(c.toString()));
  const stop = async () => {
    if (kdc.exitCode === null) {
      kdc.kill('SIGTERM');
      await new Promise<void>((resolve) => kdc.once('exit', () => resolve()));
    }
    if (process.env.KRB5_CONFIG === krb5Conf) delete process.env.KRB5_CONFIG;
    await rm(dir, { recursive: true, force: true });
  };
  try {
    await waitForPort(port, 15_000);
    // MIT kinit reads the password from stdin when stdin is not a tty.
    await new Promise<void>((resolve, reject) => {
      const child = execFile(tools.kinit, [`${USER}@${REALM}`], { env: { ...childEnv, KRB5CCNAME: ccache } }, (err, _out, stderr) => {
        if (err) reject(new Error(`kinit: ${(stderr || err.message).trim()}\nKDC output: ${kdcOutput.join('')}`));
        else resolve();
      });
      child.stdin?.end(`${PASSWORD}\n`);
    });
  } catch (err) {
    await stop();
    throw err;
  }
  process.env.KRB5_CONFIG = krb5Conf;
  return { dir, port, keytab, ccache, env, krb5ConfAes128, stop };
}

// Writes a keytab for the user alice (kadmin.local ktadd -norandkey, so the
// password stays valid) to <kdc.dir>/<name>, mode 0600, for the keytab
// sign-in test. Returns its path.
export async function exportUserKeytab(kdc: LocalKdc, name = 'alice.keytab'): Promise<string> {
  const tools = requireKdcTools();
  const file = join(kdc.dir, name);
  try {
    await execFileAsync(tools['kadmin.local'], ['-r', REALM, '-q', `ktadd -k ${file} -norandkey ${USER}`], {
      env: { ...process.env, ...kdc.env },
      encoding: 'utf8',
    });
  } catch (err) {
    const e = err as { stderr?: string; message: string };
    throw new Error(`kadmin.local ktadd: ${(e.stderr || e.message).trim()}`);
  }
  await chmod(file, 0o600);
  return file;
}

// --- The acceptor harness ---------------------------------------------

const harnessSource = join(dirname(fileURLToPath(import.meta.url)), '../../../test/kdc/acceptor.c');

// One build per KDC temp dir: the dir goes with its KDC (stop() removes
// it), and a later KDC in the same process gets its own binary.
const harnessBinaries = new Map<string, Promise<string>>();

// Compiles test/kdc/acceptor.c once per temp dir.
export function buildAcceptorHarness(dir: string): Promise<string> {
  let harnessBinary = harnessBinaries.get(dir);
  if (!harnessBinary) {
    harnessBinary = (async () => {
    const tools = requireKdcTools();
    const out = join(dir, 'acceptor');
    try {
      await execFileAsync(tools.cc, ['-O1', '-Wall', '-o', out, harnessSource, '-lgssapi_krb5'], { encoding: 'utf8' });
    } catch (err) {
      const e = err as { stderr?: string; message: string };
      throw new Error(`cannot build the acceptor harness: ${(e.stderr || e.message).trim()}`);
    }
    return out;
  })();
    harnessBinaries.set(dir, harnessBinary);
  }
  return harnessBinary;
}

export interface AcceptStep {
  token: Buffer | null;
  complete: boolean;
  // GSS_C_CHANNEL_BOUND_FLAG from the acceptor: the initiator's channel
  // bindings matched the acceptor's. Null when the library has no
  // such flag (MIT krb5 before 1.19).
  bound: boolean | null;
}

// One GSS acceptor process (one security context), driven over stdio.
export class Acceptor {
  private readonly lines: AsyncIterator<string>;
  private readonly proc: ChildProcess;

  private constructor(proc: ChildProcess) {
    this.proc = proc;
    this.lines = createInterface({ input: proc.stdout! })[Symbol.asyncIterator]();
  }

  static async start(kdc: LocalKdc, opts: { krb5Conf?: string } = {}): Promise<Acceptor> {
    const bin = await buildAcceptorHarness(kdc.dir);
    const proc = spawn(bin, [], {
      env: { ...process.env, ...kdc.env, ...(opts.krb5Conf ? { KRB5_CONFIG: opts.krb5Conf } : {}), KRB5_KTNAME: `FILE:${kdc.keytab}` },
      stdio: ['pipe', 'pipe', 'inherit'],
    });
    return new Acceptor(proc);
  }

  private async readLine(): Promise<string[]> {
    const r = await this.lines.next();
    if (r.done) throw new Error('acceptor harness exited');
    const words = r.value.split(' ');
    if (words[0] === 'error') throw new Error(`acceptor: ${r.value.slice(6)}`);
    return words;
  }

  private send(line: string): Promise<string[]> {
    this.proc.stdin!.write(`${line}\n`);
    return this.readLine();
  }

  // channelBindings: the application_data the acceptor expects (no
  // addresses), for example the tls-server-end-point binding of its own
  // certificate; the acceptor refuses an initiator whose bindings differ.
  async accept(token: Buffer, channelBindings?: Buffer): Promise<AcceptStep> {
    const cb = channelBindings ? ` ${channelBindings.toString('base64')}` : '';
    const [kind, value] = await this.send(`accept ${token.toString('base64')}${cb}`);
    if (kind !== 'token') throw new Error(`acceptor: unexpected reply ${kind}`);
    const [, done] = await this.readLine();
    const [, bound] = await this.readLine();
    return {
      token: value === '-' ? null : Buffer.from(value ?? '', 'base64'),
      complete: done === '1',
      bound: bound === '-' ? null : bound === '1',
    };
  }

  async unwrapIov(header: Buffer, data: Buffer): Promise<Buffer> {
    const [, value] = await this.send(`unwrap ${header.toString('base64')} ${data.toString('base64')}`);
    return Buffer.from(value ?? '', 'base64');
  }

  async wrapIov(plain: Buffer): Promise<{ header: Buffer; data: Buffer }> {
    const [, header, data] = await this.send(`wrap ${plain.toString('base64')}`);
    return { header: Buffer.from(header ?? '', 'base64'), data: Buffer.from(data ?? '', 'base64') };
  }

  // gss_unwrap of header || data: the addon's unwrapIov path.
  async unwrapToken(header: Buffer, data: Buffer): Promise<Buffer> {
    const [, value] = await this.send(`unwrap-token ${header.toString('base64')} ${data.toString('base64')}`);
    return Buffer.from(value ?? '', 'base64');
  }

  // gss_wrap: one RFC 4121 token with RRC 0 (the trailer at the end).
  async wrapPlain(plain: Buffer): Promise<Buffer> {
    const [, token] = await this.send(`wrap-plain ${plain.toString('base64')}`);
    return Buffer.from(token ?? '', 'base64');
  }

  // gss_wrap_iov HEADER | DATA | TRAILER: RRC 0, the trailer in its own
  // buffer, so header || data || trailer is the gss_wrap token.
  async wrapTrailer(plain: Buffer): Promise<{ header: Buffer; data: Buffer; trailer: Buffer }> {
    const [, header, data, trailer] = await this.send(`wrap-trailer ${plain.toString('base64')}`);
    return {
      header: Buffer.from(header ?? '', 'base64'),
      data: Buffer.from(data ?? '', 'base64'),
      trailer: Buffer.from(trailer ?? '', 'base64'),
    };
  }

  // The context mechanism as MIT prints it, for example "{ 1 3 6 1 5 5 2 }" (SPNEGO).
  async mech(): Promise<string> {
    const [, ...oid] = await this.send('mech');
    return oid.join(' ') || '-';
  }

  close(): void {
    this.proc.stdin?.end();
    this.proc.kill();
  }
}
