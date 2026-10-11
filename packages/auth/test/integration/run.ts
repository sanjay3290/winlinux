// Live auth integration runner: `npm run test:integration -w @winlinux/auth`.
//
// Docker mode (default): start the Samba AD DC, wait until it is provisioned,
// then run two phases, each on this host and in a Linux (MIT krb5) node:22
// container on the DC's Docker network:
//   1. live.test.js with the DC default (server signing mandatory);
//   2. live-unsigned.test.js after `server signing = auto` + smbd reload.
// Then remove the containers.
// External mode: set WINLINUX_KDC_HOST (plus the vars live.test.ts reads and
// KRB5_CONFIG) to run live.test.js against a DC you started yourself.
//
// Nothing touches host config: no sudo, no /etc/hosts, no /etc/krb5.conf.
import { execFile, spawn } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { connect } from '@winlinux/smb2';
import { defaultKinitRunner } from '../../src/auth/kerberos.js';
import { NtlmAuthProvider } from '../../src/auth/ntlm/provider.js';

const execFileAsync = promisify(execFile);
const here = dirname(fileURLToPath(import.meta.url)); // <pkg>/dist-integration/test/integration
const pkgRoot = resolve(here, '../../..');
const repoRoot = resolve(pkgRoot, '../..');
const liveTest = join(here, 'live.test.js');
const liveUnsignedTest = join(here, 'live-unsigned.test.js');
const composeFile = join(pkgRoot, 'test/integration/docker-compose.yml');

const REALM = 'EXAMPLE.COM';
const DC_FQDN = 'dc1.example.com';
const USER = 'Administrator';
const PASS = 'Passw0rd!'; // test-only value, set in docker-compose.yml

function run(cmd: string, args: string[], env: NodeJS.ProcessEnv = process.env): Promise<number> {
  return new Promise((resolveRun) => {
    const child = spawn(cmd, args, { env, stdio: 'inherit' });
    child.on('close', (code) => resolveRun(code ?? 1));
    child.on('error', (err) => {
      console.error(`${cmd}: ${err.message}`);
      resolveRun(1);
    });
  });
}

async function docker(args: string[], env: NodeJS.ProcessEnv = process.env): Promise<string> {
  try {
    const { stdout } = await execFileAsync('docker', args, { env, encoding: 'utf8' });
    return stdout.trim();
  } catch (error) {
    const stderr = (error as { stderr?: string }).stderr ?? (error as Error).message;
    throw new Error(`docker ${args.join(' ')} failed: ${stderr.trim()}`);
  }
}

function krb5Conf(kdc: string): string {
  return [
    '[libdefaults]',
    `    default_realm = ${REALM}`,
    '    dns_lookup_realm = false',
    '    dns_lookup_kdc = false',
    '    dns_canonicalize_hostname = false',
    '    rdns = false',
    '[realms]',
    `    ${REALM} = {`,
    `        kdc = ${kdc}`,
    '    }',
    '[domain_realm]',
    `    .${REALM.toLowerCase()} = ${REALM}`,
    `    ${REALM.toLowerCase()} = ${REALM}`,
    '',
  ].join('\n');
}

function hostPort(mapping: string): number {
  // `docker port` prints e.g. "127.0.0.1:23888" (first line wins).
  const first = mapping.split('\n')[0];
  return Number(first.slice(first.lastIndexOf(':') + 1));
}

// The DC is ready when a real kinit succeeds and SMB answers an NTLM logon.
async function waitForDc(env: NodeJS.ProcessEnv, smbPort: number, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  const dir = await mkdtemp(join(tmpdir(), 'winlinux-wait-cc-'));
  let last = '';
  try {
    for (;;) {
      try {
        await defaultKinitRunner([`${USER}@${REALM}`], PASS, {
          ...env,
          KRB5CCNAME: `FILE:${join(dir, 'ccache')}`,
        });
        const session = await connect({
          host: '127.0.0.1',
          port: smbPort,
          authProvider: new NtlmAuthProvider(),
          credentials: { username: USER, password: PASS, domain: REALM.split('.')[0] },
          requestTimeoutMs: 5000,
        });
        await session.close();
        return;
      } catch (err) {
        last = (err as Error).message;
      }
      if (Date.now() > deadline) throw new Error(`DC not ready after ${timeoutMs} ms: ${last}`);
      await new Promise((r) => setTimeout(r, 3000));
    }
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

// Linux leg: MIT krb5 in node:22 on the DC network; the DC is dc1.example.com:88/445.
// Setup runs once; each phase then runs one test file with `docker exec`.
function linuxSetupScript(): string {
  return [
    'set -e',
    'apt-get update -qq >/dev/null',
    'DEBIAN_FRONTEND=noninteractive apt-get install -y -qq krb5-user libkrb5-dev >/dev/null',
    'klist -V || true',
    'mkdir -p /work',
    // build/ holds the host's native addon; npm ci rebuilds it for Linux.
    'tar -C /src --exclude=node_modules --exclude=dist --exclude=dist-test --exclude=dist-integration --exclude=build --exclude=.git -cf - . | tar -C /work -xf -',
    'cd /work',
    'npm ci --no-audit --no-fund --loglevel=error',
    'npm run build -w @winlinux/smb2 --silent',
    'npm run build -w @winlinux/krb-session-key --silent',
    'cd packages/auth',
    'npx tsc -p tsconfig.integration.json',
    `printf '%s' "$KRB5_CONF_TEXT" > /tmp/krb5.conf`,
  ].join('\n');
}

function linuxTestScript(file: string): string {
  return `cd /work/packages/auth && KRB5_CONFIG=/tmp/krb5.conf node --test dist-integration/test/integration/${file}`;
}

// Samba's AD DC default is `server signing = mandatory`. For phase 2, set
// `auto` (signing offered, not required) in [global] and reload smbd; new
// connections use it. Only the test container changes.
async function allowUnsignedSmb(container: string): Promise<void> {
  await docker([
    'exec', container, 'sh', '-c',
    'sed -i "/^\\[global\\]/a\\\tserver signing = auto" /etc/samba/smb.conf && smbcontrol smbd reload-config',
  ]);
  const line = await docker(['exec', container, 'grep', '-m1', 'server signing', '/etc/samba/smb.conf']);
  console.log(`# DC smb.conf now has: ${line.trim()}`);
}

async function dockerMode(): Promise<number> {
  const project = process.env.COMPOSE_PROJECT_NAME ?? 'winlinux-auth-live';
  const container = process.env.WINLINUX_DC_CONTAINER ?? `${project}-dc`;
  const network = process.env.WINLINUX_DC_NETWORK ?? `${project}-net`;
  const linuxImage = process.env.WINLINUX_LINUX_IMAGE ?? 'node:22';
  // Default: random loopback host ports, so parallel runs cannot collide.
  const composeEnv: NodeJS.ProcessEnv = {
    ...process.env,
    COMPOSE_PROJECT_NAME: project,
    WINLINUX_DC_CONTAINER: container,
    WINLINUX_DC_NETWORK: network,
    WINLINUX_KDC_PORT: process.env.WINLINUX_KDC_PORT ?? '127.0.0.1:',
    WINLINUX_LDAP_PORT: process.env.WINLINUX_LDAP_PORT ?? '127.0.0.1:',
    WINLINUX_SMB_PORT: process.env.WINLINUX_SMB_PORT ?? '127.0.0.1:',
  };
  const compose = (args: string[]) => docker(['compose', '-f', composeFile, ...args], composeEnv);

  await docker(['info', '--format', '{{.ServerVersion}}']);
  const tmp = await mkdtemp(join(tmpdir(), 'winlinux-live-'));
  const results: Array<[string, number]> = [];
  try {
    await compose(['down', '-v', '--remove-orphans']);
    console.log(`# starting Samba AD DC: project=${project} container=${container}`);
    await compose(['up', '-d']);
    const kdcPort = hostPort(await docker(['port', container, '88/tcp']));
    const smbPort = hostPort(await docker(['port', container, '445/tcp']));
    console.log(`# DC ports on 127.0.0.1: kdc=${kdcPort} smb=${smbPort}`);

    const krb5Path = join(tmp, 'krb5.conf');
    await writeFile(krb5Path, krb5Conf(`tcp/127.0.0.1:${kdcPort}`));
    const hostEnv: NodeJS.ProcessEnv = {
      ...process.env,
      KRB5_CONFIG: krb5Path,
      WINLINUX_KDC_HOST: DC_FQDN,
      WINLINUX_REALM: REALM,
      WINLINUX_USER: USER,
      WINLINUX_PASSWORD: PASS,
      WINLINUX_SMB_HOST: '127.0.0.1',
      WINLINUX_SMB_PORT: String(smbPort),
    };
    delete hostEnv.KRB5CCNAME;

    console.log('# waiting for the DC to finish provisioning');
    await waitForDc(hostEnv, smbPort, 300_000);

    const linux = `${project}-linux`;
    console.log(`# linux leg setup: ${linuxImage} on network ${network}`);
    await docker([
      'run', '-d', '--name', linux, '--network', network,
      '-v', `${repoRoot}:/src:ro`,
      '-e', `KRB5_CONF_TEXT=${krb5Conf(`${DC_FQDN}:88`)}`,
      '-e', `WINLINUX_KDC_HOST=${DC_FQDN}`,
      '-e', `WINLINUX_REALM=${REALM}`,
      '-e', `WINLINUX_USER=${USER}`,
      '-e', `WINLINUX_PASSWORD=${PASS}`,
      '-e', `WINLINUX_SMB_HOST=${DC_FQDN}`,
      '-e', 'WINLINUX_SMB_PORT=445',
      linuxImage, 'sleep', 'infinity',
    ]);
    const linuxReady = (await run('docker', ['exec', linux, 'bash', '-c', linuxSetupScript()])) === 0;
    const linuxRun = async (file: string) =>
      linuxReady ? run('docker', ['exec', linux, 'bash', '-c', linuxTestScript(file)]) : 1;

    // The addon's own tests on Linux: lazy dlopen of libgssapi_krb5 and the
    // clear error when it is missing.
    console.log('# linux: @winlinux/krb-session-key unit tests (dlopen, missing-library error)');
    results.push([
      'linux (node:22, MIT krb5), krb-session-key addon',
      linuxReady
        ? await run('docker', ['exec', linux, 'bash', '-c', 'cd /work/packages/krb-session-key && node --test "dist/test/**/*.test.js"'])
        : 1,
    ]);

    console.log(`# phase 1, signing required: host (${process.platform}) live.test.js`);
    results.push([`host (${process.platform}), signing required`, await run(process.execPath, ['--test', liveTest], hostEnv)]);
    console.log('# phase 1, signing required: linux live.test.js');
    results.push(['linux (node:22, MIT krb5), signing required', await linuxRun('live.test.js')]);

    await allowUnsignedSmb(container);
    console.log(`# phase 2, signing not required: host (${process.platform}) live-unsigned.test.js`);
    results.push([
      `host (${process.platform}), signing not required`,
      await run(process.execPath, ['--test', liveUnsignedTest], hostEnv),
    ]);
    console.log('# phase 2, signing not required: linux live-unsigned.test.js');
    results.push(['linux (node:22, MIT krb5), signing not required', await linuxRun('live-unsigned.test.js')]);
  } finally {
    await docker(['rm', '-f', `${project}-linux`]).catch(() => undefined);
    await compose(['down', '-v', '--remove-orphans']).catch((err: Error) => {
      console.error(`# cleanup failed: ${err.message}`);
    });
    await rm(tmp, { recursive: true, force: true });
  }
  for (const [leg, code] of results) console.log(`# ${leg}: ${code === 0 ? 'PASS' : `FAIL (exit ${code})`}`);
  return results.length === 5 && results.every(([, code]) => code === 0) ? 0 : 1;
}

async function main(): Promise<number> {
  if (process.env.WINLINUX_KDC_HOST) {
    console.log('# external mode: WINLINUX_KDC_HOST is set, running live.test.js only');
    return run(process.execPath, ['--test', liveTest]);
  }
  return dockerMode();
}

main().then(
  (code) => process.exit(code),
  (err: Error) => {
    console.error(`FAIL: ${err.message}`);
    process.exit(1);
  },
);
