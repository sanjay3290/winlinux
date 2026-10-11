// Live check against a real Windows Server (needs a Windows Server test host;
// see packages/winrm/test/live/README.md).
// Not part of test:live. Run: npm run test:live:windows -w winlinux
//
//   WINLINUX_LIVE_HOST   server name or address (required)
//   WINLINUX_LIVE_USER   [DOMAIN\]user (required)
//   WINLINUX_PASSWORD    password (required unless auth is kerberos with a ticket cache)
//   WINLINUX_LIVE_AUTH   negotiate (default) | ntlm | kerberos | basic
//   WINLINUX_LIVE_TLS    0 (default) | 1. The defaults run WinRM as NTLM over HTTP;
//                        negotiate and kerberos on WinRM need 1. kerberos with 0 exits 1.
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import type { Mechanism } from '../../dist/index.js';
import { connect, WinLinuxUsageError } from '../../dist/index.js';
import { runCli } from '../helpers/cli.js';

const env = process.env;
const host = env.WINLINUX_LIVE_HOST;
const userSpec = env.WINLINUX_LIVE_USER;
if (!host || !userSpec) {
  process.stderr.write(
    'windows live check needs WINLINUX_LIVE_HOST and WINLINUX_LIVE_USER ([DOMAIN\\]user), plus WINLINUX_PASSWORD;\n' +
      'optional WINLINUX_LIVE_AUTH (negotiate|ntlm|kerberos|basic, default negotiate) and WINLINUX_LIVE_TLS (0|1, default 0)\n',
  );
  process.exit(2);
}
const auth = (env.WINLINUX_LIVE_AUTH ?? 'negotiate') as Mechanism;
const tls = env.WINLINUX_LIVE_TLS === '1';
const slash = userSpec.indexOf('\\');
const domain = slash === -1 ? undefined : userSpec.slice(0, slash);
const username = slash === -1 ? userSpec : userSpec.slice(slash + 1);
const password = env.WINLINUX_PASSWORD || undefined;

const sha256 = (file: string) => crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
let failures = 0;
async function scenario(name: string, fn: () => Promise<string>): Promise<void> {
  try {
    process.stdout.write(`ok   ${name}: ${await fn()}\n`);
  } catch (err) {
    failures += 1;
    process.stdout.write(`FAIL ${name}: ${(err as Error).name}: ${(err as Error).message}\n`);
    if (err instanceof WinLinuxUsageError) process.exitCode = 1;
  }
}

const client = await connect(host, {
  username,
  password,
  domain,
  auth,
  useTicketCache: password === undefined,
  winrm: { tls },
});
const work = fs.mkdtempSync(path.join(os.tmpdir(), 'winlinux-windows-'));
try {
  await scenario('run whoami', async () => (await client.run('whoami')).stdout.trim());
  await scenario('runPowerShell Get-Date', async () => (await client.runPowerShell('Get-Date -Format o')).stdout.trim());
  await scenario('readEventLog System max 5', async () => {
    const events = await client.readEventLog({ logName: 'System', maxEvents: 5 });
    return `${events.length} events`;
  });
  await scenario('listShares has C$', async () => {
    const shares = await client.listShares();
    if (!shares.some((s) => s.name === 'C$')) throw new Error(`no C$ in ${shares.map((s) => s.name).join(', ')}`);
    return shares.map((s) => s.name).join(', ');
  });
  await scenario('put/get SHA-256 round trip on C$\\Windows\\Temp', async () => {
    const source = path.join(work, 'up.bin');
    const back = path.join(work, 'down.bin');
    fs.writeFileSync(source, crypto.randomBytes(1024 * 1024));
    const remote = `Windows/Temp/winlinux-live-${process.pid}.bin`;
    await client.put(source, 'C$', remote);
    await client.get('C$', remote, back);
    if (sha256(source) !== sha256(back)) throw new Error('SHA-256 differs');
    return sha256(back);
  });
  await scenario('cli run hostname', async () => {
    const args = ['run', '-a', auth, ...(tls ? ['--tls'] : []), ...(password === undefined ? ['-K'] : [])];
    const r = await runCli([...args, `${userSpec}@${host}`, 'hostname'], password === undefined ? {} : { WINLINUX_PASSWORD: password });
    if (r.code !== 0) throw new Error(`exit ${r.code}: ${r.stderr.trim()}`);
    return r.stdout.trim();
  });
} finally {
  await client.close();
  fs.rmSync(work, { recursive: true, force: true });
}
if (failures > 0 && process.exitCode === undefined) process.exitCode = 1;
process.stdout.write(`${failures === 0 ? 'all scenarios passed' : `${failures} scenario(s) failed`}\n`);
