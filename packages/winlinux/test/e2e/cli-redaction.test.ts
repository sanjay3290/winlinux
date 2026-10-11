// The password must never reach argv, stdout or stderr.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { runCli, type CliResult } from '../helpers/cli.js';
import { startWinrmMock } from '../helpers/winrm-mock.js';

const SENTINEL = 'Redaction-Sentinel-Pw-9f3Q';
const USER = 'tester';
const NEEDLES = [
  SENTINEL,
  Buffer.from(SENTINEL, 'utf8').toString('base64'),
  Buffer.from(`${USER}:${SENTINEL}`, 'utf8').toString('base64'),
];

function assertClean(label: string, r: CliResult): void {
  for (const needle of NEEDLES) {
    assert.ok(!r.stdout.includes(needle), `${label}: stdout leaks ${needle}`);
    assert.ok(!r.stderr.includes(needle), `${label}: stderr leaks ${needle}`);
    assert.ok(!r.argv.some((a) => a.includes(needle)), `${label}: argv carries ${needle}`);
  }
}

async function deadPort(): Promise<number> {
  const server = net.createServer();
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = (server.address() as net.AddressInfo).port;
  await new Promise<void>((resolve) => server.close(() => resolve()));
  return port;
}

describe('password redaction', () => {
  it('password never appears in output', async () => {
    const ok = await startWinrmMock();
    const reject = await startWinrmMock({ reject401: true });
    const dead = await deadPort();
    try {
      const env = { WINLINUX_PASSWORD: SENTINEL };
      const cases: Array<[string, string[], number]> = [];
      for (const extra of [['--verbose'], ['--json'], ['--verbose', '--json']]) {
        const common = ['--auth', 'basic', '--tls', '--insecure', ...extra];
        cases.push(['success', ['run', ...common, '--winrm-port', String(ok.port), `${USER}@127.0.0.1`, 'hostname'], 4]);
        cases.push(['auth failure', ['run', ...common, '--winrm-port', String(reject.port), `${USER}@127.0.0.1`, 'hostname'], 2]);
        cases.push(['connection failure', ['run', ...common, '--winrm-port', String(dead), `${USER}@127.0.0.1`, 'hostname'], 3]);
        // NTLM without TLS: the provider handles the password itself.
        cases.push(['ntlm connection failure', ['run', '-a', 'ntlm', ...extra, '--winrm-port', String(dead), `${USER}@127.0.0.1`, 'x'], 3]);
        cases.push(['smb connection failure', ['ls', ...extra, '--smb-port', String(dead), `${USER}@127.0.0.1`, 'C$'], 3]);
      }
      for (const [label, args, code] of cases) {
        const r = await runCli(args, env);
        assert.equal(r.code, code, `${label} ${args.join(' ')}: ${r.stderr}`);
        assertClean(`${label} ${args.join(' ')}`, r);
      }
      // The mock did receive the Basic token, so the needle is real.
      assert.ok(ok.requests.some((q) => q.headers.authorization === `Basic ${NEEDLES[2]}`));
    } finally {
      await Promise.all([ok.close(), reject.close()]);
    }
  });
});
