// Spawns the built winlinux binary against the WinRM mock from @winlinux/winrm.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { spawn } from 'node:child_process';
import { kerberosSessionKeyAvailable } from '@winlinux/auth';
import { CLI, EMPTY_HOME, runCli } from '../helpers/cli.js';
import { actionOf } from '../../../winrm/dist/test/helpers/mock-server.js';
import { doneReceive, fixture, startWinrmMock } from '../helpers/winrm-mock.js';
import { countingListener } from '../helpers/listeners.js';

const SENTINEL = 'Cli-Winrm-Sentinel-Pw-41';
const ENV = { WINLINUX_PASSWORD: SENTINEL };
const TARGET = 'tester@127.0.0.1';

// The shell prints its prompt even without a TTY; drop it to see the output.
const unprompted = (stdout: string) => stdout.replaceAll(`winlinux ${TARGET}> `, '');

function tlsFlags(port: number): string[] {
  return ['--auth', 'basic', '--tls', '--insecure', '--winrm-port', String(port)];
}

async function freePort(): Promise<number> {
  const server = net.createServer();
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = (server.address() as net.AddressInfo).port;
  await new Promise<void>((resolve) => server.close(() => resolve()));
  return port;
}

describe('cli against the winrm mock', () => {
  it('run prints remote stdout and exits 4 on a non-zero remote exit', async () => {
    const mock = await startWinrmMock();
    try {
      const r = await runCli(['run', ...tlsFlags(mock.port), TARGET, 'hostname'], ENV);
      assert.equal(r.code, 4, r.stderr);
      assert.equal(r.stdout, 'world');
      assert.match(r.stderr, /winlinux: remote command exited with code 3/);
    } finally {
      await mock.close();
    }
  });

  it('run exits 0 on a zero remote exit and passes dash args after --', async () => {
    const mock = await startWinrmMock({ receive: doneReceive('fine\n', 0) });
    try {
      const r = await runCli(['run', ...tlsFlags(mock.port), TARGET, '--', 'ipconfig', '-all'], ENV);
      assert.equal(r.code, 0, r.stderr);
      assert.equal(r.stdout, 'fine\n');
      const command = mock.requests.map((q) => q.body.toString('utf8')).find((b) => b.includes('<rsp:Command>'));
      assert.ok(command?.includes('<rsp:Command>ipconfig</rsp:Command>'), command);
      assert.ok(command?.includes('<rsp:Arguments>-all</rsp:Arguments>'), command);
    } finally {
      await mock.close();
    }
  });

  it('run --json prints stdout, stderr and exitCode', async () => {
    const mock = await startWinrmMock({ receive: doneReceive('out', 2, 'bad') });
    try {
      const r = await runCli(['run', ...tlsFlags(mock.port), '--json', TARGET, 'cmd'], ENV);
      assert.equal(r.code, 4);
      assert.deepEqual(JSON.parse(r.stdout), { stdout: 'out', stderr: 'bad', exitCode: 2 });
    } finally {
      await mock.close();
    }
  });

  it('run: Ctrl+C aborts the remote command with Signal and Delete, then exits 130', async () => {
    const mock = await startWinrmMock({ hangReceive: true });
    try {
      const child = spawn(process.execPath, [CLI, 'run', ...tlsFlags(mock.port), TARGET, '--', 'ping', '-t', 'localhost'], {
        env: { PATH: process.env.PATH, NODE_NO_WARNINGS: '1', HOME: EMPTY_HOME, ...ENV },
        stdio: ['pipe', 'pipe', 'pipe'],
      });
      let stderr = '';
      child.stderr.on('data', (d: Buffer) => (stderr += d.toString('utf8')));
      const exited = new Promise<number | null>((resolve) => child.on('close', (code) => resolve(code)));
      const actions = () => mock.requests.map((q) => actionOf(q.body));
      const deadline = Date.now() + 10_000;
      while (!actions().includes('Receive')) {
        if (Date.now() > deadline) throw new Error(`no Receive seen; stderr: ${stderr}`);
        await new Promise((resolve) => setTimeout(resolve, 10));
      }
      child.kill('SIGINT');
      const code = await exited;
      assert.equal(code, 130, stderr);
      assert.match(stderr, /interrupted; closing/);
      const after = actions().slice(actions().indexOf('Receive') + 1);
      assert.deepEqual(after, ['Signal', 'Delete']);
    } finally {
      await mock.close();
    }
  });

  it('shell: cd persists across lines and a failing remote command sets the exit status', async () => {
    // One Receive per remote command: the default-directory query, the cd
    // check (prints the directory), dir in C:\Windows (exit 0), hostname (exit 3).
    const mock = await startWinrmMock({
      receive: (command) =>
        command.includes('<rsp:Command>cd</rsp:Command>')
          ? doneReceive('C:\\Users\\tester\r\n', 0)
          : command.includes('<rsp:Arguments>cd</rsp:Arguments>')
            ? doneReceive('C:\\Windows\r\n', 0)
            : command.includes('win.ini')
              ? doneReceive('win.ini\r\n', 0)
              : doneReceive('srv\r\n', 3),
    });
    try {
      const r = await runCli([...tlsFlags(mock.port), TARGET], ENV, 'cd C:\\Windows\ndir /b win.ini\nhostname\n');
      assert.equal(r.code, 4, r.stderr);
      assert.equal(unprompted(r.stdout), 'win.ini\r\nsrv\r\n');
      assert.match(r.stderr, /winlinux: remote command exited with code 3/);
      const bodies = mock.requests.map((q) => q.body.toString('utf8'));
      const commands = bodies.filter((b) => b.includes('<rsp:Command>'));
      assert.equal(commands.length, 4);
      assert.ok(commands[0]!.includes('<rsp:CommandLine><rsp:Command>cd</rsp:Command></rsp:CommandLine>'), commands[0]);
      assert.ok(commands[1]!.includes('<rsp:Command>cmd</rsp:Command><rsp:Arguments>/c</rsp:Arguments><rsp:Arguments>cd</rsp:Arguments>'), commands[1]);
      assert.ok(commands[2]!.includes('<rsp:Command>dir</rsp:Command><rsp:Arguments>/b</rsp:Arguments><rsp:Arguments>win.ini</rsp:Arguments>'), commands[2]);
      assert.ok(commands[3]!.includes('<rsp:Command>hostname</rsp:Command>'), commands[3]);
      // The directory travels on Create, not in the command line: none for the
      // query, C:\Windows for the check and the two lines after it.
      const creates = bodies.filter((b) => b.includes('<rsp:Shell')).map((b) => /<rsp:WorkingDirectory>([^<]*)</.exec(b)?.[1]);
      assert.deepEqual(creates, [undefined, 'C:\\Windows', 'C:\\Windows', 'C:\\Windows']);
    } finally {
      await mock.close();
    }
  });

  it('shell: a cd that the remote rejects keeps the old directory and exits 4', async () => {
    // The check opens a shell in the directory and prints it; the mock
    // answers `cd` with the default directory, as a server that fell back would.
    const mock = await startWinrmMock({ receive: doneReceive('C:\\Users\\tester\r\n', 0) });
    try {
      const r = await runCli([...tlsFlags(mock.port), TARGET], ENV, 'cd nope\ncd\n');
      assert.equal(r.code, 4, r.stderr);
      assert.equal(unprompted(r.stdout), 'C:\\Users\\tester\n');
      assert.equal(r.stderr, 'winlinux: cd: no such directory: C:\\Users\\tester\\nope\n');
    } finally {
      await mock.close();
    }
  });

  it('logs prints a table from events.json', async () => {
    const mock = await startWinrmMock({ receive: doneReceive(fixture('events.json')) });
    try {
      const r = await runCli(['logs', ...tlsFlags(mock.port), '--max', '5', '--level', '2', TARGET], ENV);
      assert.equal(r.code, 0, r.stderr);
      const lines = r.stdout.trimEnd().split('\n');
      assert.match(lines[0] ?? '', /^TimeCreated\s+Level\s+Id\s+Provider\s+Message$/);
      assert.equal(lines.length, 3);
      assert.match(lines[1] ?? '', /Information\s+7036\s+Service Control Manager\s+The Windows Update service entered the running state\./);
      assert.match(lines[2] ?? '', /Error\s+10016\s+Microsoft-Windows-DistributedCOM\s+Access denied\./);
      const script = mock.requests.map((q) => q.body.toString('utf8')).find((b) => b.includes('<rsp:Command>'));
      assert.ok(script?.includes('powershell.exe'), 'event log query runs PowerShell');
    } finally {
      await mock.close();
    }
  });

  it('logs --json prints EventRecord[]', async () => {
    const mock = await startWinrmMock({ receive: doneReceive(fixture('events.json')) });
    try {
      const r = await runCli(['logs', ...tlsFlags(mock.port), '--json', TARGET], ENV);
      assert.equal(r.code, 0, r.stderr);
      const events = JSON.parse(r.stdout) as Array<Record<string, unknown>>;
      assert.equal(events.length, 2);
      assert.deepEqual(Object.keys(events[0] ?? {}).sort(), ['id', 'level', 'message', 'provider', 'timeCreated']);
      assert.equal(events[0]?.id, 7036);
    } finally {
      await mock.close();
    }
  });

  it('services prints a table from services.json and --json the ServiceInfo[]', async () => {
    const mock = await startWinrmMock({ receive: doneReceive(fixture('services.json')) });
    try {
      const r = await runCli(['services', ...tlsFlags(mock.port), TARGET], ENV);
      assert.equal(r.code, 0, r.stderr);
      const lines = r.stdout.trimEnd().split('\n');
      assert.match(lines[0] ?? '', /^Name\s+Status\s+StartType\s+DisplayName$/);
      assert.match(lines[1] ?? '', /^wuauserv\s+Running\s+Manual\s+Windows Update$/);
      assert.match(lines[2] ?? '', /^Spooler\s+Stopped\s+Automatic\s+Print Spooler$/);
      assert.equal(lines.length, 3);
      const script = mock.requests.map((q) => q.body.toString('utf8')).find((b) => b.includes('<rsp:Command>'));
      assert.ok(script?.includes('powershell.exe'), 'service query runs PowerShell');
    } finally {
      await mock.close();
    }
    const filtered = await startWinrmMock({ receive: doneReceive(fixture('services.json')) });
    try {
      const r = await runCli(['services', ...tlsFlags(filtered.port), '--json', '--status', 'stopped', TARGET], ENV);
      assert.equal(r.code, 0, r.stderr);
      assert.deepEqual(JSON.parse(r.stdout), [{ name: 'Spooler', displayName: 'Print Spooler', status: 'Stopped', startType: 'Automatic' }]);
      // The filter stays on the client: no request body carries it.
      assert.ok(!filtered.requests.some((q) => q.body.toString('utf8').includes('stopped')));
    } finally {
      await filtered.close();
    }
  });

  it('ps --json prints ProcessInfo[] with a PowerShell 5.1 \\/Date(ms)\\/ start time as ISO', async () => {
    // What ConvertTo-Json writes on Windows PowerShell 5.1 for a DateTime.
    const ps51 = '[{"Id":4,"ProcessName":"System","CPU":1.5,"WS":4096,"StartTime":"\\/Date(1791551154213)\\/"},' +
      '{"Id":9999,"ProcessName":"exited","CPU":null,"WS":0,"StartTime":null}]';
    const mock = await startWinrmMock({ receive: doneReceive(ps51) });
    try {
      const r = await runCli(['ps', ...tlsFlags(mock.port), '--json', TARGET], ENV);
      assert.equal(r.code, 0, r.stderr);
      assert.deepEqual(JSON.parse(r.stdout), [
        { id: 4, name: 'System', cpuSeconds: 1.5, workingSetBytes: 4096, startTime: new Date(1791551154213).toISOString() },
        { id: 9999, name: 'exited', cpuSeconds: null, workingSetBytes: 0, startTime: null },
      ]);
    } finally {
      await mock.close();
    }
    const table = await startWinrmMock({ receive: doneReceive(fixture('processes.json')) });
    try {
      const r = await runCli(['ps', ...tlsFlags(table.port), '--name', 'sys', TARGET], ENV);
      assert.equal(r.code, 0, r.stderr);
      const lines = r.stdout.trimEnd().split('\n');
      assert.match(lines[0] ?? '', /^PID\s+Name\s+CPU\(s\)\s+WS\s+StartTime$/);
      assert.match(lines[1] ?? '', /^4\s+System\s+123\.45\s+8192\s+2026-09-11T10:24:35$/);
      assert.equal(lines.length, 2, '--name filters out the exited process');
    } finally {
      await table.close();
    }
  });

  it('unreachable winrm port exits 3', async () => {
    const port = await freePort();
    const r = await runCli(['run', ...tlsFlags(port), TARGET, 'hostname'], ENV);
    assert.equal(r.code, 3, r.stderr);
    assert.match(r.stderr, /winlinux: WinLinuxConnectionError: winrm connection failed for 127\.0\.0\.1:\d+: .*ECONNREFUSED/);
    assert.equal(r.stdout, '');
  });

  it('rejected basic auth exits 2', async () => {
    const mock = await startWinrmMock({ reject401: true });
    try {
      const r = await runCli(['run', ...tlsFlags(mock.port), TARGET, 'hostname'], ENV);
      assert.equal(r.code, 2, r.stderr);
      assert.match(r.stderr, /winlinux: WinLinuxAuthError: winrm authentication failed/);
    } finally {
      await mock.close();
    }
  });

  it('basic without --tls exits 1', async () => {
    const listener = await countingListener('reset');
    try {
      const r = await runCli(['run', '--auth', 'basic', '--winrm-port', String(listener.port), TARGET, 'hostname'], ENV);
      assert.equal(r.code, 1, r.stderr);
      assert.match(r.stderr, /winlinux: WinLinuxUsageError: winrm setup failed .*plain HTTP/);
      assert.equal(listener.count(), 0);
    } finally {
      await listener.close();
    }
  });

  it('kerberos without --tls: refused before any socket without the addon, otherwise attempted', async () => {
    const listener = await countingListener('reset');
    try {
      // TARGET is an IP address: --krb-hostname keeps Kerberos allowed.
      const r = await runCli(
        ['run', '-a', 'kerberos', '-K', '--krb-hostname', 'server.example.test', '--winrm-port', String(listener.port), TARGET, 'hostname'],
        {},
      );
      if (await kerberosSessionKeyAvailable()) {
        // The addon supplies the gss_wrap_iov split, so the plan allows
        // Kerberos over HTTP. There is no ticket cache in this test, so the
        // Kerberos step fails and that surfaces as an auth error (exit 2),
        // never as the usage refusal.
        assert.equal(r.code, 2, r.stderr);
        assert.match(r.stderr, /winlinux: WinLinuxAuthError: winrm authentication failed/);
        assert.doesNotMatch(r.stderr, /Kerberos over plain HTTP is not supported/);
      } else {
        assert.equal(r.code, 1, r.stderr);
        assert.match(r.stderr, /Kerberos over plain HTTP is not supported; use --tls/);
        assert.equal(listener.count(), 0);
      }
    } finally {
      await listener.close();
    }
  });

  it('kerberos against an IP address exits 1 before any socket, unless --krb-hostname names the server', async () => {
    const listener = await countingListener('reset');
    try {
      for (const args of [
        ['run', '-a', 'kerberos', '-K', '--winrm-port', String(listener.port), TARGET, 'hostname'],
        ['run', '-K', '--winrm-port', String(listener.port), TARGET, 'hostname'], // negotiate without a password
        ['ls', '-a', 'kerberos', '--smb-port', String(listener.port), TARGET, 'C$'],
      ]) {
        const r = await runCli(args, ENV);
        assert.equal(r.code, 1, r.stderr);
        assert.equal(
          r.stderr,
          "winlinux: WinLinuxUsageError: Kerberos needs the server's DNS name, not an IP address (127.0.0.1); use the FQDN, --krb-hostname <fqdn>, or -a ntlm\n",
        );
      }
      const bad = await runCli(['run', '-a', 'kerberos', '--krb-hostname', '127.0.0.1', '--winrm-port', String(listener.port), TARGET, 'hostname'], ENV);
      assert.equal(bad.code, 1, bad.stderr);
      assert.match(bad.stderr, /kerberosHostname must be the server's DNS name, not 127\.0\.0\.1/);
      assert.equal(listener.count(), 0);
      // negotiate with a password falls back to NTLM, so the IP is allowed
      // and the connection is attempted (the listener resets it: exit 3).
      const ntlm = await runCli(['run', '--winrm-port', String(listener.port), TARGET, 'hostname'], ENV);
      assert.equal(ntlm.code, 3, ntlm.stderr);
      assert.equal(listener.count(), 1);
    } finally {
      await listener.close();
    }
  });

  it('missing password without a TTY exits 1', async () => {
    const r = await runCli(['run', TARGET, 'hostname'], {});
    assert.equal(r.code, 1);
    assert.equal(r.stderr, 'winlinux: WinLinuxUsageError: password required: set WINLINUX_PASSWORD, run in a terminal, or use -K\n');
  });

  it('usage errors exit 1: unknown flag, bad port, host:port', async () => {
    for (const args of [
      ['run', '-k', TARGET, 'x'],
      ['run', '--winrm-port', '70000', TARGET, 'x'],
      ['run', 'tester@host:5985', 'x'],
      ['ls', '--max', '3', TARGET, 'C$'],
      ['logs', '--since', 'not-a-date', TARGET],
    ]) {
      const r = await runCli(args, ENV);
      assert.equal(r.code, 1, `${args.join(' ')}: ${r.stderr}`);
    }
  });

  it('--help and --version exit 0', async () => {
    const help = await runCli(['--help']);
    assert.equal(help.code, 0);
    assert.match(help.stdout, /^Usage:/);
    const version = await runCli(['-V']);
    assert.equal(version.code, 0);
    assert.equal(version.stdout, '1.0.0\n');
  });

  it('put with a missing local file exits 1 naming the local path and never opens SMB', async () => {
    const smb = await countingListener('reset');
    try {
      const r = await runCli(['put', '--smb-port', String(smb.port), TARGET, '/no/such/local.file', 'C$/x.txt'], ENV);
      assert.equal(r.code, 1, r.stderr);
      assert.match(r.stderr, /^winlinux: WinLinuxUsageError: put: local file \/no\/such\/local\.file: no such file$/m);
      assert.equal(smb.count(), 0);
    } finally {
      await smb.close();
    }
  });

  it('get to a missing directory (trailing slash) exits 1 and never opens SMB', async () => {
    const smb = await countingListener('reset');
    try {
      const r = await runCli(['get', '--smb-port', String(smb.port), TARGET, 'C$/x.txt', '/no/such/dir/'], ENV);
      assert.equal(r.code, 1, r.stderr);
      assert.match(r.stderr, /WinLinuxUsageError: no such directory: \/no\/such\/dir\//);
      assert.equal(smb.count(), 0);
    } finally {
      await smb.close();
    }
  });
});
