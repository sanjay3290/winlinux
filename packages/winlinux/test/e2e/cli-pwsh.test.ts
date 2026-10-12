// `winlinux pwsh -c` end to end: the built CLI against the fake PSRP
// endpoint of @winlinux/winrm over HTTPS + Basic.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { CLI, EMPTY_HOME, runCli } from '../helpers/cli.js';
import { startFakePsrp, type FakePsrp } from '../../../winrm/dist/test/helpers/fake-psrp.js';

const USER = 'tester';
const SENTINEL = 'Cli-Pwsh-Sentinel-Pw-77';
const ENV = { WINLINUX_PASSWORD: SENTINEL };
const TARGET = `${USER}@127.0.0.1`;

const flags = (port: number) => ['--auth', 'basic', '--tls', '--insecure', '--winrm-port', String(port)];

async function withFake(fn: (fake: FakePsrp) => Promise<void>): Promise<void> {
  const fake = await startFakePsrp({ tls: true, username: USER, password: SENTINEL });
  try {
    await fn(fake);
  } finally {
    await fake.close();
  }
}

function interruptWhen(args: string[], ready: () => boolean): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [CLI, ...args], { env: { PATH: process.env.PATH, NODE_NO_WARNINGS: '1', HOME: EMPTY_HOME, ...ENV }, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d: Buffer) => (stdout += d.toString('utf8')));
    child.stderr.on('data', (d: Buffer) => (stderr += d.toString('utf8')));
    child.on('error', reject);
    const poll = setInterval(() => {
      if (ready()) {
        clearInterval(poll);
        child.kill('SIGINT');
      }
    }, 5);
    child.on('close', (code) => {
      clearInterval(poll);
      resolve({ code, stdout, stderr });
    });
  });
}

describe('winlinux pwsh -c against the fake PSRP endpoint', () => {
  it('prints the formatted lines of Get-Process and exits 0, leaving no shell', () =>
    withFake(async (fake) => {
      const r = await runCli(['pwsh', ...flags(fake.port), TARGET, '-c', 'Get-Process | Select -First 3'], ENV);
      assert.equal(r.code, 0, r.stderr);
      const lines = r.stdout.split('\n').filter(Boolean);
      assert.equal(lines.length, 3);
      assert.match(lines[0] ?? '', /^\s+4 System$/);
      assert.equal(r.stderr, '');
      assert.deepEqual(fake.scripts, ['Get-Process | Select -First 3']);
      assert.deepEqual(fake.openShells(), [], 'the pool was deleted');
    }));

  it('--json prints the objects with their type names, and $x persists within one pipeline only', () =>
    withFake(async (fake) => {
      const r = await runCli(['pwsh', '--json', ...flags(fake.port), TARGET, '-c', 'Get-Process | Select -First 1'], ENV);
      assert.equal(r.code, 0, r.stderr);
      const parsed = JSON.parse(r.stdout) as { output: Array<Record<string, unknown>>; errors: unknown[]; state: string };
      assert.equal(parsed.state, 'Completed');
      assert.equal(parsed.output[0]?.['@type'], 'System.Diagnostics.Process');
      assert.equal(parsed.output[0]?.['Id'], 4);
      assert.deepEqual(parsed.errors, []);
      const two = await runCli(['pwsh', '--json', ...flags(fake.port), TARGET, '-c', '$y = 5; $y'], ENV);
      assert.deepEqual((JSON.parse(two.stdout) as { output: unknown[] }).output, [5]);
      const gone = await runCli(['pwsh', '--json', ...flags(fake.port), TARGET, '-c', '$y'], ENV);
      assert.deepEqual((JSON.parse(gone.stdout) as { output: unknown[] }).output, [], 'a new pool per command: nothing persists across commands yet');
    }));

  it('an error record exits 4 with the PowerShell-style text on stderr; a warning is prefixed', () =>
    withFake(async (fake) => {
      const r = await runCli(['pwsh', ...flags(fake.port), TARGET, '-c', "Write-Output 'a'; Write-Error 'bad thing'; Write-Warning 'hmm'"], ENV);
      assert.equal(r.code, 4, r.stderr);
      assert.equal(r.stdout, 'a\n');
      assert.match(r.stderr, /^bad thing\n    \+ CategoryInfo          : NotSpecified: \(:\) \[\], WriteErrorException\n    \+ FullyQualifiedErrorId : Microsoft\.PowerShell\.Commands\.WriteErrorException\nWARNING: hmm\n$/);
    }));

  it('Read-Host fails on the server: exit 4 with the reason', () =>
    withFake(async (fake) => {
      const r = await runCli(['pwsh', ...flags(fake.port), TARGET, '-c', 'Read-Host name'], ENV);
      assert.equal(r.code, 4);
      assert.match(r.stderr, /current host does not implement it/);
    }));

  it('Ctrl+C during Start-Sleep stops the pipeline (Signal) and exits 130', () =>
    withFake(async (fake) => {
      // Ctrl+C once the CLI waits in its first Receive on the pipeline.
      const r = await interruptWhen(['pwsh', ...flags(fake.port), TARGET, '-c', 'Start-Sleep 60'], () => fake.receives >= 1);
      assert.equal(r.code, 130, r.stderr);
      assert.match(r.stderr, /interrupted; closing/);
      assert.ok(fake.signals >= 1, 'the fake saw Signal');
      // The Delete may still be in flight when the process exits.
      const deadline = Date.now() + 3000;
      while (fake.openShells().length > 0 && Date.now() < deadline) await new Promise((resolve) => setTimeout(resolve, 20));
      assert.deepEqual(fake.openShells(), [], 'the pool was deleted');
    }));

  it('pwsh without -c, and -c on run, are usage errors', () =>
    withFake(async (fake) => {
      const r = await runCli(['pwsh', ...flags(fake.port), TARGET], ENV);
      assert.equal(r.code, 1);
      assert.match(r.stderr, /pwsh needs -c <script>/);
      const foreign = await runCli(['run', ...flags(fake.port), TARGET, '-c', 'x', 'hostname'], ENV);
      assert.equal(foreign.code, 1);
      assert.match(foreign.stderr, /--command applies to pwsh only/);
      assert.deepEqual(fake.scripts, []);
    }));
});
