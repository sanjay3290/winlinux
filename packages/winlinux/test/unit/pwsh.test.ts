// winlinux pwsh -c and the facade's PowerShell sessions:
// the pool opens with the WinRM plan, the session closes with the client,
// errors map like the WinRM slot, and the CLI prints a pipeline the way
// PowerShell does, or as one JSON value.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { PassThrough } from 'node:stream';
import { PSRemotingError, WinRMAuthError, WinRMTransportError, type PSErrorRecord, type PSObject, type PSValue } from '@winlinux/winrm';
import { createClient } from '../../dist/client.js';
import { execute, type Io, type LineValues } from '../../dist/cli/app.js';
import { formatErrorRecord, pipelineExitCode, resultJson } from '../../dist/cli/pwsh.js';
import { WinLinuxAuthError, WinLinuxConnectionError, WinLinuxUsageError } from '../../dist/index.js';
import { EXIT } from '../../dist/errors.js';
import { FakePool, FakeWinrm, fakeDeps, type FakeRun } from '../helpers/fakes.js';

const OPTS = { username: 'alice', password: 'pw-pwsh-1', auth: 'ntlm' as const };

const record = (message: string, fqid = 'MyError', categoryInfo = 'NotSpecified: (:) [], RuntimeException'): PSErrorRecord => ({
  message,
  fullyQualifiedErrorId: fqid,
  category: 0,
  categoryInfo,
  targetName: '',
  record: { kind: 'object', typeNames: [], adapted: new Map(), extended: new Map() },
});

function capture(tty = false): { io: Io; out: () => string; err: () => string } {
  const stdout = new PassThrough();
  const stderr = new PassThrough();
  let out = '';
  let err = '';
  stdout.on('data', (d: Buffer) => (out += d.toString()));
  stderr.on('data', (d: Buffer) => (err += d.toString()));
  if (tty) {
    (stdout as unknown as { isTTY: boolean; columns: number }).isTTY = true;
    (stdout as unknown as { columns: number }).columns = 80;
    (stderr as unknown as { isTTY: boolean }).isTTY = true;
  }
  return { io: { env: {}, stdin: process.stdin, stdout, stderr }, out: () => out, err: () => err };
}

describe('facade openPowerShell and invokePowerShell', () => {
  it('invokePowerShell opens a pool with the WinRM plan, runs one pipeline with the options, and closes the pool', async () => {
    const pool = new FakePool();
    const deps = fakeDeps({ pool: async () => pool });
    const client = createClient('srv', { ...OPTS, winrm: { tls: true, port: 5999, tlsVerify: false, operationTimeoutMs: 1234 } }, deps);
    try {
      const result = await client.invokePowerShell('Get-Date', { outString: { width: 100 }, configurationName: 'My.Config' });
      assert.equal(result.state, 'Completed');
      assert.deepEqual(result.output, ['ok']);
      assert.equal(deps.poolOpens.length, 1);
      const open = deps.poolOpens[0];
      assert.equal(open?.host, 'srv');
      assert.equal(open?.port, 5999);
      assert.equal(open?.tls, true);
      assert.equal(open?.tlsVerify, false);
      assert.equal(open?.operationTimeoutMs, 1234);
      assert.equal(open?.configurationName, 'My.Config');
      assert.ok(open?.authProvider, 'an auth provider from the plan');
      assert.deepEqual(deps.mechanisms, ['ntlm']);
      assert.equal(open?.credentials?.username, 'alice');
      assert.deepEqual(pool.invokes, [{ script: 'Get-Date', opts: { outString: { width: 100 } } }]);
      assert.equal(pool.closed, 1, 'the pool is closed after the pipeline');
      assert.equal(deps.winrmOpens.length, 0, 'no WinRS session');
    } finally {
      await client.close();
    }
    assert.equal(pool.closed, 1, 'close() does not close it again');
  });

  it('openPowerShell sessions close with client.close(), within the bound, and a closed session is forgotten', async () => {
    const hanging = new FakePool();
    hanging.closeImpl = () => new Promise(() => undefined);
    const quick = new FakePool();
    let n = 0;
    const deps = fakeDeps({ pool: async () => (n++ === 0 ? hanging : quick), closeTimeoutMs: 50 });
    const client = createClient('srv', OPTS, deps);
    const a = await client.openPowerShell();
    const b = await client.openPowerShell();
    assert.equal(a.host, 'srv');
    assert.equal(a.serverProtocolVersion, '2.3');
    const run = await b.invoke('$x').result();
    assert.deepEqual(run.output, ['ok']);
    await b.close();
    assert.equal(quick.closed, 1);
    const started = Date.now();
    await client.close();
    assert.ok(Date.now() - started < 1000, 'the hanging pool did not block close');
    assert.equal(hanging.closed, 1, 'close was attempted');
    assert.equal(quick.closed, 1, 'the closed session is not closed twice');
    await assert.rejects(client.openPowerShell(), WinLinuxUsageError);
  });

  it('maps an open failure like the WinRM slot: auth is exit 2 and latches, connection is exit 3, PSRemotingError stays (exit 4)', async () => {
    const auth = fakeDeps({
      pool: async () => {
        throw new WinRMAuthError('WinRM credentials were rejected by the server (HTTP 401)');
      },
    });
    const client = createClient('srv', OPTS, auth);
    const err = await client.invokePowerShell('x').catch((e: unknown) => e);
    assert.ok(err instanceof WinLinuxAuthError, String(err));
    assert.equal(auth.poolOpens.length, 1);
    await assert.rejects(client.invokePowerShell('x'), WinLinuxAuthError);
    assert.equal(auth.poolOpens.length, 1, 'latched: no second open with the refused password');
    await assert.rejects(client.run('hostname'), WinLinuxAuthError);
    assert.equal(auth.winrmOpens.length, 0, 'the WinRS slot is latched too');
    client.setPassword('pw-pwsh-2');
    await client.invokePowerShell('x').catch(() => undefined);
    assert.equal(auth.poolOpens.length, 2, 'a new password opens again');
    await client.close();

    const refused = fakeDeps({
      pool: async () => {
        const e = new Error('connect ECONNREFUSED') as Error & { code: string };
        e.code = 'ECONNREFUSED';
        throw e;
      },
    });
    const c2 = createClient('srv', OPTS, refused);
    await assert.rejects(c2.openPowerShell(), WinLinuxConnectionError);
    await c2.close();

    const remoting = fakeDeps({
      pool: async () => {
        throw new PSRemotingError('the server speaks PSRP 2.1; winlinux needs 2.2 or newer (PowerShell 3.0+)');
      },
    });
    const c3 = createClient('srv', OPTS, remoting);
    await assert.rejects(c3.openPowerShell(), (e: unknown) => e instanceof PSRemotingError);
    await c3.close();
    const transport = fakeDeps({
      pool: async () => {
        throw new WinRMTransportError('socket hang up');
      },
    });
    const c4 = createClient('srv', OPTS, transport);
    await assert.rejects(c4.openPowerShell(), WinLinuxConnectionError);
    await c4.close();
  });

  it('refuses when the deps have no pool, and keeps the WinRS methods on WinRS', async () => {
    const winrm = new FakeWinrm();
    const deps = fakeDeps({ winrm: async () => winrm });
    delete (deps as { openRunspacePool?: unknown }).openRunspacePool;
    const client = createClient('srv', OPTS, deps);
    await assert.rejects(client.openPowerShell(), /without PSRP support/);
    await client.runPowerShell('Get-Date');
    assert.equal(winrm.runs.length, 1, 'runPowerShell still runs over WinRS');
    await client.close();
  });
});

describe('winlinux pwsh -c', () => {
  function cli(run: FakeRun | ((script: string) => FakeRun), tty = false) {
    const pool = new FakePool();
    pool.invokeImpl = (script) => (typeof run === 'function' ? run(script) : run);
    const deps = fakeDeps({ pool: async () => pool });
    const client = createClient('srv', OPTS, deps);
    const c = capture(tty);
    return { pool, deps, client, ...c, exec: (values: LineValues, signal?: AbortSignal) => execute(client, 'pwsh', [], values, c.io, signal) };
  }
  const process1: PSObject = { kind: 'object', typeNames: ['System.Diagnostics.Process', 'System.Object'], adapted: new Map<string, PSValue>([['Id', 4], ['ProcessName', 'System']]), extended: new Map(), toStringValue: 'System.Diagnostics.Process (System)' };

  it('prints Out-String lines on stdout and exits 0; the width comes from the TTY', async () => {
    const t = cli({ events: [{ stream: 'output', value: '     4 System' }, { stream: 'output', value: '     8 csrss' }] }, true);
    try {
      assert.equal(await t.exec({ command: 'Get-Process | Select -First 2' }), EXIT.ok);
      assert.equal(t.out(), '     4 System\n     8 csrss\n');
      assert.equal(t.err(), '');
      assert.deepEqual(t.pool.invokes[0]?.opts, { outString: { width: 80 } });
      assert.equal(t.pool.closed, 1, 'the session is closed');
    } finally {
      await t.client.close();
    }
  });

  it('without a TTY the width is 120, and --configuration reaches the pool', async () => {
    const t = cli({ events: [] });
    try {
      assert.equal(await t.exec({ command: '$null', configuration: 'Custom.Endpoint' }), EXIT.ok);
      assert.deepEqual(t.pool.invokes[0]?.opts, { outString: { width: 120 } });
      assert.equal(t.deps.poolOpens[0]?.configurationName, 'Custom.Endpoint');
    } finally {
      await t.client.close();
    }
  });

  it('prints an error record as PowerShell does on stderr and exits 4, red on a TTY', async () => {
    const t = cli({ events: [{ stream: 'output', value: 'before' }, { stream: 'error', record: record('Access is denied', 'Denied,Get-Item', 'PermissionDenied: (C:\\secret:String) [Get-Item], UnauthorizedAccessException') }] });
    try {
      assert.equal(await t.exec({ command: 'Get-Item C:\\secret' }), EXIT.remote);
      assert.equal(t.out(), 'before\n');
      assert.equal(t.err(), 'Access is denied\n    + CategoryInfo          : PermissionDenied: (C:\\secret:String) [Get-Item], UnauthorizedAccessException\n    + FullyQualifiedErrorId : Denied,Get-Item\n');
    } finally {
      await t.client.close();
    }
    const red = cli({ events: [{ stream: 'error', record: record('boom') }] }, true);
    try {
      assert.equal(await red.exec({ command: 'x' }), EXIT.remote);
      assert.ok(red.err().startsWith('\x1b[31mboom\n'), red.err());
      assert.ok(red.err().endsWith('\x1b[0m\n'));
    } finally {
      await red.client.close();
    }
  });

  it('warning, verbose and debug go to stderr with their prefixes; information to stdout; progress only on a TTY', async () => {
    const events: FakeRun['events'] = [
      { stream: 'warning', message: 'careful' },
      { stream: 'verbose', message: 'v' },
      { stream: 'debug', message: 'd' },
      { stream: 'information', record: { messageData: 'hello from Write-Host', source: 'Write-Host', tags: [], user: '', computer: '', record: process1 } },
      { stream: 'progress', record: { activity: 'Copy', activityId: 1, currentOperation: null, parentActivityId: -1, percentComplete: 50, type: 'Processing', secondsRemaining: -1, statusDescription: 'half' } },
      { stream: 'output', value: 'done' },
    ];
    const plain = cli({ events });
    try {
      assert.equal(await plain.exec({ command: 'x' }), EXIT.ok);
      assert.equal(plain.out(), 'hello from Write-Host\ndone\n');
      assert.equal(plain.err(), 'WARNING: careful\nVERBOSE: v\nDEBUG: d\n');
    } finally {
      await plain.client.close();
    }
    const tty = cli({ events }, true);
    try {
      await tty.exec({ command: 'x' });
      assert.ok(tty.err().includes('\r\x1b[KCopy 50% half'), tty.err());
      assert.ok(tty.err().endsWith('\r\x1b[K'), 'the progress line is cleared before the output');
    } finally {
      await tty.client.close();
    }
  });

  it('a Failed pipeline prints its reason and exits 4; Stopped exits 130', async () => {
    const failed = cli({ state: 'Failed', reason: record('Cannot invoke this function because the current host does not implement it.', 'HostFunctionNotImplemented', 'NotImplemented: (:) [Read-Host], HostException') });
    try {
      assert.equal(await failed.exec({ command: 'Read-Host x' }), EXIT.remote);
      assert.match(failed.err(), /^Cannot invoke this function because the current host does not implement it\.\n    \+ CategoryInfo/);
    } finally {
      await failed.client.close();
    }
    const broken = cli({ state: 'Failed', reason: new PSRemotingError('unexpected PSRP message') });
    try {
      assert.equal(await broken.exec({ command: 'x' }), EXIT.remote);
      assert.equal(broken.err(), 'winlinux: pipeline failed: unexpected PSRP message\n');
    } finally {
      await broken.client.close();
    }
    const stopped = cli({ state: 'Stopped' });
    try {
      assert.equal(await stopped.exec({ command: 'Start-Sleep 60' }), EXIT.interrupted);
    } finally {
      await stopped.client.close();
    }
  });

  it('--json prints output objects, error records, the state and the reason, with no Out-String', async () => {
    const t = cli({ events: [{ stream: 'output', value: process1 }, { stream: 'output', value: 42n }, { stream: 'error', record: record('oops', 'Oops') }] });
    try {
      assert.equal(await t.exec({ command: 'x', json: true }), EXIT.remote);
      assert.deepEqual(JSON.parse(t.out()), {
        output: [{ '@type': 'System.Diagnostics.Process', '@toString': 'System.Diagnostics.Process (System)', Id: 4, ProcessName: 'System' }, '42'],
        errors: [{ message: 'oops', fullyQualifiedErrorId: 'Oops', category: 0, categoryInfo: 'NotSpecified: (:) [], RuntimeException', targetName: '' }],
        state: 'Completed',
      });
      assert.equal(t.err(), '');
      assert.equal(t.pool.invokes[0]?.opts?.outString, undefined, 'objects, not lines');
    } finally {
      await t.client.close();
    }
    const failed = cli({ state: 'Failed', reason: record('bad', 'Bad') });
    try {
      assert.equal(await failed.exec({ command: 'x', json: true }), EXIT.remote);
      assert.equal((JSON.parse(failed.out()) as { reason: { message: string } }).reason.message, 'bad');
    } finally {
      await failed.client.close();
    }
  });

  it('sanitizes server text for the terminal', async () => {
    const t = cli({ events: [{ stream: 'output', value: 'line\x1b[2Jcleared' }, { stream: 'warning', message: 'w\x07' }, { stream: 'error', record: record('m\x1b]0;title\x07') }] });
    try {
      await t.exec({ command: 'x' });
      assert.equal(t.out(), 'line\\x1b[2Jcleared\n');
      assert.ok(t.err().includes('WARNING: w\\x07\n'));
      assert.ok(t.err().includes('m\\x1b]0;title\\x07\n'));
    } finally {
      await t.client.close();
    }
  });

  it('refuses pwsh without -c, an empty script, and -c on another command', async () => {
    const t = cli({});
    try {
      await assert.rejects(t.exec({}), (e: unknown) => e instanceof WinLinuxUsageError && /pwsh needs -c <script>/.test(e.message));
      await assert.rejects(t.exec({ command: '  ' }), (e: unknown) => e instanceof WinLinuxUsageError && /needs a script/.test(e.message));
      await assert.rejects(execute(t.client, 'run', ['x'], { command: 'y' }, t.io), (e: unknown) => e instanceof WinLinuxUsageError && /--command applies to pwsh only, not run/.test(e.message));
      await assert.rejects(execute(t.client, 'logs', [], { configuration: 'y' }, t.io), WinLinuxUsageError);
      assert.equal(t.deps.poolOpens.length, 0, 'no pool was opened');
    } finally {
      await t.client.close();
    }
  });

  it('the abort signal reaches the pool open and the pipeline', async () => {
    const t = cli({ events: [] });
    try {
      const abort = new AbortController();
      await t.exec({ command: 'x' }, abort.signal);
      assert.equal(t.deps.poolOpens[0]?.signal, abort.signal);
      assert.equal(t.pool.invokes[0]?.opts?.signal, abort.signal);
    } finally {
      await t.client.close();
    }
  });
});

describe('pwsh helpers', () => {
  it('formatErrorRecord falls back to the id, pipelineExitCode maps the state and error records, resultJson keeps an Error reason', () => {
    assert.equal(formatErrorRecord({ ...record(''), fullyQualifiedErrorId: 'OnlyId', categoryInfo: '' }), 'OnlyId\n    + FullyQualifiedErrorId : OnlyId\n');
    const base = { output: [], errors: [] };
    assert.equal(pipelineExitCode({ ...base, state: 'Completed' }), 0);
    assert.equal(pipelineExitCode({ ...base, state: 'Completed', errors: [record('e')] }), 4);
    assert.equal(pipelineExitCode({ ...base, state: 'Failed' }), 4);
    assert.equal(pipelineExitCode({ ...base, state: 'Stopped' }), 130);
    assert.deepEqual(resultJson({ ...base, state: 'Failed', reason: new Error('x') }), { output: [], errors: [], state: 'Failed', reason: { message: 'x', name: 'Error' } });
  });
});
