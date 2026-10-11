// Service and process state in the facade and CLI: the facade
// methods reach WinRM, the tables and --json render the module's records,
// the filters run on the client, and foreign flags are usage errors.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { PassThrough } from 'node:stream';
import type { ProcessInfo, ServiceInfo } from '@winlinux/winrm';
import { createClient } from '../../dist/client.js';
import { buildServiceFilter, execute, HELP, SHELL_HELP, type Io, type LineValues } from '../../dist/cli/app.js';
import { filterProcesses, filterServices, formatProcesses, formatServices } from '../../dist/cli/output.js';
import { WinLinuxUsageError } from '../../dist/index.js';
import { FakeWinrm, fakeDeps } from '../helpers/fakes.js';

const SERVICES: ServiceInfo[] = [
  { name: 'wuauserv', displayName: 'Windows Update', status: 'Running', startType: 'Manual' },
  { name: 'Spooler', displayName: 'Print Spooler', status: 'Stopped', startType: 'Automatic' },
  { name: 'W32Time', displayName: 'Windows Time', status: 'Running', startType: 'Automatic' },
];
const PROCESSES: ProcessInfo[] = [
  { id: 4, name: 'System', cpuSeconds: 123.456, workingSetBytes: 8192, startTime: '2026-10-09T08:24:35.000Z' },
  { id: 9999, name: 'exited', cpuSeconds: null, workingSetBytes: 0, startTime: null },
  { id: 1200, name: 'svchost', cpuSeconds: 0, workingSetBytes: 1048576, startTime: '2026-10-09T08:25:00.000Z' },
];

function capture(): { io: Io; out: () => string } {
  const stdout = new PassThrough();
  let out = '';
  stdout.on('data', (d: Buffer) => (out += d.toString()));
  return { io: { env: {}, stdin: process.stdin, stdout, stderr: new PassThrough() }, out: () => out };
}

function clientWith(winrm: FakeWinrm) {
  return createClient('srv', { username: 'alice', password: 'pw-services-1', auth: 'ntlm' }, fakeDeps({ winrm: async () => winrm }));
}

describe('facade listServices and listProcesses', () => {
  it('open WinRM lazily and return what the session returns', async () => {
    const winrm = new FakeWinrm();
    let serviceCalls = 0;
    let processCalls = 0;
    winrm.servicesImpl = async () => {
      serviceCalls += 1;
      return SERVICES;
    };
    winrm.processesImpl = async () => {
      processCalls += 1;
      return PROCESSES;
    };
    const deps = fakeDeps({ winrm: async () => winrm });
    const client = createClient('srv', { username: 'alice', password: 'pw-services-1', auth: 'ntlm' }, deps);
    assert.equal(deps.winrmOpens.length, 0, 'connect opens nothing');
    assert.deepEqual(await client.listServices(), SERVICES);
    assert.deepEqual(await client.listProcesses(), PROCESSES);
    assert.equal(deps.winrmOpens.length, 1, 'one WinRM session serves both calls');
    assert.equal(deps.smbOpens.length, 0);
    assert.equal(serviceCalls, 1);
    assert.equal(processCalls, 1);
    await client.close();
  });
});

describe('services and ps output', () => {
  it('services renders Name Status StartType DisplayName', () => {
    const lines = formatServices(SERVICES).trimEnd().split('\n');
    assert.match(lines[0] ?? '', /^Name\s+Status\s+StartType\s+DisplayName$/);
    assert.match(lines[1] ?? '', /^wuauserv\s+Running\s+Manual\s+Windows Update$/);
    assert.match(lines[2] ?? '', /^Spooler\s+Stopped\s+Automatic\s+Print Spooler$/);
    assert.equal(lines.length, 4);
  });

  it('ps renders PID Name CPU(s) WS StartTime, blank for a null CPU or start time', () => {
    const lines = formatProcesses(PROCESSES).trimEnd().split('\n');
    assert.match(lines[0] ?? '', /^PID\s+Name\s+CPU\(s\)\s+WS\s+StartTime$/);
    assert.match(lines[1] ?? '', /^4\s+System\s+123\.46\s+8192\s+2026-10-09T08:24:35\.000Z$/);
    assert.match(lines[2] ?? '', /^9999\s+exited\s+0$/, 'null CPU and StartTime print as nothing');
    assert.match(lines[3] ?? '', /^1200\s+svchost\s+0\.00\s+1048576\s+2026-10-09T08:25:00\.000Z$/);
  });

  it('filters run on the client: status exactly, name as a case-insensitive substring', () => {
    assert.deepEqual(filterServices(SERVICES, { status: 'running' }).map((s) => s.name), ['wuauserv', 'W32Time']);
    assert.deepEqual(filterServices(SERVICES, { status: 'stopped' }).map((s) => s.name), ['Spooler']);
    assert.deepEqual(filterServices(SERVICES, { name: 'win' }).map((s) => s.name), ['wuauserv', 'W32Time'], 'matches the display name too');
    assert.deepEqual(filterServices(SERVICES, { status: 'running', name: 'time' }).map((s) => s.name), ['W32Time']);
    assert.deepEqual(filterServices(SERVICES, {}), SERVICES);
    assert.deepEqual(filterProcesses(PROCESSES, { name: 'SVC' }).map((p) => p.id), [1200]);
    assert.deepEqual(filterProcesses(PROCESSES, {}), PROCESSES);
  });

  it('--status accepts running or stopped in any case and rejects the rest', () => {
    assert.deepEqual(buildServiceFilter({ status: 'Running' }), { status: 'running' });
    assert.deepEqual(buildServiceFilter({ status: 'STOPPED', name: 'x' }), { status: 'stopped', name: 'x' });
    assert.deepEqual(buildServiceFilter({}), {});
    assert.throws(() => buildServiceFilter({ status: 'paused' }), WinLinuxUsageError);
  });

  it('execute: tables, --json as returned, filters applied, and no remote text', async () => {
    const winrm = new FakeWinrm();
    winrm.servicesImpl = async () => SERVICES;
    winrm.processesImpl = async () => PROCESSES;
    const client = clientWith(winrm);
    const run = async (command: 'services' | 'ps', values: LineValues) => {
      const { io, out } = capture();
      const code = await execute(client, command, [], values, io);
      assert.equal(code, 0);
      return out();
    };
    assert.deepEqual(JSON.parse(await run('services', { json: true })), SERVICES);
    assert.deepEqual(JSON.parse(await run('ps', { json: true })), PROCESSES);
    assert.deepEqual(
      JSON.parse(await run('services', { json: true, status: 'stopped' })).map((s: ServiceInfo) => s.name),
      ['Spooler'],
    );
    assert.deepEqual(JSON.parse(await run('ps', { json: true, name: 'sys' })).map((p: ProcessInfo) => p.id), [4]);
    assert.match(await run('services', { name: 'spool' }), /^Name\s+Status\s+StartType\s+DisplayName\nSpooler\s+Stopped\s+Automatic\s+Print Spooler\n$/);
    assert.match(await run('ps', {}), /^PID\s+Name/);
    // The filters never reach the server: the session saw no command line
    // (the fake answers listServices/listProcesses directly).
    assert.equal(winrm.runs.length, 0);
    await client.close();
  });

  it('rejects flags of other commands and the wrong arity', async () => {
    const client = clientWith(new FakeWinrm());
    const { io } = capture();
    await assert.rejects(execute(client, 'services', [], { max: '3' }, io), /--max applies to logs only, not services/);
    await assert.rejects(execute(client, 'logs', [], { name: 'x' }, io), /--name applies to services and ps only, not logs/);
    await assert.rejects(execute(client, 'ps', [], { status: 'running' }, io), /--status applies to services only, not ps/);
    await assert.rejects(execute(client, 'ps', ['extra'], {}, io), /wrong number of arguments for ps/);
    await client.close();
  });

  it('help lists both commands and their flags', () => {
    assert.match(HELP, /winlinux services \[flags\] <target>/);
    assert.match(HELP, /winlinux ps\s+\[flags\] <target>/);
    assert.match(HELP, /--status <running\|stopped>/);
    assert.match(SHELL_HELP, /services \[--status <running\|stopped>\] \[--name <substring>\] \[--json\]/);
    assert.match(SHELL_HELP, /ps \[--name <substring>\] \[--json\]/);
  });
});
