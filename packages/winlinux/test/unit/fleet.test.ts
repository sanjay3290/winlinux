// run --hosts with fake clients: no network.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import type { OutputChunk } from '@winlinux/winrm';
import { WinRMAbortError } from '@winlinux/winrm';
import { WinLinuxAuthError, WinLinuxConnectionError, WinLinuxUsageError } from '../../dist/errors.js';
import {
  LinePrefixer,
  dedupeHosts,
  expandHostList,
  fleetExitCode,
  formatTable,
  labelOf,
  runFleet,
  type FleetClient,
  type FleetHost,
  type HostOutcome,
} from '../../dist/cli/fleet.js';
import { parseConfig } from '../../dist/cli/config.js';
import { HELP, parseHostsParallel } from '../../dist/cli/app.js';

function sink(): { stream: NodeJS.WritableStream; text: () => string } {
  let out = '';
  return { stream: { write: (s: string) => ((out += s), true) } as unknown as NodeJS.WritableStream, text: () => out };
}

function host(label: string, username = 'svc'): FleetHost {
  return { label, host: `${label}.example.test`, username, options: { username } };
}

type Behaviour = { chunks?: OutputChunk[]; exitCode?: number | null; error?: unknown; delayMs?: number; hang?: boolean };

class FakeClient implements FleetClient {
  closed = 0;
  started = 0;
  constructor(
    private readonly b: Behaviour,
    private readonly track?: { inFlight: number; max: number },
  ) {}
  runStream(_cmd: string, _args?: string[], opts?: { signal?: AbortSignal }): AsyncIterable<OutputChunk> {
    const b = this.b;
    const track = this.track;
    const self = this;
    return (async function* () {
      self.started += 1;
      if (track) {
        track.inFlight += 1;
        track.max = Math.max(track.max, track.inFlight);
      }
      try {
        if (b.hang) {
          await new Promise<void>((_resolve, reject) => {
            const fail = () => reject(new WinRMAbortError());
            if (opts?.signal?.aborted) fail();
            opts?.signal?.addEventListener('abort', fail, { once: true });
          });
        }
        if (b.delayMs) await new Promise((r) => setTimeout(r, b.delayMs));
        for (const c of b.chunks ?? []) yield c;
        if (b.error !== undefined) throw b.error;
        return { exitCode: b.exitCode === undefined ? 0 : b.exitCode };
      } finally {
        if (track) track.inFlight -= 1;
      }
    })();
  }
  async close(): Promise<void> {
    this.closed += 1;
  }
}

const authError = () => new WinLinuxAuthError('auth failed', 'winrm', 'ntlm');
const connError = () => new WinLinuxConnectionError('connect ECONNREFUSED', 'winrm', 'h.example.test', 5985);

async function fleet(
  behaviours: Record<string, Behaviour>,
  opts: { parallel?: number; json?: boolean; signal?: AbortSignal; track?: { inFlight: number; max: number } } = {},
) {
  const out = sink();
  const err = sink();
  const clients = new Map<string, FakeClient>();
  const hosts = Object.keys(behaviours).map((l) => host(l));
  let t = 0;
  const run = await runFleet(hosts, 'hostname', [], {
    parallel: opts.parallel ?? 4,
    json: opts.json ?? false,
    io: { stdout: out.stream, stderr: err.stream },
    signal: opts.signal,
    connect: (h) => {
      const c = new FakeClient(behaviours[h.label] as Behaviour, opts.track);
      clients.set(h.label, c);
      return c;
    },
    now: () => (t += 100),
    closeTimeoutMs: 50,
  });
  return { run, stdout: out.text(), stderr: err.text(), clients };
}

describe('LinePrefixer', () => {
  it('prefixes complete lines and holds a partial line until its newline', () => {
    const out: string[] = [];
    const p = new LinePrefixer('web1 | ', (t) => out.push(t));
    p.push('one\ntw');
    p.push('o\nthr');
    assert.equal(out.join(''), 'web1 | one\nweb1 | two\n');
    p.push('ee');
    p.flush();
    assert.equal(out.join(''), 'web1 | one\nweb1 | two\nweb1 | three\n');
  });

  it('keeps a UTF-8 character that is split across two chunks whole', () => {
    const out: string[] = [];
    const p = new LinePrefixer('h | ', (t) => out.push(t));
    const bytes = Buffer.from('héllo ✓\n', 'utf8');
    const cut = bytes.indexOf(0xa9); // inside the 2-byte é
    p.push(bytes.subarray(0, cut));
    p.push(bytes.subarray(cut, cut + 6)); // ends inside the 3-byte ✓
    p.push(bytes.subarray(cut + 6));
    p.flush();
    assert.equal(out.join(''), 'h | héllo ✓\n');
  });

  it('flush adds nothing when there is no partial line', () => {
    const out: string[] = [];
    const p = new LinePrefixer('h | ', (t) => out.push(t));
    p.push('a\n');
    p.flush();
    assert.equal(out.join(''), 'h | a\n');
  });
});

describe('host lists', () => {
  const config = parseConfig('Group web web1 svc@web2.example.test\nGroup db db1\nHost web1\n  User u\n', '/c');

  it('expands @group in place, keeping the input order', () => {
    assert.deepEqual(expandHostList('db0,@web,db1', config), ['db0', 'web1', 'svc@web2.example.test', 'db1']);
    assert.deepEqual(expandHostList('@WEB', config), ['web1', 'svc@web2.example.test'], 'group names are case-insensitive');
  });

  it('an unknown group and empty items are usage errors', () => {
    assert.throws(() => expandHostList('@nope', config), (e: Error) => e instanceof WinLinuxUsageError && /unknown group @nope in \/c/.test(e.message));
    assert.throws(() => expandHostList('@web', undefined), /unknown group @web/);
    assert.throws(() => expandHostList('a,,b', config), /empty items/);
    assert.throws(() => expandHostList('', config), /empty items/);
  });

  it('a group does not nest; a group line needs members', () => {
    assert.throws(() => parseConfig('Group a @b\n', '/c'), /:1: groups do not nest: @b/);
    assert.throws(() => parseConfig('Group a\n', '/c'), /:1: Group needs a name and at least one member/);
    assert.throws(() => parseConfig('Group a x\nGroup A y\n', '/c'), /:2: group A is defined twice/);
  });

  it('removes duplicates (same user, host and port) and keeps the first', () => {
    const hosts = [
      { label: 'web1', host: 'web1.example.test', username: 'svc', options: { username: 'svc' } },
      { label: 'web1.example.test', host: 'WEB1.example.test', username: 'SVC', options: { username: 'SVC' } },
      { label: 'web1-admin', host: 'web1.example.test', username: 'admin', options: { username: 'admin' } },
      { label: 'web1-alt', host: 'web1.example.test', username: 'svc', options: { username: 'svc', winrm: { port: 15985 } } },
    ];
    assert.deepEqual(dedupeHosts(hosts).map((h) => h.label), ['web1', 'web1-admin', 'web1-alt']);
  });

  it('labels: the alias or host as typed', () => {
    assert.equal(labelOf('web1'), 'web1');
    assert.equal(labelOf('svc@web2.example.test'), 'web2.example.test');
    assert.equal(labelOf('CORP\\svc@db1'), 'db1');
  });

  it('--parallel with --hosts: 1-32, default 4', () => {
    assert.equal(parseHostsParallel(undefined), 4);
    assert.equal(parseHostsParallel('32'), 32);
    for (const bad of ['0', '33', 'x', '1.5']) assert.throws(() => parseHostsParallel(bad), /1 to 32/);
    assert.match(HELP, /winlinux run {4}\[flags\] --hosts <list>/);
  });
});

describe('runFleet', () => {
  it('never has more than n hosts in flight', async () => {
    const track = { inFlight: 0, max: 0 };
    const behaviours = Object.fromEntries(Array.from({ length: 9 }, (_, i) => [`h${i}`, { delayMs: 5 }]));
    const { run } = await fleet(behaviours, { parallel: 3, track });
    assert.equal(track.max, 3);
    assert.equal(run.outcomes.length, 9);
    assert.equal(run.exitCode, 0);
  });

  it('prefixes live output, padded to the longest label, and prints the table on stderr', async () => {
    const { stdout, stderr, run } = await fleet({
      a: { chunks: [{ stream: 'stdout', data: 'one\npart' }, { stream: 'stdout', data: 'ial\n' }] },
      'web-long': { chunks: [{ stream: 'stderr', data: 'warn' }] },
    });
    assert.equal(run.exitCode, 0);
    assert.equal(stdout, 'a        | one\na        | partial\n');
    assert.ok(stderr.startsWith('web-long | warn\n'), stderr);
    assert.match(stderr, /HOST {6}RESULT {2}TIME\na {9}ok {6}\d\.\ds\nweb-long  ok {6}\d\.\ds\n$/);
  });

  it('exit code rule: all ok is 0; one remote exit 1 is 4', async () => {
    assert.equal((await fleet({ a: {}, b: {} })).run.exitCode, 0);
    const r = await fleet({ a: {}, b: { exitCode: 1 } });
    assert.equal(r.run.exitCode, 4);
    assert.match(r.stderr, /b +exit 1/);
  });

  it('exit code rule: a mix of auth, connection and remote failures is 2', async () => {
    const r = await fleet({ a: { exitCode: 7 }, b: { error: connError() }, c: { error: authError() } }, { parallel: 3 });
    assert.equal(r.run.exitCode, 2);
    assert.match(r.stderr, /a +exit 7/);
    assert.match(r.stderr, /b +connection failed/);
    assert.match(r.stderr, /c +auth failed/);
  });

  it('a connection failure with the rest ok is 3; one host failing never stops the others', async () => {
    const r = await fleet({ a: { error: connError() }, b: {}, c: {} }, { parallel: 1 });
    assert.equal(r.run.exitCode, 3);
    assert.deepEqual(r.run.outcomes.map((o) => o.result), ['connection failed', 'ok', 'ok']);
  });

  it('lockout guard: after one auth failure no new host starts; hosts in flight finish', async () => {
    const r = await fleet(
      { a: { error: authError() }, b: { delayMs: 20 }, c: {}, d: {} },
      { parallel: 2 },
    );
    assert.deepEqual(
      r.run.outcomes.map((o) => [o.label, o.result]),
      [
        ['a', 'auth failed'],
        ['b', 'ok'],
        ['c', 'skipped (auth failed on a)'],
        ['d', 'skipped (auth failed on a)'],
      ],
    );
    assert.equal(r.clients.has('c'), false, 'no client for a skipped host');
    assert.equal(r.run.exitCode, 2);
    assert.match(r.stderr, /c +skipped \(auth failed on a\) {2}-/);
  });

  it('--json: no live output, one object per host as it finishes, no table', async () => {
    const r = await fleet(
      {
        a: { chunks: [{ stream: 'stdout', data: 'x\n' }, { stream: 'stderr', data: 'e' }], exitCode: 3 },
        b: { error: connError() },
      },
      { json: true, parallel: 1 },
    );
    assert.equal(r.stderr, '');
    const lines = r.stdout.trim().split('\n').map((l) => JSON.parse(l));
    assert.deepEqual(lines[0], { host: 'a.example.test', label: 'a', exitCode: 3, stdout: 'x\n', stderr: 'e', durationMs: 100 });
    assert.deepEqual(lines[1], {
      host: 'b.example.test',
      label: 'b',
      exitCode: null,
      stdout: '',
      stderr: '',
      durationMs: 100,
      error: { name: 'WinLinuxConnectionError', message: 'connect ECONNREFUSED', exitCode: 3 },
    });
    assert.equal(r.run.exitCode, 3);
  });

  it('Ctrl+C: no new host starts, running commands abort, every client closes, exit 130', async () => {
    const abort = new AbortController();
    const pending = fleet({ a: {}, b: { hang: true }, c: { hang: true }, d: {}, e: {} }, { parallel: 2, signal: abort.signal });
    await new Promise((r) => setTimeout(r, 20));
    abort.abort();
    const r = await pending;
    assert.equal(r.run.exitCode, 130);
    assert.equal(r.clients.has('d'), false, 'no new host after Ctrl+C');
    assert.equal(r.clients.has('e'), false);
    for (const c of r.clients.values()) assert.ok(c.closed >= 1, 'every started client is closed');
    assert.match(r.stderr, /HOST +RESULT +TIME\na +ok/);
    assert.doesNotMatch(r.stderr, /\nb +interrupted/, 'the table lists the hosts that finished');
  });

  it('a stream with no exit code is an error, not a success', async () => {
    const r = await fleet({ a: { exitCode: null } });
    assert.equal(r.run.outcomes[0]?.code, 6);
    assert.notEqual(r.run.exitCode, 0);
  });
});

describe('fleetExitCode and formatTable', () => {
  const o = (code: number, extra: Partial<HostOutcome> = {}): HostOutcome => ({
    host: 'h',
    label: 'h',
    exitCode: null,
    stdout: '',
    stderr: '',
    durationMs: 1234,
    code,
    result: 'r',
    ...extra,
  });
  it('the smallest non-zero code wins; skipped hosts add nothing', () => {
    assert.equal(fleetExitCode([o(0), o(4), o(3)]), 3);
    assert.equal(fleetExitCode([o(0), o(0)]), 0);
    assert.equal(fleetExitCode([o(5), o(2, { skipped: true })]), 5);
    assert.equal(fleetExitCode([o(4), o(1)]), 1);
  });
  it('formats TIME as seconds', () => {
    assert.equal(formatTable([o(0, { result: 'ok', durationMs: 1234 })]), 'HOST  RESULT  TIME\nh     ok      1.2s\n');
  });
});
