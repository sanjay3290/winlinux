// Recursive transfer: name and path safety, the local walk, the
// pool, getDir/putDir over a fake and a mock SMB session, and the CLI.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { PassThrough } from 'node:stream';
import { connect as smbConnect, SmbError, SmbNotFoundError, type DirEntry } from '@winlinux/smb2';
import { createClient } from '../../dist/client.js';
import { execute, HELP, interruptSubcommand, type Io, type LineValues } from '../../dist/cli/app.js';
import { exitCodeFor, EXIT } from '../../dist/errors.js';
import { WinLinuxAbortError, WinLinuxUsageError } from '../../dist/index.js';
import type { WinLinuxClient } from '../../dist/types.js';
import { checkLocalName, checkParallel, checkRemoteName, runPool, safeJoin, walkLocal } from '../../dist/tree.js';
import { StubAuthProvider as SmbStubProvider } from '../../../smb2/dist-test/test/helpers/stub-provider.js';
import { MockSmbServer } from '../../../smb2/dist-test/test/mock/server.js';
import { FakeSmb, fakeDeps } from '../helpers/fakes.js';

const OPTS = { username: 'u', password: 'p', auth: 'ntlm' as const };
const tempDir = () => fs.mkdtempSync(path.join(os.tmpdir(), 'winlinux-tree-'));
const entry = (name: string, isDirectory = false, size = 1, isReparsePoint = false): DirEntry => ({
  name,
  isDirectory,
  sizeBytes: BigInt(size),
  mtime: new Date(0),
  isReparsePoint,
});

// Lists the files under `dir`, relative, sorted, with their contents.
function snapshot(dir: string): Record<string, string> {
  const out: Record<string, string> = {};
  const walk = (rel: string) => {
    for (const d of fs.readdirSync(path.join(dir, rel), { withFileTypes: true })) {
      const r = rel ? `${rel}/${d.name}` : d.name;
      if (d.isDirectory()) {
        out[`${r}/`] = '';
        walk(r);
      } else out[r] = fs.readFileSync(path.join(dir, r), 'utf8');
    }
  };
  walk('');
  return out;
}

function capture(tty = false): { io: Io; out: () => string; err: () => string } {
  const stdout = new PassThrough();
  const stderr = Object.assign(new PassThrough(), { isTTY: tty });
  let out = '';
  let err = '';
  stdout.on('data', (d: Buffer) => (out += d.toString()));
  stderr.on('data', (d: Buffer) => (err += d.toString()));
  return { io: { env: {}, stdin: process.stdin, stdout, stderr }, out: () => out, err: () => err };
}

// A fake remote tree: path ('' = share root) -> entries; file contents by path.
function fakeRemote(smb: FakeSmb, tree: Record<string, DirEntry[]>, contents: Record<string, string> = {}) {
  smb.listImpl = async (_share, dir) => {
    const list = tree[dir ?? ''];
    if (!list) throw new SmbNotFoundError(`no such file or directory: list ${dir}`, 0xc0000034);
    return list;
  };
  smb.statImpl = async (_share, p) => ({ sizeBytes: 0n, mtime: new Date(0), atime: new Date(0), isDirectory: p in tree, readonly: false });
  smb.downloadImpl = async (_share, remote, local) => fs.writeFileSync(local, contents[remote] ?? `content of ${remote}`);
}

describe('tree safety', () => {
  it('refuses unsafe remote names, and names Windows cannot hold on a Windows client', () => {
    for (const bad of ['', '.', '..', 'a/b', 'a\\b', '/etc', 'x\0y']) assert.throws(() => checkRemoteName(bad, 'linux'), SmbError, bad);
    for (const ok of ['a', 'é ü.txt', '日本語', 'a:b', 'CON']) checkRemoteName(ok, 'linux');
    for (const bad of ['a:b', 'CON', 'nul.txt', 'x?', 'trail.', 'trail ']) assert.throws(() => checkRemoteName(bad, 'win32'), SmbError, bad);
  });

  it('refuses local names Windows cannot hold for put -r', () => {
    for (const bad of ['a\\b', 'a:b', 'q?', 'LPT1', 'dot.']) assert.throws(() => checkLocalName(bad), WinLinuxUsageError, bad);
    checkLocalName('normal name.txt');
  });

  it('safeJoin never leaves the root', () => {
    const root = path.join(os.tmpdir(), 'root');
    assert.equal(safeJoin(root, ['a', 'b']), path.join(root, 'a', 'b'));
    assert.equal(safeJoin(root, []), root);
    assert.throws(() => safeJoin(root, ['..', 'x']), /refusing to write outside/);
    assert.throws(() => safeJoin(root, ['a', '..', '..', 'x']), /refusing to write outside/);
    assert.throws(() => safeJoin(root, ['/etc/passwd']), /refusing to write outside/);
  });

  it('parallel is an integer from 1 to 8', () => {
    assert.equal(checkParallel(undefined), 1);
    assert.equal(checkParallel(8), 8);
    for (const bad of [0, 9, 1.5, -1]) assert.throws(() => checkParallel(bad), WinLinuxUsageError);
  });

  it('runPool caps concurrency, stops on the first failure, and stops on abort', async () => {
    let inFlight = 0;
    let peak = 0;
    const seen: number[] = [];
    await runPool([1, 2, 3, 4, 5, 6, 7], 3, undefined, async (n) => {
      inFlight++;
      peak = Math.max(peak, inFlight);
      await new Promise((r) => setTimeout(r, 5));
      seen.push(n);
      inFlight--;
    });
    assert.equal(peak, 3);
    assert.equal(seen.length, 7);

    const started: number[] = [];
    await assert.rejects(
      runPool([1, 2, 3, 4], 1, undefined, async (n) => {
        started.push(n);
        if (n === 2) throw new Error('boom 2');
      }),
      /boom 2/,
    );
    assert.deepEqual(started, [1, 2]);

    const abort = new AbortController();
    const ran: number[] = [];
    await runPool([1, 2, 3], 1, abort.signal, async (n) => {
      ran.push(n);
      abort.abort();
    });
    assert.deepEqual(ran, [1]);
  });

  it('walkLocal skips symlinks and special files and never follows them', async () => {
    const dir = tempDir();
    try {
      fs.mkdirSync(path.join(dir, 'sub', 'empty'), { recursive: true });
      fs.writeFileSync(path.join(dir, 'a.txt'), 'aaa');
      fs.writeFileSync(path.join(dir, 'sub', 'b.txt'), 'b');
      fs.symlinkSync(os.tmpdir(), path.join(dir, 'link-dir'));
      fs.symlinkSync(path.join(dir, 'a.txt'), path.join(dir, 'link-file'));
      execFileSync('mkfifo', [path.join(dir, 'fifo')]);
      const plan = await walkLocal(dir);
      assert.deepEqual(plan.dirs, ['', 'sub', 'sub/empty']);
      assert.deepEqual(plan.files, [{ rel: 'a.txt', size: 3 }, { rel: 'sub/b.txt', size: 1 }]);
      assert.deepEqual(plan.skipped, [
        { path: 'fifo', reason: 'special file' },
        { path: 'link-dir', reason: 'symlink' },
        { path: 'link-file', reason: 'symlink' },
      ]);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('getDir and putDir (fake session)', () => {
  it('getDir copies a tree into <dir>/<base>, skips reparse points, and reports events', async () => {
    const dir = tempDir();
    const smb = new FakeSmb();
    fakeRemote(smb, {
      data: [entry('a.txt', false, 3), entry('sub', true, 0), entry('link', true, 0, true), entry('empty', true, 0)],
      'data/sub': [entry('é.txt', false, 2), entry('deeper', true, 0)],
      'data/sub/deeper': [entry('z.bin', false, 1)],
      'data/empty': [],
    }, { 'data/a.txt': 'aaa', 'data/sub/é.txt': 'éé' });
    const client = createClient('h', OPTS, fakeDeps({ smb: async () => smb }));
    const events: string[] = [];
    try {
      const summary = await client.getDir('S', 'data/', dir, {
        onFile: (e) => events.push(`start ${e.index}/${e.total} ${e.path}`),
        onFileDone: (e) => events.push(`done ${e.path}`),
        onSkip: (e) => events.push(`skip ${e.reason} ${e.path}`),
      });
      const target = path.join(dir, 'data');
      assert.deepEqual(summary, { share: 'S', remotePath: 'data', localPath: target, directories: 4, skipped: 1, files: 3, bytes: Buffer.byteLength('aaa') + Buffer.byteLength('éé') + 'content of data/sub/deeper/z.bin'.length });
      assert.deepEqual(snapshot(target), {
        'a.txt': 'aaa',
        'empty/': '',
        'sub/': '',
        'sub/deeper/': '',
        'sub/deeper/z.bin': 'content of data/sub/deeper/z.bin',
        'sub/é.txt': 'éé',
      });
      assert.deepEqual(events, [
        'skip reparse point link',
        'start 1/3 a.txt', 'done a.txt',
        'start 2/3 sub/é.txt', 'done sub/é.txt',
        'start 3/3 sub/deeper/z.bin', 'done sub/deeper/z.bin',
      ]);
      // No temp file is left behind.
      assert.ok(!Object.keys(snapshot(target)).some((k) => k.endsWith('.part')));
    } finally {
      await client.close();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('getDir into a missing directory makes it the copy; refuses a file root, a missing parent and unsafe names', async () => {
    const dir = tempDir();
    const smb = new FakeSmb();
    fakeRemote(smb, { d: [entry('f', false)], evil: [entry('..', true)], 'evil2': [entry('x/../../y', false)] });
    const client = createClient('h', OPTS, fakeDeps({ smb: async () => smb }));
    try {
      const fresh = path.join(dir, 'fresh');
      const summary = await client.getDir('S', 'd', fresh);
      assert.equal(summary.localPath, fresh);
      assert.deepEqual(snapshot(fresh), { f: 'content of d/f' });
      fs.writeFileSync(path.join(dir, 'file'), 'x');
      await assert.rejects(client.getDir('S', 'd', path.join(dir, 'file')), /get -r: not a directory/);
      await assert.rejects(client.getDir('S', 'd', path.join(dir, 'no', 'such')), /get -r: no such directory/);
      await assert.rejects(client.getDir('S', 'd/f', dir), /not a directory: S\/d\/f; use get without -r/);
      await assert.rejects(client.getDir('S', 'evil', dir), /unsafe remote name refused: "\.\."/);
      await assert.rejects(client.getDir('S', 'evil2', dir), /unsafe remote name refused/);
      await assert.rejects(client.getDir('S', 'd', dir, { parallel: 9 }), WinLinuxUsageError);
      assert.ok(!fs.existsSync(path.join(dir, 'y')) && !fs.existsSync(path.join(os.tmpdir(), 'y')));
    } finally {
      await client.close();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('getDir stops on the first failed file, keeps copied files and leaves no temp file', async () => {
    const dir = tempDir();
    const smb = new FakeSmb();
    fakeRemote(smb, { d: [entry('1'), entry('2'), entry('3')] });
    smb.downloadImpl = async (_share, remote, local) => {
      fs.writeFileSync(local, 'partial');
      if (remote === 'd/2') throw new SmbError(`SMB request failed during download S/${remote} to ${local}`, 0xc0000185);
    };
    const client = createClient('h', OPTS, fakeDeps({ smb: async () => smb }));
    try {
      await assert.rejects(client.getDir('S', 'd', dir), (err: unknown) => {
        assert.ok(err instanceof SmbError);
        assert.equal(exitCodeFor(err), EXIT.file);
        assert.match(err.message, /download S\/d\/2 to .*[/\\]d[/\\]2 /, 'the error names the failed file');
        return true;
      });
      assert.deepEqual(snapshot(path.join(dir, 'd')), { '1': 'partial' });
    } finally {
      await client.close();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('an abort stops after the file in flight: WinLinuxAbortError, exit 130, copied files stay', async () => {
    const dir = tempDir();
    const smb = new FakeSmb();
    fakeRemote(smb, { d: [entry('1'), entry('2'), entry('3')] });
    const abort = new AbortController();
    const client = createClient('h', OPTS, fakeDeps({ smb: async () => smb }));
    try {
      await assert.rejects(
        client.getDir('S', 'd', dir, { signal: abort.signal, onFile: (e) => e.index === 1 && abort.abort() }),
        (err: unknown) => {
          assert.ok(err instanceof WinLinuxAbortError);
          assert.equal(err.message, 'interrupted after 1 of 3 files');
          assert.equal(exitCodeFor(err), EXIT.interrupted);
          return true;
        },
      );
      assert.deepEqual(snapshot(path.join(dir, 'd')), { '1': 'content of d/1' });
    } finally {
      await client.close();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('putDir uploads into an existing remote directory or creates the target, skipping symlinks', async () => {
    const dir = tempDir();
    const src = path.join(dir, 'proj');
    fs.mkdirSync(path.join(src, 'src', 'empty'), { recursive: true });
    fs.writeFileSync(path.join(src, 'README'), 'hi');
    fs.writeFileSync(path.join(src, 'src', 'main.ts'), 'code');
    fs.symlinkSync('/etc/hostname', path.join(src, 'link'));
    const smb = new FakeSmb();
    const existing = new Set(['Upload']);
    smb.statImpl = async (_share, p) => {
      if (!existing.has(p)) throw new SmbNotFoundError(`no such file or directory: stat S/${p}`, 0xc0000034);
      return { sizeBytes: 0n, mtime: new Date(0), atime: new Date(0), isDirectory: true, readonly: false };
    };
    smb.mkdirImpl = async (_share, p) => void existing.add(p);
    const client = createClient('h', OPTS, fakeDeps({ smb: async () => smb }));
    const skips: string[] = [];
    try {
      const into = await client.putDir(src, 'S', 'Upload', { onSkip: (e) => skips.push(`${e.reason} ${e.path}`), parallel: 2 });
      assert.deepEqual(into, { share: 'S', remotePath: 'Upload/proj', localPath: src, directories: 3, skipped: 1, files: 2, bytes: 6 });
      assert.deepEqual(skips, ['symlink link']);
      assert.deepEqual(smb.ops.filter((o) => o.op === 'mkdir').map((o) => o.path), ['Upload/proj', 'Upload/proj/src', 'Upload/proj/src/empty']);
      assert.deepEqual(smb.uploads.map((u) => u.remotePath).sort(), ['Upload/proj/README', 'Upload/proj/src/main.ts']);
      assert.deepEqual(smb.uploads.map((u) => u.localPath).sort(), [path.join(src, 'README'), path.join(src, 'src', 'main.ts')]);

      smb.uploads.length = 0;
      const fresh = await client.putDir(src, 'S', 'New/');
      assert.equal(fresh.remotePath, 'New');
      assert.deepEqual(smb.uploads.map((u) => u.remotePath).sort(), ['New/README', 'New/src/main.ts']);

      // The local side is checked before any SMB open.
      await assert.rejects(client.putDir(path.join(dir, 'missing'), 'S', 'x'), /put -r: local directory .*missing: no such directory/);
      await assert.rejects(client.putDir(path.join(src, 'README'), 'S', 'x'), /not a directory/);
      fs.writeFileSync(path.join(src, 'bad:name'), 'x');
      await assert.rejects(client.putDir(src, 'S', 'x'), /local name is not valid on Windows: "bad:name"/);
    } finally {
      await client.close();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('getDir over the SMB mock server', () => {
  it('walks nested directories with Unicode names, skips a reparse point, refuses a name with separators', async () => {
    const big = Buffer.alloc(70000, 7);
    const server = new MockSmbServer({
      securityMode: 0,
      files: new Map([
        ['tree', { data: Buffer.alloc(0), isDirectory: true }],
        ['tree\\a.txt', { data: Buffer.from('alpha'), isDirectory: false }],
        ['tree\\ünï', { data: Buffer.alloc(0), isDirectory: true }],
        ['tree\\ünï\\日本.bin', { data: big, isDirectory: false }],
        ['tree\\empty', { data: Buffer.alloc(0), isDirectory: true }],
        ['bad', { data: Buffer.alloc(0), isDirectory: true }],
      ]),
      dirTree: new Map([
        ['tree', [
          { name: 'a.txt', isDirectory: false, size: 5 },
          { name: 'ünï', isDirectory: true, size: 0 },
          { name: 'junction', isDirectory: true, size: 0, reparse: true },
          { name: 'empty', isDirectory: true, size: 0 },
        ]],
        ['tree\\ünï', [{ name: '日本.bin', isDirectory: false, size: big.length }]],
        ['tree\\empty', []],
        // smb2 drops '.' and '..' from listings itself; a name with
        // separators must still be refused here.
        ['bad', [{ name: '..\\..\\evil', isDirectory: false, size: 1 }]],
      ]),
    });
    const port = await server.listen();
    const dir = tempDir();
    const deps = fakeDeps({});
    deps.smbConnect = async (o) => smbConnect(o);
    deps.createAuthProvider = () => new SmbStubProvider({ sessionKey: Buffer.alloc(16, 1) });
    const client = createClient('127.0.0.1', { ...OPTS, smb: { port } }, deps);
    try {
      const skips: string[] = [];
      const summary = await client.getDir('share', 'tree', dir, { parallel: 2, onSkip: (e) => skips.push(`${e.reason} ${e.path}`) });
      assert.deepEqual({ ...summary, localPath: undefined }, { share: 'share', remotePath: 'tree', localPath: undefined, directories: 3, skipped: 1, files: 2, bytes: 5 + big.length });
      assert.deepEqual(skips, ['reparse point junction']);
      const target = path.join(dir, 'tree');
      assert.equal(fs.readFileSync(path.join(target, 'a.txt'), 'utf8'), 'alpha');
      assert.deepEqual(fs.readFileSync(path.join(target, 'ünï', '日本.bin')), big);
      assert.ok(fs.statSync(path.join(target, 'empty')).isDirectory());
      assert.equal(server.connections, 1, 'one SMB session for the whole copy');
      await assert.rejects(client.getDir('share', 'bad', dir), /unsafe remote name refused/);
    } finally {
      await client.close();
      await server.close();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('cli get -r and put -r', () => {
  it('prints a summary line or one --json object, progress only on a TTY, skips always', async () => {
    const dir = tempDir();
    const smb = new FakeSmb();
    fakeRemote(smb, { d: [entry('x'), entry('l', false, 1, true)] });
    const client = createClient('h', OPTS, fakeDeps({ smb: async () => smb }));
    try {
      const plain = capture();
      assert.equal(await execute(client, 'get', ['S/d', dir], { recursive: true }, plain.io), 0);
      assert.equal(plain.out(), `downloaded S/d -> ${path.join(dir, 'd')} (1 files, 1 directories, 14 bytes, 1 skipped)\n`);
      assert.equal(plain.err(), 'winlinux: skipped reparse point l\n');

      const tty = capture(true);
      assert.equal(await execute(client, 'get', ['S/d', path.join(dir, 'again')], { recursive: true, json: true }, tty.io), 0);
      assert.deepEqual(JSON.parse(tty.out()), { files: 1, directories: 1, bytes: 14, skipped: 1 });
      assert.match(tty.err(), /\[1\/1\] x/);

      fs.mkdirSync(path.join(dir, 'up'));
      fs.writeFileSync(path.join(dir, 'up', 'f'), 'abc');
      smb.statImpl = async (_s, p) => {
        throw new SmbNotFoundError(`no such file or directory: stat S/${p}`, 0xc0000034);
      };
      const put = capture();
      assert.equal(await execute(client, 'put', [path.join(dir, 'up'), 'S/dest'], { recursive: true, parallel: '3' }, put.io), 0);
      assert.equal(put.out(), `uploaded ${path.join(dir, 'up')} -> S/dest (1 files, 1 directories, 3 bytes, 0 skipped)\n`);
    } finally {
      await client.close();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('a failure names the stop point; usage errors for --parallel', async () => {
    const dir = tempDir();
    const smb = new FakeSmb();
    fakeRemote(smb, { d: [entry('1'), entry('2')] });
    smb.downloadImpl = async (_s, remote, local) => {
      if (remote === 'd/2') throw new SmbError(`SMB request failed during download S/${remote}`, 0xc0000185);
      fs.writeFileSync(local, 'ok');
    };
    const client = createClient('h', OPTS, fakeDeps({ smb: async () => smb }));
    try {
      const c = capture();
      await assert.rejects(execute(client, 'get', ['S/d', dir], { recursive: true }, c.io), SmbError);
      assert.equal(c.err(), 'winlinux: get -r stopped after 1 of 2 files; copied files stay\n');
      for (const [values, pattern] of [
        [{ parallel: '2' }, /--parallel needs -r/],
        [{ recursive: true, parallel: '0' }, /--parallel must be an integer from 1 to 8/],
        [{ recursive: true, parallel: '9' }, /--parallel must be an integer from 1 to 8/],
        [{ recursive: true, parallel: 'x' }, /--parallel must be an integer from 1 to 8/],
      ] as Array<[LineValues, RegExp]>) {
        await assert.rejects(execute(client, 'get', ['S/d', dir], values, capture().io), pattern);
      }
      await assert.rejects(execute(client, 'ls', ['S'], { recursive: true }, capture().io), /--recursive applies to get and put only, not ls/);
      assert.match(HELP, /winlinux get -r \[flags\] <target> <share>\[\/<dir>\] \[<localDir>\]/);
      assert.match(HELP, /--parallel <n>/);
    } finally {
      await client.close();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('first Ctrl+C on -r waits for the copy to settle, then closes', async () => {
    let closes = 0;
    const client = { close: async () => void (closes += 1) } as unknown as WinLinuxClient;
    const abort = new AbortController();
    let settle!: () => void;
    const running = new Promise<number>((_r, reject) => (settle = () => reject(new WinLinuxAbortError(1, 3))));
    const done = interruptSubcommand('get', client, running, abort, true);
    assert.equal(abort.signal.aborted, true);
    await new Promise((r) => setTimeout(r, 20));
    assert.equal(closes, 0, 'the file in flight finishes first');
    settle();
    await done;
    assert.equal(closes, 1);
  });
});
