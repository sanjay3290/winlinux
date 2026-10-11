// File operations in the facade and CLI: stat, mkdir [-p], rm, rmdir,
// mv, readFile and writeFile reach the SMB session with the paths as given,
// the CLI renders a table or --json, and the shape rules hold.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { PassThrough } from 'node:stream';
import { SmbAlreadyExistsError, SmbIsADirectoryError } from '@winlinux/smb2';
import { createClient } from '../../dist/client.js';
import { execute, HELP, SHELL_HELP, type Io, type LineValues } from '../../dist/cli/app.js';
import { WinLinuxUsageError } from '../../dist/index.js';
import { FakeSmb, fakeDeps } from '../helpers/fakes.js';

function capture(): { io: Io; out: () => string } {
  const stdout = new PassThrough();
  let out = '';
  stdout.on('data', (d: Buffer) => (out += d.toString()));
  return { io: { env: {}, stdin: process.stdin, stdout, stderr: new PassThrough() }, out: () => out };
}

function clientWith(smb: FakeSmb) {
  return createClient('srv', { username: 'alice', password: 'pw-files-1', auth: 'ntlm' }, fakeDeps({ smb: async () => smb }));
}

describe('facade file operations', () => {
  it('pass share and path through to the session, after the share check', async () => {
    const smb = new FakeSmb();
    const client = clientWith(smb);
    const info = await client.stat('C$', 'Temp/a.txt');
    assert.equal(info.sizeBytes, 5n);
    await client.mkdir('C$', 'Temp/new');
    await client.rm('C$', 'Temp/a.txt');
    await client.rmdir('C$', 'Temp/new');
    await client.mv('C$', 'Temp/a.txt', 'Temp/b.txt');
    assert.equal((await client.readFile('C$', 'Temp/b.txt')).toString(), 'fake-content');
    await client.writeFile('C$', 'Temp/c.txt', 'hello');
    assert.deepEqual(smb.ops, [
      { op: 'stat', share: 'C$', path: 'Temp/a.txt' },
      { op: 'mkdir', share: 'C$', path: 'Temp/new' },
      { op: 'deleteFile', share: 'C$', path: 'Temp/a.txt' },
      { op: 'deleteDirectory', share: 'C$', path: 'Temp/new' },
      { op: 'rename', share: 'C$', path: 'Temp/a.txt', to: 'Temp/b.txt' },
      { op: 'readFile', share: 'C$', path: 'Temp/b.txt' },
      { op: 'writeFile', share: 'C$', path: 'Temp/c.txt', data: 'hello' },
    ]);
    for (const bad of [
      () => client.stat('C$/x', 'a'),
      () => client.stat('C$', ''),
      () => client.mkdir('C$', ''),
      () => client.rm('C$', ''),
      () => client.rmdir('C$', ''),
      () => client.mv('C$', '', 'b'),
      () => client.mv('C$', 'a', ''),
      () => client.readFile('', 'a'),
      () => client.writeFile('C$', '', 'x'),
    ]) {
      await assert.rejects(bad(), WinLinuxUsageError);
    }
    assert.equal(smb.ops.length, 7, 'usage errors reach no session');
    await client.close();
  });

  it('mkdir with parents creates each prefix, accepts existing directories and keeps a file collision', async () => {
    const smb = new FakeSmb();
    const existing = new Map<string, boolean>([
      ['a', true], // directory
      ['a/b', true],
      ['x', false], // a file in the way
    ]);
    smb.mkdirImpl = async (_share, path) => {
      if (existing.has(path)) throw new SmbAlreadyExistsError(`already exists: mkdir S/${path}`, 0xc0000035);
      existing.set(path, true);
    };
    smb.statImpl = async (_share, path) => ({
      sizeBytes: 0n,
      mtime: new Date(0),
      atime: new Date(0),
      isDirectory: existing.get(path) === true,
      readonly: false,
    });
    const client = clientWith(smb);
    await client.mkdir('S', 'a/b/c/d', { parents: true });
    assert.deepEqual(
      smb.ops.map((o) => `${o.op} ${o.path}`),
      ['mkdir a', 'stat a', 'mkdir a/b', 'stat a/b', 'mkdir a/b/c', 'mkdir a/b/c/d'],
    );
    assert.equal(existing.get('a/b/c/d'), true);

    smb.ops.length = 0;
    await assert.rejects(client.mkdir('S', 'x/y', { parents: true }), SmbAlreadyExistsError);
    assert.deepEqual(smb.ops.map((o) => `${o.op} ${o.path}`), ['mkdir x', 'stat x']);

    // Without parents an existing directory is the module's error, like mkdir(1).
    smb.ops.length = 0;
    await assert.rejects(client.mkdir('S', 'a'), SmbAlreadyExistsError);
    assert.deepEqual(smb.ops.map((o) => `${o.op} ${o.path}`), ['mkdir a']);
    await client.close();
  });
});

describe('SMB 3 diagnostics', () => {
  it('passes smb.maxDialect through and logs the negotiated dialect, signing and encryption', async () => {
    const smb = new FakeSmb();
    smb.security = { dialect: '3.1.1', signingAlgorithm: 'AES-GMAC', cipher: 'AES-128-GCM', encryptData: true, signing: true };
    const deps = fakeDeps({ smb: async () => smb });
    const lines: string[] = [];
    deps.log = (line) => lines.push(line);
    const client = createClient('srv', { username: 'alice', password: 'pw-files-1', auth: 'ntlm', smb: { maxDialect: '2.1' } }, deps);
    await client.ls('C$');
    assert.equal(deps.smbOpens[0]?.maxDialect, '2.1');
    assert.ok(lines.includes('smb dialect 3.1.1, signing AES-GMAC, encryption AES-128-GCM (whole session)'), lines.join('\n'));
    await client.close();
    const plain = fakeDeps({ smb: async () => new FakeSmb() });
    const c2 = createClient('srv', { username: 'alice', password: 'pw-files-1', auth: 'ntlm' }, plain);
    await c2.ls('C$');
    assert.equal(plain.smbOpens[0]?.maxDialect, undefined, 'default: the module offers up to 3.1.1');

    // -v says whether signing is actually in effect, not only the
    // algorithm the dialect would use.
    const unsigned = new FakeSmb();
    unsigned.security = { dialect: '2.1', signingAlgorithm: 'HMAC-SHA256', cipher: 'none', encryptData: false, signing: false };
    const deps3 = fakeDeps({ smb: async () => unsigned });
    const lines3: string[] = [];
    deps3.log = (line) => lines3.push(line);
    const c3 = createClient('srv', { username: 'alice', password: 'pw-files-1', auth: 'ntlm' }, deps3);
    await c3.ls('C$');
    assert.ok(lines3.includes('smb dialect 2.1, signing off, encryption none'), lines3.join('\n'));
    await c3.close();
    await c2.close();
  });
});

describe('cli file operations', () => {
  const run = async (client: ReturnType<typeof clientWith>, command: 'stat' | 'mkdir' | 'rm' | 'rmdir' | 'mv', args: string[], values: LineValues = {}) => {
    const { io, out } = capture();
    const code = await execute(client, command, args, values, io);
    assert.equal(code, 0);
    return out();
  };

  it('stat renders a table and --json with decimal sizeBytes and ISO times', async () => {
    const smb = new FakeSmb();
    smb.statImpl = async () => ({
      sizeBytes: 12345678901n,
      mtime: new Date('2026-10-09T10:00:00.000Z'),
      atime: new Date('2026-10-09T11:00:00.000Z'),
      isDirectory: true,
      readonly: true,
    });
    const client = clientWith(smb);
    const text = await run(client, 'stat', ['C$/Windows/Temp']);
    assert.equal(
      text,
      'Type  Size         Modified                  Accessed                  ReadOnly  Path\n' +
        'dir   12345678901  2026-10-09T10:00:00.000Z  2026-10-09T11:00:00.000Z  yes       C$/Windows/Temp\n',
    );
    assert.deepEqual(JSON.parse(await run(client, 'stat', ['C$/Windows/Temp'], { json: true })), {
      share: 'C$',
      path: 'Windows/Temp',
      isDirectory: true,
      sizeBytes: '12345678901',
      mtime: '2026-10-09T10:00:00.000Z',
      atime: '2026-10-09T11:00:00.000Z',
      readonly: true,
    });
    await client.close();
  });

  it('mkdir, rm, rmdir and mv print what they did, in text and --json', async () => {
    const smb = new FakeSmb();
    const client = clientWith(smb);
    assert.equal(await run(client, 'mkdir', ['C$/Temp/new']), 'created directory C$/Temp/new\n');
    assert.equal(await run(client, 'mkdir', ['C$/Temp/a/b'], { parents: true }), 'created directory C$/Temp/a/b\n');
    assert.equal(await run(client, 'rm', ['C$/Temp/x.txt']), 'removed C$/Temp/x.txt\n');
    assert.equal(await run(client, 'rmdir', ['C$/Temp/new']), 'removed directory C$/Temp/new\n');
    assert.equal(await run(client, 'mv', ['C$/Temp/a.txt', 'C$/Temp/b.txt']), 'moved C$/Temp/a.txt -> C$/Temp/b.txt\n');
    assert.deepEqual(JSON.parse(await run(client, 'mkdir', ['C$/Temp/j'], { json: true })), { share: 'C$', path: 'Temp/j' });
    assert.deepEqual(JSON.parse(await run(client, 'rm', ['C$/Temp/j.txt'], { json: true })), { share: 'C$', path: 'Temp/j.txt' });
    assert.deepEqual(JSON.parse(await run(client, 'rmdir', ['C$/Temp/j'], { json: true })), { share: 'C$', path: 'Temp/j' });
    assert.deepEqual(JSON.parse(await run(client, 'mv', ['C$/Temp/j.txt', 'C$/k.txt'], { json: true })), {
      share: 'C$',
      from: 'Temp/j.txt',
      to: 'k.txt',
    });
    assert.deepEqual(
      smb.ops.map((o) => `${o.op} ${o.share}/${o.path}${o.to ? ' -> ' + o.to : ''}`),
      [
        'mkdir C$/Temp/new',
        'mkdir C$/Temp',
        'mkdir C$/Temp/a',
        'mkdir C$/Temp/a/b',
        'deleteFile C$/Temp/x.txt',
        'deleteDirectory C$/Temp/new',
        'rename C$/Temp/a.txt -> Temp/b.txt',
        'mkdir C$/Temp/j',
        'deleteFile C$/Temp/j.txt',
        'deleteDirectory C$/Temp/j',
        'rename C$/Temp/j.txt -> k.txt',
      ],
    );
    await client.close();
  });

  it('usage errors: a bare share, mv across shares, -p elsewhere, and arity', async () => {
    const client = clientWith(new FakeSmb());
    const { io } = capture();
    await assert.rejects(execute(client, 'stat', ['C$'], {}, io), /stat needs <share>\/<path>: C\$/);
    await assert.rejects(execute(client, 'mkdir', ['C$/'], {}, io), /mkdir needs <share>\/<path>/);
    await assert.rejects(execute(client, 'rm', ['C$'], {}, io), /rm needs <share>\/<path>/);
    await assert.rejects(execute(client, 'rmdir', ['C$'], {}, io), /rmdir needs <share>\/<path>/);
    await assert.rejects(execute(client, 'mv', ['C$/a', 'D$/a'], {}, io), /mv works within one share: C\$ and D\$ differ/);
    await assert.rejects(execute(client, 'mv', ['C$/a'], {}, io), /wrong number of arguments for mv/);
    await assert.rejects(execute(client, 'rm', ['C$/a', 'C$/b'], {}, io), /wrong number of arguments for rm/);
    await assert.rejects(execute(client, 'rm', ['C$/a'], { parents: true }, io), /--parents applies to mkdir only, not rm/);
    await assert.rejects(execute(client, 'ls', ['C$'], { parents: true }, io), /--parents applies to mkdir only, not ls/);
    await client.close();
  });

  it('module errors pass through unchanged (exit 5 in the CLI)', async () => {
    const smb = new FakeSmb();
    smb.deleteFile = async (share: string, path: string) => {
      throw new SmbIsADirectoryError(`is a directory: ${share}/${path}; use rmdir`);
    };
    const client = clientWith(smb);
    const { io } = capture();
    await assert.rejects(execute(client, 'rm', ['C$/Temp'], {}, io), (err: unknown) => {
      assert.ok(err instanceof SmbIsADirectoryError);
      assert.equal(err.message, 'is a directory: C$/Temp; use rmdir');
      return true;
    });
    await client.close();
  });

  it('help lists the commands and the mkdir flag', () => {
    for (const line of [/winlinux stat\s+\[flags\] <target> <share>\/<path>/, /winlinux mkdir\s+\[flags\] \[-p\]/, /winlinux rm\s+/, /winlinux rmdir\s+/, /winlinux mv\s+\[flags\] <target> <share>\/<from> <share>\/<to>/, /-p, --parents/]) {
      assert.match(HELP, line);
    }
    for (const line of [/stat <share>\/<path> \[--json\]/, /mkdir \[-p\] <share>\/<path> \[--json\]/, /rm <share>\/<path> \[--json\]/, /rmdir <share>\/<path> \[--json\]/, /mv <share>\/<from> <share>\/<to> \[--json\]/]) {
      assert.match(SHELL_HELP, line);
    }
  });
});
