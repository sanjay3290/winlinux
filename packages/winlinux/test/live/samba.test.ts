// Live test against dperson/samba in Docker. Same container
// arguments as packages/smb2/test/live/samba.test.ts, with server signing
// required. Docker down fails the run: it is a blocked condition, not a skip.
//
// Env overrides so parallel runs do not collide:
//   WINLINUX_LIVE_SAMBA_NAME  container name (default winlinux-live-samba-<pid>)
//   WINLINUX_LIVE_SAMBA_PORT  host port for 445 (default: a free port)
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { connect, SmbAlreadyExistsError, SmbDirectoryNotEmptyError, SmbIsADirectoryError, SmbNotFoundError, WinLinuxAuthError } from '../../dist/index.js';
import { runCli } from '../helpers/cli.js';
import { countingListener } from '../helpers/listeners.js';

const IMAGE = 'dperson/samba:latest';
const USER = 'testuser';
const PASS = 'testpass123';
const SHARE = 'testshare';
const DOMAIN = 'WORKGROUP';
const CONTAINER = process.env.WINLINUX_LIVE_SAMBA_NAME ?? `winlinux-live-samba-${process.pid}`;

const execFileAsync = promisify(execFile);

async function docker(...args: string[]): Promise<string> {
  try {
    const { stdout } = await execFileAsync('docker', args, { encoding: 'utf8' });
    return stdout;
  } catch (error) {
    const stderr = (error as { stderr?: string }).stderr ?? (error as Error).message;
    throw new Error(`docker ${args.join(' ')} failed: ${stderr}`);
  }
}

async function freePort(): Promise<number> {
  const server = net.createServer();
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = (server.address() as net.AddressInfo).port;
  await new Promise<void>((resolve) => server.close(() => resolve()));
  return port;
}

function sha256(file: string): string {
  return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

// The docker proxy accepts TCP before smbd is up, so poll with a real
// bad-password logon through the facade until the server says LOGON_FAILURE.
async function waitForSmb(port: number, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const client = await connect('127.0.0.1', {
      username: USER,
      password: 'wrong-password',
      domain: DOMAIN,
      smb: { port, requestTimeoutMs: 3000 },
    });
    try {
      await client.listShares();
      throw new Error('bad-password logon unexpectedly succeeded');
    } catch (error) {
      if (error instanceof WinLinuxAuthError) return;
      if (Date.now() > deadline) throw new Error(`timed out waiting for SMB on 127.0.0.1:${port}: ${(error as Error).message}`);
      await new Promise((resolve) => setTimeout(resolve, 1000));
    } finally {
      await client.close();
    }
  }
}

describe('live samba (server signing = required)', () => {
  let port = 0;
  let work = '';

  before(async () => {
    port = process.env.WINLINUX_LIVE_SAMBA_PORT ? Number(process.env.WINLINUX_LIVE_SAMBA_PORT) : await freePort();
    work = fs.mkdtempSync(path.join(os.tmpdir(), 'winlinux-live-'));
    await docker('rm', '-f', CONTAINER).catch(() => undefined);
    await docker(
      'run', '-d', '--rm', '--name', CONTAINER,
      '-p', `127.0.0.1:${port}:445`,
      IMAGE,
      '-u', `${USER};${PASS}`,
      '-s', `${SHARE};/share;yes;no;no;${USER}`,
      '-p',
      '-g', 'server signing = required',
      '-w', DOMAIN,
    );
    await waitForSmb(port, 90000);
  }, { timeout: 180000 });

  after(async () => {
    await docker('rm', '-f', CONTAINER).catch(() => undefined);
    if (work) fs.rmSync(work, { recursive: true, force: true });
  }, { timeout: 60000 });

  it('facade lists shares and round-trips a file', { timeout: 120000 }, async () => {
    const source = path.join(work, 'lib-source.bin');
    const back = path.join(work, 'lib-back.bin');
    fs.writeFileSync(source, crypto.randomBytes(1024 * 1024));
    // Default auth 'negotiate' with a password: SMB uses NTLM.
    const client = await connect('127.0.0.1', {
      username: USER,
      password: PASS,
      domain: DOMAIN,
      smb: { port, requestTimeoutMs: 15000 },
    });
    try {
      const shares = await client.listShares();
      assert.ok(shares.some((s) => s.name === SHARE), JSON.stringify(shares));
      await client.put(source, SHARE, 'lib-roundtrip.bin');
      await client.get(SHARE, 'lib-roundtrip.bin', back);
      assert.equal(sha256(back), sha256(source));
      const entries = await client.ls(SHARE);
      const entry = entries.find((e) => e.name === 'lib-roundtrip.bin');
      assert.ok(entry, JSON.stringify(entries.map((e) => e.name)));
      assert.equal(entry.sizeBytes, 1024n * 1024n);
      assert.equal(entry.isDirectory, false);
    } finally {
      await client.close();
    }
  });

  it('cli shares, ls, put, get round-trip with equal SHA-256', { timeout: 120000 }, async () => {
    const source = path.join(work, 'cli-source.bin');
    const back = path.join(work, 'cli-back.bin');
    fs.writeFileSync(source, crypto.randomBytes(1024 * 1024 + 123));
    const env = { WINLINUX_PASSWORD: PASS };
    const common = ['-d', DOMAIN, '--smb-port', String(port)];
    const target = `${USER}@127.0.0.1`;

    const shares = await runCli(['shares', ...common, target], env);
    assert.equal(shares.code, 0, shares.stderr);
    assert.match(shares.stdout, /^Name\s+Type\s+Comment\n/);
    assert.match(shares.stdout, new RegExp(`^${SHARE}\\s+disk`, 'm'));

    const put = await runCli(['put', ...common, target, source, `${SHARE}/cli-roundtrip.bin`], env);
    assert.equal(put.code, 0, put.stderr);
    assert.equal(put.stdout, `uploaded ${source} -> ${SHARE}/cli-roundtrip.bin (${1024 * 1024 + 123} bytes)\n`);

    const ls = await runCli(['ls', ...common, target, SHARE], env);
    assert.equal(ls.code, 0, ls.stderr);
    assert.match(ls.stdout, new RegExp(`^- +${1024 * 1024 + 123} \\d{4}-\\d\\d-\\d\\dT[^ ]+Z cli-roundtrip\\.bin$`, 'm'));

    const lsJson = await runCli(['ls', ...common, '--json', target, SHARE], env);
    assert.equal(lsJson.code, 0, lsJson.stderr);
    const entry = (JSON.parse(lsJson.stdout) as Array<{ name: string; sizeBytes: string }>).find((e) => e.name === 'cli-roundtrip.bin');
    assert.equal(entry?.sizeBytes, String(1024 * 1024 + 123));

    const get = await runCli(['get', ...common, '--json', target, `${SHARE}/cli-roundtrip.bin`, back], env);
    assert.equal(get.code, 0, get.stderr);
    assert.deepEqual(JSON.parse(get.stdout), {
      share: SHARE,
      remotePath: 'cli-roundtrip.bin',
      localPath: back,
      sizeBytes: String(1024 * 1024 + 123),
    });
    assert.equal(sha256(back), sha256(source));

    const missing = await runCli(['get', ...common, target, `${SHARE}/no-such-file.bin`, path.join(work, 'x')], env);
    assert.equal(missing.code, 5, missing.stderr);
    assert.match(missing.stderr, /SmbNotFoundError/);

    const badPw = await runCli(['shares', ...common, target], { WINLINUX_PASSWORD: 'wrong-password' });
    assert.equal(badPw.code, 2, badPw.stderr);
    for (const r of [shares, put, ls, lsJson, get, missing]) {
      assert.ok(!r.stdout.includes(PASS) && !r.stderr.includes(PASS));
    }
  });

  it('facade stat, mkdir -p, writeFile, readFile, mv, rm and rmdir', { timeout: 120000 }, async () => {
    const client = await connect('127.0.0.1', {
      username: USER,
      password: PASS,
      domain: DOMAIN,
      smb: { port, requestTimeoutMs: 15000 },
    });
    try {
      await client.mkdir(SHARE, 'ops/a/b', { parents: true });
      await client.mkdir(SHARE, 'ops/a/b', { parents: true }); // idempotent
      await assert.rejects(client.mkdir(SHARE, 'ops/a/b'), SmbAlreadyExistsError);
      await client.writeFile(SHARE, 'ops/a/b/one.txt', 'one\n');
      assert.equal((await client.readFile(SHARE, 'ops/a/b/one.txt')).toString(), 'one\n');
      const file = await client.stat(SHARE, 'ops/a/b/one.txt');
      assert.equal(file.isDirectory, false);
      assert.equal(file.sizeBytes, 4n);
      const dir = await client.stat(SHARE, 'ops/a');
      assert.equal(dir.isDirectory, true);
      await assert.rejects(client.rm(SHARE, 'ops/a/b'), SmbIsADirectoryError);
      await assert.rejects(client.rmdir(SHARE, 'ops/a'), SmbDirectoryNotEmptyError);
      await client.mv(SHARE, 'ops/a/b/one.txt', 'ops/two.txt');
      assert.deepEqual((await client.ls(SHARE, 'ops/a/b')).map((e) => e.name), []);
      await assert.rejects(client.stat(SHARE, 'ops/a/b/one.txt'), SmbNotFoundError);
      await client.mv(SHARE, 'ops/a/b', 'ops/c');
      assert.deepEqual((await client.ls(SHARE, 'ops/a')).map((e) => e.name), []);
      await client.rm(SHARE, 'ops/two.txt');
      await client.rmdir(SHARE, 'ops/c');
      await client.rmdir(SHARE, 'ops/a');
      await client.rmdir(SHARE, 'ops');
      assert.ok(!(await client.ls(SHARE)).some((e) => e.name === 'ops'));
    } finally {
      await client.close();
    }
  });

  it('cli stat, mkdir -p, mv, rm and rmdir with exit codes', { timeout: 120000 }, async () => {
    const env = { WINLINUX_PASSWORD: PASS };
    const common = ['-d', DOMAIN, '--smb-port', String(port)];
    const target = `${USER}@127.0.0.1`;
    const source = path.join(work, 'cli-ops.txt');
    fs.writeFileSync(source, 'cli ops\n');

    const mkdir = await runCli(['mkdir', ...common, '-p', target, `${SHARE}/cli-ops/deep/er`], env);
    assert.equal(mkdir.code, 0, mkdir.stderr);
    assert.equal(mkdir.stdout, `created directory ${SHARE}/cli-ops/deep/er\n`);
    const again = await runCli(['mkdir', ...common, target, `${SHARE}/cli-ops`], env);
    assert.equal(again.code, 5, again.stderr);
    assert.match(again.stderr, /SmbAlreadyExistsError/);

    const put = await runCli(['put', ...common, target, source, `${SHARE}/cli-ops/deep/er/f.txt`], env);
    assert.equal(put.code, 0, put.stderr);
    const stat = await runCli(['stat', ...common, '--json', target, `${SHARE}/cli-ops/deep/er/f.txt`], env);
    assert.equal(stat.code, 0, stat.stderr);
    const info = JSON.parse(stat.stdout) as { isDirectory: boolean; sizeBytes: string; path: string };
    assert.equal(info.isDirectory, false);
    assert.equal(info.sizeBytes, '8');
    assert.equal(info.path, 'cli-ops/deep/er/f.txt');
    const statDir = await runCli(['stat', ...common, target, `${SHARE}/cli-ops`], env);
    assert.equal(statDir.code, 0, statDir.stderr);
    assert.match(statDir.stdout, new RegExp(`^dir\\s+\\d+\\s+\\S+\\s+\\S+\\s+no\\s+${SHARE}/cli-ops$`, 'm'));

    const rmDir = await runCli(['rm', ...common, target, `${SHARE}/cli-ops/deep`], env);
    assert.equal(rmDir.code, 5, rmDir.stderr);
    assert.match(rmDir.stderr, /SmbIsADirectoryError: is a directory/);
    const rmdirFull = await runCli(['rmdir', ...common, target, `${SHARE}/cli-ops/deep`], env);
    assert.equal(rmdirFull.code, 5, rmdirFull.stderr);
    assert.match(rmdirFull.stderr, /SmbDirectoryNotEmptyError: directory not empty/);
    const across = await runCli(['mv', ...common, target, `${SHARE}/cli-ops/deep/er/f.txt`, `other/f.txt`], env);
    assert.equal(across.code, 1, across.stderr);

    const mv = await runCli(['mv', ...common, target, `${SHARE}/cli-ops/deep/er/f.txt`, `${SHARE}/cli-ops/g.txt`], env);
    assert.equal(mv.code, 0, mv.stderr);
    assert.equal(mv.stdout, `moved ${SHARE}/cli-ops/deep/er/f.txt -> ${SHARE}/cli-ops/g.txt\n`);
    const rm = await runCli(['rm', ...common, '--json', target, `${SHARE}/cli-ops/g.txt`], env);
    assert.equal(rm.code, 0, rm.stderr);
    assert.deepEqual(JSON.parse(rm.stdout), { share: SHARE, path: 'cli-ops/g.txt' });
    for (const dir of ['cli-ops/deep/er', 'cli-ops/deep', 'cli-ops']) {
      const r = await runCli(['rmdir', ...common, target, `${SHARE}/${dir}`], env);
      assert.equal(r.code, 0, r.stderr);
      assert.equal(r.stdout, `removed directory ${SHARE}/${dir}\n`);
    }
    const gone = await runCli(['stat', ...common, target, `${SHARE}/cli-ops`], env);
    assert.equal(gone.code, 5, gone.stderr);
    assert.match(gone.stderr, /SmbNotFoundError/);
  });

  it('get -r and put -r round-trip a tree with nested dirs, Unicode, an empty dir and a 50 MB file', { timeout: 300000 }, async () => {
    const src = path.join(work, 'tree-src');
    fs.mkdirSync(path.join(src, 'a', 'b', 'c'), { recursive: true });
    fs.mkdirSync(path.join(src, 'empty'));
    fs.mkdirSync(path.join(src, 'ünïcødé 日本'));
    fs.writeFileSync(path.join(src, 'top.txt'), 'top\n');
    fs.writeFileSync(path.join(src, 'a', 'b', 'c', 'deep.txt'), 'deep\n');
    fs.writeFileSync(path.join(src, 'ünïcødé 日本', 'fïlé.txt'), 'unicode\n');
    fs.writeFileSync(path.join(src, 'a', 'big.bin'), crypto.randomBytes(50 * 1024 * 1024));
    fs.symlinkSync(path.join(src, 'top.txt'), path.join(src, 'link.txt'));
    const env = { WINLINUX_PASSWORD: PASS };
    const common = ['-d', DOMAIN, '--smb-port', String(port)];
    const target = `${USER}@127.0.0.1`;

    const put = await runCli(['put', ...common, '-r', '--parallel', '4', '--json', target, src, `${SHARE}/trees`], env);
    assert.equal(put.code, 0, put.stderr);
    assert.deepEqual(JSON.parse(put.stdout), { files: 4, directories: 6, bytes: 50 * 1024 * 1024 + 4 + 5 + 8, skipped: 1 });
    assert.match(put.stderr, /winlinux: skipped symlink link\.txt/);

    const back = path.join(work, 'tree-back');
    fs.mkdirSync(back);
    const get = await runCli(['get', ...common, '-r', target, `${SHARE}/trees`, back], env);
    assert.equal(get.code, 0, get.stderr);
    assert.equal(get.stdout, `downloaded ${SHARE}/trees -> ${path.join(back, 'trees')} (4 files, 6 directories, ${50 * 1024 * 1024 + 17} bytes, 0 skipped)\n`);
    const copy = path.join(back, 'trees');
    for (const rel of ['top.txt', 'a/b/c/deep.txt', 'ünïcødé 日本/fïlé.txt', 'a/big.bin']) {
      assert.equal(sha256(path.join(copy, ...rel.split('/'))), sha256(path.join(src, ...rel.split('/'))), rel);
    }
    assert.ok(fs.statSync(path.join(copy, 'empty')).isDirectory());
    assert.ok(!fs.existsSync(path.join(copy, 'link.txt')));
    assert.deepEqual(fs.readdirSync(copy).filter((n) => n.endsWith('.part')), []);

    // The remote root did not exist: put -r made it the copy (trees/, not trees/tree-src/).
    const ls = await runCli(['ls', ...common, target, `${SHARE}/trees`], env);
    assert.match(ls.stdout, /top\.txt/);

    // A remote file as the root of get -r is refused with exit 5.
    const notDir = await runCli(['get', ...common, '-r', target, `${SHARE}/trees/top.txt`, back], env);
    assert.equal(notDir.code, 5, notDir.stderr);
  });

  it('cli never opens winrm for file commands', { timeout: 120000 }, async () => {
    const listener = await countingListener('reset');
    const source = path.join(work, 'nowinrm.txt');
    fs.writeFileSync(source, 'no winrm here\n');
    const env = { WINLINUX_PASSWORD: PASS };
    const common = ['-d', DOMAIN, '--smb-port', String(port), '--winrm-port', String(listener.port)];
    const target = `${USER}@127.0.0.1`;
    try {
      for (const args of [
        ['shares', ...common, target],
        ['ls', ...common, target, SHARE],
        ['put', ...common, target, source, `${SHARE}/nowinrm.txt`],
        ['get', ...common, target, `${SHARE}/nowinrm.txt`, path.join(work, 'nowinrm-back.txt')],
      ]) {
        const r = await runCli(args, env);
        assert.equal(r.code, 0, `${args[0]}: ${r.stderr}`);
      }
      assert.equal(listener.count(), 0);
    } finally {
      await listener.close();
    }
  });
});
