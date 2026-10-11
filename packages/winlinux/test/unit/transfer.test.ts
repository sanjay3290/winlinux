// put checks the local file before any SMB open; get writes a temp file and
// renames it, so a failed transfer never harms an existing local file.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { connect as smbConnect } from '@winlinux/smb2';
import { SmbError, SmbNotFoundError, SmbTimeoutError, WinLinuxConnectionError, WinLinuxUsageError } from '../../dist/index.js';
import { createClient, resolveGetDestination } from '../../dist/client.js';
import { StubAuthProvider as SmbStubProvider } from '../../../smb2/dist-test/test/helpers/stub-provider.js';
import { MockSmbServer } from '../../../smb2/dist-test/test/mock/server.js';
import { FakeSmb, fakeDeps, deferred } from '../helpers/fakes.js';

const OPTS = { username: 'u', password: 'p', auth: 'ntlm' as const };

function tempDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'winlinux-transfer-'));
}

describe('file transfers', () => {
  it('put with a missing or non-regular local file sends no Create and opens no SMB socket', async () => {
    const server = new MockSmbServer({ securityMode: 0 });
    const port = await server.listen();
    const dir = tempDir();
    const deps = fakeDeps({});
    deps.smbConnect = async (o) => {
      deps.smbOpens.push(o);
      return smbConnect(o);
    };
    deps.createAuthProvider = () => new SmbStubProvider({ sessionKey: Buffer.alloc(16, 1) });
    const client = createClient('127.0.0.1', { ...OPTS, smb: { port } }, deps);
    try {
      // Typed, naming the local path; the system error stays as cause.
      const nope = path.join(dir, 'nope.txt');
      const missing = await client.put(nope, 'share', 'target.txt').catch((e: unknown) => e);
      assert.ok(missing instanceof WinLinuxUsageError, String(missing));
      assert.equal(missing.message, `put: local file ${nope}: no such file`);
      assert.equal(((missing as { cause?: unknown }).cause as { code?: string }).code, 'ENOENT');
      const isDir = await client.put(dir, 'share', 'target.txt').catch((e: unknown) => e);
      assert.ok(isDir instanceof WinLinuxUsageError, String(isDir));
      assert.equal(isDir.message, `put: local file ${dir}: is a directory`);
      assert.equal(server.creates.length, 0, 'no SMB2 CREATE, so the remote file is untouched');
      assert.equal(server.connections, 0);
      assert.equal(deps.smbOpens.length, 0);
      // A real file still uploads through the same client.
      const real = path.join(dir, 'real.txt');
      fs.writeFileSync(real, 'hello');
      await client.put(real, 'share', 'target.txt');
      assert.ok(server.creates.some((c) => c.name === 'target.txt'), JSON.stringify(server.creates));
      assert.equal(server.writtenBytes('target.txt').toString(), 'hello');
    } finally {
      await client.close();
      await server.close();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('get failing mid-transfer keeps the existing local file and leaves no .part file', async () => {
    const dir = tempDir();
    const dest = path.join(dir, 'report.csv');
    fs.writeFileSync(dest, 'original');
    const session = new FakeSmb();
    const seen: string[] = [];
    session.downloadImpl = async (_share, _remote, localPath) => {
      seen.push(localPath);
      fs.writeFileSync(localPath, 'partial da');
      throw new SmbError('SMB request failed during read', 0xc0000185);
    };
    const client = createClient('h', OPTS, fakeDeps({ smb: async () => session }));
    try {
      await assert.rejects(client.get('C$', 'report.csv', dest), SmbError);
      assert.equal(fs.readFileSync(dest, 'utf8'), 'original');
      assert.deepEqual(fs.readdirSync(dir), ['report.csv']);
      assert.equal(path.dirname(seen[0] ?? ''), dir, 'temp file sits next to the destination');
      assert.match(path.basename(seen[0] ?? ''), /^\.report\.csv\.winlinux-[0-9a-f]+\.part$/);

      session.downloadImpl = async (_share, _remote, localPath) => fs.writeFileSync(localPath, 'new content');
      await client.get('C$', 'report.csv', dest);
      assert.equal(fs.readFileSync(dest, 'utf8'), 'new content', 'overwrites like scp');
      assert.deepEqual(fs.readdirSync(dir), ['report.csv']);
    } finally {
      await client.close();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('close removes the .part file of an interrupted get', async () => {
    const dir = tempDir();
    const dest = path.join(dir, 'big.bin');
    const started = deferred<void>();
    const session = new FakeSmb();
    session.downloadImpl = async (_share, _remote, localPath) => {
      fs.writeFileSync(localPath, 'some bytes');
      started.resolve();
      await new Promise(() => undefined); // never finishes, like a hung read
    };
    const client = createClient('h', OPTS, fakeDeps({ smb: async () => session, closeTimeoutMs: 50 }));
    try {
      void client.get('C$', 'big.bin', dest).catch(() => undefined);
      await started.promise;
      assert.equal(fs.readdirSync(dir).length, 1);
      await client.close();
      assert.deepEqual(fs.readdirSync(dir), []);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('get into an existing directory, or a path ending in /, writes <dir>/<remote base name>', async () => {
    const dir = tempDir();
    const sub = path.join(dir, 'dlx');
    fs.mkdirSync(sub);
    const session = new FakeSmb();
    const seen: string[] = [];
    session.downloadImpl = async (_share, _remote, localPath) => {
      seen.push(localPath);
      fs.writeFileSync(localPath, 'content');
    };
    const deps = fakeDeps({ smb: async () => session });
    const client = createClient('h', OPTS, deps);
    try {
      await client.get('C$', 'docs/small.txt', sub);
      assert.equal(fs.readFileSync(path.join(sub, 'small.txt'), 'utf8'), 'content');
      await client.get('C$', 'docs\\other.txt', `${sub}/`);
      assert.equal(fs.readFileSync(path.join(sub, 'other.txt'), 'utf8'), 'content');
      assert.deepEqual(fs.readdirSync(sub).sort(), ['other.txt', 'small.txt'], 'no .part file left');
      assert.deepEqual(fs.readdirSync(dir), ['dlx'], 'no temp file in the parent');
      // The temp file sits inside the directory, named after the remote base name.
      assert.equal(path.dirname(seen[0] ?? ''), sub);
      assert.match(path.basename(seen[0] ?? ''), /^\.small\.txt\.winlinux-[0-9a-f]+\.part$/);
      // Resolving the result again changes nothing, so the CLI can resolve first.
      assert.equal(await resolveGetDestination('docs/small.txt', path.join(sub, 'small.txt')), path.join(sub, 'small.txt'));
      assert.equal(await resolveGetDestination('docs/new.txt', path.join(sub, 'new.txt')), path.join(sub, 'new.txt'));
    } finally {
      await client.close();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('get refuses a missing directory, a file used as a directory, and a directory at <dir>/<base> before any SMB open', async () => {
    const dir = tempDir();
    fs.writeFileSync(path.join(dir, 'plain.txt'), 'x');
    fs.mkdirSync(path.join(dir, 'small.txt'));
    const session = new FakeSmb();
    session.downloadImpl = async () => assert.fail('no download expected');
    const deps = fakeDeps({ smb: async () => session });
    const client = createClient('h', OPTS, deps);
    try {
      const cases: Array<[string, RegExp]> = [
        [path.join(dir, 'missing') + '/', /^no such directory: .*missing\/$/],
        [path.join(dir, 'plain.txt') + '/', /^not a directory: .*plain\.txt\/$/],
        [dir, /^cannot overwrite directory .*small\.txt with docs\/small\.txt$/],
      ];
      for (const [local, pattern] of cases) {
        const err = await client.get('C$', 'docs/small.txt', local).catch((e: unknown) => e);
        assert.ok(err instanceof WinLinuxUsageError, String(err));
        assert.match(err.message, pattern);
      }
      assert.equal(deps.smbOpens.length, 0, 'no SMB open');
      assert.deepEqual(fs.readdirSync(dir).sort(), ['plain.txt', 'small.txt'], 'no temp file written');
    } finally {
      await client.close();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('get errors name the destination, never the .part temp file', async () => {
    const dir = tempDir();
    const dest = path.join(dir, 'keep.txt');
    const session = new FakeSmb();
    session.downloadImpl = async (share, remote, localPath) => {
      throw new SmbNotFoundError(`no such file or directory: download ${share}/${remote} to ${localPath}`, 0xc0000034);
    };
    // A password that no path contains, so redaction leaves the messages alone.
    const client = createClient('h', { ...OPTS, password: 'Zq9-Secret' }, fakeDeps({ smb: async () => session }));
    try {
      const notFound = await client.get('C$', 'nope.txt', dest).catch((e: unknown) => e);
      assert.ok(notFound instanceof SmbNotFoundError, String(notFound));
      assert.equal(notFound.message, `no such file or directory: download C$/nope.txt to ${dest} (status 0xc0000034)`);
      assert.equal(notFound.status, 0xc0000034);
      // A local fs error on the temp file: message and path name the destination.
      session.downloadImpl = async (_share, _remote, localPath) => {
        throw Object.assign(new Error(`EACCES: permission denied, open '${localPath}'`), { code: 'EACCES', path: localPath });
      };
      const denied = await client.get('C$', 'keep.txt', dest).catch((e: unknown) => e);
      assert.equal((denied as { path?: string }).path, dest);
      assert.equal((denied as Error).message, `EACCES: permission denied, open '${dest}'`);
      assert.equal((denied as { code?: string }).code, 'EACCES');
      // A timeout is wrapped as a connection error; the wrapper names the destination too.
      session.downloadImpl = async (_share, _remote, localPath) => {
        throw new SmbTimeoutError(`request timed out during download C$/keep.txt to ${localPath}: request_timeout`);
      };
      const timeout = await client.get('C$', 'keep.txt', dest).catch((e: unknown) => e);
      assert.ok(timeout instanceof WinLinuxConnectionError, String(timeout));
      assert.doesNotMatch(timeout.message, /\.part/);
      assert.ok(timeout.message.includes(dest), timeout.message);
      assert.deepEqual(fs.readdirSync(dir), [], 'no .part file left');
    } finally {
      await client.close();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
