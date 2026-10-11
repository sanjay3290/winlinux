// get and put over WinRM end to end through the real @winlinux/winrm
// session (TLS, Basic) against the transfer mock, which fakes the two
// PowerShell scripts.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import { createHash, randomBytes } from 'node:crypto';
import { SEND_CHUNK_BYTES, WinRMAbortError } from '@winlinux/winrm';
import { createAuthProvider } from '@winlinux/auth';
import { SmbAccessDeniedError, SmbIsADirectoryError, SmbNotFoundError, SmbSharingViolationError } from '@winlinux/smb2';
import { createClient, type ClientDeps } from '../../dist/client.js';
import { realDeps } from '../../dist/real-deps.js';
import { WinLinuxTransferError, WinLinuxUsageError, exitCodeFor } from '../../dist/errors.js';
import { LINE_BYTES } from '../../dist/winrm-transfer.js';
import type { ConnectOptions, WinLinuxClient } from '../../dist/types.js';
import { startTransferMock, type TransferMock, type TransferMockOptions } from '../helpers/transfer-mock.js';

const PASSWORD = 'Transfer-Mock-Sentinel-Pw-7';

function sha(data: Buffer): string {
  return createHash('sha256').update(data).digest('hex');
}

async function freePort(): Promise<number> {
  const server = net.createServer();
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = (server.address() as net.AddressInfo).port;
  await new Promise<void>((resolve) => server.close(() => resolve()));
  return port;
}

interface Rig {
  mock: TransferMock;
  client: WinLinuxClient;
  remote: string; // the share's directory
  local: string; // a local working directory
  done: () => Promise<void>;
}

async function rig(mockOpts: TransferMockOptions = {}, extra: Partial<ConnectOptions> = {}, deps: ClientDeps = realDeps()): Promise<Rig> {
  const remote = fs.mkdtempSync(path.join(os.tmpdir(), 'winlinux-remote-'));
  const local = fs.mkdtempSync(path.join(os.tmpdir(), 'winlinux-local-'));
  const mock = await startTransferMock({ shares: { Data: remote, "it's Ünï": remote }, drives: { C: remote }, password: PASSWORD, ...mockOpts });
  const client = createClient(
    '127.0.0.1',
    {
      username: 'tester',
      password: PASSWORD,
      auth: 'basic',
      winrm: { tls: true, tlsVerify: false, port: mock.port },
      smb: { port: await freePort() },
      transfer: { via: 'winrm' },
      ...extra,
    },
    deps,
  );
  return {
    mock,
    client,
    remote,
    local,
    done: async () => {
      await client.close();
      await mock.close();
      fs.rmSync(remote, { recursive: true, force: true });
      fs.rmSync(local, { recursive: true, force: true });
    },
  };
}

const SIZES: Array<[string, number]> = [
  ['0 bytes', 0],
  ['1 byte', 1],
  ['exactly one line', LINE_BYTES],
  ['exactly one Send of stdin', SEND_CHUNK_BYTES],
  ['several lines and a remainder', LINE_BYTES * 5 + 2],
];

describe('get and put over WinRM against the mock', () => {
  for (const [what, size] of SIZES) {
    it(`round-trips ${what} (${size}) with matching SHA-256 on both sides`, async () => {
      const r = await rig();
      try {
        const data = randomBytes(size);
        const src = path.join(r.local, 'src.bin');
        fs.writeFileSync(src, data);
        await r.client.put(src, 'Data', 'up.bin');
        assert.equal(sha(fs.readFileSync(path.join(r.remote, 'up.bin'))), sha(data), 'server copy');
        const back = path.join(r.local, 'back.bin');
        await r.client.get('Data', 'up.bin', back);
        assert.equal(sha(fs.readFileSync(back)), sha(data), 'client copy');
        assert.deepEqual(fs.readdirSync(r.remote), ['up.bin'], 'no temp file on the server');
        assert.deepEqual(fs.readdirSync(r.local).sort(), ['back.bin', 'src.bin'], 'no .part file on the client');
        assert.ok(r.mock.ends >= 2, 'each command closed stdin with End');
        assert.deepEqual(r.mock.killedTemps, []);
      } finally {
        await r.done();
      }
    });
  }

  it("resolves names with ', spaces and Unicode, admin share C$ and nested directories", async () => {
    const r = await rig();
    try {
      const name = "it's a ‘smart’ Ünï 日本.txt";
      fs.mkdirSync(path.join(r.remote, 'nested dir'));
      const src = path.join(r.local, 'x');
      fs.writeFileSync(src, 'quoted');
      await r.client.put(src, "it's Ünï", `nested dir/${name}`);
      assert.equal(fs.readFileSync(path.join(r.remote, 'nested dir', name), 'utf8'), 'quoted');
      const back = path.join(r.local, 'y');
      await r.client.get('C$', `nested dir\\${name}`, back);
      assert.equal(fs.readFileSync(back, 'utf8'), 'quoted');
      // put overwrites like scp; the old content is replaced only on success.
      fs.writeFileSync(src, 'second');
      await r.client.put(src, 'data', `nested dir/${name}`);
      assert.equal(fs.readFileSync(path.join(r.remote, 'nested dir', name), 'utf8'), 'second');
    } finally {
      await r.done();
    }
  });

  it('refuses .. before any WinRM request', async () => {
    const r = await rig();
    try {
      const src = path.join(r.local, 'x');
      fs.writeFileSync(src, 'x');
      await assert.rejects(r.client.put(src, 'Data', '../escape.txt'), WinLinuxUsageError);
      await assert.rejects(r.client.get('Data', 'a/../../escape.txt', path.join(r.local, 'e')), WinLinuxUsageError);
      assert.equal(r.mock.actions.length, 0);
    } finally {
      await r.done();
    }
  });

  it('remote errors: missing file, missing share, missing directory (exit 5, nothing left behind)', async () => {
    const r = await rig();
    try {
      const dest = path.join(r.local, 'gone.txt');
      // The same class and message as the SMB path, naming the
      // user's <share>/<path>; the raw .NET text (with the server's local
      // path) only in the cause.
      const missing = await r.client.get('Data', 'nope.txt', dest).catch((e: unknown) => e);
      assert.ok(missing instanceof SmbNotFoundError, String(missing));
      assert.equal(missing.message, `no such file or directory: download Data/nope.txt to ${dest}`);
      assert.ok(!missing.message.includes(r.remote), 'no server-local path in the message');
      const cause = (missing as Error & { cause?: unknown }).cause;
      assert.ok(cause instanceof WinLinuxTransferError && cause.reason === 'remote');
      assert.match(cause.message, /Could not find file '.*nope\.txt'/);
      const share = await r.client.get('Nope', 'x.txt', dest).catch((e: unknown) => e);
      assert.ok(share instanceof SmbNotFoundError, String(share));
      assert.equal(share.message, `share not found: download Nope/x.txt to ${dest}`);
      const src = path.join(r.local, 'src');
      fs.writeFileSync(src, Buffer.alloc(SEND_CHUNK_BYTES * 3));
      const sendsBefore = r.mock.sends;
      const dir = await r.client.put(src, 'Data', 'no/such/dir/x.bin').catch((e: unknown) => e);
      assert.ok(dir instanceof SmbNotFoundError, String(dir));
      assert.equal(dir.message, `no such file or directory: upload ${src} to Data/no/such/dir/x.bin`);
      assert.ok(!dir.message.includes(r.remote));
      assert.equal(r.mock.sends - sendsBefore, 1, 'the first Send faults; no more data goes out');
      assert.deepEqual(fs.readdirSync(r.local), ['src']);
      assert.deepEqual(fs.readdirSync(r.remote), []);
    } finally {
      await r.done();
    }
  });

  it('access denied, file in use and a directory map to the SMB classes; exit code 5', async () => {
    for (const [failWith, cls, text] of [
      ['denied', SmbAccessDeniedError, 'access denied'],
      ['inuse', SmbSharingViolationError, 'sharing violation (file in use)'],
    ] as const) {
      const r = await rig({ failWith });
      try {
        fs.writeFileSync(path.join(r.remote, 'f.txt'), 'x');
        const dest = path.join(r.local, 'f.txt');
        const got = await r.client.get('Data', 'f.txt', dest).catch((e: unknown) => e);
        assert.ok(got instanceof cls, `${failWith}: ${String(got)}`);
        assert.equal(got.message, `${text}: download Data/f.txt to ${dest}`);
        assert.equal(exitCodeFor(got), 5);
        const src = path.join(r.local, 'src');
        fs.writeFileSync(src, 'y');
        const put = await r.client.put(src, 'Data', 'f.txt').catch((e: unknown) => e);
        assert.ok(put instanceof cls, `${failWith} put: ${String(put)}`);
        assert.equal(put.message, `${text}: upload ${src} to Data/f.txt`);
        assert.ok(!put.message.includes(r.remote));
      } finally {
        await r.done();
      }
    }
    const r = await rig();
    try {
      fs.mkdirSync(path.join(r.remote, 'sub'));
      const dest = path.join(r.local, 'sub');
      const got = await r.client.get('Data', 'sub', dest).catch((e: unknown) => e);
      assert.ok(got instanceof SmbIsADirectoryError, String(got));
      assert.equal(got.message, `is a directory: download Data/sub to ${dest}`);
    } finally {
      await r.done();
    }
  });

  it('put: a server-side hash mismatch keeps the old destination and removes the temp file', async () => {
    const r = await rig({ corruptPut: true });
    try {
      fs.writeFileSync(path.join(r.remote, 'keep.txt'), 'old');
      const src = path.join(r.local, 'src');
      fs.writeFileSync(src, 'new data');
      const err = await r.client.put(src, 'Data', 'keep.txt').catch((e: unknown) => e);
      assert.ok(err instanceof WinLinuxTransferError && err.reason === 'mismatch', String(err));
      assert.equal(fs.readFileSync(path.join(r.remote, 'keep.txt'), 'utf8'), 'old');
      assert.deepEqual(fs.readdirSync(r.remote), ['keep.txt']);
    } finally {
      await r.done();
    }
  });

  it('get: a client-side hash mismatch removes the .part file and keeps the old local file', async () => {
    const r = await rig({ corruptGet: true });
    try {
      fs.writeFileSync(path.join(r.remote, 'f.bin'), randomBytes(LINE_BYTES * 3));
      const dest = path.join(r.local, 'f.bin');
      fs.writeFileSync(dest, 'old');
      const err = await r.client.get('Data', 'f.bin', dest).catch((e: unknown) => e);
      assert.ok(err instanceof WinLinuxTransferError && err.reason === 'mismatch', String(err));
      assert.equal(fs.readFileSync(dest, 'utf8'), 'old');
      assert.deepEqual(fs.readdirSync(r.local), ['f.bin']);
    } finally {
      await r.done();
    }
  });

  it('an abort during put closes stdin first: the server removes its temp file, then sees Signal', async () => {
    const r = await rig({ delayMs: 5 });
    try {
      const src = path.join(r.local, 'big');
      fs.writeFileSync(src, Buffer.alloc(SEND_CHUNK_BYTES * 40, 1));
      fs.writeFileSync(path.join(r.remote, 'big'), 'old');
      const abort = new AbortController();
      const running = r.client.put(src, 'Data', 'big', { signal: abort.signal });
      while (r.mock.sends < 3) await new Promise((resolve) => setTimeout(resolve, 2));
      abort.abort();
      await assert.rejects(running, WinRMAbortError);
      assert.ok(r.mock.sends < 40, `stopped after ${r.mock.sends} Sends`);
      assert.equal(r.mock.ends, 1, 'stdin closed with End');
      assert.ok(r.mock.signals >= 1, 'Signal terminate went out');
      assert.deepEqual(r.mock.killedTemps, [], 'the script exited by itself before Signal');
      assert.deepEqual(fs.readdirSync(r.remote), ['big']);
      assert.equal(fs.readFileSync(path.join(r.remote, 'big'), 'utf8'), 'old');
    } finally {
      await r.done();
    }
  });

  it('an abort during get sends Signal and leaves no .part file', async () => {
    const r = await rig({ delayMs: 5, receiveBytes: 4096 });
    try {
      fs.writeFileSync(path.join(r.remote, 'big'), Buffer.alloc(LINE_BYTES * 20, 2));
      const abort = new AbortController();
      const running = r.client.get('Data', 'big', path.join(r.local, 'big'), { signal: abort.signal });
      while (r.mock.actions.filter((a) => a === 'Receive').length < 3) await new Promise((resolve) => setTimeout(resolve, 2));
      abort.abort();
      await assert.rejects(running, WinRMAbortError);
      assert.ok(r.mock.signals >= 1);
      assert.deepEqual(fs.readdirSync(r.local), []);
    } finally {
      await r.done();
    }
  });

  it('close() during a WinRM get removes the .part file and stops the remote command', async () => {
    const r = await rig({ delayMs: 5, receiveBytes: 4096 });
    try {
      fs.writeFileSync(path.join(r.remote, 'big'), Buffer.alloc(LINE_BYTES * 20, 3));
      const running = r.client.get('Data', 'big', path.join(r.local, 'big')).catch((e: unknown) => e);
      while (r.mock.actions.filter((a) => a === 'Receive').length < 2) await new Promise((resolve) => setTimeout(resolve, 2));
      await r.client.close();
      assert.ok((await running) instanceof Error);
      assert.deepEqual(fs.readdirSync(r.local), []);
      assert.ok(r.mock.signals >= 1, 'Signal before the session closed');
    } finally {
      await r.done();
    }
  });

  it('auto: with SMB refused, get and put go over WinRM after one notice', async () => {
    const notices: number[] = [];
    // SMB refuses Basic by plan, so the client plans NTLM; the provider
    // speaks Basic to the mock, and the real smb2 connect finds port 445
    // (a free port here) closed before any auth.
    const deps = { ...realDeps(), createAuthProvider: () => createAuthProvider('basic') };
    const r = await rig({}, { auth: 'ntlm', transfer: { via: 'auto', onFallback: (e) => notices.push(e.smbPort) } }, deps);
    try {
      const src = path.join(r.local, 'a');
      fs.writeFileSync(src, 'auto');
      await r.client.put(src, 'Data', 'a');
      await r.client.get('Data', 'a', path.join(r.local, 'b'));
      assert.equal(fs.readFileSync(path.join(r.local, 'b'), 'utf8'), 'auto');
      assert.equal(notices.length, 1);
    } finally {
      await r.done();
    }
  });
});
