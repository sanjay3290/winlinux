// Test target: 100 MB each way over WinRM against the transfer mock.
// The SHA-256 must match, and the client's memory must stay bounded: it
// may not hold the file. The client runs in a child process
// (helpers/large-client.ts), so its samples exclude the mock. The child
// also runs with a 48 MB old-space cap: a client that kept the file would
// fail with out-of-memory, and the cap makes V8 collect the large base64
// strings of each request early instead of growing the heap first. The
// time is reported, not asserted.
//
// The assertion is on the peak of heapUsed + arrayBuffers (live JS heap and
// Buffer memory), sampled in the child after a full GC at the baseline.
// RSS is reported only: it also counts freed pages the allocator has not
// returned and moves with GC timing, so it flaked at 66 MB against 64 MB
// about 1 run in 18 in the full suite. A client that held the file
// would still fail: its Buffers count in arrayBuffers, and the 48 MB
// old-space cap stops it keeping the base64 text. The `hold` control below
// proves the check catches a client that holds 100 MB.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createHash, randomBytes } from 'node:crypto';
import { startTransferMock } from '../helpers/transfer-mock.js';

const SIZE = 100 * 1024 * 1024;
const LIMIT = 64 * 1024 * 1024;
const PASSWORD = 'Transfer-Large-Sentinel-Pw-3';
const CHILD = fileURLToPath(new URL('../helpers/large-client.js', import.meta.url));

// SIZE bytes from a 1 MiB random block with a counter in each block, so
// no two blocks are equal. Returns the SHA-256.
function writeFile(file: string): string {
  const hash = createHash('sha256');
  const fd = fs.openSync(file, 'w');
  try {
    const block = randomBytes(1024 * 1024);
    for (let i = 0; i < SIZE / block.length; i++) {
      block.writeUInt32LE(i, 0);
      hash.update(block);
      fs.writeSync(fd, block);
    }
  } finally {
    fs.closeSync(fd);
  }
  return hash.digest('hex');
}

async function hashFile(file: string): Promise<string> {
  const hash = createHash('sha256');
  for await (const chunk of fs.createReadStream(file)) hash.update(chunk as Buffer);
  return hash.digest('hex');
}

interface Sample {
  ms: number;
  rss: number;
  heap: number;
}

function runClient(args: string[]): Promise<Sample> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--max-old-space-size=48', '--expose-gc', CHILD, ...args], { env: { PATH: process.env.PATH, NODE_NO_WARNINGS: '1' }, stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '';
    let err = '';
    child.stdout.on('data', (d: Buffer) => (out += d.toString('utf8')));
    child.stderr.on('data', (d: Buffer) => (err += d.toString('utf8')));
    child.on('error', reject);
    child.on('close', (code) => {
      if (code !== 0) return reject(new Error(`client exited ${code}: ${err}`));
      resolve(JSON.parse(out) as Sample);
    });
  });
}

const mb = (bytes: number) => (bytes / 1024 / 1024).toFixed(1);

describe('100 MB over WinRM (mock)', () => {
  it('put and get 100 MB: SHA-256 matches and client memory growth stays under 64 MB', { timeout: 600_000 }, async (t) => {
    const remote = fs.mkdtempSync(path.join(os.tmpdir(), 'winlinux-remote-large-'));
    const local = fs.mkdtempSync(path.join(os.tmpdir(), 'winlinux-local-large-'));
    const mock = await startTransferMock({ shares: { Data: remote }, password: PASSWORD });
    try {
      const src = path.join(local, 'src.bin');
      const expected = writeFile(src);

      const put = await runClient(['put', String(mock.port), PASSWORD, src, 'big.bin']);
      assert.equal(await hashFile(path.join(remote, 'big.bin')), expected, 'server copy');
      const back = path.join(local, 'back.bin');
      const get = await runClient(['get', String(mock.port), PASSWORD, back, 'big.bin']);
      assert.equal(await hashFile(back), expected, 'client copy');
      assert.deepEqual(fs.readdirSync(remote), ['big.bin']);
      assert.deepEqual(fs.readdirSync(local).sort(), ['back.bin', 'src.bin']);

      for (const [what, m] of [['put', put], ['get', get]] as const) {
        t.diagnostic(
          `${what} 100 MB over the mock (TLS, loopback): ${(m.ms / 1000).toFixed(1)} s, ${(SIZE / 1024 / 1024 / (m.ms / 1000)).toFixed(1)} MB/s; ` +
            `client growth rss ${mb(m.rss)} MB, heap+buffers ${mb(m.heap)} MB`,
        );
      }
      t.diagnostic(`requests: ${mock.sends} Send, ${mock.actions.filter((a) => a === 'Receive').length} Receive`);
      for (const [what, m] of [['put', put], ['get', get]] as const) {
        assert.ok(m.heap < LIMIT, `${what}: heap and Buffer growth ${mb(m.heap)} MB`);
      }

      // Negative control: a client that holds the file in memory fails the
      // same check.
      const hold = await runClient(['hold', String(mock.port), PASSWORD, src, 'big.bin']);
      t.diagnostic(`hold (control): heap+buffers ${mb(hold.heap)} MB, rss ${mb(hold.rss)} MB`);
      assert.ok(hold.heap >= LIMIT, `the control holds 100 MB, so its growth ${mb(hold.heap)} MB must reach the ${mb(LIMIT)} MB limit`);
    } finally {
      await mock.close();
      fs.rmSync(remote, { recursive: true, force: true });
      fs.rmSync(local, { recursive: true, force: true });
    }
  });
});
