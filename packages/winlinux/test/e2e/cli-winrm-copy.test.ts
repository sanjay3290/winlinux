// The winlinux binary copying files over WinRM against the transfer
// mock: unchanged output, --via rules, and Ctrl+C.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { SEND_CHUNK_BYTES } from '@winlinux/winrm';
import { CLI, EMPTY_HOME, runCli } from '../helpers/cli.js';
import { startTransferMock, type TransferMock } from '../helpers/transfer-mock.js';

const SENTINEL = 'Cli-Copy-Sentinel-Pw-58';
const ENV = { WINLINUX_PASSWORD: SENTINEL };
const TARGET = 'tester@127.0.0.1';

function flags(port: number): string[] {
  return ['--auth', 'basic', '--tls', '--insecure', '--winrm-port', String(port)];
}

function dirs(): { remote: string; local: string; done: () => void } {
  const remote = fs.mkdtempSync(path.join(os.tmpdir(), 'winlinux-cli-remote-'));
  const local = fs.mkdtempSync(path.join(os.tmpdir(), 'winlinux-cli-local-'));
  return {
    remote,
    local,
    done: () => {
      fs.rmSync(remote, { recursive: true, force: true });
      fs.rmSync(local, { recursive: true, force: true });
    },
  };
}

// Starts the CLI, sends SIGINT once `ready` holds, and resolves with the
// exit code and stderr.
function interruptWhen(args: string[], ready: () => boolean): Promise<{ code: number | null; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [CLI, ...args], {
      env: { PATH: process.env.PATH, NODE_NO_WARNINGS: '1', HOME: EMPTY_HOME, ...ENV },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stderr = '';
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
      resolve({ code, stderr });
    });
  });
}

const receives = (mock: TransferMock) => mock.actions.filter((a) => a === 'Receive').length;

describe('cli get and put over WinRM', () => {
  it('a profile Via winrm routes get and put over WinRM without --via; --via smb on the command line beats it', async () => {
    const d = dirs();
    const mock = await startTransferMock({ shares: { Data: d.remote }, password: SENTINEL });
    try {
      const home = fs.mkdtempSync(path.join(os.tmpdir(), 'winlinux-home-'));
      fs.mkdirSync(path.join(home, '.winlinux'));
      fs.writeFileSync(
        path.join(home, '.winlinux', 'config'),
        `Host files\n  HostName 127.0.0.1\n  User tester\n  Auth basic\n  TLS yes\n  Insecure yes\n  WinRMPort ${mock.port}\n  Via winrm\n`,
        { mode: 0o600 },
      );
      const env = { ...ENV, HOME: home };
      const src = path.join(d.local, 'p.txt');
      fs.writeFileSync(src, 'profile via');
      const put = await runCli(['put', 'files', src, 'Data/p.txt'], env);
      assert.equal(put.code, 0, put.stderr);
      assert.equal(fs.readFileSync(path.join(d.remote, 'p.txt'), 'utf8'), 'profile via');
      const out = path.join(d.local, 'back.txt');
      const get = await runCli(['get', 'files', 'Data/p.txt', out], env);
      assert.equal(get.code, 0, get.stderr);
      assert.equal(fs.readFileSync(out, 'utf8'), 'profile via');
      // The flag wins: Basic over SMB is refused by plan, so --via smb is a usage error here.
      const smb = await runCli(['get', '--via', 'smb', 'files', 'Data/p.txt', out], env);
      assert.equal(smb.code, 1);
      assert.match(smb.stderr, /Basic authentication is HTTP-only/);
    } finally {
      await mock.close();
      d.done();
    }
  });

  it('put and get --via winrm print the usual lines and --json objects', async () => {
    const d = dirs();
    const mock = await startTransferMock({ shares: { Data: d.remote }, password: SENTINEL });
    try {
      const src = path.join(d.local, 'notes.txt');
      fs.writeFileSync(src, 'hello over winrm');
      const put = await runCli(['put', ...flags(mock.port), '--via', 'winrm', TARGET, src, 'Data/notes.txt'], ENV);
      assert.equal(put.code, 0, put.stderr);
      assert.equal(put.stdout, `uploaded ${src} -> Data/notes.txt (16 bytes)\n`);
      assert.equal(put.stderr, '');
      const dest = path.join(d.local, 'copy.txt');
      const get = await runCli(['get', ...flags(mock.port), '--via', 'winrm', TARGET, 'Data/notes.txt', dest], ENV);
      assert.equal(get.code, 0, get.stderr);
      assert.equal(get.stdout, `downloaded Data/notes.txt -> ${dest} (16 bytes)\n`);
      assert.equal(fs.readFileSync(dest, 'utf8'), 'hello over winrm');
      const json = await runCli(['get', ...flags(mock.port), '--via', 'winrm', '--json', TARGET, 'Data/notes.txt', dest], ENV);
      assert.equal(json.code, 0, json.stderr);
      assert.deepEqual(JSON.parse(json.stdout), { share: 'Data', remotePath: 'notes.txt', localPath: dest, sizeBytes: '16' });
      assert.ok(!put.stderr.includes(SENTINEL) && !get.stderr.includes(SENTINEL));
    } finally {
      await mock.close();
      d.done();
    }
  });

  it('a missing remote file exits 5; --via winrm with -r and a bad --via exit 1', async () => {
    const d = dirs();
    const mock = await startTransferMock({ shares: { Data: d.remote }, password: SENTINEL });
    try {
      const missing = await runCli(['get', ...flags(mock.port), '--via', 'winrm', TARGET, 'Data/none.txt', path.join(d.local, 'x')], ENV);
      assert.equal(missing.code, 5, missing.stderr);
      // The SMB wording, the user's path, no server-local path; the
      // raw .NET text only with -v.
      assert.equal(missing.stderr, `winlinux: SmbNotFoundError: no such file or directory: download Data/none.txt to ${path.join(d.local, 'x')}\n`);
      assert.ok(!missing.stderr.includes(d.remote));
      const verbose = await runCli(['get', '-v', ...flags(mock.port), '--via', 'winrm', TARGET, 'Data/none.txt', path.join(d.local, 'x')], ENV);
      assert.equal(verbose.code, 5);
      assert.match(verbose.stderr, /winlinux: cause: WinLinuxTransferError: get Data\/none\.txt over WinRM failed: Could not find file/);
      const recursive = await runCli(['get', ...flags(mock.port), '-r', '--via', 'winrm', TARGET, 'Data/dir', d.local], ENV);
      assert.equal(recursive.code, 1);
      assert.match(recursive.stderr, /not supported yet/);
      const src = path.join(d.local, 'src.txt');
      fs.writeFileSync(src, 'x');
      const bad = await runCli(['put', ...flags(mock.port), '--via', 'ftp', TARGET, src, 'Data/x'], ENV);
      assert.equal(bad.code, 1);
      assert.match(bad.stderr, /--via must be auto, smb or winrm/);
      const foreign = await runCli(['ls', ...flags(mock.port), '--via', 'winrm', TARGET, 'Data'], ENV);
      assert.equal(foreign.code, 1);
      assert.match(foreign.stderr, /--via applies to get and put only, not ls/);
      assert.deepEqual(mock.actions.filter((a) => a === 'Command').length, 2, 'only the two missing-file runs reached the server');
    } finally {
      await mock.close();
      d.done();
    }
  });

  it('Ctrl+C during put: stdin closes, the server removes its temp file, Signal goes out, exit 130', async () => {
    const d = dirs();
    const mock = await startTransferMock({ shares: { Data: d.remote }, password: SENTINEL, delayMs: 10 });
    try {
      const src = path.join(d.local, 'big.bin');
      fs.writeFileSync(src, Buffer.alloc(SEND_CHUNK_BYTES * 60, 5));
      fs.writeFileSync(path.join(d.remote, 'big.bin'), 'old');
      const r = await interruptWhen(['put', ...flags(mock.port), '--via', 'winrm', TARGET, src, 'Data/big.bin'], () => mock.sends >= 3);
      assert.equal(r.code, 130, r.stderr);
      assert.match(r.stderr, /interrupted; closing/);
      assert.ok(mock.sends < 60, `stopped after ${mock.sends} Sends`);
      assert.equal(mock.ends, 1, 'stdin closed with End before Signal');
      assert.ok(mock.signals >= 1, 'the mock saw Signal');
      assert.deepEqual(mock.killedTemps, []);
      assert.deepEqual(fs.readdirSync(d.remote), ['big.bin'], 'no temp file on the server');
      assert.equal(fs.readFileSync(path.join(d.remote, 'big.bin'), 'utf8'), 'old');
    } finally {
      await mock.close();
      d.done();
    }
  });

  it('Ctrl+C during get: no .part file stays, the mock sees Signal, exit 130', async () => {
    const d = dirs();
    const mock = await startTransferMock({ shares: { Data: d.remote }, password: SENTINEL, delayMs: 10, receiveBytes: 8192 });
    try {
      fs.writeFileSync(path.join(d.remote, 'big.bin'), Buffer.alloc(4 * 1024 * 1024, 6));
      const dest = path.join(d.local, 'big.bin');
      fs.writeFileSync(dest, 'old');
      const r = await interruptWhen(['get', ...flags(mock.port), '--via', 'winrm', TARGET, 'Data/big.bin', dest], () => receives(mock) >= 3);
      assert.equal(r.code, 130, r.stderr);
      assert.ok(mock.signals >= 1, 'the mock saw Signal');
      assert.deepEqual(fs.readdirSync(d.local), ['big.bin'], 'no .part file');
      assert.equal(fs.readFileSync(dest, 'utf8'), 'old');
    } finally {
      await mock.close();
      d.done();
    }
  });
});
