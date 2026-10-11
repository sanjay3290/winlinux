// The committed bin shim. npm links bins at install time, before
// any build, and skips a bin whose file is missing; so `bin` must point at a
// file that is in git, not under dist/.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { readFileSync, statSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const PKG_DIR = fileURLToPath(new URL('../../', import.meta.url));
const pkg = JSON.parse(readFileSync(`${PKG_DIR}package.json`, 'utf8')) as { version: string; bin: Record<string, string>; files: string[] };

function run(file: string, args: string[]): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [file, ...args], { env: { PATH: process.env.PATH }, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d: Buffer) => (stdout += d.toString('utf8')));
    child.stderr.on('data', (d: Buffer) => (stderr += d.toString('utf8')));
    child.on('error', reject);
    child.on('close', (code) => resolve({ code, stdout, stderr }));
  });
}

describe('cli bin', () => {
  it('bin points at a committed file outside dist/, and it is packed', () => {
    assert.equal(pkg.bin.winlinux, 'bin/winlinux.js');
    assert.ok(!pkg.bin.winlinux.startsWith('dist/'), 'dist/ does not exist when npm links bins');
    assert.ok(statSync(`${PKG_DIR}${pkg.bin.winlinux}`).isFile());
    assert.ok(pkg.files.includes('bin'), 'npm pack must ship the shim');
  });

  it('the shim runs the CLI: --version prints the package version', async () => {
    const r = await run(`${PKG_DIR}${pkg.bin.winlinux}`, ['--version']);
    assert.equal(r.code, 0, r.stderr);
    assert.equal(r.stdout, `${pkg.version}\n`);
  });
});
