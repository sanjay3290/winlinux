// The packages stay ESM only; a CommonJS project loads them with a dynamic
// import. The fixture is the README's CommonJS example.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const FIXTURE = fileURLToPath(new URL('../../test/fixtures/cjs-consumer.cjs', import.meta.url));

function run(file: string): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [file], { env: { PATH: process.env.PATH }, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d: Buffer) => (stdout += d.toString('utf8')));
    child.stderr.on('data', (d: Buffer) => (stderr += d.toString('utf8')));
    child.on('error', reject);
    child.on('close', (code) => resolve({ code, stdout, stderr }));
  });
}

// Node 22.12 can require() an ES module graph without top-level await.
function canRequireEsm(version: string): boolean {
  const [major, minor] = version.split('.').map(Number) as [number, number];
  return major > 22 || (major === 22 && minor >= 12);
}

describe('CommonJS consumer', () => {
  it('a .cjs file loads winlinux with await import()', async () => {
    const r = await run(FIXTURE);
    assert.equal(r.code, 0, r.stderr);
    const out = JSON.parse(r.stdout) as { connect: string; usageError: string; required: string; node: string };
    assert.equal(out.connect, 'function');
    assert.equal(out.usageError, 'function');
    // require() works where Node can require ES modules, and fails with
    // ERR_REQUIRE_ESM before that; never with another error.
    assert.equal(out.required, canRequireEsm(out.node) ? 'function' : 'ERR_REQUIRE_ESM');
  });
});
