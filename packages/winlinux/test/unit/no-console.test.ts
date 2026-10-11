// Shipped code never writes to the console: the CLI prints through
// process.stdout/stderr on purpose, and the libraries report through typed
// errors and events. This scans every workspace's src tree, so a stray
// console.log in @winlinux/smb2 or @winlinux/auth fails `npm test` here.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// dist-test/unit/no-console.test.js -> packages/winlinux -> packages
const packagesDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..');

function* sourceFiles(dir: string): Generator<string> {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) yield* sourceFiles(full);
    else if (/\.(ts|js|mjs|cjs|c|cc|h)$/.test(entry.name) && !entry.name.endsWith('.d.ts')) yield full;
  }
}

describe('no console output in shipped sources', () => {
  it('packages/*/src has no console.log, console.error or console.warn', () => {
    const packages = fs
      .readdirSync(packagesDir, { withFileTypes: true })
      .filter((entry) => entry.isDirectory() && fs.existsSync(path.join(packagesDir, entry.name, 'src')))
      .map((entry) => entry.name);
    assert.ok(packages.length >= 5, `expected the five workspaces under ${packagesDir}, found ${packages.join(', ')}`);

    const offenders: string[] = [];
    let scanned = 0;
    for (const name of packages) {
      for (const file of sourceFiles(path.join(packagesDir, name, 'src'))) {
        scanned++;
        const lines = fs.readFileSync(file, 'utf8').split('\n');
        lines.forEach((line, index) => {
          if (/\bconsole\.(log|error|warn|info|debug|trace)\s*\(/.test(line)) {
            offenders.push(`${path.relative(packagesDir, file)}:${index + 1}: ${line.trim()}`);
          }
        });
      }
    }
    assert.ok(scanned > 50, `scanned only ${scanned} source files`);
    assert.deepEqual(offenders, []);
  });
});
