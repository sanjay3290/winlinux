// The five packages ship in lockstep at one version (docs/RELEASING.md).
// The internal runtime pins are exact, so winlinux@X never pairs
// with another version of its own packages.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

interface Manifest {
  name: string;
  version: string;
  private?: boolean;
  dependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
}

const ROOT = new URL('../../../../', import.meta.url);
const read = (path: string): Manifest => JSON.parse(readFileSync(new URL(path, ROOT), 'utf8')) as Manifest;
const root = read('package.json');
const packages = ['krb-session-key', 'auth', 'smb2', 'winrm', 'winlinux'].map((p) => read(`packages/${p}/package.json`));

describe('package versions', () => {
  it('every package has the root version', () => {
    for (const p of packages) assert.equal(p.version, root.version, p.name);
  });

  it('internal runtime dependencies are pinned to exactly that version', () => {
    let pins = 0;
    for (const p of packages) {
      for (const deps of [p.dependencies, p.optionalDependencies]) {
        for (const [name, range] of Object.entries(deps ?? {})) {
          if (!name.startsWith('@winlinux/')) continue;
          assert.equal(range, root.version, `${p.name} -> ${name}`);
          pins++;
        }
      }
    }
    assert.equal(pins, 4, 'winlinux pins auth, smb2 and winrm; auth pins krb-session-key');
  });

  it('internal dev dependencies accept that version', () => {
    for (const p of packages) {
      for (const [name, range] of Object.entries(p.devDependencies ?? {})) {
        if (name.startsWith('@winlinux/')) assert.equal(range, `^${root.version}`, `${p.name} -> ${name}`);
      }
    }
  });

  it('no publishable package is private', () => {
    for (const p of packages) assert.notEqual(p.private, true, p.name);
  });
});
