import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { dirEntriesToJson, formatLs } from '../../dist/cli/output.js';

describe('JSON output', () => {
  it('ls json renders sizeBytes as a decimal string and mtime as ISO', () => {
    const entries = [
      { name: 'big.bin', isDirectory: false, sizeBytes: 9007199254740993n, mtime: new Date(Date.UTC(2024, 0, 2, 3, 4, 5)), isReparsePoint: false },
      { name: 'sub', isDirectory: true, sizeBytes: 0n, mtime: new Date(0), isReparsePoint: false },
    ];
    assert.throws(() => JSON.stringify(entries), TypeError, 'raw bigint cannot be serialized');
    const text = JSON.stringify(dirEntriesToJson(entries));
    assert.deepEqual(JSON.parse(text), [
      { name: 'big.bin', isDirectory: false, sizeBytes: '9007199254740993', mtime: '2024-01-02T03:04:05.000Z' },
      { name: 'sub', isDirectory: true, sizeBytes: '0', mtime: '1970-01-01T00:00:00.000Z' },
    ]);
    assert.match(formatLs(entries), /^- +9007199254740993 2024-01-02T03:04:05\.000Z big\.bin\nd +0 1970-01-01T00:00:00\.000Z sub\n$/);
  });
});
