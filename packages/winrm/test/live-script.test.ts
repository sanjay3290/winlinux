// The PowerShell the live runner sends must parse on Windows PowerShell 5.1.
// This cannot run PowerShell, so it checks the shapes that bit.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { LIST_SHELLS_SCRIPT } from './live/scenarios.js';

describe('live runner scripts', () => {
  it('LIST_SHELLS_SCRIPT keeps try and catch on separate statements, not joined by ;', () => {
    // `try { ... }; catch { ... }` is a parse error: PowerShell wants the
    // catch right after the try block (whitespace or a newline only).
    assert.doesNotMatch(LIST_SHELLS_SCRIPT, /}\s*;\s*catch/);
    assert.match(LIST_SHELLS_SCRIPT, /}\s*\n\s*catch\s*{/);
    assert.ok(LIST_SHELLS_SCRIPT.includes('Get-WSManInstance'));
    assert.ok(LIST_SHELLS_SCRIPT.includes("Name='winrshost.exe'"));
  });
});
