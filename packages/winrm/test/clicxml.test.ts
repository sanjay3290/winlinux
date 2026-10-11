import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { stripCliXml } from '../src/winrm/mapping.js';

function fixture(name: string): string {
  return readFileSync(new URL(`./fixtures/${name}`, import.meta.url), 'utf8');
}

describe('CLIXML stderr stripper', () => {
  it('converts a CLIXML error to readable text', () => {
    assert.equal(
      stripCliXml(fixture('clixml-error.txt')),
      'Get-Process : Cannot find a process with the name "nope". Verify the process name and call the cmdlet again.\n' +
        'At line:1 char:1\n' +
        '+ Get-Process -Name nope\n' +
        '+ ~~~~~~~~~~~~~~~~~~~~~~\n' +
        '    + CategoryInfo          : ObjectNotFound: (nope:String) [Get-Process], ProcessCommandException\n' +
        '    + FullyQualifiedErrorId : NoProcessFoundForGivenName,Microsoft.PowerShell.Commands.GetProcessCommand',
    );
  });

  it('passes plain stderr through untouched', () => {
    assert.equal(stripCliXml('plain error text\nsecond line'), 'plain error text\nsecond line');
    assert.equal(stripCliXml(''), '');
  });

  it('passes malformed CLIXML through untouched', () => {
    const bad = '#< CLIXML\r\n<Objs><S>unclosed';
    assert.equal(stripCliXml(bad), bad);
  });
});
