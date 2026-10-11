import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { buildEventLogScript, buildProcessesScript, buildServicesScript, psQuote } from '../src/winrm/powershell.js';

const SELECT_EVENT = 'Select-Object TimeCreated,Id,LevelDisplayName,ProviderName,Message';

describe('PowerShell script builders', () => {
  it('builds the default event log query', () => {
    assert.equal(
      buildEventLogScript({ logName: 'System' }),
      `@(Get-WinEvent -LogName 'System' -MaxEvents 100 | ${SELECT_EVENT}) | ConvertTo-Json -Compress -Depth 3`,
    );
  });

  it('builds a filtered query with FilterHashtable, MaxEvents, Oldest', () => {
    assert.equal(
      buildEventLogScript({
        logName: 'System',
        maxEvents: 50,
        level: 2,
        provider: 'Service Control Manager',
        oldest: true,
        startTime: new Date('2026-09-01T00:00:00Z'),
      }),
      `@(Get-WinEvent -FilterHashtable @{LogName='System'; Level=2; ProviderName='Service Control Manager'; StartTime='2026-09-01T00:00:00'} -MaxEvents 50 -Oldest | ${SELECT_EVENT}) | ConvertTo-Json -Compress -Depth 3`,
    );
  });

  it('escapes single quotes in log name and provider', () => {
    assert.equal(
      buildEventLogScript({ logName: "Loc'al", provider: "O'Brien" }),
      `@(Get-WinEvent -FilterHashtable @{LogName='Loc''al'; ProviderName='O''Brien'} -MaxEvents 100 | ${SELECT_EVENT}) | ConvertTo-Json -Compress -Depth 3`,
    );
  });

  it('builds the services query', () => {
    assert.equal(
      buildServicesScript(),
      'Get-Service | Select-Object Name,DisplayName,Status,StartType | ConvertTo-Json -Compress -Depth 2',
    );
  });

  it('builds the processes query', () => {
    assert.equal(
      buildProcessesScript(),
      'Get-Process | Select-Object Id,ProcessName,CPU,WS,StartTime | ConvertTo-Json -Compress -Depth 2',
    );
  });
});

// PowerShell ends a single-quoted string at the ASCII apostrophe and at
// U+2018, U+2019, U+201A and U+201B; any two of them in a row stand for
// the second one. This reads a literal the way PowerShell does.
const PS_QUOTES = new Set(["'", '‘', '’', '‚', '‛']);

function readLiteral(text: string, at: number): { value: string; end: number } {
  assert.ok(PS_QUOTES.has(text[at]), `no single-quoted literal at ${at}`);
  let value = '';
  let i = at + 1;
  for (;;) {
    assert.ok(i < text.length, 'unterminated literal');
    const c = text[i];
    if (PS_QUOTES.has(c)) {
      if (!PS_QUOTES.has(text[i + 1] ?? '')) return { value, end: i + 1 };
      value += text[i + 1];
      i += 2;
    } else {
      value += c;
      i++;
    }
  }
}

// The script with every literal replaced by '': what PowerShell runs as code.
function codeOnly(text: string): string {
  let out = '';
  for (let i = 0; i < text.length; ) {
    if (PS_QUOTES.has(text[i])) {
      i = readLiteral(text, i).end;
      out += "''";
    } else {
      out += text[i++];
    }
  }
  return out;
}

const literalAfter = (script: string, prefix: string) => {
  const at = script.indexOf(prefix);
  assert.ok(at >= 0, `no ${prefix} in ${script}`);
  return readLiteral(script, at + prefix.length).value;
};

describe('PowerShell quoting of user values', () => {
  const quotes: Array<[string, string]> = [
    ['U+0027 apostrophe', "'"],
    ['U+2018 left single quotation mark', '‘'],
    ['U+2019 right single quotation mark', '’'],
    ['U+201A single low-9 quotation mark', '‚'],
    ['U+201B single high-reversed-9 quotation mark', '‛'],
  ];
  for (const [name, q] of quotes) {
    it(`${name}: psQuote doubles it and the literal round-trips`, () => {
      assert.equal(psQuote(`a${q}b`), `'a${q}${q}b'`);
      const quoted = psQuote(`${q}${q}x${q}`);
      assert.deepEqual(readLiteral(quoted, 0), { value: `${q}${q}x${q}`, end: quoted.length });
    });

    it(`${name}: logName and provider stay data, the payload is not code`, () => {
      const logName = `Sys${q}tem`;
      const provider = `x${q}; Write-Output pwned; ${q}`;
      const filtered = buildEventLogScript({ logName, provider });
      assert.equal(literalAfter(filtered, 'LogName='), logName);
      assert.equal(literalAfter(filtered, 'ProviderName='), provider);
      assert.equal(
        codeOnly(filtered),
        `@(Get-WinEvent -FilterHashtable @{LogName=''; ProviderName=''} -MaxEvents 100 | ${SELECT_EVENT}) | ConvertTo-Json -Compress -Depth 3`,
      );

      const plain = buildEventLogScript({ logName: `x${q}; Write-Output pwned; ${q}` });
      assert.equal(literalAfter(plain, '-LogName '), `x${q}; Write-Output pwned; ${q}`);
      assert.equal(codeOnly(plain), `@(Get-WinEvent -LogName '' -MaxEvents 100 | ${SELECT_EVENT}) | ConvertTo-Json -Compress -Depth 3`);
    });
  }
});
