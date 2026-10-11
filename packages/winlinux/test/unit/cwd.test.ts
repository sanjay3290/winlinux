import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { cdTarget, isCd, resolveCd, sameDirectory } from '../../dist/cli/cwd.js';

describe('shell cd parsing', () => {
  it('recognises cd and chdir in any case', () => {
    for (const word of ['cd', 'CD', 'Cd', 'chdir', 'CHDIR']) assert.ok(isCd(word), word);
    for (const word of ['cdx', 'dir', 'run', undefined]) assert.ok(!isCd(word), String(word));
  });

  it('drops /d, joins unquoted spaces, and treats a bare cd as a query', () => {
    assert.equal(cdTarget([]), undefined);
    assert.equal(cdTarget(['/d']), undefined);
    assert.equal(cdTarget(['/d', 'C:\\Windows']), 'C:\\Windows');
    assert.equal(cdTarget(['/D', 'C:\\Windows']), 'C:\\Windows');
    assert.equal(cdTarget(['C:\\Program', 'Files']), 'C:\\Program Files');
    assert.equal(cdTarget(['C:\\Program Files']), 'C:\\Program Files', 'quoted by the tokenizer');
  });
});

describe('shell cd resolution', () => {
  const home = 'C:\\Users\\winlinux';

  it('resolves absolute, rooted and relative paths like cmd.exe', () => {
    assert.equal(resolveCd(home, 'C:\\Windows'), 'C:\\Windows');
    assert.equal(resolveCd(home, 'c:/windows/system32'), 'C:\\windows\\system32');
    assert.equal(resolveCd(home, '\\Temp'), 'C:\\Temp');
    assert.equal(resolveCd(home, 'Desktop'), 'C:\\Users\\winlinux\\Desktop');
    assert.equal(resolveCd(home, '.\\Desktop\\'), 'C:\\Users\\winlinux\\Desktop');
    assert.equal(resolveCd(home, 'Program Files'), 'C:\\Users\\winlinux\\Program Files');
  });

  it('walks .. and never climbs above the drive root', () => {
    assert.equal(resolveCd(home, '..'), 'C:\\Users');
    assert.equal(resolveCd(home, '..\\..'), 'C:\\');
    assert.equal(resolveCd(home, '..\\..\\..\\..'), 'C:\\');
    assert.equal(resolveCd('C:\\', '..'), 'C:\\');
    assert.equal(resolveCd(home, '..\\other\\.\\sub'), 'C:\\Users\\other\\sub');
    assert.equal(resolveCd(home, '.'), home);
  });

  it('handles drive letters', () => {
    assert.equal(resolveCd(home, 'D:'), 'D:\\');
    assert.equal(resolveCd(home, 'd:\\'), 'D:\\');
    assert.equal(resolveCd(home, 'D:\\data\\in'), 'D:\\data\\in');
    assert.equal(resolveCd(home, 'C:'), 'C:\\', 'the current drive, with no per-drive memory');
    assert.equal(resolveCd(home, 'C:Desktop'), 'C:\\Users\\winlinux\\Desktop', 'drive-relative on the current drive');
    assert.equal(resolveCd(home, 'D:data'), 'D:\\data', 'drive-relative on another drive starts at its root');
    assert.equal(resolveCd('D:\\data', '..'), 'D:\\');
  });

  it('passes UNC paths through for cmd to reject', () => {
    assert.equal(resolveCd(home, '\\\\srv\\share\\dir'), '\\\\srv\\share\\dir');
  });
});

describe('shell directory comparison', () => {
  it('ignores case, surrounding whitespace and a trailing separator', () => {
    assert.ok(sameDirectory('C:\\Windows\r\n', 'c:\\windows'));
    assert.ok(sameDirectory('C:\\', 'C:'));
    assert.ok(sameDirectory('C:\\Temp & Files\\', 'C:\\Temp & Files'));
    assert.ok(!sameDirectory('C:\\Users\\winlinux', 'C:\\Windows'));
  });
});
