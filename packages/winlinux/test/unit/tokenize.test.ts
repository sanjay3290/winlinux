import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { tokenize } from '../../dist/cli/tokenize.js';

describe('shell tokenizer', () => {
  it('splits on whitespace, groups quotes, keeps backslashes', () => {
    assert.deepEqual(tokenize('  dir   C:\\Windows\\Temp  '), ['dir', 'C:\\Windows\\Temp']);
    assert.deepEqual(tokenize(`echo "hello world" 'a b'`), ['echo', 'hello world', 'a b']);
    assert.deepEqual(tokenize(`put "my file.txt" C$/x`), ['put', 'my file.txt', 'C$/x']);
    assert.deepEqual(tokenize(`say "it's"`), ['say', "it's"]);
    assert.deepEqual(tokenize(`a""b ""`), ['ab', '']);
    assert.deepEqual(tokenize(''), []);
    assert.throws(() => tokenize('echo "open'), /unclosed/);
  });
});
