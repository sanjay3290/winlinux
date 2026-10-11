import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { parseTarget, splitSharePath } from '../../dist/cli/target.js';
import { WinLinuxUsageError } from '../../dist/index.js';

describe('CLI target parsing', () => {
  it('parses user@host, DOMAIN\\user@host and upn@realm@host', () => {
    assert.deepEqual(parseTarget('alice@server'), { username: 'alice', host: 'server' });
    assert.deepEqual(parseTarget('CORP\\alice@server'), { username: 'alice', domain: 'CORP', host: 'server' });
    assert.deepEqual(parseTarget('alice@CORP.EXAMPLE@server'), { username: 'alice@CORP.EXAMPLE', host: 'server' });
    assert.deepEqual(parseTarget('alice@server', 'CORP'), { username: 'alice', domain: 'CORP', host: 'server' });
    assert.deepEqual(parseTarget('corp\\alice@server', 'CORP'), { username: 'alice', domain: 'corp', host: 'server' });
    assert.throws(() => parseTarget('CORP\\alice@server', 'OTHER'), WinLinuxUsageError);
    assert.throws(() => parseTarget('server'), WinLinuxUsageError);
    assert.throws(() => parseTarget('@server'), WinLinuxUsageError);
    assert.throws(() => parseTarget('alice@'), WinLinuxUsageError);
  });

  it('accepts bracketed IPv6 and rejects host:port', () => {
    assert.deepEqual(parseTarget('alice@[fe80::1]'), { username: 'alice', host: 'fe80::1' });
    assert.throws(() => parseTarget('alice@server:5985'), /--winrm-port/);
    assert.throws(() => parseTarget('alice@[fe80::1]:445'), /--smb-port/);
    assert.throws(() => parseTarget('alice@fe80::1'), WinLinuxUsageError);
  });

  it('splits share/path at the first slash', () => {
    assert.deepEqual(splitSharePath('C$'), { share: 'C$' });
    assert.deepEqual(splitSharePath('C$/'), { share: 'C$' });
    assert.deepEqual(splitSharePath('C$/Windows/Temp/x.txt'), { share: 'C$', path: 'Windows/Temp/x.txt' });
    assert.throws(() => splitSharePath('/x'), WinLinuxUsageError);
  });
});
