// Real winrm.connect and smb2.connect against counting TCP listeners.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { connect, WinLinuxConnectionError } from '../../dist/index.js';
import { createClient } from '../../dist/client.js';
import { countingListener } from '../helpers/listeners.js';
import { fakeDeps, FakeWinrm } from '../helpers/fakes.js';

const PASSWORD = 'lazy-test-password';

async function withListeners(fn: (winrmPort: number, smbPort: number, counts: () => [number, number]) => Promise<void>) {
  const winrm = await countingListener('reset');
  const smb = await countingListener('silent');
  try {
    await fn(winrm.port, smb.port, () => [winrm.count(), smb.count()]);
  } finally {
    await Promise.all([winrm.close(), smb.close()]);
  }
}

function options(winrmPort: number, smbPort: number) {
  return {
    username: 'user',
    password: PASSWORD,
    auth: 'ntlm' as const,
    winrm: { port: winrmPort },
    smb: { port: smbPort, requestTimeoutMs: 500 },
  };
}

describe('lazy connect', () => {
  it('connect opens no socket', async () => {
    await withListeners(async (w, s, counts) => {
      const client = await connect('127.0.0.1', options(w, s));
      await new Promise((r) => setTimeout(r, 100));
      assert.deepEqual(counts(), [0, 0]);
      await client.close();
      assert.deepEqual(counts(), [0, 0]);
    });
  });

  it('run opens only the winrm port', async () => {
    await withListeners(async (w, s, counts) => {
      const client = await connect('127.0.0.1', options(w, s));
      try {
        await assert.rejects(client.run('hostname'), WinLinuxConnectionError);
        assert.deepEqual(counts(), [1, 0]);
      } finally {
        await client.close();
      }
    });
  });

  it('ls opens only the smb port', async () => {
    await withListeners(async (w, s, counts) => {
      const client = await connect('127.0.0.1', options(w, s));
      try {
        await assert.rejects(client.ls('C$'), WinLinuxConnectionError);
        assert.deepEqual(counts(), [0, 1]);
      } finally {
        await client.close();
      }
    });
  });

  it('negotiate with password and realm asks for negotiate on smb only when the addon reports a session key', async () => {
    for (const [available, expected] of [
      [true, 'negotiate'],
      [false, 'ntlm'],
      [undefined, 'ntlm'],
    ] as const) {
      const deps = fakeDeps({});
      let asked = 0;
      if (available !== undefined) {
        deps.kerberosSessionKey = async () => {
          asked += 1;
          return available;
        };
      }
      const client = createClient('h', { username: 'u', password: 'p', realm: 'EXAMPLE.COM' }, deps);
      await client.listShares();
      assert.deepEqual(deps.mechanisms, [expected]);
      assert.equal(asked, available === undefined ? 0 : 1, 'checked once, at the smb open');
      await client.close();
    }
  });

  it('kerberos over http is refused before any open without the addon and attempted with it', async () => {
    const creds = { username: 'u', useTicketCache: true, auth: 'kerberos' as const };
    for (const [available, expected] of [
      [true, ['kerberos']],
      [false, []],
      [undefined, []],
    ] as const) {
      const deps = fakeDeps({});
      let asked = 0;
      if (available !== undefined) {
        deps.kerberosSessionKey = async () => {
          asked += 1;
          return available;
        };
      }
      const client = createClient('h', creds, deps);
      if (available) {
        await client.run('x');
      } else {
        await assert.rejects(client.run('x'), { name: 'WinLinuxUsageError', message: /Kerberos over plain HTTP/ });
      }
      assert.deepEqual(deps.mechanisms, expected);
      assert.equal(deps.winrmOpens.length, expected.length, 'winrm opens only when the plan allows it');
      assert.equal(asked, available === undefined ? 0 : 1, 'checked once, at the winrm open');
      await client.close();
    }
  });

  it('negotiate with password over http asks for negotiate on winrm only with the addon', async () => {
    for (const [available, expected] of [
      [true, 'negotiate'],
      [false, 'ntlm'],
    ] as const) {
      const deps = fakeDeps({});
      deps.kerberosSessionKey = async () => available;
      const client = createClient('h', { username: 'u', password: 'p' }, deps);
      await client.run('x');
      assert.deepEqual(deps.mechanisms, [expected]);
      await client.close();
    }
  });

  it('close closes only opened slots', async () => {
    const session = new FakeWinrm();
    const deps = fakeDeps({ winrm: async () => session });
    const client = createClient('h', { username: 'u', password: 'p' }, deps);
    await client.run('x');
    await client.close();
    assert.equal(session.closed, 1);
    assert.equal(deps.smbOpens.length, 0, 'the smb slot never opened, so nothing to close');
  });
});
