import { describe, it, mock } from 'node:test';
import assert from 'node:assert/strict';
import { WinRMFaultError, WinRMTransportError, WinRMAuthError, type WinRMSession } from '@winlinux/winrm';
import type { SMBSession } from '@winlinux/smb2';
import { SmbAuthError, SmbTimeoutError } from '@winlinux/smb2';
import { WinLinuxAuthError, WinLinuxConnectionError, WinLinuxUsageError } from '../../dist/index.js';
import { createClient } from '../../dist/client.js';
import { EXIT, exitCodeFor } from '../../dist/errors.js';
import { FakeSmb, FakeWinrm, deferred, fakeDeps, OK } from '../helpers/fakes.js';

const OPTS = { username: 'u', password: 'slot-test-password', auth: 'ntlm' as const };
const tick = () => new Promise((r) => setImmediate(r));

describe('slot state machine', () => {
  it('concurrent first calls share one open', async () => {
    const gate = deferred<WinRMSession>();
    const deps = fakeDeps({ winrm: () => gate.promise });
    const client = createClient('h', OPTS, deps);
    const a = client.run('a');
    const b = client.runPowerShell('b');
    await tick();
    assert.equal(deps.winrmOpens.length, 1);
    gate.resolve(new FakeWinrm());
    assert.deepEqual(await Promise.all([a, b]), [OK, OK]);
    assert.equal(deps.winrmOpens.length, 1);
  });

  it('failed open is not cached', async () => {
    let attempt = 0;
    const deps = fakeDeps({
      smb: async () => {
        attempt += 1;
        if (attempt === 1) throw new SmbTimeoutError('request timed out');
        return new FakeSmb();
      },
    });
    const client = createClient('h', OPTS, deps);
    await assert.rejects(client.ls('C$'), WinLinuxConnectionError);
    assert.deepEqual(await client.ls('C$'), []);
    assert.equal(deps.smbOpens.length, 2);
  });

  it('connection error on an op resets the slot to idle', async () => {
    const sessions: FakeWinrm[] = [];
    const deps = fakeDeps({
      winrm: async () => {
        const s = new FakeWinrm();
        if (sessions.length === 0) s.runImpl = async () => Promise.reject(new WinRMTransportError('HTTP 503'));
        sessions.push(s);
        return s;
      },
    });
    const client = createClient('h', OPTS, deps);
    await assert.rejects(client.run('x'), WinLinuxConnectionError);
    await tick();
    assert.equal(sessions[0]?.closed, 1, 'the broken session is closed in the background');
    assert.deepEqual(await client.run('x'), OK);
    assert.equal(deps.winrmOpens.length, 2);
  });

  it('auth error is latched: the next call rejects with no connect until setPassword or reset', async () => {
    const sessions: FakeWinrm[] = [];
    const deps = fakeDeps({
      winrm: async () => {
        const s = new FakeWinrm();
        if (sessions.length === 0) s.runImpl = async () => Promise.reject(new WinRMAuthError('401'));
        sessions.push(s);
        return s;
      },
      smb: async () => {
        throw new SmbAuthError('logon failure', 0xc000006d);
      },
    });
    const client = createClient('h', OPTS, deps);
    // op-time latch (winrm)
    const first = await client.run('x').catch((e: unknown) => e);
    assert.ok(first instanceof WinLinuxAuthError);
    await tick();
    assert.equal(sessions[0]?.closed, 1);
    assert.equal(await client.run('x').catch((e: unknown) => e), first, 'same latched error');
    assert.equal(deps.winrmOpens.length, 1, 'no new connect while latched');
    // open-time latch (smb)
    const smbErr = await client.ls('C$').catch((e: unknown) => e);
    assert.ok(smbErr instanceof WinLinuxAuthError);
    assert.equal(await client.ls('C$').catch((e: unknown) => e), smbErr);
    assert.equal(deps.smbOpens.length, 1);
    // reset one slot
    client.reset('winrm');
    assert.deepEqual(await client.run('x'), OK);
    assert.equal(deps.winrmOpens.length, 2);
    assert.equal(await client.ls('C$').catch((e: unknown) => e), smbErr, 'smb latch untouched');
    client.reset();
    await assert.rejects(client.ls('C$'), WinLinuxAuthError);
    assert.equal(deps.smbOpens.length, 2);
  });

  it('a Kerberos password rejection over WinRM exits 2 and latches the winrm slot', async () => {
    // What @winlinux/winrm raises when Negotiate throws KerberosCredentialError.
    const krb = Object.assign(new Error('KDC rejected the password'), { name: 'KerberosCredentialError' });
    const deps = fakeDeps({
      winrm: async () => {
        const s = new FakeWinrm();
        s.runImpl = async () => Promise.reject(new WinRMAuthError(`WinRM credentials were rejected: ${krb.message}`, { cause: krb }));
        return s;
      },
    });
    const client = createClient('h', OPTS, deps);
    const first = await client.run('x').catch((e: unknown) => e);
    assert.ok(first instanceof WinLinuxAuthError);
    assert.equal(exitCodeFor(first), EXIT.auth);
    assert.equal(EXIT.auth, 2);
    await tick();
    assert.equal(await client.run('x').catch((e: unknown) => e), first, 'same latched error');
    assert.equal(deps.winrmOpens.length, 1, 'no new connect while latched');
  });

  it('setPassword clears both latches and later opens get the new Credentials object', async () => {
    let fail = true;
    const deps = fakeDeps({
      // winrm open errors are usage errors, so the winrm latch comes from an op.
      winrm: async () => {
        const s = new FakeWinrm();
        if (fail) s.runImpl = async () => Promise.reject(new WinRMAuthError('401'));
        return s;
      },
      smb: async () => {
        if (fail) throw new SmbAuthError('logon failure', 0xc000006d);
        return new FakeSmb();
      },
    });
    const client = createClient('h', OPTS, deps);
    await assert.rejects(client.run('x'), WinLinuxAuthError);
    await assert.rejects(client.ls('C$'), WinLinuxAuthError);
    assert.throws(() => client.setPassword(''), WinLinuxUsageError);
    fail = false;
    client.setPassword('new-password');
    assert.deepEqual(await client.run('x'), OK);
    assert.deepEqual(await client.ls('C$'), []);
    const oldCreds = deps.winrmOpens[0]?.credentials;
    const newCreds = deps.winrmOpens[1]?.credentials;
    assert.notEqual(newCreds, oldCreds);
    assert.equal(newCreds?.password, 'new-password');
    assert.ok(Object.isFrozen(newCreds));
    assert.equal(deps.smbOpens[1]?.credentials, newCreds, 'both slots get the same new object');
    assert.equal(oldCreds?.password, 'slot-test-password', 'the old object is unchanged');
  });

  it('a hung session close is bounded at 5 s', async () => {
    mock.timers.enable({ apis: ['setTimeout'] });
    try {
      const session = new FakeWinrm();
      session.closeImpl = () => new Promise(() => undefined);
      const logs: string[] = [];
      const deps = fakeDeps({ winrm: async () => session });
      deps.log = (line) => logs.push(line);
      const client = createClient('h', OPTS, deps);
      await client.run('x');
      let done = false;
      const closing = client.close().then(() => (done = true));
      await tick();
      mock.timers.tick(4999);
      await tick();
      assert.equal(done, false, 'still waiting before 5 s');
      mock.timers.tick(1);
      await closing;
      assert.equal(done, true);
      assert.ok(logs.some((l) => /winrm close error: session close timed out after 5000 ms/.test(l)), logs.join('\n'));
    } finally {
      mock.timers.reset();
    }
  });

  it('close during a hung open resolves within the bound, then closes the late session', async () => {
    const gate = deferred<SMBSession>();
    const logs: string[] = [];
    const deps = fakeDeps({ smb: () => gate.promise, closeTimeoutMs: 50 });
    deps.log = (line) => logs.push(line);
    const client = createClient('h', OPTS, deps);
    const pending = client.ls('C$');
    await tick();
    const started = Date.now();
    await client.close();
    assert.ok(Date.now() - started < 1000, 'close did not wait for the hung open');
    assert.ok(logs.some((l) => /smb close error: open did not finish within 50 ms/.test(l)), logs.join('\n'));
    const late = new FakeSmb();
    gate.resolve(late);
    await assert.rejects(pending, WinLinuxUsageError);
    await tick();
    assert.equal(late.closed, 1, 'the late session is closed in the background');
  });

  it('pass-through error keeps the slot open', async () => {
    const fault = new WinRMFaultError('fault', null, null, 'r', 1, null, '');
    let calls = 0;
    const deps = fakeDeps({
      winrm: async () => {
        const s = new FakeWinrm();
        s.runImpl = async () => (++calls === 1 ? Promise.reject(fault) : OK);
        return s;
      },
    });
    const client = createClient('h', OPTS, deps);
    await assert.rejects(client.run('x'), (err) => err === fault);
    assert.deepEqual(await client.run('x'), OK);
    assert.equal(deps.winrmOpens.length, 1);
  });

  it('close during opening waits, then closes the new session', async () => {
    const gate = deferred<WinRMSession>();
    const deps = fakeDeps({ winrm: () => gate.promise });
    const client = createClient('h', OPTS, deps);
    const pending = client.run('x');
    await tick();
    let closed = false;
    const closing = client.close().then(() => (closed = true));
    await tick();
    assert.equal(closed, false, 'close waits for the open');
    const session = new FakeWinrm();
    gate.resolve(session);
    await closing;
    assert.equal(session.closed, 1);
    await assert.rejects(pending, WinLinuxUsageError);
  });

  it('close is idempotent and calls after close throw WinLinuxUsageError', async () => {
    const session = new FakeWinrm();
    const deps = fakeDeps({ winrm: async () => session });
    const client = createClient('h', OPTS, deps);
    await client.run('x');
    const first = client.close();
    assert.equal(client.close(), first);
    await first;
    assert.equal(session.closed, 1);
    await assert.rejects(client.run('x'), /client is closed/);
    await assert.rejects(client.ls('C$'), WinLinuxUsageError);
    assert.equal(deps.smbOpens.length, 0);
  });
});
