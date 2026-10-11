import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { connect } from '../src/winrm/index.js';
import { basicStub, challengeStub, CREDENTIALS } from './helpers/stub-auth.js';

describe('transport encryption rule', () => {
  it('refuses plain HTTP when the context has no wrap', async () => {
    await assert.rejects(
      connect({ host: 'host', authProvider: basicStub(), credentials: CREDENTIALS }),
      /plain HTTP.*HTTPS|HTTPS.*plain HTTP/i,
    );
  });

  it("refuses plain HTTP with encryption 'never'", async () => {
    await assert.rejects(
      connect({ host: 'host', authProvider: challengeStub({ seal: true }), credentials: CREDENTIALS, encryption: 'never' }),
      /plain HTTP/i,
    );
  });

  it("refuses encryption 'always' when the context has no wrap, even on HTTPS", async () => {
    await assert.rejects(
      connect({ host: 'host', tls: true, authProvider: basicStub(), credentials: CREDENTIALS, encryption: 'always' }),
      /wrap/i,
    );
  });

  it('allows plain HTTP when the context offers wrap/unwrap', async () => {
    const session = await connect({ host: 'host', authProvider: challengeStub({ seal: true }), credentials: CREDENTIALS });
    assert.equal(typeof session.runCommand, 'function');
    await session.close();
  });

  it('allows HTTPS without wrap', async () => {
    const session = await connect({ host: 'host', tls: true, authProvider: basicStub(), credentials: CREDENTIALS });
    assert.equal(typeof session.runCommand, 'function');
    await session.close();
  });

  it('exposes the exact public session API', async () => {
    const session = await connect({ host: 'host', tls: true, authProvider: basicStub(), credentials: CREDENTIALS });
    for (const method of [
      'runCommand',
      'runPowerShell',
      'runCommandStream',
      'runPowerShellStream',
      'readEventLog',
      'listServices',
      'listProcesses',
      'close',
    ] as const) {
      assert.equal(typeof session[method], 'function', `WinRMSession.${method} is a function`);
    }
    await session.close();
  });
});
