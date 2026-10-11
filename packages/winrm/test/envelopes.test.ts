import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  buildCommandRequest,
  buildCreateShellRequest,
  buildDeleteShellRequest,
  buildReceiveRequest,
  buildSignalRequest,
} from '../src/winrm/envelopes.js';

function golden(name: string): string {
  return readFileSync(new URL(`./fixtures/golden/${name}`, import.meta.url), 'utf8');
}

const BASE = {
  to: 'http://host:5985/wsman',
  messageId: '11111111-1111-4111-8111-111111111111',
  operationTimeout: 'PT60S',
};

describe('SOAP envelope builders', () => {
  it('builds Create shell (UTF-8 codepage 65001)', () => {
    assert.equal(buildCreateShellRequest({ ...BASE }), golden('create-shell.xml'));
  });

  it('builds Create shell with working directory, XML-escaped', () => {
    assert.equal(buildCreateShellRequest({ ...BASE, workingDirectory: 'C:\\Temp & Files' }), golden('create-shell-cwd.xml'));
  });

  it('builds Command with one Arguments element per arg, XML-escaped', () => {
    assert.equal(
      buildCommandRequest({ ...BASE, shellId: 'SHELL-ID-1', command: 'echo', args: ['hello', 'a&b'] }),
      golden('command.xml'),
    );
  });

  it('builds Receive with DesiredStream', () => {
    assert.equal(
      buildReceiveRequest({ ...BASE, shellId: 'SHELL-ID-1', commandId: 'COMMAND-ID-1' }),
      golden('receive.xml'),
    );
  });

  it('builds Signal terminate', () => {
    assert.equal(
      buildSignalRequest({ ...BASE, shellId: 'SHELL-ID-1', commandId: 'COMMAND-ID-1' }),
      golden('signal.xml'),
    );
  });

  it('builds Delete shell', () => {
    assert.equal(buildDeleteShellRequest({ ...BASE, shellId: 'SHELL-ID-1' }), golden('delete.xml'));
  });
});
