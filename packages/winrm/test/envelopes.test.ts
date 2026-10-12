import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  buildCommandRequest,
  buildCreateShellRequest,
  buildDeleteShellRequest,
  buildPsrpCommandRequest,
  buildPsrpCreateRequest,
  buildPsrpReceiveRequest,
  buildPsrpSendRequest,
  buildPsrpSignalRequest,
  buildReceiveRequest,
  buildSignalRequest,
  PSRP_SIGNAL_CRTL_C,
  psrpResourceUri,
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

// PSRP envelopes (MS-PSRP 3.1.5.3). The WinRS golden files above are
// unchanged: a resource URI, a session id and MustComply only appear when
// a caller asks for them.
describe('PSRP SOAP envelope builders', () => {
  const POOL = 'AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE';
  const PIPELINE = 'FFFFFFFF-0000-4000-8000-000000000001';
  const SESSION = '22222222-2222-4222-8222-222222222222';
  const PS = { ...BASE, resourceUri: psrpResourceUri() };

  it('psrpResourceUri names the session configuration and refuses odd names', () => {
    assert.equal(psrpResourceUri(), 'http://schemas.microsoft.com/powershell/Microsoft.PowerShell');
    assert.equal(psrpResourceUri('My.Config_1'), 'http://schemas.microsoft.com/powershell/My.Config_1');
    assert.throws(() => psrpResourceUri('a b'), RangeError);
    assert.throws(() => psrpResourceUri('x/../y'), RangeError);
    assert.throws(() => psrpResourceUri(''), RangeError);
  });

  it('builds Create with the ShellId attribute, protocolversion MustComply, stdin pr / stdout and creationXml, no SelectorSet', () => {
    const xml = buildPsrpCreateRequest({ ...PS, shellId: POOL, protocolVersion: '2.3', creationXml: Buffer.from('creation-xml-bytes') });
    assert.equal(xml, golden('psrp-create.xml'));
    assert.ok(!xml.includes('SelectorSet'));
    assert.ok(xml.includes('<wsman:Option Name="protocolversion" MustComply="true">2.3</wsman:Option>'));
    assert.ok(xml.includes('<creationXml xmlns="http://schemas.microsoft.com/powershell">Y3JlYXRpb24teG1sLWJ5dGVz</creationXml>'));
    assert.ok(xml.includes('<wsman:ResourceURI mustUnderstand="true">http://schemas.microsoft.com/powershell/Microsoft.PowerShell</wsman:ResourceURI>'));
  });

  it('builds Create with wsmv:SessionId and IdleTimeOut, declaring the wsmv namespace only then', () => {
    const xml = buildPsrpCreateRequest({ ...PS, sessionId: SESSION, shellId: POOL, protocolVersion: '2.3', creationXml: Buffer.from('creation-xml-bytes'), idleTimeoutMs: 240000 });
    assert.equal(xml, golden('psrp-create-idle.xml'));
    assert.ok(xml.includes('xmlns:wsmv="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd"'));
    assert.ok(xml.includes(`<wsmv:SessionId mustUnderstand="false">uuid:${SESSION}</wsmv:SessionId>`));
    assert.ok(xml.includes('<rsp:IdleTimeOut>PT240S</rsp:IdleTimeOut>'));
    assert.ok(!golden('psrp-create.xml').includes('wsmv'), 'no session id, no wsmv namespace');
  });

  it('builds Command with the client CommandId, an empty rsp:Command and base64 rsp:Arguments', () => {
    const xml = buildPsrpCommandRequest({ ...PS, shellId: POOL, commandId: PIPELINE, arguments: Buffer.from('create-pipeline-fragment') });
    assert.equal(xml, golden('psrp-command.xml'));
    assert.ok(xml.includes(`<rsp:CommandLine CommandId="${PIPELINE}"><rsp:Command></rsp:Command><rsp:Arguments>Y3JlYXRlLXBpcGVsaW5lLWZyYWdtZW50</rsp:Arguments></rsp:CommandLine>`));
    assert.ok(!xml.includes('WINRS_'), 'no WinRS options');
    assert.ok(xml.includes(`<wsman:Selector Name="ShellId">${POOL}</wsman:Selector>`));
  });

  it('builds Receive for the pool and for a pipeline, stdout only', () => {
    assert.equal(buildPsrpReceiveRequest({ ...PS, shellId: POOL }), golden('psrp-receive-pool.xml'));
    assert.equal(buildPsrpReceiveRequest({ ...PS, shellId: POOL, commandId: PIPELINE }), golden('psrp-receive-pipeline.xml'));
    assert.ok(golden('psrp-receive-pool.xml').includes('<rsp:DesiredStream>stdout</rsp:DesiredStream>'));
    assert.ok(golden('psrp-receive-pipeline.xml').includes(`<rsp:DesiredStream CommandId="${PIPELINE}">stdout</rsp:DesiredStream>`));
  });

  it('builds Send on stdin for the pool and on pr for a pipeline, without End', () => {
    const pool = buildPsrpSendRequest({ ...PS, shellId: POOL, stream: 'stdin', data: Buffer.from('pool-fragment') });
    const pipeline = buildPsrpSendRequest({ ...PS, shellId: POOL, stream: 'pr', commandId: PIPELINE, data: Buffer.from('host-response') });
    assert.equal(pool, golden('psrp-send-stdin-pool.xml'));
    assert.equal(pipeline, golden('psrp-send-pr-pipeline.xml'));
    assert.ok(pool.includes('<rsp:Stream Name="stdin">cG9vbC1mcmFnbWVudA==</rsp:Stream>'));
    assert.ok(pipeline.includes(`<rsp:Stream Name="pr" CommandId="${PIPELINE}">aG9zdC1yZXNwb25zZQ==</rsp:Stream>`));
    assert.ok(!pool.includes('End='));
  });

  it('builds Signal with the PowerShell ctrl_c code by default, and any code on request', () => {
    const xml = buildPsrpSignalRequest({ ...PS, shellId: POOL, commandId: PIPELINE });
    assert.equal(xml, golden('psrp-signal.xml'));
    assert.ok(xml.includes('<rsp:Code>powershell/signal/ctrl_c</rsp:Code>'));
    assert.ok(buildPsrpSignalRequest({ ...PS, shellId: POOL, commandId: PIPELINE, code: PSRP_SIGNAL_CRTL_C }).includes('<rsp:Code>powershell/signal/crtl_c</rsp:Code>'));
  });

  it('builds Delete on the PSRP resource with the session id', () => {
    assert.equal(buildDeleteShellRequest({ ...PS, sessionId: SESSION, shellId: POOL }), golden('psrp-delete-session.xml'));
  });

  it('WinRS builders are byte-identical with no PSRP argument', () => {
    // The same check as the golden tests above, in one place, so a change
    // to buildEnvelope that leaks a header into WinRS fails here too.
    for (const [xml, name] of [
      [buildCreateShellRequest({ ...BASE }), 'create-shell.xml'],
      [buildCommandRequest({ ...BASE, shellId: 'SHELL-ID-1', command: 'echo', args: ['hello', 'a&b'] }), 'command.xml'],
      [buildReceiveRequest({ ...BASE, shellId: 'SHELL-ID-1', commandId: 'COMMAND-ID-1' }), 'receive.xml'],
      [buildSignalRequest({ ...BASE, shellId: 'SHELL-ID-1', commandId: 'COMMAND-ID-1' }), 'signal.xml'],
      [buildDeleteShellRequest({ ...BASE, shellId: 'SHELL-ID-1' }), 'delete.xml'],
    ] as const) {
      assert.equal(xml, golden(name));
      assert.ok(!xml.includes('wsmv') && !xml.includes('MustComply'), name);
    }
  });
});
