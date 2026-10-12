import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  ReceiveAccumulator,
  parseCommandResponse,
  parseCreateShellResponse,
  parsePsrpReceiveResponse,
  parseReceiveResponse,
  parseSoapFault,
} from '../src/winrm/parse.js';
import { WinRMFaultError, WinRMProtocolError } from '../src/winrm/errors.js';

function fixture(name: string): string {
  return readFileSync(new URL(`./fixtures/${name}`, import.meta.url), 'utf8');
}

describe('response parsing', () => {
  it('extracts shell id from ResourceCreated selectors', () => {
    assert.equal(parseCreateShellResponse(fixture('create-response.xml')), 'SHELL-ID-1');
  });

  it('extracts shell id from rsp:Shell fallback shape', () => {
    const xml =
      '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body>' +
      '<rsp:Shell xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell">' +
      '<rsp:ShellId>SHELL-9</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>';
    assert.equal(parseCreateShellResponse(xml), 'SHELL-9');
  });

  it('throws WinRMProtocolError when no shell id is present', () => {
    assert.throws(() => parseCreateShellResponse('<s:Envelope xmlns:s="urn:x"><s:Body/></s:Envelope>'), WinRMProtocolError);
  });

  it('extracts command id', () => {
    assert.equal(parseCommandResponse(fixture('command-response.xml')), 'COMMAND-ID-1');
  });

  it('parses a Running poll with one stdout chunk', () => {
    const poll = parseReceiveResponse(fixture('receive-running.xml'));
    assert.equal(poll.done, false);
    assert.equal(poll.exitCode, null);
    assert.equal(poll.stdout.toString('utf8'), 'hello ');
    assert.equal(poll.stderr.length, 0);
  });

  it('assembles multi-chunk stdout/stderr and reads the exit code', () => {
    const acc = new ReceiveAccumulator();
    acc.push(parseReceiveResponse(fixture('receive-running.xml')));
    assert.equal(acc.done, false);
    acc.push(parseReceiveResponse(fixture('receive-running2.xml')));
    assert.equal(acc.done, false);
    acc.push(parseReceiveResponse(fixture('receive-done.xml')));
    assert.equal(acc.done, true);
    assert.deepEqual(acc.result(), { stdout: 'hello world', stderr: 'oops', exitCode: 3 });
  });

  it('throws WinRMProtocolError when Done carries no ExitCode', () => {
    assert.throws(() => parseReceiveResponse(fixture('receive-noexit.xml')), WinRMProtocolError);
  });

  it('result() before Done throws WinRMProtocolError', () => {
    const acc = new ReceiveAccumulator();
    acc.push(parseReceiveResponse(fixture('receive-running.xml')));
    assert.throws(() => acc.result(), WinRMProtocolError);
  });

  it('returns null for a non-fault response', () => {
    assert.equal(parseSoapFault(fixture('receive-done.xml')), null);
  });

  it('maps a SOAP fault to WinRMFaultError with code, reason, wsman code', () => {
    const fault = parseSoapFault(fixture('fault-500.xml'));
    assert.ok(fault instanceof WinRMFaultError);
    assert.equal(fault.faultCode, 's:Receiver');
    assert.equal(fault.faultSubcode, 'w:InternalError');
    assert.equal(fault.reason, 'The request failed: no such shell.');
    assert.equal(fault.wsmanCode, 2150859174);
    assert.equal(fault.machine, 'WIN-HOST');
  });

  it('reads the operation-timeout fault code 2150858793', () => {
    const fault = parseSoapFault(fixture('fault-optimeout.xml'));
    assert.ok(fault instanceof WinRMFaultError);
    assert.equal(fault.wsmanCode, 2150858793);
  });

  it('parse* entry points raise the fault instead of returning data', () => {
    const faultXml = fixture('fault-500.xml');
    assert.throws(() => parseCreateShellResponse(faultXml), WinRMFaultError);
    assert.throws(() => parseCommandResponse(faultXml), WinRMFaultError);
    assert.throws(() => parseReceiveResponse(faultXml), WinRMFaultError);
  });
});

// A PSRP ReceiveResponse (MS-PSRP 3.1.5.3.8): stdout streams with
// their CommandId, in order; other names discarded; Done without an
// ExitCode is fine, where parseReceiveResponse throws.
describe('parsePsrpReceiveResponse', () => {
  const RSP = 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell';
  const PIPELINE = 'FFFFFFFF-0000-4000-8000-000000000001';
  const b64 = (text: string) => Buffer.from(text).toString('base64');
  const envelope = (body: string) =>
    `<?xml version="1.0"?><s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:rsp="${RSP}"><s:Header/><s:Body>${body}</s:Body></s:Envelope>`;
  const done = `<rsp:CommandState CommandId="${PIPELINE}" State="${RSP}/CommandState/Done"/>`;

  it('stdout only with Done and no ExitCode: done is true, and the WinRS parser refuses the same response', () => {
    const xml = envelope(`<rsp:ReceiveResponse><rsp:Stream Name="stdout" CommandId="${PIPELINE}">${b64('state')}</rsp:Stream>${done}</rsp:ReceiveResponse>`);
    const poll = parsePsrpReceiveResponse(xml);
    assert.equal(poll.done, true);
    assert.deepEqual(poll.streams.map((s) => [s.commandId, s.data.toString()]), [[PIPELINE, 'state']]);
    assert.throws(() => parseReceiveResponse(xml), WinRMProtocolError);
  });

  it('keeps several stdout elements in order with their CommandId, pool streams without one, and drops stderr', () => {
    const xml = envelope(
      '<rsp:ReceiveResponse>' +
        `<rsp:Stream Name="stdout">${b64('pool-1')}</rsp:Stream>` +
        `<rsp:Stream Name="stderr" CommandId="${PIPELINE}">${b64('ignored')}</rsp:Stream>` +
        `<rsp:Stream Name="stdout" CommandId="${PIPELINE}">${b64('pipe-1')}</rsp:Stream>` +
        `<rsp:Stream Name="stdout" CommandId="${PIPELINE}"></rsp:Stream>` +
        `<rsp:Stream Name="stdout">${b64('pool-2')}</rsp:Stream>` +
        '</rsp:ReceiveResponse>',
    );
    const poll = parsePsrpReceiveResponse(xml);
    assert.equal(poll.done, false);
    assert.deepEqual(
      poll.streams.map((s) => [s.commandId ?? null, s.data.toString()]),
      [
        [null, 'pool-1'],
        [PIPELINE, 'pipe-1'],
        [null, 'pool-2'],
      ],
    );
  });

  it('a Running state is not done; a response with no streams is empty', () => {
    const xml = envelope(`<rsp:ReceiveResponse><rsp:CommandState CommandId="${PIPELINE}" State="${RSP}/CommandState/Running"/></rsp:ReceiveResponse>`);
    assert.deepEqual(parsePsrpReceiveResponse(xml), { streams: [], done: false });
  });

  it('a fault throws WinRMFaultError, and a body without ReceiveResponse throws WinRMProtocolError', () => {
    assert.throws(() => parsePsrpReceiveResponse(fixture('fault-500.xml')), WinRMFaultError);
    assert.throws(() => parsePsrpReceiveResponse(envelope('<rsp:Nothing/>')), WinRMProtocolError);
  });
});
