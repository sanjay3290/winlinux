import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { connect } from '../src/winrm/index.js';
import { WinRMFaultError } from '../src/winrm/errors.js';
import { basicStub, challengeStub, CREDENTIALS, fakeNtlmWrap, fakeNtlmUnwrap } from './helpers/stub-auth.js';
import { actionOf, mimeUnwrap, mimeWrap, negotiateGate, startMockServer, type MockResponse, type RecordedRequest } from './helpers/mock-server.js';

const B64 = (s: string) => Buffer.from(s).toString('base64');

function fixture(name: string): string {
  return readFileSync(new URL(`./fixtures/${name}`, import.meta.url), 'utf8');
}

const SIGNAL_RESPONSE =
  '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body>' +
  '<rsp:SignalResponse xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell"/>' +
  '</s:Body></s:Envelope>';
const DELETE_RESPONSE =
  '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body>' +
  '<x:DeleteResponse xmlns:x="http://schemas.xmlsoap.org/ws/2004/09/transfer"/>' +
  '</s:Body></s:Envelope>';

// The PowerShell script inside a Command envelope's -EncodedCommand argument.
function encodedScript(soap: string): string {
  const args = [...soap.matchAll(/<rsp:Arguments>([^<]*)<\/rsp:Arguments>/g)].map((m) => m[1] ?? '');
  return Buffer.from(args[args.indexOf('-EncodedCommand') + 1] ?? '', 'base64').toString('utf16le');
}

function doneReceive(stdoutText: string, exitCode = 0, stderrText = ''): string {
  const streams = [
    `<rsp:Stream Name="stdout" CommandId="COMMAND-ID-1">${B64(stdoutText)}</rsp:Stream>`,
  ];
  if (stderrText) streams.push(`<rsp:Stream Name="stderr" CommandId="COMMAND-ID-1">${B64(stderrText)}</rsp:Stream>`);
  return (
    '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body>' +
    '<rsp:ReceiveResponse xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell">' +
    `${streams.join('')}` +
    `<rsp:CommandState CommandId="COMMAND-ID-1" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done">` +
    `<rsp:ExitCode>${exitCode}</rsp:ExitCode></rsp:CommandState></rsp:ReceiveResponse></s:Body></s:Envelope>`
  );
}

interface Script {
  // Queued SOAP responses per action; {fault} entries go out as HTTP 500.
  routes: Record<string, Array<string | { fault: string }>>;
  seenActions: string[];
  seenSoaps: string[];
}

// Challenge-auth router over plain HTTP: the client must wrap every SOAP
// request and unwrap every SOAP response with the fake context. Auth is
// bound to the connection (negotiateGate), as on Windows.
function encryptedHandler(script: Script) {
  const gate = negotiateGate();
  return (req: RecordedRequest): MockResponse => {
    const denied = gate.check(req);
    if (denied) return denied;
    const contentType = req.headers['content-type'] ?? '';
    const soap = contentType.includes('multipart/encrypted') ? mimeUnwrap(req.body, fakeNtlmUnwrap) : req.body.toString('utf8');
    const action = actionOf(Buffer.from(soap));
    script.seenActions.push(action);
    script.seenSoaps.push(soap);
    const next = script.routes[action]?.shift();
    if (next === undefined) throw new Error(`no scripted response for action ${action}`);
    if (typeof next !== 'string') {
      const wrapped = mimeWrap(next.fault, fakeNtlmWrap);
      return { status: 500, headers: { 'Content-Type': wrapped.contentType }, body: wrapped.body };
    }
    const wrapped = mimeWrap(next, fakeNtlmWrap);
    return { status: 200, headers: { 'Content-Type': wrapped.contentType }, body: wrapped.body };
  };
}

function newScript(routes: Record<string, Array<string | { fault: string }>>): Script {
  return { routes, seenActions: [], seenSoaps: [] };
}

describe('mock-server session flows', () => {
  it('runs a full runCommand round trip with Signal+Delete cleanup', async () => {
    const script = newScript({
      Create: [fixture('create-response.xml')],
      Command: [fixture('command-response.xml')],
      Receive: [fixture('receive-running.xml'), fixture('receive-done.xml')],
      Signal: [SIGNAL_RESPONSE],
      Delete: [DELETE_RESPONSE],
    });
    const server = await startMockServer(encryptedHandler(script));
    try {
      const session = await connect({ host: '127.0.0.1', port: server.port, authProvider: challengeStub({ seal: true }), credentials: CREDENTIALS });
      try {
        const result = await session.runCommand('echo', ['hello']);
        assert.deepEqual(result, { stdout: 'hello world', stderr: '', exitCode: 3 });
      } finally {
        await session.close();
      }
      assert.deepEqual(script.seenActions, ['Create', 'Command', 'Receive', 'Receive', 'Signal', 'Delete']);
      assert.match(script.seenSoaps[0] ?? '', /<wsman:OperationTimeout>PT60S<\/wsman:OperationTimeout>/);
      assert.match(script.seenSoaps[1] ?? '', /<rsp:Command>echo<\/rsp:Command>/);
    } finally {
      await server.close();
    }
  });

  it('streams chunks in poll order', async () => {
    const script = newScript({
      Create: [fixture('create-response.xml')],
      Command: [fixture('command-response.xml')],
      Receive: [fixture('receive-running.xml'), fixture('receive-running2.xml'), fixture('receive-done.xml')],
      Signal: [SIGNAL_RESPONSE],
      Delete: [DELETE_RESPONSE],
    });
    const server = await startMockServer(encryptedHandler(script));
    try {
      const session = await connect({ host: '127.0.0.1', port: server.port, authProvider: challengeStub({ seal: true }), credentials: CREDENTIALS });
      try {
        const chunks = [];
        for await (const chunk of session.runCommandStream('echo')) chunks.push(chunk);
        assert.deepEqual(chunks, [
          { stream: 'stdout', data: 'hello ' },
          { stream: 'stderr', data: 'oops' },
          { stream: 'stdout', data: 'world' },
        ]);
      } finally {
        await session.close();
      }
    } finally {
      await server.close();
    }
  });

  it('the stream ends with { exitCode } as its final iterator value', async () => {
    const script = newScript({
      Create: [fixture('create-response.xml')],
      Command: [fixture('command-response.xml')],
      Receive: [fixture('receive-running.xml'), fixture('receive-done.xml')],
      Signal: [SIGNAL_RESPONSE],
      Delete: [DELETE_RESPONSE],
    });
    const server = await startMockServer(encryptedHandler(script));
    try {
      const session = await connect({ host: '127.0.0.1', port: server.port, authProvider: challengeStub({ seal: true }), credentials: CREDENTIALS });
      try {
        const it = session.runCommandStream('echo')[Symbol.asyncIterator]();
        const seen: unknown[] = [];
        for (;;) {
          const r = await it.next();
          seen.push(r.value);
          if (r.done) break;
        }
        assert.deepEqual(seen, [
          { stream: 'stdout', data: 'hello ' },
          { stream: 'stdout', data: 'world' },
          { exitCode: 3 },
        ]);
      } finally {
        await session.close();
      }
    } finally {
      await server.close();
    }
  });

  it('a UTF-8 character split across two Receives comes out whole', async () => {
    const bytes = Buffer.from('é✓\n', 'utf8'); // 2 + 3 + 1 bytes
    const receive = (data: Buffer, done: boolean) =>
      fixture(done ? 'receive-done.xml' : 'receive-running.xml').replace(
        /(<rsp:Stream Name="stdout" CommandId="COMMAND-ID-1">)[^<]*(<\/rsp:Stream>)/,
        `$1${data.toString('base64')}$2`,
      );
    const script = newScript({
      Create: [fixture('create-response.xml')],
      Command: [fixture('command-response.xml')],
      Receive: [receive(bytes.subarray(0, 1), false), receive(bytes.subarray(1, 3), false), receive(bytes.subarray(3), true)],
      Signal: [SIGNAL_RESPONSE],
      Delete: [DELETE_RESPONSE],
    });
    const server = await startMockServer(encryptedHandler(script));
    try {
      const session = await connect({ host: '127.0.0.1', port: server.port, authProvider: challengeStub({ seal: true }), credentials: CREDENTIALS });
      try {
        let text = '';
        for await (const chunk of session.runCommandStream('echo')) text += chunk.data;
        assert.equal(text, 'é✓\n');
        assert.ok(!text.includes('\ufffd'));
      } finally {
        await session.close();
      }
    } finally {
      await server.close();
    }
  });

  it('encrypts SOAP requests: probe stays plain, bodies go multipart', async () => {
    const script = newScript({
      Create: [fixture('create-response.xml')],
      Command: [fixture('command-response.xml')],
      Receive: [fixture('receive-done.xml')],
      Signal: [SIGNAL_RESPONSE],
      Delete: [DELETE_RESPONSE],
    });
    const server = await startMockServer(encryptedHandler(script));
    try {
      const session = await connect({ host: '127.0.0.1', port: server.port, authProvider: challengeStub({ seal: true }), credentials: CREDENTIALS });
      try {
        await session.runCommand('hostname');
      } finally {
        await session.close();
      }
      const types = server.requests.map((r) => r.headers['content-type']);
      assert.equal(types[0], 'application/soap+xml;charset=UTF-8');
      assert.equal(server.requests[0]?.body.length, 0);
      for (const t of types.slice(1)) {
        assert.match(t ?? '', /^multipart\/encrypted;protocol="application\/HTTP-SPNEGO-session-encrypted";boundary="Encrypted Boundary"$/);
      }
      // Every wrapped body unwraps to a real SOAP envelope for the right action.
      assert.deepEqual(script.seenActions, ['Create', 'Command', 'Receive', 'Signal', 'Delete']);
    } finally {
      await server.close();
    }
  });

  it('maps a SOAP fault to WinRMFaultError and still deletes the shell', async () => {
    const script = newScript({
      Create: [fixture('create-response.xml')],
      Command: [{ fault: fixture('fault-500.xml') }],
      Delete: [DELETE_RESPONSE],
    });
    const server = await startMockServer(encryptedHandler(script));
    try {
      const session = await connect({ host: '127.0.0.1', port: server.port, authProvider: challengeStub({ seal: true }), credentials: CREDENTIALS });
      try {
        let err: unknown;
        try {
          await session.runCommand('bad');
        } catch (e) {
          err = e;
        }
        assert.ok(err instanceof WinRMFaultError);
        assert.equal(err.reason, 'The request failed: no such shell.');
        assert.equal(err.wsmanCode, 2150859174);
      } finally {
        await session.close();
      }
      assert.deepEqual(script.seenActions, ['Create', 'Command', 'Delete']);
    } finally {
      await server.close();
    }
  });

  it('retries Receive on operation-timeout faults', async () => {
    const script = newScript({
      Create: [fixture('create-response.xml')],
      Command: [fixture('command-response.xml')],
      Receive: [{ fault: fixture('fault-optimeout.xml') }, fixture('receive-done.xml')],
      Signal: [SIGNAL_RESPONSE],
      Delete: [DELETE_RESPONSE],
    });
    const server = await startMockServer(encryptedHandler(script));
    try {
      const session = await connect({ host: '127.0.0.1', port: server.port, authProvider: challengeStub({ seal: true }), credentials: CREDENTIALS });
      try {
        const result = await session.runCommand('slow');
        assert.deepEqual(result, { stdout: 'world', stderr: '', exitCode: 3 });
      } finally {
        await session.close();
      }
      assert.deepEqual(script.seenActions, ['Create', 'Command', 'Receive', 'Receive', 'Signal', 'Delete']);
    } finally {
      await server.close();
    }
  });

  it('runPowerShell sends powershell.exe and strips CLIXML stderr', async () => {
    const clixml = readFileSync(new URL('./fixtures/clixml-error.txt', import.meta.url), 'utf8');
    const script = newScript({
      Create: [fixture('create-response.xml')],
      Command: [fixture('command-response.xml')],
      Receive: [doneReceive('', 1, clixml)],
      Signal: [SIGNAL_RESPONSE],
      Delete: [DELETE_RESPONSE],
    });
    const server = await startMockServer(encryptedHandler(script));
    try {
      const session = await connect({ host: '127.0.0.1', port: server.port, authProvider: challengeStub({ seal: true }), credentials: CREDENTIALS });
      try {
        const result = await session.runPowerShell('Get-Process -Name nope');
        assert.equal(result.exitCode, 1);
        assert.match(result.stderr, /^Get-Process : Cannot find a process/);
        assert.doesNotMatch(result.stderr, /CLIXML/);
        assert.match(script.seenSoaps[1] ?? '', /<rsp:Command>powershell\.exe<\/rsp:Command>/);
        // The script goes out as -EncodedCommand, never in clear.
        assert.match(script.seenSoaps[1] ?? '', /<rsp:Arguments>-NoProfile<\/rsp:Arguments><rsp:Arguments>-NonInteractive<\/rsp:Arguments><rsp:Arguments>-EncodedCommand<\/rsp:Arguments>/);
        assert.equal(encodedScript(script.seenSoaps[1] ?? ''), 'Get-Process -Name nope');
        assert.doesNotMatch(script.seenSoaps[1] ?? '', /Get-Process -Name nope/);
      } finally {
        await session.close();
      }
    } finally {
      await server.close();
    }
  });

  it('reads event logs, services, and processes through JSON queries', async () => {
    const script = newScript({
      Create: [fixture('create-response.xml'), fixture('create-response.xml'), fixture('create-response.xml')],
      Command: [fixture('command-response.xml'), fixture('command-response.xml'), fixture('command-response.xml')],
      Receive: [doneReceive(fixture('events.json')), doneReceive(fixture('services.json')), doneReceive(fixture('processes.json'))],
      Signal: [SIGNAL_RESPONSE, SIGNAL_RESPONSE, SIGNAL_RESPONSE],
      Delete: [DELETE_RESPONSE, DELETE_RESPONSE, DELETE_RESPONSE],
    });
    const server = await startMockServer(encryptedHandler(script));
    try {
      const session = await connect({ host: '127.0.0.1', port: server.port, authProvider: challengeStub({ seal: true }), credentials: CREDENTIALS });
      try {
        const events = await session.readEventLog({ logName: 'System', maxEvents: 10 });
        assert.equal(events.length, 2);
        assert.equal(events[0]?.id, 7036);
        const services = await session.listServices();
        assert.deepEqual(services[0], { name: 'wuauserv', displayName: 'Windows Update', status: 'Running', startType: 'Manual' });
        const processes = await session.listProcesses();
        assert.equal(processes[1]?.startTime, null);
        // The query script travels as -EncodedCommand.
        assert.match(encodedScript(script.seenSoaps[1] ?? ''), /^@\(Get-WinEvent -LogName 'System' -MaxEvents 10 \| /);
      } finally {
        await session.close();
      }
    } finally {
      await server.close();
    }
  });

  it('structured queries reject when PowerShell exits non-zero', async () => {
    const script = newScript({
      Create: [fixture('create-response.xml')],
      Command: [fixture('command-response.xml')],
      Receive: [doneReceive('', 1, 'boom')],
      Signal: [SIGNAL_RESPONSE],
      Delete: [DELETE_RESPONSE],
    });
    const server = await startMockServer(encryptedHandler(script));
    try {
      const session = await connect({ host: '127.0.0.1', port: server.port, authProvider: challengeStub({ seal: true }), credentials: CREDENTIALS });
      try {
        await assert.rejects(() => session.readEventLog({ logName: 'System' }), /boom/);
      } finally {
        await session.close();
      }
    } finally {
      await server.close();
    }
  });

  it('runs a plain round trip over HTTPS', async () => {
    const seen: string[] = [];
    const server = await startMockServer(
      (req) => {
        assert.equal(req.headers.authorization, 'Basic dXNlcjpwYXNz');
        const action = actionOf(req.body);
        seen.push(action);
        const body =
          action === 'Create'
            ? fixture('create-response.xml')
            : action === 'Command'
              ? fixture('command-response.xml')
              : action === 'Receive'
                ? fixture('receive-done.xml')
                : action === 'Signal'
                  ? SIGNAL_RESPONSE
                  : DELETE_RESPONSE;
        return { status: 200, headers: { 'Content-Type': 'application/soap+xml;charset=UTF-8' }, body };
      },
      {
        tls: {
          cert: readFileSync(new URL('./fixtures/tls-test-cert.pem', import.meta.url)),
          key: readFileSync(new URL('./fixtures/tls-test-key.pem', import.meta.url)),
        },
      },
    );
    try {
      const session = await connect({
        host: '127.0.0.1',
        port: server.port,
        tls: true,
        tlsVerify: false,
        authProvider: basicStub('dXNlcjpwYXNz'),
        credentials: CREDENTIALS,
      });
      try {
        const result = await session.runCommand('hostname');
        assert.deepEqual(result, { stdout: 'world', stderr: '', exitCode: 3 });
      } finally {
        await session.close();
      }
      assert.deepEqual(seen, ['Create', 'Command', 'Receive', 'Signal', 'Delete']);
      assert.equal(server.connectionCount(), 1);
    } finally {
      await server.close();
    }
  });

  // A server whose Receive never answers until the test releases it: the
  // only way out is the abort. Everything else follows the script.
  function hangingReceiveHandler(script: Script, hangAfter = 0) {
    const inner = encryptedHandler(script);
    const release: Array<() => void> = [];
    let receives = 0;
    const handler = (req: RecordedRequest): MockResponse | Promise<MockResponse> => {
      const contentType = req.headers['content-type'] ?? '';
      if (contentType.includes('multipart/encrypted') && actionOf(Buffer.from(mimeUnwrap(req.body, fakeNtlmUnwrap))) === 'Receive') {
        receives += 1;
        if (receives > hangAfter) {
          script.seenActions.push('Receive');
          return new Promise<MockResponse>((resolve) => release.push(() => resolve({ status: 500, body: 'released' })));
        }
      }
      return inner(req);
    };
    return { handler, release: () => release.forEach((r) => r()) };
  }

  it('aborts runCommand: rejects with AbortError, then sends Signal and Delete', async () => {
    const script = newScript({
      Create: [fixture('create-response.xml')],
      Command: [fixture('command-response.xml')],
      Signal: [SIGNAL_RESPONSE],
      Delete: [DELETE_RESPONSE],
    });
    const hang = hangingReceiveHandler(script);
    const server = await startMockServer(hang.handler);
    try {
      const session = await connect({ host: '127.0.0.1', port: server.port, authProvider: challengeStub({ seal: true }), credentials: CREDENTIALS });
      try {
        const controller = new AbortController();
        const run = session.runCommand('ping', ['-t', 'localhost'], { signal: controller.signal });
        while (!script.seenActions.includes('Receive')) await new Promise((resolve) => setTimeout(resolve, 5));
        controller.abort();
        await assert.rejects(run, (err: Error) => err.name === 'AbortError');
        assert.deepEqual(script.seenActions, ['Create', 'Command', 'Receive', 'Signal', 'Delete']);
        // An already-aborted signal sends nothing.
        await assert.rejects(session.runCommand('hostname', [], { signal: controller.signal }), (err: Error) => err.name === 'AbortError');
        assert.equal(script.seenActions.length, 5);
      } finally {
        await session.close();
      }
    } finally {
      hang.release();
      await server.close();
    }
  });

  it('aborts runCommandStream mid-stream and cleans up the shell', async () => {
    const script = newScript({
      Create: [fixture('create-response.xml')],
      Command: [fixture('command-response.xml')],
      Receive: [fixture('receive-running.xml')],
      Signal: [SIGNAL_RESPONSE],
      Delete: [DELETE_RESPONSE],
    });
    const hang = hangingReceiveHandler(script, 1);
    const server = await startMockServer(hang.handler);
    try {
      const session = await connect({ host: '127.0.0.1', port: server.port, authProvider: challengeStub({ seal: true }), credentials: CREDENTIALS });
      try {
        const controller = new AbortController();
        const chunks: string[] = [];
        await assert.rejects(
          (async () => {
            for await (const chunk of session.runCommandStream('ping', ['-t', 'localhost'], { signal: controller.signal })) {
              chunks.push(chunk.data);
              setTimeout(() => controller.abort(), 20);
            }
          })(),
          (err: Error) => err.name === 'AbortError',
        );
        assert.equal(chunks[0], 'hello ');
        assert.deepEqual(script.seenActions, ['Create', 'Command', 'Receive', 'Receive', 'Signal', 'Delete']);
      } finally {
        await session.close();
      }
    } finally {
      hang.release();
      await server.close();
    }
  });
});
