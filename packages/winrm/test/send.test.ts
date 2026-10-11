// rsp:Send: the envelope, and runCommandWithInput against the mock
// with NTLM-style message encryption, so every Send goes through the same
// transport (auth, wrap, unwrap) as the other requests.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { XMLParser } from 'fast-xml-parser';
import { connect, WinRMAbortError, type InputCommandChunk } from '../src/winrm/index.js';
import { buildCommandRequest, buildSendRequest, MAX_ENVELOPE_SIZE, SEND_CHUNK_BYTES } from '../src/winrm/envelopes.js';
import { challengeStub, CREDENTIALS, fakeNtlmUnwrap, fakeNtlmWrap } from './helpers/stub-auth.js';
import { actionOf, mimeUnwrap, mimeWrap, negotiateGate, startMockServer, type MockResponse, type RecordedRequest } from './helpers/mock-server.js';

function fixture(name: string): string {
  return readFileSync(new URL(`./fixtures/${name}`, import.meta.url), 'utf8');
}

const BASE = {
  to: 'http://host:5985/wsman',
  messageId: '11111111-1111-4111-8111-111111111111',
  operationTimeout: 'PT60S',
};

const parser = new XMLParser({ ignoreAttributes: false, attributeNamePrefix: '@', removeNSPrefix: true, parseTagValue: false });

interface SendStream {
  name: string;
  commandId: string;
  end: boolean;
  data: Buffer;
}

function parseSend(soap: string): SendStream {
  const doc = parser.parse(soap) as { Envelope: { Body: { Send: { Stream: Record<string, string> | string } } } };
  const stream = doc.Envelope.Body.Send.Stream;
  const node = typeof stream === 'string' ? { '#text': stream } : stream;
  return {
    name: node['@Name'] ?? '',
    commandId: node['@CommandId'] ?? '',
    end: node['@End'] === 'true',
    data: Buffer.from(node['#text'] ?? '', 'base64'),
  };
}

const SIGNAL_RESPONSE =
  '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body>' +
  '<rsp:SignalResponse xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell"/>' +
  '</s:Body></s:Envelope>';
const DELETE_RESPONSE =
  '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body>' +
  '<x:DeleteResponse xmlns:x="http://schemas.xmlsoap.org/ws/2004/09/transfer"/>' +
  '</s:Body></s:Envelope>';
const SEND_RESPONSE =
  '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body>' +
  '<rsp:SendResponse xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell"/>' +
  '</s:Body></s:Envelope>';
const FAULT =
  '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><s:Fault>' +
  '<s:Code><s:Value>s:Receiver</s:Value></s:Code><s:Reason><s:Text xml:lang="en-US">The pipe has been ended.</s:Text></s:Reason>' +
  '</s:Fault></s:Body></s:Envelope>';

function doneReceive(stdout: string, exitCode: number, stderr = ''): string {
  const b64 = (s: string) => Buffer.from(s).toString('base64');
  return (
    '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body>' +
    '<rsp:ReceiveResponse xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell">' +
    `<rsp:Stream Name="stdout" CommandId="COMMAND-ID-1">${b64(stdout)}</rsp:Stream>` +
    (stderr ? `<rsp:Stream Name="stderr" CommandId="COMMAND-ID-1">${b64(stderr)}</rsp:Stream>` : '') +
    '<rsp:CommandState CommandId="COMMAND-ID-1" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done">' +
    `<rsp:ExitCode>${exitCode}</rsp:ExitCode></rsp:CommandState></rsp:ReceiveResponse></s:Body></s:Envelope>`
  );
}

interface Echo {
  actions: string[];
  sends: SendStream[];
  commands: string[];
  stdin: Buffer[];
  // Called for each Send before the answer; may delay or fault.
  onSend?: (send: SendStream, index: number) => Promise<string | { fault: string }> | string | { fault: string };
  receive?: () => string;
}

// A sealed endpoint whose command echoes the byte count of its stdin.
function echoHandler(state: Echo) {
  const gate = negotiateGate();
  return async (req: RecordedRequest): Promise<MockResponse> => {
    const denied = gate.check(req);
    if (denied) return denied;
    assert.match(req.headers['content-type'] ?? '', /^multipart\/encrypted/, 'every request after the handshake is sealed');
    const soap = mimeUnwrap(req.body, fakeNtlmUnwrap);
    const action = actionOf(Buffer.from(soap));
    state.actions.push(action);
    let body: string | { fault: string } = DELETE_RESPONSE;
    if (action === 'Create') body = fixture('create-response.xml');
    else if (action === 'Command') {
      state.commands.push(soap);
      body = fixture('command-response.xml');
    } else if (action === 'Send') {
      const send = parseSend(soap);
      state.sends.push(send);
      state.stdin.push(send.data);
      body = state.onSend ? await state.onSend(send, state.sends.length - 1) : SEND_RESPONSE;
    } else if (action === 'Receive') {
      body = state.receive ? state.receive() : doneReceive(`got ${Buffer.concat(state.stdin).length}`, 0);
    } else if (action === 'Signal') body = SIGNAL_RESPONSE;
    const status = typeof body === 'string' ? 200 : 500;
    const wrapped = mimeWrap(typeof body === 'string' ? body : body.fault, fakeNtlmWrap);
    return { status, headers: { 'Content-Type': wrapped.contentType }, body: wrapped.body };
  };
}

function newEcho(): Echo {
  return { actions: [], sends: [], commands: [], stdin: [] };
}

async function* chunks(...parts: Buffer[]): AsyncIterable<Buffer> {
  for (const part of parts) yield part;
}

async function collect(it: AsyncIterable<InputCommandChunk>): Promise<InputCommandChunk[]> {
  const out: InputCommandChunk[] = [];
  for await (const c of it) out.push(c);
  return out;
}

describe('buildSendRequest', () => {
  it('builds rsp:Send with a base64 stdin stream for one command', () => {
    const xml = buildSendRequest({ ...BASE, shellId: 'SHELL-ID-1', commandId: 'COMMAND-ID-1', data: Buffer.from('a&<b>\n') });
    assert.match(xml, /<wsa:Action mustUnderstand="true">http:\/\/schemas\.microsoft\.com\/wbem\/wsman\/1\/windows\/shell\/Send<\/wsa:Action>/);
    assert.match(xml, /<wsman:Selector Name="ShellId">SHELL-ID-1<\/wsman:Selector>/);
    assert.match(xml, /<wsman:MaxEnvelopeSize mustUnderstand="true">153600<\/wsman:MaxEnvelopeSize>/);
    const send = parseSend(xml);
    assert.deepEqual(send, { name: 'stdin', commandId: 'COMMAND-ID-1', end: false, data: Buffer.from('a&<b>\n') });
    assert.doesNotMatch(xml, /End=/, 'no End attribute before the last chunk');
  });

  it('sets End="true" on the last chunk, also with no data', () => {
    const last = buildSendRequest({ ...BASE, shellId: 'S', commandId: 'C', data: Buffer.from('x'), end: true });
    assert.match(last, /<rsp:Stream Name="stdin" CommandId="C" End="true">eA==<\/rsp:Stream>/);
    const empty = parseSend(buildSendRequest({ ...BASE, shellId: 'S', commandId: 'C', data: Buffer.alloc(0), end: true }));
    assert.equal(empty.end, true);
    assert.equal(empty.data.length, 0);
  });

  it('keeps a full chunk under MaxEnvelopeSize, even with a 253-character host name', () => {
    assert.ok(SEND_CHUNK_BYTES % 3 === 0, 'whole base64 quads');
    assert.ok(SEND_CHUNK_BYTES > 100_000, `a chunk is ${SEND_CHUNK_BYTES} bytes`);
    const host = `${'a'.repeat(63)}.${'b'.repeat(63)}.${'c'.repeat(63)}.${'d'.repeat(61)}`;
    assert.equal(host.length, 253);
    const xml = buildSendRequest({
      to: `https://${host}:65535/wsman`,
      messageId: 'ffffffff-ffff-4fff-8fff-ffffffffffff',
      operationTimeout: 'PT99999S',
      shellId: '01234567-89AB-CDEF-0123-456789ABCDEF',
      commandId: '01234567-89AB-CDEF-0123-456789ABCDEF',
      data: Buffer.alloc(SEND_CHUNK_BYTES, 0xff),
      end: true,
    });
    const size = Buffer.byteLength(xml, 'utf8');
    assert.ok(size < MAX_ENVELOPE_SIZE, `${size} bytes`);
  });

  it('Command asks for a pipe as stdin only when told to', () => {
    const pipe = buildCommandRequest({ ...BASE, shellId: 'S', command: 'x', consoleModeStdin: false });
    assert.match(pipe, /<wsman:Option Name="WINRS_CONSOLEMODE_STDIN">FALSE<\/wsman:Option>/);
    const console = buildCommandRequest({ ...BASE, shellId: 'S', command: 'x' });
    assert.match(console, /<wsman:Option Name="WINRS_CONSOLEMODE_STDIN">TRUE<\/wsman:Option>/);
  });
});

describe('runCommandWithInput', () => {
  it('sends stdin in full chunks, End on the last, then receives; all sealed', async () => {
    const state = newEcho();
    const server = await startMockServer(echoHandler(state));
    try {
      const session = await connect({ host: '127.0.0.1', port: server.port, authProvider: challengeStub({ seal: true }), credentials: CREDENTIALS });
      const input = Buffer.alloc(SEND_CHUNK_BYTES * 2 + 5, 7);
      try {
        // Uneven input chunks are regrouped into full Sends.
        const out = await collect(session.runCommandWithInput('prog', ['a'], chunks(input.subarray(0, 10), input.subarray(10, 150_000), input.subarray(150_000))));
        assert.deepEqual(out, [
          { stream: 'stdout', data: `got ${input.length}` },
          { stream: 'exit', exitCode: 0, inputComplete: true },
        ]);
      } finally {
        await session.close();
      }
      assert.deepEqual(state.actions, ['Create', 'Command', 'Send', 'Send', 'Send', 'Receive', 'Signal', 'Delete']);
      assert.deepEqual(state.sends.map((s) => [s.data.length, s.end]), [
        [SEND_CHUNK_BYTES, false],
        [SEND_CHUNK_BYTES, false],
        [5, true],
      ]);
      assert.ok(state.sends.every((s) => s.name === 'stdin' && s.commandId === 'COMMAND-ID-1'));
      assert.ok(Buffer.concat(state.stdin).equals(input));
      assert.match(state.commands[0] ?? '', /WINRS_CONSOLEMODE_STDIN">FALSE/);
    } finally {
      await server.close();
    }
  });

  it('empty input is one Send with End and no data', async () => {
    const state = newEcho();
    const server = await startMockServer(echoHandler(state));
    try {
      const session = await connect({ host: '127.0.0.1', port: server.port, authProvider: challengeStub({ seal: true }), credentials: CREDENTIALS });
      try {
        const out = await collect(session.runCommandWithInput('prog', [], chunks()));
        assert.deepEqual(out.at(-1), { stream: 'exit', exitCode: 0, inputComplete: true });
      } finally {
        await session.close();
      }
      assert.deepEqual(state.sends.map((s) => [s.data.length, s.end]), [[0, true]]);
    } finally {
      await server.close();
    }
  });

  it('reads the next input chunk only after the server acknowledged the last Send', async () => {
    const state = newEcho();
    let answered = 0;
    state.onSend = async () => {
      await new Promise((resolve) => setTimeout(resolve, 20));
      answered += 1;
      return SEND_RESPONSE;
    };
    const pulls: Array<{ pull: number; answered: number }> = [];
    async function* paced(): AsyncIterable<Buffer> {
      for (let i = 1; i <= 6; i++) {
        pulls.push({ pull: i, answered });
        yield Buffer.alloc(SEND_CHUNK_BYTES, i);
      }
    }
    const server = await startMockServer(echoHandler(state));
    try {
      const session = await connect({ host: '127.0.0.1', port: server.port, authProvider: challengeStub({ seal: true }), credentials: CREDENTIALS });
      try {
        await collect(session.runCommandWithInput('prog', [], paced()));
      } finally {
        await session.close();
      }
      // Pull k happens after Send k-2 was answered and before Send k-1 went out.
      assert.deepEqual(pulls.map((p) => p.answered), [0, 0, 1, 2, 3, 4]);
      assert.equal(state.sends.length, 6);
      assert.equal(state.sends.filter((s) => s.end).length, 1);
    } finally {
      await server.close();
    }
  });

  it('a Send fault stops the feed; Receive reports the exit code and stderr', async () => {
    const state = newEcho();
    state.onSend = (_send, index) => (index === 1 ? { fault: FAULT } : SEND_RESPONSE);
    state.receive = () => doneReceive('', 1, 'cannot write');
    let pulled = 0;
    async function* many(): AsyncIterable<Buffer> {
      for (let i = 0; i < 10; i++) {
        pulled += 1;
        yield Buffer.alloc(SEND_CHUNK_BYTES, 1);
      }
    }
    const server = await startMockServer(echoHandler(state));
    try {
      const session = await connect({ host: '127.0.0.1', port: server.port, authProvider: challengeStub({ seal: true }), credentials: CREDENTIALS });
      try {
        const out = await collect(session.runCommandWithInput('prog', [], many()));
        assert.deepEqual(out, [
          { stream: 'stderr', data: 'cannot write' },
          { stream: 'exit', exitCode: 1, inputComplete: false },
        ]);
      } finally {
        await session.close();
      }
      assert.equal(state.sends.length, 2);
      assert.equal(pulled, 3, 'no input is read after the failed Send');
      assert.deepEqual(state.actions.slice(-3), ['Receive', 'Signal', 'Delete']);
    } finally {
      await server.close();
    }
  });

  it('an abort closes stdin, waits for the command, then Signals and throws WinRMAbortError', async () => {
    const state = newEcho();
    const abort = new AbortController();
    state.onSend = (_send, index) => {
      if (index === 1) abort.abort();
      return SEND_RESPONSE;
    };
    state.receive = () => doneReceive('', 1, 'interrupted');
    async function* endless(): AsyncIterable<Buffer> {
      for (;;) yield Buffer.alloc(SEND_CHUNK_BYTES, 2);
    }
    const server = await startMockServer(echoHandler(state));
    try {
      const session = await connect({ host: '127.0.0.1', port: server.port, authProvider: challengeStub({ seal: true }), credentials: CREDENTIALS });
      try {
        await assert.rejects(collect(session.runCommandWithInput('prog', [], endless(), { signal: abort.signal })), WinRMAbortError);
      } finally {
        await session.close();
      }
      assert.deepEqual(state.actions, ['Create', 'Command', 'Send', 'Send', 'Send', 'Receive', 'Signal', 'Delete']);
      assert.deepEqual(state.sends.map((s) => [s.data.length, s.end]), [
        [SEND_CHUNK_BYTES, false],
        [SEND_CHUNK_BYTES, false],
        [0, true],
      ]);
    } finally {
      await server.close();
    }
  });

  it('an input error closes stdin, Signals, and rethrows the input error', async () => {
    const state = newEcho();
    state.receive = () => doneReceive('', 1, 'interrupted');
    const readError = Object.assign(new Error('EIO: i/o error, read'), { code: 'EIO', path: '/local/file' });
    async function* broken(): AsyncIterable<Buffer> {
      yield Buffer.alloc(SEND_CHUNK_BYTES, 3);
      yield Buffer.alloc(SEND_CHUNK_BYTES, 3);
      throw readError;
    }
    const server = await startMockServer(echoHandler(state));
    try {
      const session = await connect({ host: '127.0.0.1', port: server.port, authProvider: challengeStub({ seal: true }), credentials: CREDENTIALS });
      try {
        await assert.rejects(collect(session.runCommandWithInput('prog', [], broken())), (e: unknown) => e === readError);
      } finally {
        await session.close();
      }
      assert.deepEqual(state.actions, ['Create', 'Command', 'Send', 'Send', 'Receive', 'Signal', 'Delete']);
      assert.deepEqual(state.sends.map((s) => [s.data.length, s.end]), [
        [SEND_CHUNK_BYTES, false],
        [0, true],
      ]);
    } finally {
      await server.close();
    }
  });

  it('runPowerShellWithInput strips CLIXML from stderr and sends -EncodedCommand', async () => {
    const state = newEcho();
    const clixml =
      '#< CLIXML\r\n<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">' +
      '<S S="Error">boom_x000D__x000A_</S></Objs>';
    state.receive = () => doneReceive('', 1, clixml);
    const server = await startMockServer(echoHandler(state));
    try {
      const session = await connect({ host: '127.0.0.1', port: server.port, authProvider: challengeStub({ seal: true }), credentials: CREDENTIALS });
      try {
        const out = await collect(session.runPowerShellWithInput('$input | Out-Null', chunks(Buffer.from('x\n'))));
        assert.deepEqual(out, [
          { stream: 'stderr', data: 'boom' },
          { stream: 'exit', exitCode: 1, inputComplete: true },
        ]);
      } finally {
        await session.close();
      }
      assert.match(state.commands[0] ?? '', /<rsp:Command>powershell\.exe<\/rsp:Command>/);
      assert.match(state.commands[0] ?? '', /-EncodedCommand/);
    } finally {
      await server.close();
    }
  });
});
