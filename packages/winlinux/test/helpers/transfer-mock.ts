// A WinRM endpoint that fakes the two file transfer scripts over TLS
// with Basic auth, on top of @winlinux/winrm's mock server. It decodes the
// -EncodedCommand script, reads the quoted share, path, hash and temp
// suffix out of it (PowerShell single-quote rules), and acts on a local
// directory per share:
//   get: streams the file as base64 lines over as many Receives as it
//        takes (each Receive ends at an arbitrary byte, mid-line), then
//        `sha256:<hex>`.
//   put: takes stdin from rsp:Send, decodes its base64 lines into
//        `<dest><suffix>`, and on End checks the `end` line and the hash,
//        then renames over the destination. Signal terminate on a put
//        still running models a killed process: the temp file stays.
// Everything streams: the mock never holds a whole file in memory.
import fs from 'node:fs';
import path from 'node:path';
import { createHash, type Hash } from 'node:crypto';
import { actionOf, startMockServer, type MockServer } from '../../../winrm/dist/test/helpers/mock-server.js';
import { fixture } from './winrm-mock.js';

const NS = 'xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell"';
const DONE = 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done';
const RUNNING = 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Running';
const QUOTES = new Set(["'", '‘', '’', '‚', '‛']);
const READ_BYTES = 48 * 1024;

function envelope(body: string): string {
  return `<s:Envelope ${NS}><s:Body>${body}</s:Body></s:Envelope>`;
}

function fault(reason: string): string {
  return envelope(
    '<s:Fault><s:Code><s:Value>s:Receiver</s:Value></s:Code>' +
      `<s:Reason><s:Text xml:lang="en-US">${reason}</s:Text></s:Reason></s:Fault>`,
  );
}

// Reads a PowerShell single-quoted literal that starts at `text[at]`.
// Any single-quote character doubled stands for itself.
export function psUnquote(text: string, at = 0): { value: string; end: number } {
  if (!QUOTES.has(text[at] ?? '')) throw new Error(`no quoted literal at ${at}`);
  let value = '';
  let i = at + 1;
  for (;;) {
    const ch = text[i];
    if (ch === undefined) throw new Error('unterminated literal');
    if (QUOTES.has(ch)) {
      if (QUOTES.has(text[i + 1] ?? '')) {
        value += ch;
        i += 2;
        continue;
      }
      return { value, end: i + 1 };
    }
    value += ch;
    i += 1;
  }
}

// The literal assigned by the line `<prefix>'...'`.
export function assigned(script: string, prefix: string): string | undefined {
  const at = script.indexOf(prefix);
  return at < 0 ? undefined : psUnquote(script, at + prefix.length).value;
}

// Removes every single-quoted literal: what is left is script code only.
export function withoutLiterals(script: string): string {
  let out = '';
  let i = 0;
  while (i < script.length) {
    const ch = script[i] as string;
    if (QUOTES.has(ch)) {
      i = psUnquote(script, i).end;
      out += "''";
    } else {
      out += ch;
      i += 1;
    }
  }
  return out;
}

export function scriptOf(soap: string): string | undefined {
  const args = [...soap.matchAll(/<rsp:Arguments>([^<]*)<\/rsp:Arguments>/g)].map((m) => m[1] ?? '');
  const i = args.indexOf('-EncodedCommand');
  return i < 0 ? undefined : Buffer.from(args[i + 1] ?? '', 'base64').toString('utf16le');
}

interface Outcome {
  stdout: Buffer;
  stderr: string;
  exitCode: number;
}

interface GetState {
  kind: 'get';
  fd: number;
  hash: Hash;
  pending: Buffer;
  eof: boolean;
  corrupt: boolean;
}

interface PutState {
  kind: 'put';
  fd: number;
  temp: string;
  full: string;
  expected: string;
  hash: Hash;
  carry: string;
  complete: boolean;
  outcome?: Outcome;
}

type CommandState = GetState | PutState | { kind: 'failed'; outcome: Outcome } | { kind: 'other' };

export interface TransferMockOptions {
  // share name -> directory; drive shares (C$) use `drives`.
  shares?: Record<string, string>;
  drives?: Record<string, string>;
  password?: string; // Basic auth password; any Authorization header when absent
  receiveBytes?: number; // stdout bytes per Receive; default 99_999 (ends mid-line)
  // Fake a .NET failure of the get or put script after the path resolved
  //: the script's stderr contract with that kind and its raw text.
  failWith?: 'denied' | 'inuse';
  corruptGet?: boolean; // the trailer names a wrong hash
  corruptPut?: boolean; // the server writes one byte wrong
  delayMs?: number; // every Send and Receive waits this long
}

export interface TransferMock extends MockServer {
  actions: string[]; // every action, in order
  sends: number;
  ends: number; // Sends with End="true"
  signals: number;
  scripts: string[];
  killedTemps: string[]; // temp files left by a Signal on a running put
}

export async function startTransferMock(opts: TransferMockOptions = {}): Promise<TransferMock> {
  const commands = new Map<string, CommandState>();
  let ids = 0;
  const state = { actions: [] as string[], sends: 0, ends: 0, signals: 0, scripts: [] as string[], killedTemps: [] as string[] };
  const receiveBytes = opts.receiveBytes ?? 99_999;

  // The scripts' stderr contract: `winlinux: [kind] <message>` with
  // the server's local path replaced by <share>/<path>, then the raw text.
  const fail = (kind: string, raw: string, script = '', full = ''): { kind: 'failed'; outcome: Outcome } => {
    const share = assigned(script, '$share = ') ?? '';
    const rel = assigned(script, '$rel = ') ?? '';
    const clean = full ? raw.split(full).join(`${share}/${rel.split('\\').join('/')}`) : raw;
    return { kind: 'failed', outcome: { stdout: Buffer.alloc(0), stderr: `winlinux: [${kind}] ${clean}\nwinlinux-raw: ${raw}\n`, exitCode: 1 } };
  };

  const resolve = (script: string): { full: string } | { error: string } => {
    const share = assigned(script, '$share = ') ?? '';
    const rel = assigned(script, '$rel = ') ?? '';
    let root: string | undefined;
    if (/^[A-Za-z]\$$/.test(share)) root = opts.drives?.[share[0]?.toUpperCase() ?? ''];
    else {
      const key = Object.keys(opts.shares ?? {}).find((k) => k.toLowerCase() === share.toLowerCase());
      root = key === undefined ? undefined : opts.shares?.[key];
    }
    if (root === undefined) return { error: `no such share: ${share}` };
    const full = path.resolve(root, ...rel.split('\\'));
    if (!full.startsWith(path.resolve(root) + path.sep)) return { error: `path leaves the share: ${rel}` };
    return { full };
  };

  const startCommand = (script: string | undefined): CommandState => {
    if (script === undefined) return { kind: 'other' };
    state.scripts.push(script);
    const kind = /^# winlinux-transfer:(get|put)$/m.exec(script)?.[1];
    if (kind === undefined) return { kind: 'other' };
    const where = resolve(script);
    if ('error' in where) return fail(where.error.startsWith('no such share') ? 'noshare' : 'error', where.error);
    if (kind === 'get') {
      if (!fs.existsSync(where.full)) return fail('notfound', `Could not find file '${where.full}'.`, script, where.full);
      if (fs.statSync(where.full).isDirectory()) return fail('isdir', `is a directory: ${assigned(script, '$rel = ') ?? ''}`);
      if (opts.failWith === 'denied') return fail('denied', `Access to the path '${where.full}' is denied.`, script, where.full);
      if (opts.failWith === 'inuse') return fail('inuse', `The process cannot access the file '${where.full}' because it is being used by another process.`, script, where.full);
      return { kind: 'get', fd: fs.openSync(where.full, 'r'), hash: createHash('sha256'), pending: Buffer.alloc(0), eof: false, corrupt: opts.corruptGet === true };
    }
    const expected = assigned(script, '$expected = ') ?? '';
    const suffix = assigned(script, '$temp = $full + ') ?? '';
    if (!fs.existsSync(path.dirname(where.full))) return fail('notfound', `no such directory: ${path.dirname(where.full)}`, script, where.full);
    if (opts.failWith === 'denied') return fail('denied', `Access to the path '${where.full}' is denied.`, script, where.full);
    if (opts.failWith === 'inuse') return fail('inuse', `The process cannot access the file '${where.full}' because it is being used by another process.`, script, where.full);
    const temp = where.full + suffix;
    return { kind: 'put', fd: fs.openSync(temp, 'wx'), temp, full: where.full, expected, hash: createHash('sha256'), carry: '', complete: false };
  };

  const finishPut = (put: PutState): Outcome => {
    fs.closeSync(put.fd);
    const actual = put.hash.digest('hex');
    let outcome: Outcome;
    if (!put.complete) outcome = { stdout: Buffer.alloc(0), stderr: 'winlinux: upload interrupted; the destination is unchanged\n', exitCode: 1 };
    else if (actual !== put.expected) outcome = { stdout: Buffer.alloc(0), stderr: `winlinux: sha256 mismatch: the client sent ${put.expected}, the server wrote ${actual}\n`, exitCode: 3 };
    else {
      fs.renameSync(put.temp, put.full);
      return { stdout: Buffer.from(`sha256:${actual}\r\n`), stderr: '', exitCode: 0 };
    }
    fs.rmSync(put.temp, { force: true });
    return outcome;
  };

  const feedPut = (put: PutState, data: Buffer): void => {
    let text = put.carry + data.toString('ascii');
    let nl: number;
    while ((nl = text.indexOf('\n')) >= 0) {
      const line = text.slice(0, nl).replace(/\r$/, '');
      text = text.slice(nl + 1);
      if (put.complete) continue;
      if (line === 'end') {
        put.complete = true;
        continue;
      }
      if (line === '') continue;
      const bytes = Buffer.from(line, 'base64');
      // corruptPut: the disk got a different byte than the wire carried.
      if (opts.corruptPut && bytes.length > 0) bytes[0] = (bytes[0] as number) ^ 0xff;
      put.hash.update(bytes);
      fs.writeSync(put.fd, bytes);
    }
    put.carry = text;
  };

  // The next slice of the get script's stdout, generated on demand.
  const pullGet = (get: GetState): { stdout: Buffer; done: boolean } => {
    const buf = Buffer.alloc(READ_BYTES);
    while (get.pending.length < receiveBytes && !get.eof) {
      const n = fs.readSync(get.fd, buf, 0, READ_BYTES, null);
      if (n === 0) {
        get.eof = true;
        fs.closeSync(get.fd);
        const hex = get.corrupt ? '0'.repeat(64) : get.hash.digest('hex');
        get.pending = Buffer.concat([get.pending, Buffer.from(`sha256:${hex}\n`)]);
        break;
      }
      get.hash.update(buf.subarray(0, n));
      get.pending = Buffer.concat([get.pending, Buffer.from(`${buf.subarray(0, n).toString('base64')}\n`)]);
    }
    const stdout = get.pending.subarray(0, receiveBytes);
    get.pending = Buffer.from(get.pending.subarray(stdout.length));
    return { stdout, done: get.eof && get.pending.length === 0 };
  };

  const receiveXml = (id: string, out: { stdout: Buffer; stderr?: string; exitCode?: number; done: boolean }): string => {
    let streams = '';
    if (out.stdout.length > 0) streams += `<rsp:Stream Name="stdout" CommandId="${id}">${out.stdout.toString('base64')}</rsp:Stream>`;
    if (out.stderr) streams += `<rsp:Stream Name="stderr" CommandId="${id}">${Buffer.from(out.stderr).toString('base64')}</rsp:Stream>`;
    const cmdState = out.done
      ? `<rsp:CommandState CommandId="${id}" State="${DONE}"><rsp:ExitCode>${out.exitCode ?? 0}</rsp:ExitCode></rsp:CommandState>`
      : `<rsp:CommandState CommandId="${id}" State="${RUNNING}"/>`;
    return envelope(`<rsp:ReceiveResponse>${streams}${cmdState}</rsp:ReceiveResponse>`);
  };

  const handle = (soap: string): { status: number; body: string } => {
    const action = actionOf(Buffer.from(soap));
    state.actions.push(action);
    const commandId = /CommandId="([^"]+)"/.exec(soap)?.[1] ?? '';
    switch (action) {
      case 'Create':
        return { status: 200, body: fixture('create-response.xml') };
      case 'Command': {
        const id = `COMMAND-${++ids}`;
        commands.set(id, startCommand(scriptOf(soap)));
        return { status: 200, body: envelope(`<rsp:CommandResponse><rsp:CommandId>${id}</rsp:CommandId></rsp:CommandResponse>`) };
      }
      case 'Send': {
        state.sends += 1;
        const m = /<rsp:Stream ([^>]*?)(?:\/>|>([^<]*)<\/rsp:Stream>)/.exec(soap);
        const end = /End="true"/.test(m?.[1] ?? '');
        if (end) state.ends += 1;
        const cmd = commands.get(commandId);
        if (cmd?.kind !== 'put' || cmd.outcome) return { status: 500, body: fault('The pipe is being closed.') };
        feedPut(cmd, Buffer.from(m?.[2] ?? '', 'base64'));
        if (end) cmd.outcome = finishPut(cmd);
        return { status: 200, body: envelope('<rsp:SendResponse/>') };
      }
      case 'Receive': {
        const cmd = commands.get(commandId);
        if (cmd === undefined || cmd.kind === 'other') return { status: 200, body: receiveXml(commandId, { stdout: Buffer.alloc(0), done: true }) };
        if (cmd.kind === 'failed') return { status: 200, body: receiveXml(commandId, { ...cmd.outcome, done: true }) };
        if (cmd.kind === 'get') {
          const slice = pullGet(cmd);
          return { status: 200, body: receiveXml(commandId, { stdout: slice.stdout, exitCode: 0, done: slice.done }) };
        }
        // A put answers once stdin is closed.
        if (!cmd.outcome) return { status: 500, body: fault('The WS-Management service cannot complete the operation within the time specified in OperationTimeout.') };
        return { status: 200, body: receiveXml(commandId, { ...cmd.outcome, done: true }) };
      }
      case 'Signal': {
        state.signals += 1;
        const cmd = commands.get(commandId);
        if (cmd?.kind === 'put' && !cmd.outcome) {
          // Terminated: no finally block runs, the temp file stays.
          fs.closeSync(cmd.fd);
          cmd.outcome = { stdout: Buffer.alloc(0), stderr: '', exitCode: 1 };
          state.killedTemps.push(cmd.temp);
        }
        if (cmd?.kind === 'get' && !cmd.eof) {
          cmd.eof = true;
          fs.closeSync(cmd.fd);
        }
        commands.delete(commandId);
        return { status: 200, body: envelope('<rsp:SignalResponse/>') };
      }
      default:
        return { status: 200, body: envelope('<x:DeleteResponse xmlns:x="http://schemas.xmlsoap.org/ws/2004/09/transfer"/>') };
    }
  };

  const server = await startMockServer(
    async (req) => {
      const header = req.headers.authorization;
      if (!header) return { status: 401 };
      if (opts.password !== undefined) {
        const decoded = Buffer.from(header.replace(/^Basic /, ''), 'base64').toString('utf8');
        if (decoded.slice(decoded.indexOf(':') + 1) !== opts.password) return { status: 401 };
      }
      const soap = req.body.toString('utf8');
      if (opts.delayMs && /\/(Send|Receive)<\/wsa:Action>/.test(soap)) await new Promise((r) => setTimeout(r, opts.delayMs));
      const out = handle(soap);
      return { status: out.status, headers: { 'Content-Type': 'application/soap+xml;charset=UTF-8' }, body: out.body };
    },
    { tls: { cert: fixture('tls-test-cert.pem'), key: fixture('tls-test-key.pem') }, recordBodies: false },
  );
  return {
    port: server.port,
    requests: server.requests,
    connectionCount: server.connectionCount,
    close: server.close,
    actions: state.actions,
    scripts: state.scripts,
    killedTemps: state.killedTemps,
    get sends() {
      return state.sends;
    },
    get ends() {
      return state.ends;
    },
    get signals() {
      return state.signals;
    },
  };
}
