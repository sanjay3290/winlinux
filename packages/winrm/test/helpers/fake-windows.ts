// A stateful fake Windows WinRM endpoint for the offline live-harness test.
// It keeps real shell state (Create adds a shell, Delete removes it), runs
// a small table of "programs" that print what Windows prints for the live
// scenarios, and enforces the listener rules the scenarios depend on:
// Basic only over HTTPS, and sealed bodies only over HTTP.
import { readFileSync } from 'node:fs';
import { FAKE_KRB_HEADER_LENGTH, fakeKrbUnwrapIov, fakeKrbWrapIov, fakeNtlmUnwrap, fakeNtlmWrap } from './stub-auth.js';
import {
  actionOf,
  mimeParts,
  mimeUnwrap,
  mimeUnwrapIov,
  mimeWrap,
  mimeWrapIov,
  negotiateGate,
  startMockServer,
  type MockResponse,
  type MockServer,
  type RecordedRequest,
} from './mock-server.js';
import { LIST_SHELLS_SCRIPT, LONG_COMMAND, PS_ERR_MARKER, PS_OUT_MARKER, PS_SCRIPT, STREAM_LINES, STREAM_SCRIPT, streamLine } from '../live/scenarios.js';
import { decodePowerShellArgs } from '../../src/winrm/cmdline.js';
import { windowsArgv } from './cmdline-sim.js';

export const FAKE_HOSTNAME = 'FAKEWIN01';
const B64 = (s: string | Buffer) => Buffer.from(s).toString('base64');
const RSP = 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell';
const STREAM_CHUNK_BYTES = 64 * 1024;

export interface FakeWindowsOptions {
  tls: boolean;
  username: string;
  password: string;
  // Deliberate faults, to prove the scenarios catch them.
  faults?: {
    exitCodeAlwaysZero?: boolean;
    // The WinRS race: a command that exits at once without
    // writing anything is reported Done with exit code 0.
    silentExitReportsZero?: boolean;
    ignoreDelete?: boolean;
    dropStreamChunk?: boolean;
  };
}

export interface FakeWindows {
  port: number;
  openShells(): string[];
  // The rsp:WorkingDirectory of every Create, in order (undefined when none).
  workingDirectories(): Array<string | undefined>;
  sealedRequests: number;
  plainSoapRequests: number;
  // Negotiate handshakes that completed, and requests that re-sent the
  // completed token on an authenticated connection (refused).
  handshakes: number;
  staleTokens: number;
  // Sealed bodies refused with 400 because the connection authenticated
  // with SPNEGO-wrapped NTLM.
  spnegoSealsRefused: number;
  close(): Promise<void>;
}

interface Poll {
  stdout?: string;
  stderr?: string;
  done: boolean;
  exitCode?: number;
}

interface Program {
  next(): Poll;
}

function fixed(polls: Poll[]): Program {
  return {
    next: () => {
      const p = polls.shift();
      if (!p) throw new Error('fake windows: Receive after the command finished');
      return p;
    },
  };
}

function unescapeXml(s: string): string {
  return s
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&amp;/g, '&');
}

function clixmlError(message: string): string {
  return (
    '#< CLIXML\r\n<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">' +
    `<S S="Error">${message} : ${message}_x000D__x000A_</S>` +
    '<S S="Error">    + CategoryInfo          : NotSpecified: (:) [Write-Error], WriteErrorException_x000D__x000A_</S></Objs>'
  );
}

function tenSystemEvents(): string {
  const start = Date.parse('2026-09-27T12:00:00Z');
  const events = Array.from({ length: 10 }, (_, i) => ({
    TimeCreated: new Date(start - i * 60_000).toISOString(),
    Id: 7036 + i,
    LevelDisplayName: 'Information',
    ProviderName: 'Service Control Manager',
    Message: `event ${i}`,
  }));
  return JSON.stringify(events);
}

// Directories the fake has, for rsp:WorkingDirectory and the shell's `cd`
// in winlinux. Windows refuses a Create whose WorkingDirectory is
// missing with a WSManFault (0x8007010B, "The directory name is invalid.").
const DEFAULT_DIRECTORY = (user: string) => `C:\\Users\\${user}`;
const DIRECTORIES = (user: string) => ['C:\\', 'C:\\Users', DEFAULT_DIRECTORY(user), 'C:\\Windows', 'C:\\Windows\\Temp', 'C:\\Temp & Files'];
const DIRECTORY_INVALID = 2147942667;

function sameDirectory(a: string, b: string): boolean {
  const norm = (p: string) => p.replace(/[\\/]+$/, '').toLowerCase();
  return norm(a) === norm(b);
}

export async function startFakeWindows(opts: FakeWindowsOptions): Promise<FakeWindows> {
  const shells = new Map<string, { cwd: string; commands: Map<string, Program> }>();
  const workingDirectories: Array<string | undefined> = [];
  let nextId = 1;
  const stats = { sealedRequests: 0, plainSoapRequests: 0, spnegoSealsRefused: 0 };
  const faults = opts.faults ?? {};
  const basic = `Basic ${B64(`${opts.username}:${opts.password}`)}`;
  // Negotiate binds auth to the connection, as HTTP.sys does.
  const gate = negotiateGate();

  function program(command: string, args: string[], cwd: string): Program {
    const exit = (code: number) => (faults.exitCodeAlwaysZero ? 0 : code);
    if (command === 'hostname' && args.length === 0) return fixed([{ stdout: `${FAKE_HOSTNAME}\r\n`, done: true, exitCode: 0 }]);
    // cmd.exe's `cd` prints the shell's directory; `dir /b win.ini` finds the
    // file only in C:\Windows (the shell's `cd` check).
    if ((command === 'cd' && args.length === 0) || (command === 'cmd' && args[0] === '/c' && args[1] === 'cd' && args.length === 2)) {
      return fixed([{ stdout: `${cwd}\r\n`, done: true, exitCode: 0 }]);
    }
    if (command === 'dir' && args.join(' ') === '/b win.ini') {
      return sameDirectory(cwd, 'C:\\Windows')
        ? fixed([{ stdout: 'win.ini\r\n', done: true, exitCode: 0 }])
        : fixed([{ stderr: 'File Not Found\r\n', done: true, exitCode: exit(1) }]);
    }
    // Prints its argv, for the quoting test in cmdline.test.ts.
    if (command === 'fake-argv') return fixed([{ stdout: `${JSON.stringify(args)}\r\n`, done: true, exitCode: 0 }]);
    if (command === 'cmd' && args[0] === '/c' && args[1] === 'echo %COMPUTERNAME%') {
      return fixed([{ stdout: `${FAKE_HOSTNAME}\r\n`, done: true, exitCode: 0 }]);
    }
    // `cmd /c exit N` and `cmd /c "echo x& exit N"`: the second one
    // prints a line first, so the silent-exit race cannot touch it.
    const exitMatch = command === 'cmd' && args[0] === '/c' ? /^(?:echo (\S+)& ?)?exit (\d+)$/.exec(args[1] ?? '') : null;
    if (exitMatch) {
      const [, echoed, code] = exitMatch;
      if (echoed === undefined) return fixed([{ done: true, exitCode: faults.silentExitReportsZero ? 0 : exit(Number(code)) }]);
      return fixed([{ stdout: `${echoed}\r\n`, done: true, exitCode: exit(Number(code)) }]);
    }
    if (command === LONG_COMMAND.cmd && args.join(' ') === LONG_COMMAND.args.join(' ')) {
      let n = 0;
      return {
        next: () => {
          n += 1;
          return { stdout: `Reply from 127.0.0.1: bytes=32 time<1ms TTL=128 (${n})\r\n`, done: false };
        },
      };
    }
    if (command === 'powershell.exe') {
      const script = decodePowerShellArgs(args) ?? '';
      if (script === STREAM_SCRIPT) {
        let text = '';
        for (let i = 1; i <= STREAM_LINES; i += 1) text += `${streamLine(i)}\r\n`;
        const polls: Poll[] = [];
        for (let off = 0; off < text.length; off += STREAM_CHUNK_BYTES) {
          polls.push({ stdout: text.slice(off, off + STREAM_CHUNK_BYTES), done: false });
        }
        if (faults.dropStreamChunk) polls.splice(3, 1);
        polls.push({ done: true, exitCode: 0 });
        return fixed(polls);
      }
      if (script === PS_SCRIPT) {
        return fixed([{ stdout: `${PS_OUT_MARKER}\r\n`, stderr: clixmlError(PS_ERR_MARKER), done: true, exitCode: exit(1) }]);
      }
      if (script.startsWith("@(Get-WinEvent -LogName 'System' -MaxEvents 10 ")) {
        return fixed([{ stdout: `${tenSystemEvents()}\r\n`, done: true, exitCode: 0 }]);
      }
      if (script === LIST_SHELLS_SCRIPT) {
        const listing = JSON.stringify({ method: 'wsman', ids: [...shells.keys()] });
        return fixed([{ stdout: `${listing}\r\n`, done: true, exitCode: 0 }]);
      }
    }
    return fixed([{ stderr: `'${command}' is not recognized in the fake\r\n`, done: true, exitCode: exit(1) }]);
  }

  function envelope(body: string): string {
    return `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body>${body}</s:Body></s:Envelope>`;
  }

  function wsmanFault(code: number, reason: string): string {
    return envelope(
      '<s:Fault><s:Code><s:Value>s:Receiver</s:Value><s:Subcode><s:Value>w:InternalError</s:Value></s:Subcode></s:Code>' +
        `<s:Reason><s:Text xml:lang="en-US">${reason}</s:Text></s:Reason>` +
        `<s:Detail><f:WSManFault Code="${code}" Machine="${FAKE_HOSTNAME}" xmlns:f="http://schemas.microsoft.com/wbem/wsman/1/wsmanfault"></f:WSManFault></s:Detail></s:Fault>`,
    );
  }

  function soapFor(soap: string): string {
    const action = actionOf(Buffer.from(soap));
    const shellId = /<wsman:Selector Name="ShellId">([^<]+)<\/wsman:Selector>/.exec(soap)?.[1];
    if (action === 'Create') {
      const wanted = /<rsp:WorkingDirectory>([^<]*)<\/rsp:WorkingDirectory>/.exec(soap)?.[1];
      const cwd = wanted === undefined ? undefined : unescapeXml(wanted);
      workingDirectories.push(cwd);
      if (cwd !== undefined && !DIRECTORIES(opts.username).some((d) => sameDirectory(d, cwd))) {
        return wsmanFault(DIRECTORY_INVALID, 'The directory name is invalid.');
      }
      const id = `FAKE-SHELL-${nextId++}`;
      shells.set(id, { cwd: cwd ?? DEFAULT_DIRECTORY(opts.username), commands: new Map() });
      return envelope(
        '<x:ResourceCreated xmlns:x="http://schemas.xmlsoap.org/ws/2004/09/transfer"><a:ReferenceParameters xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing">' +
          `<w:SelectorSet xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"><w:Selector Name="ShellId">${id}</w:Selector></w:SelectorSet>` +
          '</a:ReferenceParameters></x:ResourceCreated>',
      );
    }
    const shell = shellId ? shells.get(shellId) : undefined;
    if (!shell) throw new Error(`fake windows: unknown shell ${shellId}`);
    if (action === 'Command') {
      const command = unescapeXml(/<rsp:Command>([^<]*)<\/rsp:Command>/.exec(soap)?.[1] ?? '');
      const args = [...soap.matchAll(/<rsp:Arguments>([^<]*)<\/rsp:Arguments>/g)].map((m) => unescapeXml(m[1] ?? ''));
      const commandId = `FAKE-CMD-${nextId++}`;
      // The line crosses cmd.exe and the program's argv split, as on Windows.
      const [program0 = '', ...argv] = windowsArgv(command, args);
      shell.commands.set(commandId, program(program0, argv, shell.cwd));
      return envelope(`<rsp:CommandResponse xmlns:rsp="${RSP}"><rsp:CommandId>${commandId}</rsp:CommandId></rsp:CommandResponse>`);
    }
    if (action === 'Receive') {
      const commandId = /<rsp:DesiredStream CommandId="([^"]+)"/.exec(soap)?.[1] ?? '';
      const prog = shell.commands.get(commandId);
      if (!prog) throw new Error(`fake windows: unknown command ${commandId}`);
      const p = prog.next();
      let streams = '';
      if (p.stdout) streams += `<rsp:Stream Name="stdout" CommandId="${commandId}">${B64(p.stdout)}</rsp:Stream>`;
      if (p.stderr) streams += `<rsp:Stream Name="stderr" CommandId="${commandId}">${B64(p.stderr)}</rsp:Stream>`;
      const state = p.done
        ? `<rsp:CommandState CommandId="${commandId}" State="${RSP}/CommandState/Done"><rsp:ExitCode>${p.exitCode ?? 0}</rsp:ExitCode></rsp:CommandState>`
        : `<rsp:CommandState CommandId="${commandId}" State="${RSP}/CommandState/Running"/>`;
      return envelope(`<rsp:ReceiveResponse xmlns:rsp="${RSP}">${streams}${state}</rsp:ReceiveResponse>`);
    }
    if (action === 'Signal') {
      return envelope(`<rsp:SignalResponse xmlns:rsp="${RSP}"/>`);
    }
    if (action === 'Delete') {
      if (!faults.ignoreDelete && shellId) shells.delete(shellId);
      return envelope('<x:DeleteResponse xmlns:x="http://schemas.xmlsoap.org/ws/2004/09/transfer"/>');
    }
    throw new Error(`fake windows: unsupported action ${action}`);
  }

  const challenge: MockResponse = {
    status: 401,
    headers: { 'WWW-Authenticate': 'Negotiate' },
  };

  const handler = (req: RecordedRequest): MockResponse => {
    const auth = req.headers.authorization ?? '';
    if (auth === basic) {
      // Windows refuses Basic on an unencrypted listener (AllowUnencrypted=false).
      if (!opts.tls) return challenge;
      stats.plainSoapRequests += 1;
      return { status: 200, headers: { 'Content-Type': 'application/soap+xml;charset=UTF-8' }, body: soapFor(req.body.toString('utf8')) };
    }
    const denied = gate.check(req);
    if (denied) return denied;

    const sealed = (req.headers['content-type'] ?? '').includes('multipart/encrypted');
    if (!sealed && !opts.tls) {
      // AllowUnencrypted=false: plain SOAP over HTTP is rejected.
      return { status: 400, body: 'unencrypted SOAP refused on the HTTP listener' };
    }
    if (sealed && gate.framingOf(req.socketId) === 'spnego') {
      // Windows Server 2022: after NTLM inside SPNEGO, HTTP.sys holds a
      // seal state the client does not match and answers the first sealed
      // body with 400. Bare NTLMSSP (pywinrm) is accepted.
      stats.spnegoSealsRefused += 1;
      return { status: 400, body: 'sealed body refused after SPNEGO-wrapped NTLM' };
    }
    // The Length-Field says which fake sealed the body: 16 is the NTLM
    // signature, 60 the Kerberos (gss_wrap_iov) header. The reply
    // uses the same one.
    const kerberos = sealed && mimeParts(req.body)[0]?.lengthField === FAKE_KRB_HEADER_LENGTH;
    const soap = !sealed ? req.body.toString('utf8') : kerberos ? mimeUnwrapIov(req.body, fakeKrbUnwrapIov) : mimeUnwrap(req.body, fakeNtlmUnwrap);
    if (sealed) stats.sealedRequests += 1;
    else stats.plainSoapRequests += 1;
    const reply = soapFor(soap);
    if (!sealed) return { status: 200, headers: { 'Content-Type': 'application/soap+xml;charset=UTF-8' }, body: reply };
    const wrapped = kerberos ? mimeWrapIov(reply, (m) => fakeKrbWrapIov(m)) : mimeWrap(reply, fakeNtlmWrap);
    return { status: 200, headers: { 'Content-Type': wrapped.contentType }, body: wrapped.body };
  };

  const tls = opts.tls
    ? {
        cert: readFileSync(new URL('../fixtures/tls-test-cert.pem', import.meta.url)),
        key: readFileSync(new URL('../fixtures/tls-test-key.pem', import.meta.url)),
      }
    : undefined;
  const server: MockServer = await startMockServer(handler, tls ? { tls } : undefined);
  return {
    port: server.port,
    openShells: () => [...shells.keys()],
    workingDirectories: () => [...workingDirectories],
    get sealedRequests() {
      return stats.sealedRequests;
    },
    get plainSoapRequests() {
      return stats.plainSoapRequests;
    },
    get handshakes() {
      return gate.handshakes;
    },
    get staleTokens() {
      return gate.staleTokens;
    },
    get spnegoSealsRefused() {
      return stats.spnegoSealsRefused;
    },
    close: () => server.close(),
  };
}
