// A stateful fake PSRP endpoint for the offline tests: the server
// side of MS-PSRP the client uses, on top of the mock server, with the auth gate
// and sealed bodies over HTTP of fake-windows.ts. It keeps real shell
// state (a pool is a shell until Delete), a variable table per pool, and
// a small script table that answers the scripts the scenarios run. It
// also serves the WinRS shell listing script, so the "no shell left"
// check of the live scenarios runs against it unchanged.
import { readFileSync } from 'node:fs';
import { XMLParser } from 'fast-xml-parser';
import { FAKE_KRB_HEADER_LENGTH, fakeKrbUnwrapIov, fakeKrbWrapIov, fakeNtlmUnwrap, fakeNtlmWrap } from './stub-auth.js';
import { actionOf, mimeParts, mimeUnwrap, mimeUnwrapIov, mimeWrap, mimeWrapIov, negotiateGate, startMockServer, type MockResponse, type MockServer, type RecordedRequest } from './mock-server.js';
import { Defragmenter, encodeFragments } from '../../src/winrm/psrp/fragments.js';
import { Destination, EMPTY_GUID, MessageType, encodeMessage, type PsrpMessage } from '../../src/winrm/psrp/messages.js';
import { deserializeClixml, isPSObject, psObject, serializeClixml, type PSObject, type PSValue } from '../../src/winrm/psrp/clixml.js';
import { decodePowerShellArgs } from '../../src/winrm/cmdline.js';
import { LIST_SHELLS_SCRIPT } from '../live/scenarios.js';
import { SERVER_INFO_SCRIPT, WINRM_AUTH_CONFIG_COMMAND } from '../live/gate.js';
import { windowsArgv } from './cmdline-sim.js';

export const FAKE_PSRP_HOSTNAME = 'FAKEPS01';
// What the fake answers the live gate's server info script with.
export const FAKE_SERVER_INFO = { ProductName: 'Windows Server 2022 Datacenter', DisplayVersion: '21H2', Build: '20348.1', PSVersion: '5.1.20348.1', PSEdition: 'Desktop' } as const;
const RSP = 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell';
const B64 = (s: string | Buffer) => Buffer.from(s).toString('base64');
const OPERATION_TIMEOUT_CODE = 2150858793;
const WAIT_CAP_MS = 1000;
const POLL_MS = 20;

export interface FakePsrpOptions {
  tls: boolean;
  username: string;
  password: string;
  // The protocol version the server claims (default 2.3; 2.1 for the refusal).
  protocolVersion?: string;
  // Bytes of fragments one ReceiveResponse carries at most (default 150 KB).
  receiveBytes?: number;
  // What `winrm get winrm/config/service/auth` reports (default Strict).
  cbtHardeningLevel?: string;
  faults?: {
    // The pool opens Broken with an error record.
    brokenPool?: boolean;
    // Every Command faults.
    faultOnCommand?: boolean;
    // The second pool Receive faults.
    faultOnPoolReceive?: boolean;
    ignoreDelete?: boolean;
    // Drop the fragments of the second ReceiveResponse of a pipeline.
    dropReceive?: boolean;
  };
}

export interface FakePsrp {
  port: number;
  // Shell ids the server holds: PSRP pools and WinRS shells.
  openShells(): string[];
  // Every pipeline script the fake ran, in order.
  scripts: string[];
  sealedRequests: number;
  plainSoapRequests: number;
  signals: number;
  // Receives on pipelines, in all.
  receives: number;
  close(): Promise<void>;
}

interface Pipeline {
  commandId: string;
  pid: string;
  fragments: Defragmenter;
  outbox: Buffer[]; // whole fragments, in order
  running: boolean; // true until the final PIPELINE_STATE is queued
  finished: boolean;
  longRunning: boolean; // Start-Sleep: ends only on Signal
  receives: number;
}

interface Pool {
  rpid: string;
  variables: Map<string, PSValue>;
  fragments: Defragmenter;
  outbox: Buffer[];
  pipelines: Map<string, Pipeline>;
  nextObjectId: bigint;
  poolReceives: number;
}

interface WinrsShell {
  commands: Map<string, { stdout: string; exitCode: number }>;
}

const parser = new XMLParser({ ignoreAttributes: false, attributeNamePrefix: '@', removeNSPrefix: true, parseTagValue: false, textNodeName: '#text' });
const node = (v: unknown): Record<string, unknown> => (typeof v === 'object' && v !== null ? (v as Record<string, unknown>) : {});
const text = (v: unknown): string => (typeof v === 'string' ? v : typeof node(v)['#text'] === 'string' ? (node(v)['#text'] as string) : '');

const envelope = (body: string) => `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body>${body}</s:Body></s:Envelope>`;
function wsmanFault(code: number, reason: string): string {
  return envelope(
    '<s:Fault><s:Code><s:Value>s:Receiver</s:Value><s:Subcode><s:Value>w:InternalError</s:Value></s:Subcode></s:Code>' +
      `<s:Reason><s:Text xml:lang="en-US">${reason}</s:Text></s:Reason>` +
      `<s:Detail><f:WSManFault Code="${code}" Machine="${FAKE_PSRP_HOSTNAME}" xmlns:f="http://schemas.microsoft.com/wbem/wsman/1/wsmanfault"></f:WSManFault></s:Detail></s:Fault>`,
  );
}
const TIMEOUT_FAULT = wsmanFault(OPERATION_TIMEOUT_CODE, 'The WS-Management service cannot complete the operation within the time specified in OperationTimeout.');

// --- CLIXML the fake writes (the shapes Windows PowerShell 5.1 sends) ---

const ERROR_RECORD_TYPES = ['System.Management.Automation.ErrorRecord', 'System.Object'];
function errorRecord(message: string, fqid: string, category = 0, categoryText = 'NotSpecified', exceptionType = 'System.Management.Automation.RuntimeException'): PSObject {
  return psObject(
    {
      Exception: psObject({}, [exceptionType, 'System.Exception', 'System.Object'], message),
      TargetObject: null,
      FullyQualifiedErrorId: fqid,
      InvocationInfo: psObject({ MyCommand: '', ScriptLineNumber: 1, Line: '' }),
      ErrorCategory_Category: category,
      ErrorCategory_Activity: '',
      ErrorCategory_Reason: exceptionType.split('.').pop() ?? '',
      ErrorCategory_TargetName: '',
      ErrorCategory_TargetType: '',
      ErrorCategory_Message: `${categoryText}: (:) [], ${exceptionType.split('.').pop() ?? ''}`,
      SerializeExtendedInfo: false,
    },
    ERROR_RECORD_TYPES,
    message,
  );
}
// The Exception's Message lives in Props on the wire.
function errorRecordXml(record: PSObject): string {
  const exception = record.extended.get('Exception') ?? null;
  if (isPSObject(exception)) exception.adapted.set('Message', exception.toStringValue ?? '');
  return serializeClixml(record);
}
const informational = (type: string, message: string) => serializeClixml(psObject({ InformationalRecord_Message: message, InformationalRecord_SerializeInvocationInfo: false }, [`System.Management.Automation.${type}`, 'System.Management.Automation.InformationalRecord', 'System.Object'], message));
const information = (message: string) =>
  serializeClixml(
    psObject(
      {
        MessageData: psObject({ Message: message, NoNewLine: false }, ['System.Management.Automation.HostInformationMessage', 'System.Object'], message),
        Source: 'Write-Host',
        TimeGenerated: { kind: 'datetime', iso: '2026-01-01T00:00:00.0000000Z', date: new Date('2026-01-01T00:00:00Z') },
        Tags: ['PSHOST'],
        User: 'EXAMPLE\\user',
        Computer: FAKE_PSRP_HOSTNAME,
        ProcessId: 4,
        NativeThreadId: 8,
        ManagedThreadId: 12,
      },
      ['System.Management.Automation.InformationRecord', 'System.Object'],
    ),
  );
const progress = (activity: string, percent: number, status: string) => `<PR><AV>${activity}</AV><AI>1</AI><Nil/><PI>-1</PI><PC>${percent}</PC><T>Processing</T><SR>-1</SR><SD>${status}</SD></PR>`;
// A Process carries its properties as adapted ones (Props), as the server
// serializes a .NET object.
const processObject = (id: number, name: string): PSObject => ({
  kind: 'object',
  typeNames: ['System.Diagnostics.Process', 'System.ComponentModel.Component', 'System.Object'],
  toStringValue: `System.Diagnostics.Process (${name})`,
  adapted: new Map<string, PSValue>([
    ['Id', id],
    ['ProcessName', name],
    ['WorkingSet64', 1024 * 1024 * id],
  ]),
  extended: new Map(),
});
const pipelineState = (state: number, error?: PSObject) => serializeClixml(psObject(error ? { PipelineState: state, ExceptionAsErrorRecord: error } : { PipelineState: state }));

// --- script interpretation ---

interface Emit {
  output(value: PSValue): void;
  message(type: number, data: string): void;
}

// Parses a PowerShell literal: a number, a 'single' or "double" quoted
// string, $null, $true, $false, a variable, or "x" * n.
function literal(expr: string, variables: Map<string, PSValue>): PSValue {
  const e = expr.trim();
  const repeat = /^(['"])(.*)\1\s*\*\s*(\d+)$/.exec(e);
  if (repeat) return (repeat[2] as string).repeat(Number(repeat[3]));
  const quoted = /^(['"])(.*)\1$/s.exec(e);
  if (quoted) return quoted[2] as string;
  if (/^-?\d+$/.test(e)) return Number(e);
  if (e === '$null') return null;
  if (e === '$true') return true;
  if (e === '$false') return false;
  const variable = /^\$(\w+)$/.exec(e);
  if (variable) return variables.get((variable[1] as string).toLowerCase()) ?? null;
  return e;
}

// Runs one statement; returns false when the statement is a terminating
// error (the pipeline then fails with it).
function statement(line: string, variables: Map<string, PSValue>, emit: Emit): { failed?: PSObject; long?: boolean } {
  const s = line.trim();
  if (s === '') return {};
  if (s === SERVER_INFO_SCRIPT) {
    emit.output(psObject({ ...FAKE_SERVER_INFO }, ['System.Management.Automation.PSCustomObject', 'System.Object']));
    return {};
  }
  let m: RegExpExecArray | null;
  if ((m = /^\$(\w+)\s*=\s*(.+)$/s.exec(s))) {
    variables.set((m[1] as string).toLowerCase(), literal(m[2] as string, variables));
    return {};
  }
  if ((m = /^\$(\w+)$/.exec(s))) {
    const value = variables.get((m[1] as string).toLowerCase());
    if (value !== undefined && value !== null) emit.output(value);
    return {};
  }
  if ((m = /^(?:Write-Output\s+)?(['"])(.*)\1$/s.exec(s)) || (m = /^(['"])(.*)\1\s*\*\s*\d+$/.exec(s))) {
    emit.output(literal(s.replace(/^Write-Output\s+/, ''), variables));
    return {};
  }
  if ((m = /^Get-Process\s*\|\s*Select(?:-Object)?\s+-First\s+(\d+)$/i.exec(s))) {
    const names = ['System', 'csrss', 'svchost', 'pwsh', 'winlogon'];
    for (let i = 0; i < Number(m[1]); i++) emit.output(processObject(4 + i * 4, names[i % names.length] as string));
    return {};
  }
  if ((m = /^1\.\.(\d+)\s*\|\s*(?:ForEach-Object|%)\s*\{\s*"line\$_"\s*\}$/.exec(s))) {
    for (let i = 1; i <= Number(m[1]); i++) emit.output(`line${i}`);
    return {};
  }
  if ((m = /^Write-Error\s+(['"])(.*)\1$/.exec(s))) {
    emit.message(MessageType.ERROR_RECORD, errorRecordXml(errorRecord(m[2] as string, `Microsoft.PowerShell.Commands.WriteErrorException`, 0, 'NotSpecified', 'Microsoft.PowerShell.Commands.WriteErrorException')));
    return {};
  }
  if ((m = /^Write-Warning\s+(['"])(.*)\1$/.exec(s))) {
    emit.message(MessageType.WARNING_RECORD, informational('WarningRecord', m[2] as string));
    return {};
  }
  if ((m = /^Write-Verbose\s+(['"])(.*)\1\s+-Verbose$/.exec(s))) {
    emit.message(MessageType.VERBOSE_RECORD, informational('VerboseRecord', m[2] as string));
    return {};
  }
  if ((m = /^Write-Debug\s+(['"])(.*)\1\s+-Debug$/.exec(s))) {
    emit.message(MessageType.DEBUG_RECORD, informational('DebugRecord', m[2] as string));
    return {};
  }
  if ((m = /^Write-(?:Information|Host)\s+(['"])(.*)\1$/.exec(s))) {
    emit.message(MessageType.INFORMATION_RECORD, information(m[2] as string));
    return {};
  }
  if ((m = /^Write-Progress\s+-Activity\s+(['"])(.*)\1\s+-PercentComplete\s+(\d+)(?:\s+-Status\s+(['"])(.*)\4)?$/.exec(s))) {
    emit.message(MessageType.PROGRESS_RECORD, progress(m[2] as string, Number(m[3]), (m[5] as string | undefined) ?? ''));
    return {};
  }
  if (/^Start-Sleep\s+(-Seconds\s+)?\d+$/.test(s)) return { long: true };
  if ((m = /^Read-Host(\s+.*)?$/.exec(s))) {
    return {
      failed: errorRecord('Cannot invoke this function because the current host does not implement it.', 'HostFunctionNotImplemented,Microsoft.PowerShell.Commands.ReadHostCommand', 7, 'NotImplemented', 'System.Management.Automation.Host.HostException'),
    };
  }
  if ((m = /^throw\s+(['"])(.*)\1$/.exec(s))) return { failed: errorRecord(m[2] as string, m[2] as string) };
  return { failed: errorRecord(`The term '${s.split(/\s+/)[0]}' is not recognized as the name of a cmdlet, function, script file, or operable program.`, 'CommandNotFoundException', 13, 'ObjectNotFound', 'System.Management.Automation.CommandNotFoundException') };
}

// Out-String -Stream: every output as the lines PowerShell would print.
function formatLine(value: PSValue): string[] {
  if (value === null) return [];
  if (typeof value === 'string') return value.split(/\r?\n/);
  if (typeof value === 'number' || typeof value === 'bigint' || typeof value === 'boolean') return [String(value)];
  if (isPSObject(value)) {
    if (value.adapted.has('ProcessName')) return [`${String(value.adapted.get('Id')).padStart(6)} ${String(value.adapted.get('ProcessName'))}`];
    return [value.toStringValue ?? ''];
  }
  return [String(value)];
}

export async function startFakePsrp(opts: FakePsrpOptions): Promise<FakePsrp> {
  const pools = new Map<string, Pool>();
  const winrs = new Map<string, WinrsShell>();
  const scripts: string[] = [];
  const stats = { sealedRequests: 0, plainSoapRequests: 0, signals: 0, receives: 0 };
  const faults = opts.faults ?? {};
  const basic = `Basic ${B64(`${opts.username}:${opts.password}`)}`;
  const gate = negotiateGate();
  const receiveBytes = opts.receiveBytes ?? 150 * 1024;
  let nextId = 1;

  function serverMessage(pool: Pool, type: number, pid: string, data: string): Buffer[] {
    const bytes = encodeMessage({ destination: Destination.client, messageType: type, rpid: pool.rpid, pid, data });
    const id = pool.nextObjectId++;
    return encodeFragments(id, bytes);
  }

  function openPool(rpid: string): Pool {
    const pool: Pool = { rpid, variables: new Map(), fragments: new Defragmenter(), outbox: [], pipelines: new Map(), nextObjectId: 1n, poolReceives: 0 };
    const caps = serializeClixml(psObject({ protocolversion: { kind: 'version', typeNames: [], adapted: new Map(), extended: new Map(), value: opts.protocolVersion ?? '2.3' }, PSVersion: { kind: 'version', typeNames: [], adapted: new Map(), extended: new Map(), value: '2.0' }, SerializationVersion: { kind: 'version', typeNames: [], adapted: new Map(), extended: new Map(), value: '1.1.0.1' } }));
    pool.outbox.push(...serverMessage(pool, MessageType.SESSION_CAPABILITY, EMPTY_GUID, caps));
    const appData = serializeClixml(psObject({ ApplicationPrivateData: new Map<PSValue, PSValue>([['PSVersionTable', new Map<PSValue, PSValue>([['PSVersion', { kind: 'version', typeNames: [], adapted: new Map(), extended: new Map(), value: '5.1.20348.1' }]])]]) }));
    pool.outbox.push(...serverMessage(pool, MessageType.APPLICATION_PRIVATE_DATA, EMPTY_GUID, appData));
    const state = faults.brokenPool
      ? serializeClixml(psObject({ RunspaceState: 5, ExceptionAsErrorRecord: errorRecord('The fake refused the pool.', 'FakeBrokenPool') }))
      : serializeClixml(psObject({ RunspaceState: 2 }));
    pool.outbox.push(...serverMessage(pool, MessageType.RUNSPACEPOOL_STATE, EMPTY_GUID, state));
    return pool;
  }

  // Decodes the client's fragments for a target and runs any CREATE_PIPELINE.
  function feed(pool: Pool, target: Defragmenter, bytes: Buffer, pipeline?: Pipeline): PsrpMessage[] {
    return target.push(bytes).map((m) => {
      if (m.messageType === MessageType.CREATE_PIPELINE && pipeline) runPipeline(pool, pipeline, m);
      return m;
    });
  }

  function runPipeline(pool: Pool, pipeline: Pipeline, create: PsrpMessage): void {
    const value = deserializeClixml(create.data)[0];
    const ps = isPSObject(value) ? (value.extended.get('PowerShell') ?? null) : null;
    const cmds = isPSObject(ps) ? (ps.extended.get('Cmds') as PSValue[]) : [];
    const first = isPSObject(cmds[0] ?? null) ? (cmds[0] as PSObject) : null;
    const script = first ? String(first.extended.get('Cmd') ?? '') : '';
    const outString = cmds.slice(1).some((c) => isPSObject(c) && c.extended.get('Cmd') === 'Out-String');
    scripts.push(script);
    const queue = (type: number, data: string) => pipeline.outbox.push(...serverMessage(pool, type, pipeline.pid, data));
    const emit: Emit = {
      output: (v) => {
        if (outString) for (const line of formatLine(v)) queue(MessageType.PIPELINE_OUTPUT, serializeClixml(line));
        else queue(MessageType.PIPELINE_OUTPUT, v === null ? '' : serializeClixml(v));
      },
      message: queue,
    };
    const lines = script === SERVER_INFO_SCRIPT ? [script] : script.split(/;|\r?\n/);
    for (const line of lines) {
      const r = statement(line, pool.variables, emit);
      if (r.failed) {
        queue(MessageType.PIPELINE_STATE, pipelineState(5, r.failed));
        pipeline.running = false;
        return;
      }
      if (r.long) {
        pipeline.longRunning = true;
        return;
      }
    }
    queue(MessageType.PIPELINE_STATE, pipelineState(4));
    pipeline.running = false;
  }

  function stopPipeline(pool: Pool, pipeline: Pipeline): void {
    if (!pipeline.running) return;
    pipeline.outbox.push(...serverMessage(pool, MessageType.PIPELINE_STATE, pipeline.pid, pipelineState(3)));
    pipeline.running = false;
  }

  // Takes fragments from an outbox up to receiveBytes, never splitting one.
  function take(outbox: Buffer[]): Buffer[] {
    const out: Buffer[] = [];
    let size = 0;
    while (outbox.length > 0 && (out.length === 0 || size + (outbox[0] as Buffer).length <= receiveBytes)) {
      const f = outbox.shift() as Buffer;
      out.push(f);
      size += f.length;
    }
    return out;
  }

  function receiveResponse(fragments: Buffer[], commandId: string | undefined, done: boolean): string {
    const streams = fragments.map((f) => `<rsp:Stream Name="stdout"${commandId ? ` CommandId="${commandId}"` : ''}>${f.toString('base64')}</rsp:Stream>`).join('');
    const state = commandId ? `<rsp:CommandState CommandId="${commandId}" State="${RSP}/CommandState/${done ? 'Done' : 'Running'}"/>` : '';
    return envelope(`<rsp:ReceiveResponse xmlns:rsp="${RSP}">${streams}${state}</rsp:ReceiveResponse>`);
  }

  async function waitFor(ready: () => boolean, opTimeoutMs: number): Promise<boolean> {
    const deadline = Date.now() + Math.min(opTimeoutMs, WAIT_CAP_MS);
    while (!ready()) {
      if (Date.now() >= deadline) return false;
      await new Promise((r) => setTimeout(r, POLL_MS));
    }
    return true;
  }

  function winrsFor(soap: string, action: string, shellId: string | undefined): string {
    if (action === 'Create') {
      const id = `FAKE-WINRS-${nextId++}`;
      winrs.set(id, { commands: new Map() });
      return envelope(
        '<x:ResourceCreated xmlns:x="http://schemas.xmlsoap.org/ws/2004/09/transfer"><a:ReferenceParameters xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing">' +
          `<w:SelectorSet xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"><w:Selector Name="ShellId">${id}</w:Selector></w:SelectorSet>` +
          '</a:ReferenceParameters></x:ResourceCreated>',
      );
    }
    const shell = shellId ? winrs.get(shellId) : undefined;
    if (!shell) throw new Error(`fake psrp: unknown WinRS shell ${shellId}`);
    if (action === 'Command') {
      const unescape = (t: string) => t.replace(/&quot;/g, '"').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');
      const command = unescape(/<rsp:Command>([^<]*)<\/rsp:Command>/.exec(soap)?.[1] ?? '');
      const args = [...soap.matchAll(/<rsp:Arguments>([^<]*)<\/rsp:Arguments>/g)].map((m) => unescape(m[1] ?? ''));
      const script = decodePowerShellArgs(args.map((a) => a.replace(/^"|"$/g, ''))) ?? '';
      const [program = '', ...argv] = windowsArgv(command, args);
      const commandId = `FAKE-CMD-${nextId++}`;
      const result =
        script === LIST_SHELLS_SCRIPT
          ? { stdout: `${JSON.stringify({ method: 'wsman', ids: [...pools.keys(), ...winrs.keys()] })}\r\n`, exitCode: 0 }
          : program === 'hostname' && argv.length === 0
            ? { stdout: `${FAKE_PSRP_HOSTNAME}\r\n`, exitCode: 0 }
            : program === WINRM_AUTH_CONFIG_COMMAND.cmd && argv.join(' ') === WINRM_AUTH_CONFIG_COMMAND.args.join(' ')
              ? { stdout: `Auth\r\n    Basic = true\r\n    Kerberos = true\r\n    Negotiate = true\r\n    Certificate = false\r\n    CredSSP = false\r\n    CbtHardeningLevel = ${opts.cbtHardeningLevel ?? 'Strict'}\r\n`, exitCode: 0 }
              : { stdout: `the fake runs only the shell listing, hostname and the WinRM auth config over WinRS\r\n`, exitCode: 1 };
      shell.commands.set(commandId, result);
      return envelope(`<rsp:CommandResponse xmlns:rsp="${RSP}"><rsp:CommandId>${commandId}</rsp:CommandId></rsp:CommandResponse>`);
    }
    if (action === 'Receive') {
      const commandId = /<rsp:DesiredStream CommandId="([^"]+)"/.exec(soap)?.[1] ?? '';
      const result = shell.commands.get(commandId);
      if (!result) throw new Error(`fake psrp: unknown WinRS command ${commandId}`);
      return envelope(
        `<rsp:ReceiveResponse xmlns:rsp="${RSP}"><rsp:Stream Name="stdout" CommandId="${commandId}">${B64(result.stdout)}</rsp:Stream>` +
          `<rsp:CommandState CommandId="${commandId}" State="${RSP}/CommandState/Done"><rsp:ExitCode>${result.exitCode}</rsp:ExitCode></rsp:CommandState></rsp:ReceiveResponse>`,
      );
    }
    if (action === 'Signal') return envelope(`<rsp:SignalResponse xmlns:rsp="${RSP}"/>`);
    if (action === 'Delete') {
      if (shellId) winrs.delete(shellId);
      return envelope('<x:DeleteResponse xmlns:x="http://schemas.xmlsoap.org/ws/2004/09/transfer"/>');
    }
    throw new Error(`fake psrp: unsupported WinRS action ${action}`);
  }

  async function soapFor(soap: string): Promise<string | { fault: string }> {
    const action = actionOf(Buffer.from(soap));
    const doc = parser.parse(soap) as Record<string, unknown>;
    const header = node(node(doc['Envelope'])['Header']);
    const body = node(node(doc['Envelope'])['Body']);
    const resourceUri = text(header['ResourceURI']);
    const shellId = text(node(node(header['SelectorSet'])['Selector'])) || undefined;
    const opTimeout = /^PT(\d+(?:\.\d+)?)S$/.exec(text(header['OperationTimeout']));
    const opTimeoutMs = opTimeout ? Number(opTimeout[1]) * 1000 : 60_000;
    if (!resourceUri.startsWith('http://schemas.microsoft.com/powershell/')) return winrsFor(soap, action, shellId);

    if (action === 'Create') {
      const shell = node(body['Shell']);
      const rpid = String(shell['@ShellId'] ?? '').toUpperCase();
      if (!/^[0-9A-F-]{36}$/.test(rpid)) return { fault: wsmanFault(2150858843, 'The fake needs a GUID ShellId.') };
      const option = node(node(header['OptionSet'])['Option']);
      if (String(option['@Name']) !== 'protocolversion') return { fault: wsmanFault(2150858843, 'The fake needs the protocolversion option.') };
      const pool = openPool(rpid.toLowerCase());
      feed(pool, pool.fragments, Buffer.from(text(shell['creationXml']), 'base64'));
      pools.set(rpid, pool);
      return envelope(
        '<x:ResourceCreated xmlns:x="http://schemas.xmlsoap.org/ws/2004/09/transfer"><a:ReferenceParameters xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing">' +
          `<w:SelectorSet xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"><w:Selector Name="ShellId">${rpid}</w:Selector></w:SelectorSet>` +
          '</a:ReferenceParameters></x:ResourceCreated>',
      );
    }
    const pool = shellId ? pools.get(shellId.toUpperCase()) : undefined;
    if (!pool) return { fault: wsmanFault(2150858843, `The fake has no shell ${shellId}.`) };
    if (action === 'Command') {
      if (faults.faultOnCommand) return { fault: wsmanFault(2150858843, 'The fake refuses the Command.') };
      const line = node(body['CommandLine']);
      const commandId = String(line['@CommandId'] ?? '').toUpperCase();
      const pipeline: Pipeline = { commandId, pid: commandId.toLowerCase(), fragments: new Defragmenter(), outbox: [], running: true, finished: false, longRunning: false, receives: 0 };
      pool.pipelines.set(commandId, pipeline);
      feed(pool, pipeline.fragments, Buffer.from(text(line['Arguments']), 'base64'), pipeline);
      return envelope(`<rsp:CommandResponse xmlns:rsp="${RSP}"><rsp:CommandId>${commandId}</rsp:CommandId></rsp:CommandResponse>`);
    }
    if (action === 'Send') {
      const stream = node(node(body['Send'])['Stream']);
      const commandId = stream['@CommandId'] as string | undefined;
      const pipeline = commandId ? pool.pipelines.get(commandId.toUpperCase()) : undefined;
      feed(pool, pipeline ? pipeline.fragments : pool.fragments, Buffer.from(text(stream), 'base64'), pipeline);
      return envelope(`<rsp:SendResponse xmlns:rsp="${RSP}"/>`);
    }
    if (action === 'Signal') {
      stats.signals += 1;
      const signal = node(body['Signal']);
      const pipeline = pool.pipelines.get(String(signal['@CommandId'] ?? '').toUpperCase());
      if (pipeline) stopPipeline(pool, pipeline);
      return envelope(`<rsp:SignalResponse xmlns:rsp="${RSP}"/>`);
    }
    if (action === 'Delete') {
      if (!faults.ignoreDelete && shellId) pools.delete(shellId.toUpperCase());
      return envelope('<x:DeleteResponse xmlns:x="http://schemas.xmlsoap.org/ws/2004/09/transfer"/>');
    }
    if (action === 'Receive') {
      const desired = node(node(body['Receive'])['DesiredStream']);
      const commandId = (desired['@CommandId'] as string | undefined)?.toUpperCase();
      if (!commandId) {
        pool.poolReceives += 1;
        if (faults.faultOnPoolReceive && pool.poolReceives === 2) return { fault: wsmanFault(2150858843, 'The fake faults the pool Receive.') };
        if (pool.outbox.length === 0 && !(await waitFor(() => pool.outbox.length > 0, opTimeoutMs))) return { fault: TIMEOUT_FAULT };
        return receiveResponse(take(pool.outbox), undefined, false);
      }
      const pipeline = pool.pipelines.get(commandId);
      if (!pipeline) return { fault: wsmanFault(2150858843, `The fake has no command ${commandId}.`) };
      pipeline.receives += 1;
      stats.receives += 1;
      const ready = () => pipeline.outbox.length > 0 || !pipeline.running;
      if (!(await waitFor(ready, opTimeoutMs))) return { fault: TIMEOUT_FAULT };
      let fragments = take(pipeline.outbox);
      if (faults.dropReceive && pipeline.receives === 2) fragments = [];
      const done = !pipeline.running && pipeline.outbox.length === 0;
      if (done) pipeline.finished = true;
      return receiveResponse(fragments, commandId, done);
    }
    throw new Error(`fake psrp: unsupported action ${action}`);
  }

  const challenge: MockResponse = { status: 401, headers: { 'WWW-Authenticate': 'Negotiate' } };
  const handler = async (req: RecordedRequest): Promise<MockResponse> => {
    const auth = req.headers.authorization ?? '';
    const answer = async (soap: string): Promise<{ status: number; reply: string }> => {
      const out = await soapFor(soap);
      return typeof out === 'string' ? { status: 200, reply: out } : { status: 500, reply: out.fault };
    };
    if (auth === basic) {
      if (!opts.tls) return challenge;
      stats.plainSoapRequests += 1;
      const { status, reply } = await answer(req.body.toString('utf8'));
      return { status, headers: { 'Content-Type': 'application/soap+xml;charset=UTF-8' }, body: reply };
    }
    const denied = gate.check(req);
    if (denied) return denied;
    const sealed = (req.headers['content-type'] ?? '').includes('multipart/encrypted');
    if (!sealed && !opts.tls) return { status: 400, body: 'unencrypted SOAP refused on the HTTP listener' };
    const kerberos = sealed && mimeParts(req.body)[0]?.lengthField === FAKE_KRB_HEADER_LENGTH;
    const soap = !sealed ? req.body.toString('utf8') : kerberos ? mimeUnwrapIov(req.body, fakeKrbUnwrapIov) : mimeUnwrap(req.body, fakeNtlmUnwrap);
    if (sealed) stats.sealedRequests += 1;
    else stats.plainSoapRequests += 1;
    const { status, reply } = await answer(soap);
    if (!sealed) return { status, headers: { 'Content-Type': 'application/soap+xml;charset=UTF-8' }, body: reply };
    const wrapped = kerberos ? mimeWrapIov(reply, (m) => fakeKrbWrapIov(m)) : mimeWrap(reply, fakeNtlmWrap);
    return { status, headers: { 'Content-Type': wrapped.contentType }, body: wrapped.body };
  };

  const tls = opts.tls
    ? { cert: readFileSync(new URL('../fixtures/tls-test-cert.pem', import.meta.url)), key: readFileSync(new URL('../fixtures/tls-test-key.pem', import.meta.url)) }
    : undefined;
  const server: MockServer = await startMockServer(handler, { ...(tls ? { tls } : {}), recordBodies: false });
  return {
    port: server.port,
    openShells: () => [...pools.keys(), ...winrs.keys()],
    scripts,
    get sealedRequests() {
      return stats.sealedRequests;
    },
    get plainSoapRequests() {
      return stats.plainSoapRequests;
    },
    get signals() {
      return stats.signals;
    },
    get receives() {
      return stats.receives;
    },
    close: () => server.close(),
  };
}
