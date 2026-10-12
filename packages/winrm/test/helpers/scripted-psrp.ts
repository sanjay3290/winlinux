// A scripted PSRP server for the pool and pipeline state-machine tests:
// the test lists the messages each Receive answers with, and the server
// records what the client sent, decoded. It speaks sealed NTLM over HTTP
// through the mock server, like the Send tests. The stateful fake
// endpoint that runs scripts lives in fake-psrp.ts.
import { XMLParser } from 'fast-xml-parser';
import { Defragmenter, encodeFragments } from '../../src/winrm/psrp/fragments.js';
import { Destination, EMPTY_GUID, decodeMessage, encodeMessage, type PsrpMessage } from '../../src/winrm/psrp/messages.js';
import { deserializeClixml, type PSValue } from '../../src/winrm/psrp/clixml.js';
import { fakeNtlmUnwrap, fakeNtlmWrap } from './stub-auth.js';
import { actionOf, mimeUnwrap, mimeWrap, negotiateGate, startMockServer, type MockResponse, type RecordedRequest } from './mock-server.js';

const RSP = 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell';
const OPERATION_TIMEOUT_CODE = 2150858793;

export interface ServerMessage {
  type: number;
  data: string;
  // Default: the pipeline for pipeline Receives, the pool for pool Receives.
  target?: 'pool' | 'pipeline';
}

// One Receive answer: messages, an operation-timeout fault, another
// fault, or wait until the client sends Signal, then answer these.
export type ReceiveAnswer = ServerMessage[] | 'timeout' | { fault: string } | { afterSignal: ServerMessage[] } | { done: true } | { doneAfterSignal: true };

export interface ClientMessage extends PsrpMessage {
  value: PSValue;
}

export interface ScriptedPsrpOptions {
  // Pool Receive answers, in order; the default opens the pool with 2.3.
  pool?: ReceiveAnswer[];
  // Pipeline Receive answers for each pipeline, in order of creation.
  pipelines?: ReceiveAnswer[][];
  // Delay or fault the Command response.
  command?: { delayMs?: number; fault?: string };
  // Delay the SendResponse of the nth Send (1-based).
  sendDelayMs?: (nth: number) => number;
  // Fragment size for server messages (default one fragment), and the
  // number of fragments one ReceiveResponse carries (default all).
  fragmentBytes?: number;
  fragmentsPerReceive?: number;
}

export interface ScriptedPsrp {
  port: number;
  actions: string[];
  // Every message the client sent, decoded, in order.
  received: ClientMessage[];
  signals: string[];
  sends: Array<{ stream: string; commandId?: string; bytes: number }>;
  shellIds: string[];
  commandIds: string[];
  close(): Promise<void>;
}

const parser = new XMLParser({ ignoreAttributes: false, attributeNamePrefix: '@', removeNSPrefix: true, parseTagValue: false, textNodeName: '#text' });

const envelope = (body: string) => `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body>${body}</s:Body></s:Envelope>`;

export function wsmanFault(code: number, reason: string): string {
  return envelope(
    '<s:Fault><s:Code><s:Value>s:Receiver</s:Value><s:Subcode><s:Value>w:InternalError</s:Value></s:Subcode></s:Code>' +
      `<s:Reason><s:Text xml:lang="en-US">${reason}</s:Text></s:Reason>` +
      `<s:Detail><f:WSManFault Code="${code}" Machine="scripted" xmlns:f="http://schemas.microsoft.com/wbem/wsman/1/wsmanfault"></f:WSManFault></s:Detail></s:Fault>`,
  );
}
export const OPERATION_TIMEOUT_FAULT = wsmanFault(OPERATION_TIMEOUT_CODE, 'The WS-Management service cannot complete the operation within the time specified in OperationTimeout.');

export const CAPS_23 = '<Obj RefId="0"><MS><Version N="protocolversion">2.3</Version><Version N="PSVersion">2.0</Version><Version N="SerializationVersion">1.1.0.1</Version></MS></Obj>';
export const APP_DATA = '<Obj RefId="0"><MS><Obj N="ApplicationPrivateData" RefId="1"><TN RefId="0"><T>System.Collections.Hashtable</T><T>System.Object</T></TN><DCT><En><S N="Key">PSVersionTable</S><Obj N="Value" RefId="2"><TN RefId="1"><T>System.Collections.Hashtable</T><T>System.Object</T></TN><DCT><En><S N="Key">PSVersion</S><Version N="Value">5.1.20348.1</Version></En></DCT></Obj></En></DCT></Obj></MS></Obj>';
export const poolState = (state: number, error?: string) => `<Obj RefId="0"><MS><I32 N="RunspaceState">${state}</I32>${error ?? ''}</MS></Obj>`;
export const pipelineState = (state: number, error?: string) => `<Obj RefId="0"><MS><I32 N="PipelineState">${state}</I32>${error ?? ''}</MS></Obj>`;
export const errorRecord = (name: string, message: string, fqid = 'ScriptedError') =>
  `<Obj N="${name}" RefId="1"><TN RefId="0"><T>System.Management.Automation.ErrorRecord</T><T>System.Object</T></TN><ToString>${message}</ToString><MS>` +
  `<Obj N="Exception" RefId="2"><TN RefId="1"><T>System.Management.Automation.RuntimeException</T><T>System.Exception</T><T>System.Object</T></TN><ToString>${message}</ToString><Props><S N="Message">${message}</S></Props></Obj>` +
  `<Nil N="TargetObject"/><S N="FullyQualifiedErrorId">${fqid}</S><Nil N="InvocationInfo"/><I32 N="ErrorCategory_Category">0</I32><S N="ErrorCategory_Activity"></S><S N="ErrorCategory_Reason">RuntimeException</S><S N="ErrorCategory_TargetName"></S><S N="ErrorCategory_TargetType"></S><S N="ErrorCategory_Message">NotSpecified: (:) [], RuntimeException</S><B N="SerializeExtendedInfo">false</B></MS></Obj>`;
// A top-level error record message (ERROR_RECORD data has no N attribute).
export const errorRecordMessage = (message: string, fqid = 'ScriptedError') => errorRecord('x', message, fqid).replace(' N="x"', '');

export const DEFAULT_OPEN: ReceiveAnswer[] = [[{ type: 0x00010002, data: CAPS_23 }], [{ type: 0x00021009, data: APP_DATA }, { type: 0x00021005, data: poolState(2) }]];

function parseSoap(soap: string): Record<string, unknown> {
  return parser.parse(soap) as Record<string, unknown>;
}
const node = (v: unknown): Record<string, unknown> => (typeof v === 'object' && v !== null ? (v as Record<string, unknown>) : {});
const text = (v: unknown): string => (typeof v === 'string' ? v : typeof node(v)['#text'] === 'string' ? (node(v)['#text'] as string) : '');

export async function startScriptedPsrp(opts: ScriptedPsrpOptions = {}): Promise<ScriptedPsrp> {
  const gate = negotiateGate();
  const state: ScriptedPsrp = { port: 0, actions: [], received: [], signals: [], sends: [], shellIds: [], commandIds: [], close: async () => undefined };
  const poolAnswers = [...(opts.pool ?? DEFAULT_OPEN)];
  const pipelineScripts = (opts.pipelines ?? []).map((answers) => [...answers]);
  const clientFragments = new Map<string, Defragmenter>(); // by target
  let nextObjectId = 1n;
  let pipelineIndex = -1;
  let currentPipeline: { id: string; answers: ReceiveAnswer[] } | null = null;
  // Signals not yet matched to an afterSignal answer, and the handlers
  // waiting for the next one.
  let pendingSignals = 0;
  let signalWaiters: Array<() => void> = [];
  let sendCount = 0;
  const rpidOf = (m: PsrpMessage) => m.rpid;

  function decodeClient(target: string, bytes: Buffer): void {
    let d = clientFragments.get(target);
    if (!d) clientFragments.set(target, (d = new Defragmenter()));
    for (const message of d.push(bytes)) {
      const value = message.data.length > 0 ? (deserializeClixml(message.data)[0] ?? null) : null;
      state.received.push({ ...message, value });
    }
  }

  // The fragments of the answer's messages, as rsp:Stream elements across
  // one or more ReceiveResponses.
  function encodeAnswer(messages: ServerMessage[], pipelineId: string | undefined, rpid: string): Buffer[] {
    const fragments: Buffer[] = [];
    for (const m of messages) {
      const toPipeline = m.target === 'pipeline' || (m.target === undefined && pipelineId !== undefined);
      const bytes = encodeMessage({ destination: Destination.client, messageType: m.type, rpid, pid: toPipeline && pipelineId ? pipelineId : EMPTY_GUID, data: m.data });
      for (const f of encodeFragments(nextObjectId++, bytes, opts.fragmentBytes ?? 32768)) fragments.push(Buffer.concat([Buffer.from([toPipeline ? 1 : 0]), f]));
    }
    return fragments;
  }

  // Pending fragments not yet delivered (when fragmentsPerReceive splits an answer).
  let pending: Buffer[] = [];
  function receiveResponse(pipelineId: string | undefined, commandIdAttr: string | undefined, done = false): string {
    const take = opts.fragmentsPerReceive ?? pending.length;
    const now = pending.splice(0, take);
    let streams = '';
    for (const tagged of now) {
      const toPipeline = tagged[0] === 1;
      const fragment = tagged.subarray(1);
      streams += `<rsp:Stream Name="stdout"${toPipeline && commandIdAttr ? ` CommandId="${commandIdAttr}"` : ''}>${fragment.toString('base64')}</rsp:Stream>`;
    }
    const stateXml = commandIdAttr
      ? `<rsp:CommandState CommandId="${commandIdAttr}" State="${RSP}/CommandState/${done ? 'Done' : 'Running'}"/>`
      : '';
    void pipelineId;
    return envelope(`<rsp:ReceiveResponse xmlns:rsp="${RSP}">${streams}${stateXml}</rsp:ReceiveResponse>`);
  }

  async function answer(soap: string): Promise<string | { fault: string }> {
    const action = actionOf(Buffer.from(soap));
    state.actions.push(action);
    const doc = parseSoap(soap);
    const body = node(node(doc['Envelope'])['Body']);
    const header = node(node(doc['Envelope'])['Header']);
    const selector = node(node(header['SelectorSet'])['Selector']);
    const shellId = text(selector);
    if (action === 'Create') {
      const shell = node(body['Shell']);
      const id = String(shell['@ShellId'] ?? '');
      state.shellIds.push(id);
      decodeClient('pool', Buffer.from(text(shell['creationXml']), 'base64'));
      return envelope(
        '<x:ResourceCreated xmlns:x="http://schemas.xmlsoap.org/ws/2004/09/transfer"><a:ReferenceParameters xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing">' +
          `<w:SelectorSet xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"><w:Selector Name="ShellId">${id}</w:Selector></w:SelectorSet>` +
          '</a:ReferenceParameters></x:ResourceCreated>',
      );
    }
    if (action === 'Command') {
      const line = node(body['CommandLine']);
      const commandId = String(line['@CommandId'] ?? '');
      state.commandIds.push(commandId);
      decodeClient(commandId, Buffer.from(text(line['Arguments']), 'base64'));
      if (opts.command?.delayMs) await new Promise((r) => setTimeout(r, opts.command?.delayMs));
      if (opts.command?.fault) return { fault: wsmanFault(2150858843, opts.command.fault) };
      pipelineIndex += 1;
      currentPipeline = { id: commandId, answers: pipelineScripts[pipelineIndex] ?? [] };
      return envelope(`<rsp:CommandResponse xmlns:rsp="${RSP}"><rsp:CommandId>${commandId}</rsp:CommandId></rsp:CommandResponse>`);
    }
    if (action === 'Send') {
      const stream = node(node(body['Send'])['Stream']);
      const commandId = stream['@CommandId'] as string | undefined;
      const data = Buffer.from(text(stream), 'base64');
      sendCount += 1;
      state.sends.push({ stream: String(stream['@Name']), ...(commandId ? { commandId } : {}), bytes: data.length });
      decodeClient(commandId ?? 'pool', data);
      const delay = opts.sendDelayMs?.(sendCount) ?? 0;
      if (delay > 0) await new Promise((r) => setTimeout(r, delay));
      return envelope(`<rsp:SendResponse xmlns:rsp="${RSP}"/>`);
    }
    if (action === 'Signal') {
      const signal = node(body['Signal']);
      state.signals.push(text(signal['Code']));
      pendingSignals += 1;
      const waiters = signalWaiters;
      signalWaiters = [];
      for (const wake of waiters) wake();
      return envelope(`<rsp:SignalResponse xmlns:rsp="${RSP}"/>`);
    }
    if (action === 'Delete') return envelope('<x:DeleteResponse xmlns:x="http://schemas.xmlsoap.org/ws/2004/09/transfer"/>');
    if (action === 'Receive') {
      const desired = node(node(body['Receive'])['DesiredStream']);
      const commandIdAttr = desired['@CommandId'] as string | undefined;
      const rpid = state.received[0] ? rpidOf(state.received[0]) : EMPTY_GUID;
      if (pending.length > 0) return receiveResponse(commandIdAttr ? currentPipeline?.id : undefined, commandIdAttr);
      const queue = commandIdAttr ? (currentPipeline?.answers ?? []) : poolAnswers;
      const next = queue.shift();
      if (next === undefined) return { fault: OPERATION_TIMEOUT_FAULT };
      if (next === 'timeout') return { fault: OPERATION_TIMEOUT_FAULT };
      if ('fault' in next) return { fault: next.fault };
      if ('done' in next) return receiveResponse(undefined, commandIdAttr, true);
      let messages: ServerMessage[];
      if ('doneAfterSignal' in next) {
        // The Stopped state went to the Receive the client cut: this one
        // only reports the command Done, as a server does.
        if (pendingSignals === 0) {
          queue.unshift(next);
          await new Promise<void>((resolve) => signalWaiters.push(resolve));
          return { fault: OPERATION_TIMEOUT_FAULT };
        }
        pendingSignals -= 1;
        return receiveResponse(undefined, commandIdAttr, true);
      }
      if ('afterSignal' in next) {
        if (pendingSignals === 0) {
          // Hold this Receive until a Signal arrives. The client cuts the
          // held Receive before it signals, so the
          // answer stays queued for the Receive that follows the Signal;
          // this one gets the timeout fault on its dead socket.
          queue.unshift(next);
          await new Promise<void>((resolve) => signalWaiters.push(resolve));
          return { fault: OPERATION_TIMEOUT_FAULT };
        }
        pendingSignals -= 1;
        messages = next.afterSignal;
      } else messages = next;
      pending = encodeAnswer(messages, commandIdAttr ? currentPipeline?.id.toLowerCase() : undefined, rpid);
      const last = messages.some((m) => m.type === 0x00041006); // PIPELINE_STATE: the server marks Done too
      const out = receiveResponse(undefined, commandIdAttr, last && pending.length <= (opts.fragmentsPerReceive ?? pending.length));
      return out;
    }
    void shellId;
    throw new Error(`scripted psrp: unsupported action ${action}`);
  }

  const handler = async (req: RecordedRequest): Promise<MockResponse> => {
    const denied = gate.check(req);
    if (denied) return denied;
    const soap = mimeUnwrap(req.body, fakeNtlmUnwrap);
    const reply = await answer(soap);
    const wrapped = mimeWrap(typeof reply === 'string' ? reply : reply.fault, fakeNtlmWrap);
    return { status: typeof reply === 'string' ? 200 : 500, headers: { 'Content-Type': wrapped.contentType }, body: wrapped.body };
  };
  const server = await startMockServer(handler, { recordBodies: false });
  state.port = server.port;
  state.close = () => server.close();
  return state;
}
