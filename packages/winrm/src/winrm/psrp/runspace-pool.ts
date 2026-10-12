// A PSRP runspace pool and its pipelines over the WinRM transport
// (MS-PSRP 3.1.4.1, 3.1.4.3, 3.1.4.4). One runspace
// (Min = Max = 1), one socket, one request at a time; the pool owns its
// transport, so it never queues behind WinRS commands. Not yet: a host,
// key exchange, disconnect.
import { v4 as uuidv4 } from 'uuid';
import type { WinRMConnectOptions } from '../index.js';
import { WinRMTransport } from '../transport.js';
import {
  MAX_ENVELOPE_SIZE,
  SEND_ENVELOPE_OVERHEAD,
  buildDeleteShellRequest,
  buildPsrpCommandRequest,
  buildPsrpCreateRequest,
  buildPsrpReceiveRequest,
  buildPsrpSendRequest,
  buildPsrpSignalRequest,
  psrpResourceUri,
} from '../envelopes.js';
import { parseCommandResponse, parseCreateShellResponse, parsePsrpReceiveResponse } from '../parse.js';
import { PSRemotingError, WinRMError, WinRMFaultError } from '../errors.js';
import { Destination, EMPTY_GUID, MessageType, encodeMessage, messageTypeName, type PsrpMessage } from './messages.js';
import { Defragmenter, encodeFragments } from './fragments.js';
import { deserializeClixml, isPSObject, toErrorRecord, toInformationRecord, toInformationalMessage, toProgressRecord, type PSErrorRecord, type PSInformationRecord, type PSProgressRecord, type PSValue } from './clixml.js';
import {
  PROTOCOL_VERSION,
  PSInvocationStateValue,
  RunspacePoolStateValue,
  compareVersions,
  createPipelineBody,
  initRunspacePoolBody,
  pipelineInputBody,
  readPipelineState,
  readRunspacePoolState,
  readSessionCapability,
  sessionCapabilityBody,
  type PSCommand,
} from './bodies.js';

export type { PSCommand } from './bodies.js';

// The oldest server version accepted: 2.2 is PowerShell
// 3.0, the floor for Disconnect and Connect.
export const MIN_SERVER_PROTOCOL_VERSION = '2.2';
const OPERATION_TIMEOUT_CODE = 2150858793;
const REQUEST_TIMEOUT_MARGIN_MS = 30_000;
const DEFAULT_OPERATION_TIMEOUT_MS = 60_000;

export interface PSConnectOptions extends WinRMConnectOptions {
  // The session configuration the pool runs in; default Microsoft.PowerShell.
  configurationName?: string;
  // Aborts the open (Create and the Receives until Opened).
  signal?: AbortSignal;
  // Every SOAP request and response (decrypted) and every PSRP message
  // in and out, for the fixture recorder of the test runners. The
  // library never writes these anywhere itself.
  trace?: (event: PsrpTraceEvent) => void;
}

export type PsrpTraceEvent =
  | { kind: 'request'; soap: string }
  | { kind: 'response'; soap: string }
  | { kind: 'fault'; error: unknown }
  | { kind: 'message'; direction: 'out' | 'in'; message: PsrpMessage };

export type RunspacePoolState = 'Opening' | 'Opened' | 'Closing' | 'Closed' | 'Broken';

export interface InvokeOptions {
  // Values for the pipeline's input, one PIPELINE_INPUT each, then
  // END_OF_PIPELINE_INPUT. Without it the pipeline runs with NoInput.
  input?: AsyncIterable<PSValue> | Iterable<PSValue>;
  // Appends `Out-String -Stream -Width n`, so the server formats the
  // output and every output value is a string.
  outString?: { width: number };
  addToHistory?: boolean;
  // An abort stops the pipeline (Signal); the pool stays open.
  signal?: AbortSignal;
}

export type PSStreamEvent =
  | { stream: 'output'; value: PSValue }
  | { stream: 'error'; record: PSErrorRecord }
  | { stream: 'warning' | 'verbose' | 'debug'; message: string }
  | { stream: 'information'; record: PSInformationRecord }
  | { stream: 'progress'; record: PSProgressRecord };

export type PSInvocationState = 'Running' | 'Completed' | 'Failed' | 'Stopped';

export interface PSInvocationResult {
  state: Exclude<PSInvocationState, 'Running'>;
  output: PSValue[];
  errors: PSErrorRecord[];
  // The ExceptionAsErrorRecord of a Failed pipeline (2.2.2.21), or the
  // client-side reason (a fault, a protocol error).
  reason?: PSErrorRecord | Error;
}

export interface PSPipeline extends AsyncIterable<PSStreamEvent> {
  readonly id: string;
  readonly state: PSInvocationState;
  // Sends Signal; resolves once the pipeline reports Stopped (or ended
  // on its own first). The pool stays Opened.
  stop(): Promise<void>;
  // Waits for the end and returns everything, whether or not the events
  // were iterated.
  result(): Promise<PSInvocationResult>;
}

export interface RunspacePool {
  readonly shellId: string;
  readonly serverProtocolVersion: string;
  readonly state: RunspacePoolState;
  // The server's APPLICATION_PRIVATE_DATA (2.2.2.13), kept as sent.
  readonly applicationPrivateData: PSValue | null;
  invoke(script: string, opts?: InvokeOptions): PSPipeline;
  invokeCommand(commands: PSCommand[], opts?: InvokeOptions): PSPipeline;
  // Stops running pipelines and deletes the shell. Idempotent.
  close(): Promise<void>;
}

export async function openRunspacePool(opts: PSConnectOptions): Promise<RunspacePool> {
  const pool = new RunspacePoolImpl(opts);
  await pool.open(opts.signal);
  return pool;
}

// --- helpers ---

// A queue of events for one consumer: push() from the receive loop,
// next() from the async iterator; end() finishes it.
class EventQueue<T> {
  private readonly items: T[] = [];
  private waiter: (() => void) | null = null;
  private ended = false;

  push(item: T): void {
    this.items.push(item);
    this.wake();
  }

  end(): void {
    this.ended = true;
    this.wake();
  }

  private wake(): void {
    const w = this.waiter;
    this.waiter = null;
    w?.();
  }

  async next(): Promise<IteratorResult<T>> {
    for (;;) {
      const item = this.items.shift();
      if (item !== undefined) return { value: item, done: false };
      if (this.ended) return { value: undefined, done: true };
      await new Promise<void>((resolve) => (this.waiter = resolve));
    }
  }
}

function isAbort(err: unknown): boolean {
  return err instanceof Error && err.name === 'AbortError';
}

function isOperationTimeout(err: unknown): boolean {
  return err instanceof WinRMFaultError && err.wsmanCode === OPERATION_TIMEOUT_CODE;
}

// Whole fragments packed into Sends that stay under MaxEnvelopeSize after base64.
function packSends(fragments: Buffer[]): Buffer[] {
  const limit = Math.floor((MAX_ENVELOPE_SIZE - SEND_ENVELOPE_OVERHEAD) / 4) * 3;
  const out: Buffer[] = [];
  let current: Buffer[] = [];
  let size = 0;
  for (const fragment of fragments) {
    if (size > 0 && size + fragment.length > limit) {
      out.push(Buffer.concat(current));
      current = [];
      size = 0;
    }
    current.push(fragment);
    size += fragment.length;
  }
  if (current.length > 0) out.push(Buffer.concat(current));
  return out;
}

const firstValue = (data: string): PSValue => (data.length === 0 ? null : (deserializeClixml(data)[0] ?? null));
const asObject = (data: string) => {
  const value = firstValue(data);
  return isPSObject(value) ? value : null;
};

// --- the pool ---

class RunspacePoolImpl implements RunspacePool {
  readonly rpid = uuidv4();
  shellId = '';
  serverProtocolVersion = '';
  state: RunspacePoolState = 'Opening';
  applicationPrivateData: PSValue | null = null;
  readonly transport: WinRMTransport;
  readonly to: string;
  readonly operationTimeout: string;
  readonly resourceUri: string;
  private nextObjectId = 1n;
  private readonly poolFragments = new Defragmenter();
  private readonly pipelines = new Map<string, PipelineImpl>();
  private closing: Promise<void> | null = null;
  private readonly trace: ((event: PsrpTraceEvent) => void) | undefined;

  constructor(opts: PSConnectOptions) {
    this.trace = opts.trace;
    if (!opts.host) throw new WinRMError('PSRP connect needs a host');
    const tls = opts.tls ?? false;
    const port = opts.port ?? (tls ? 5986 : 5985);
    const path = opts.path ?? '/wsman';
    this.to = `${tls ? 'https' : 'http'}://${opts.host}:${port}${path}`;
    const operationTimeoutMs = opts.operationTimeoutMs ?? DEFAULT_OPERATION_TIMEOUT_MS;
    this.operationTimeout = `PT${Math.max(1, Math.ceil(operationTimeoutMs / 1000))}S`;
    this.resourceUri = psrpResourceUri(opts.configurationName);
    this.transport = new WinRMTransport({
      host: opts.host,
      port,
      path,
      tls,
      tlsVerify: opts.tlsVerify ?? true,
      authProvider: opts.authProvider,
      credentials: opts.credentials,
      ...(opts.clientCertificate ? { clientCertificate: opts.clientCertificate } : {}),
      encryption: opts.encryption ?? 'auto',
      requestTimeoutMs: operationTimeoutMs + REQUEST_TIMEOUT_MARGIN_MS,
      ...(opts.connectTimeoutMs !== undefined ? { connectTimeoutMs: opts.connectTimeoutMs } : {}),
      ...(opts.credsspAllowHttp !== undefined ? { credsspAllowHttp: opts.credsspAllowHttp } : {}),
      ...(opts.onCredSSPDelegation ? { onCredSSPDelegation: opts.onCredSSPDelegation } : {}),
    });
  }

  base() {
    return { to: this.to, messageId: uuidv4(), operationTimeout: this.operationTimeout, resourceUri: this.resourceUri, shellId: this.shellId };
  }

  objectId(): bigint {
    return this.nextObjectId++;
  }

  // One request through the transport, traced.
  async post(soap: string, signal?: AbortSignal): Promise<string> {
    this.trace?.({ kind: 'request', soap });
    try {
      const xml = await this.transport.post(soap, signal);
      this.trace?.({ kind: 'response', soap: xml });
      return xml;
    } catch (err) {
      this.trace?.({ kind: 'fault', error: err });
      throw err;
    }
  }

  // The fragments of one message to the server.
  fragments(messageType: number, pid: string, data: string): Buffer[] {
    const message = { destination: Destination.server, messageType, rpid: this.rpid, pid, data };
    this.trace?.({ kind: 'message', direction: 'out', message });
    return encodeFragments(this.objectId(), encodeMessage(message));
  }

  private traceIn(messages: PsrpMessage[]): PsrpMessage[] {
    if (this.trace) for (const message of messages) this.trace({ kind: 'message', direction: 'in', message });
    return messages;
  }

  async open(signal?: AbortSignal): Promise<void> {
    const creationXml = Buffer.concat([...this.fragments(MessageType.SESSION_CAPABILITY, EMPTY_GUID, sessionCapabilityBody()), ...this.fragments(MessageType.INIT_RUNSPACEPOOL, EMPTY_GUID, initRunspacePoolBody())]);
    try {
      const xml = await this.post(
        buildPsrpCreateRequest({ ...this.base(), shellId: this.rpid.toUpperCase(), protocolVersion: PROTOCOL_VERSION, creationXml }),
        signal,
      );
      this.shellId = parseCreateShellResponse(xml);
      while (this.state === 'Opening') {
        for (const message of await this.receive(undefined, signal)) this.handlePoolMessage(message);
      }
    } catch (err) {
      await this.abandon();
      throw err;
    }
  }

  // Closes everything after a failed open or a broken pool, keeping the error.
  private async abandon(): Promise<void> {
    if (this.state !== 'Broken') this.state = 'Broken';
    if (this.shellId) await this.post(buildDeleteShellRequest(this.base())).catch(() => undefined);
    await this.transport.close().catch(() => undefined);
  }

  // One Receive on the pool (no CommandId) or a pipeline, with the
  // operation-timeout retry WinRS uses too. Streams for the pool are
  // handled here; the pipeline's messages are returned to it.
  async receive(pipeline: PipelineImpl | undefined, signal?: AbortSignal): Promise<PsrpMessage[]> {
    for (;;) {
      let xml: string;
      try {
        xml = await this.post(buildPsrpReceiveRequest({ ...this.base(), ...(pipeline ? { commandId: pipeline.commandId } : {}) }), signal);
      } catch (err) {
        if (isOperationTimeout(err)) continue;
        throw err;
      }
      const poll = parsePsrpReceiveResponse(xml);
      const out: PsrpMessage[] = [];
      for (const stream of poll.streams) {
        if (stream.commandId === undefined) {
          for (const message of this.traceIn(this.poolFragments.push(stream.data))) {
            if (pipeline) this.handlePoolMessage(message);
            else out.push(message);
          }
        } else {
          const target = this.pipelines.get(stream.commandId.toLowerCase());
          if (!target) continue; // a pipeline that is gone
          out.push(...this.traceIn(target.fragments.push(stream.data)));
        }
      }
      if (pipeline && poll.done) pipeline.serverDone = true;
      if (out.length > 0 || (pipeline && poll.done)) return out;
      if (!pipeline && this.state !== 'Opening') return out;
    }
  }

  handlePoolMessage(message: PsrpMessage): void {
    switch (message.messageType) {
      case MessageType.SESSION_CAPABILITY: {
        const { protocolVersion } = readSessionCapability(firstValue(message.data));
        this.serverProtocolVersion = protocolVersion;
        if (compareVersions(protocolVersion || '0', MIN_SERVER_PROTOCOL_VERSION) < 0) {
          throw new PSRemotingError(`the server speaks PSRP ${protocolVersion || '(unknown)'}; winlinux needs ${MIN_SERVER_PROTOCOL_VERSION} or newer (PowerShell 3.0+)`);
        }
        return;
      }
      case MessageType.APPLICATION_PRIVATE_DATA:
        this.applicationPrivateData = firstValue(message.data);
        return;
      case MessageType.RUNSPACEPOOL_STATE: {
        const { state, error } = readRunspacePoolState(firstValue(message.data));
        if (state === RunspacePoolStateValue.Opened) this.state = 'Opened';
        else if (state === RunspacePoolStateValue.Closed) this.state = 'Closed';
        else if (state === RunspacePoolStateValue.Broken) {
          this.state = 'Broken';
          throw new PSRemotingError(`the runspace pool is broken${error ? `: ${error.message}` : ''}`);
        }
        return;
      }
      case MessageType.RUNSPACEPOOL_HOST_CALL:
        // No host was offered (HostInfo _isHostNull), so the server has
        // nothing to ask. A later release answers these.
        throw new PSRemotingError('the server made a runspace pool host call, which winlinux does not answer yet (no host)');
      default:
        // USER_EVENT, RUNSPACE_AVAILABILITY, PUBLIC_KEY_REQUEST: nothing to do yet.
        return;
    }
  }

  // A fault on a pool-level message (MS-PSRP 3.1.5.3.13): the pool is
  // Broken and the shell is deleted.
  async poolFault(err: unknown): Promise<never> {
    await this.abandon();
    throw err;
  }

  invoke(script: string, opts: InvokeOptions = {}): PSPipeline {
    return this.invokeCommand([{ name: script, isScript: true }], opts);
  }

  invokeCommand(commands: PSCommand[], opts: InvokeOptions = {}): PSPipeline {
    if (this.state !== 'Opened') throw new PSRemotingError(`the runspace pool is ${this.state}; it must be Opened to run a pipeline`);
    if (commands.length === 0) throw new RangeError('a pipeline needs at least one command');
    const all = opts.outString ? [...commands, { name: 'Out-String', parameters: [{ name: 'Stream', value: true }, { name: 'Width', value: opts.outString.width }] }] : commands;
    const pipeline = new PipelineImpl(this, all, opts);
    this.pipelines.set(pipeline.id, pipeline);
    pipeline.start();
    return pipeline;
  }

  forget(pipeline: PipelineImpl): void {
    this.pipelines.delete(pipeline.id);
  }

  close(): Promise<void> {
    this.closing ??= this.doClose();
    return this.closing;
  }

  private async doClose(): Promise<void> {
    if (this.state === 'Closed') return;
    const open = this.state === 'Opened';
    this.state = 'Closing';
    for (const pipeline of [...this.pipelines.values()]) await pipeline.stop().catch(() => undefined);
    if (open && this.shellId) await this.post(buildDeleteShellRequest(this.base())).catch(() => undefined);
    await this.transport.close().catch(() => undefined);
    this.state = 'Closed';
  }
}

// --- a pipeline ---

class PipelineImpl implements PSPipeline {
  readonly id = uuidv4();
  readonly commandId = this.id.toUpperCase();
  readonly fragments = new Defragmenter();
  state: PSInvocationState = 'Running';
  serverDone = false;
  private readonly events = new EventQueue<PSStreamEvent>();
  private readonly output: PSValue[] = [];
  private readonly errors: PSErrorRecord[] = [];
  private reason: PSErrorRecord | Error | undefined;
  private stopRequested = false;
  private signalSent = false;
  // True once the server accepted the Command: only then is there a
  // pipeline to Signal.
  private commandAccepted = false;
  private receiveAbort: AbortController | null = null;
  private commandSent!: Promise<void>;
  private resolveCommandSent!: () => void;
  private finished!: Promise<void>;
  private resolveFinished!: () => void;
  private failure: Error | null = null;

  constructor(
    private readonly pool: RunspacePoolImpl,
    private readonly commands: PSCommand[],
    private readonly opts: InvokeOptions,
  ) {
    this.commandSent = new Promise<void>((resolve) => (this.resolveCommandSent = resolve));
    this.finished = new Promise<void>((resolve) => (this.resolveFinished = resolve));
  }

  start(): void {
    this.opts.signal?.addEventListener('abort', () => void this.stop().catch(() => undefined), { once: true });
    void this.run();
  }

  private async run(): Promise<void> {
    try {
      await this.sendCreatePipeline();
      if (this.opts.input) await this.sendInput(this.opts.input);
      if (this.stopRequested) await this.sendSignal();
      await this.receiveUntilFinal();
    } catch (err) {
      // A fault on a pipeline message (3.1.5.3.13) or any other failure:
      // the pipeline is Failed and Signal goes out, once there is a
      // pipeline on the server to signal.
      this.finish('Failed', err instanceof Error ? err : new Error(String(err)));
      if (this.commandAccepted) await this.sendSignal().catch(() => undefined);
    } finally {
      this.resolveCommandSent();
      this.pool.forget(this);
      this.events.end();
      this.resolveFinished();
    }
  }

  private base() {
    return this.pool.base();
  }

  private async sendCreatePipeline(): Promise<void> {
    const fragments = this.pool.fragments(MessageType.CREATE_PIPELINE, this.id, createPipelineBody(this.commands, { noInput: this.opts.input === undefined, ...(this.opts.addToHistory !== undefined ? { addToHistory: this.opts.addToHistory } : {}) }));
    const [first, ...rest] = fragments as [Buffer, ...Buffer[]];
    const xml = await this.pool.post(buildPsrpCommandRequest({ ...this.base(), commandId: this.commandId, arguments: first }));
    const echoed = parseCommandResponse(xml);
    if (echoed.toLowerCase() !== this.commandId.toLowerCase()) {
      throw new PSRemotingError(`the server answered the pipeline ${this.commandId} with CommandId ${echoed}`);
    }
    this.commandAccepted = true;
    this.resolveCommandSent();
    for (const data of packSends(rest)) await this.send('stdin', data);
  }

  private async send(stream: 'stdin' | 'pr', data: Buffer): Promise<void> {
    await this.pool.post(buildPsrpSendRequest({ ...this.base(), stream, commandId: this.commandId, data }));
  }

  private async sendInput(input: AsyncIterable<PSValue> | Iterable<PSValue>): Promise<void> {
    for await (const value of input) {
      if (this.stopRequested || this.state !== 'Running') return;
      // One Send outstanding at a time (3.1.5.3.5): the next value is read
      // only after this one was acknowledged.
      for (const data of packSends(this.pool.fragments(MessageType.PIPELINE_INPUT, this.id, pipelineInputBody(value)))) await this.send('stdin', data);
    }
    for (const data of packSends(this.pool.fragments(MessageType.END_OF_PIPELINE_INPUT, this.id, ''))) await this.send('stdin', data);
  }

  private async sendSignal(): Promise<void> {
    if (this.signalSent) return;
    this.signalSent = true;
    await this.pool.post(buildPsrpSignalRequest({ ...this.base(), commandId: this.commandId }));
  }

  private async receiveUntilFinal(): Promise<void> {
    while (this.state === 'Running') {
      // A stop asked for between requests (a host call, stop() while input
      // was going out): Signal first, then read on until Stopped.
      if (this.stopRequested) await this.sendSignal();
      this.receiveAbort = new AbortController();
      let messages: PsrpMessage[];
      try {
        messages = await this.pool.receive(this, this.receiveAbort.signal);
      } catch (err) {
        if (isAbort(err) && this.stopRequested) {
          // Ctrl+C: the in-flight Receive was cut (its socket is gone; the
          // next request re-authenticates), now Signal, then read on until
          // the server reports Stopped.
          await this.sendSignal();
          continue;
        }
        throw err;
      } finally {
        this.receiveAbort = null;
      }
      for (const message of messages) this.handle(message);
      if (this.state === 'Running' && this.serverDone) {
        // CommandState Done without a final PIPELINE_STATE: the server
        // closed the command, so nothing more will come. After a stop the
        // Stopped state went out on the Receive the stop cut, so the
        // pipeline is Stopped; otherwise it ran to its end.
        this.finish(this.stopRequested ? 'Stopped' : 'Completed');
      }
    }
  }

  private handle(message: PsrpMessage): void {
    if (this.state !== 'Running') return;
    switch (message.messageType) {
      case MessageType.PIPELINE_OUTPUT: {
        const value = firstValue(message.data);
        this.output.push(value);
        this.events.push({ stream: 'output', value });
        return;
      }
      case MessageType.ERROR_RECORD: {
        const obj = asObject(message.data);
        if (!obj) return;
        const record = toErrorRecord(obj);
        this.errors.push(record);
        this.events.push({ stream: 'error', record });
        return;
      }
      case MessageType.WARNING_RECORD:
      case MessageType.VERBOSE_RECORD:
      case MessageType.DEBUG_RECORD: {
        const obj = asObject(message.data);
        const stream = message.messageType === MessageType.WARNING_RECORD ? 'warning' : message.messageType === MessageType.VERBOSE_RECORD ? 'verbose' : 'debug';
        this.events.push({ stream, message: obj ? toInformationalMessage(obj) : '' });
        return;
      }
      case MessageType.INFORMATION_RECORD: {
        const obj = asObject(message.data);
        if (obj) this.events.push({ stream: 'information', record: toInformationRecord(obj) });
        return;
      }
      case MessageType.PROGRESS_RECORD: {
        const obj = asObject(message.data);
        if (obj) this.events.push({ stream: 'progress', record: toProgressRecord(obj) });
        return;
      }
      case MessageType.PIPELINE_STATE: {
        const { state, error } = readPipelineState(firstValue(message.data));
        if (state === PSInvocationStateValue.Completed) this.finish('Completed');
        else if (state === PSInvocationStateValue.Failed) this.finish('Failed', error);
        else if (state === PSInvocationStateValue.Stopped) this.finish('Stopped', error);
        return;
      }
      case MessageType.PIPELINE_HOST_CALL:
        // No host was offered, so a call cannot be answered: the pipeline
        // is stopped with a clear reason (no host calls are answered yet).
        this.failure = new PSRemotingError('the server made a pipeline host call, which winlinux does not answer yet (no host)');
        this.requestStop();
        return;
      default:
        // Any other message for the pipeline means stop it (MS-PSRP 3.1.4.3 step 3).
        this.failure = new PSRemotingError(`unexpected PSRP message ${messageTypeName(message.messageType)} for the pipeline`);
        this.requestStop();
    }
  }

  private finish(state: Exclude<PSInvocationState, 'Running'>, reason?: PSErrorRecord | Error): void {
    if (this.state !== 'Running') return;
    this.state = state;
    const why = reason ?? this.failure ?? undefined;
    if (why !== undefined) this.reason = why;
    if (this.failure && state === 'Stopped') this.state = 'Failed';
  }

  private requestStop(): void {
    if (this.stopRequested) return;
    this.stopRequested = true;
    this.receiveAbort?.abort();
  }

  async stop(): Promise<void> {
    if (this.state !== 'Running') return;
    this.requestStop();
    await this.commandSent;
    if (this.state !== 'Running') return;
    // When no Receive is in flight (input is being sent, or the loop is
    // between requests), the run loop sends Signal before its next Receive.
    await this.finished;
  }

  async result(): Promise<PSInvocationResult> {
    await this.finished;
    const state = this.state as Exclude<PSInvocationState, 'Running'>;
    return { state, output: [...this.output], errors: [...this.errors], ...(this.reason !== undefined ? { reason: this.reason } : {}) };
  }

  [Symbol.asyncIterator](): AsyncIterator<PSStreamEvent> {
    return { next: () => this.events.next() };
  }
}
