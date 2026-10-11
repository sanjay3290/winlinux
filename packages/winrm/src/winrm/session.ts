import { StringDecoder } from 'node:string_decoder';
import { v4 as uuidv4 } from 'uuid';
import type { WinRMConnectOptions, WinRMSession, CommandResult, OutputChunk, InputCommandChunk, InputCommandOptions } from './index.js';
import { WinRMTransport } from './transport.js';
import {
  buildCommandRequest,
  buildCreateShellRequest,
  buildDeleteShellRequest,
  buildReceiveRequest,
  buildSendRequest,
  buildSignalRequest,
  SEND_CHUNK_BYTES,
} from './envelopes.js';
import { ReceiveAccumulator, parseCommandResponse, parseCreateShellResponse, parseReceiveResponse } from './parse.js';
import { WinRMAbortError, WinRMError, WinRMFaultError } from './errors.js';
import { buildEventLogScript, buildProcessesScript, buildServicesScript } from './powershell.js';
import { mapEventRecords, mapProcesses, mapServices, stripCliXml } from './mapping.js';
import { powerShellArgs, quoteCmdArg } from './cmdline.js';
import type { EventLogQuery, EventRecord, ProcessInfo, ServiceInfo } from './index.js';

// WSMan Receive operation-timeout fault: the poll waited out with no new
// output. Expected for long commands; the loop retries (as pywinrm does).
const OPERATION_TIMEOUT_CODE = 2150858793;
// Time on top of the OperationTimeout for the server to answer a Receive.
const REQUEST_TIMEOUT_MARGIN_MS = 30_000;
// After an abort, how long a command with stdin may take to see its stdin
// close and exit by itself, before Signal terminate.
const DEFAULT_ABORT_GRACE_MS = 2000;
// PowerShell stderr is kept for the CLIXML strip; more than this is cut.
const MAX_STDERR_BYTES = 64 * 1024;

type FeedResult =
  | { kind: 'done' }
  | { kind: 'aborted' }
  | { kind: 'failed'; error: WinRMFaultError } // a Send faulted
  | { kind: 'inputFailed'; error: unknown }; // reading the input threw

function throwIfAborted(signal: AbortSignal | undefined): void {
  if (signal?.aborted) throw new WinRMAbortError('WinRM command was aborted', { cause: signal.reason });
}

function toOperationTimeout(ms: number): string {
  return `PT${Math.max(1, Math.ceil(ms / 1000))}S`;
}

// One session per server connection. Every command opens its own shell and
// deletes it in a finally block; close() cleans up stragglers and the agent.
// The final iterator result of runCommandStream.
interface StreamEnd {
  exitCode: number | null;
}

export class WinRMSessionImpl implements WinRMSession {
  private readonly transport: WinRMTransport;
  private readonly to: string;
  private readonly operationTimeout: string;
  private readonly openShells = new Set<string>();
  private closed = false;

  constructor(private readonly opts: WinRMConnectOptions) {
    if (!opts.host) throw new WinRMError('WinRM connect needs a host');
    const tls = opts.tls ?? false;
    const port = opts.port ?? (tls ? 5986 : 5985);
    const path = opts.path ?? '/wsman';
    this.to = `${tls ? 'https' : 'http'}://${opts.host}:${port}${path}`;
    const operationTimeoutMs = opts.operationTimeoutMs ?? 60000;
    this.operationTimeout = toOperationTimeout(operationTimeoutMs);
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
      // A Receive can wait the whole OperationTimeout before it answers.
      requestTimeoutMs: operationTimeoutMs + REQUEST_TIMEOUT_MARGIN_MS,
      ...(opts.connectTimeoutMs !== undefined ? { connectTimeoutMs: opts.connectTimeoutMs } : {}),
      ...(opts.credsspAllowHttp !== undefined ? { credsspAllowHttp: opts.credsspAllowHttp } : {}),
      ...(opts.onCredSSPDelegation ? { onCredSSPDelegation: opts.onCredSSPDelegation } : {}),
    });
  }

  private base() {
    return { to: this.to, messageId: uuidv4(), operationTimeout: this.operationTimeout };
  }

  private async createShell(cwd?: string): Promise<string> {
    const xml = await this.transport.post(buildCreateShellRequest({ ...this.base(), workingDirectory: cwd }));
    const shellId = parseCreateShellResponse(xml);
    this.openShells.add(shellId);
    return shellId;
  }

  private deleteShell(shellId: string): Promise<void> {
    this.openShells.delete(shellId);
    return this.transport
      .post(buildDeleteShellRequest({ ...this.base(), shellId }))
      .then(() => undefined);
  }

  private async collect(shellId: string, commandId: string, signal?: AbortSignal): Promise<CommandResult> {
    const acc = new ReceiveAccumulator();
    for (;;) {
      const poll = await this.poll(shellId, commandId, signal);
      acc.push(poll);
      if (poll.done) return acc.result();
    }
  }

  // Only Receive takes the signal: it is the request that waits. Create
  // and Command answer at once, and cutting them could orphan a shell.
  private async poll(shellId: string, commandId: string, signal?: AbortSignal) {
    for (;;) {
      throwIfAborted(signal);
      try {
        const xml = await this.transport.post(buildReceiveRequest({ ...this.base(), shellId, commandId }), signal);
        return parseReceiveResponse(xml);
      } catch (err) {
        throwIfAborted(signal);
        if (err instanceof WinRMFaultError && err.wsmanCode === OPERATION_TIMEOUT_CODE) continue;
        throw err;
      }
    }
  }

  // The command line crosses cmd.exe and then the program's own argv
  // split: every word is quoted for both, see cmdline.ts.
  private commandRequest(shellId: string, cmd: string, args: string[], consoleModeStdin = true): string {
    return buildCommandRequest({
      ...this.base(),
      shellId,
      command: quoteCmdArg(cmd),
      args: args.map(quoteCmdArg),
      ...(consoleModeStdin ? {} : { consoleModeStdin: false }),
    });
  }

  private async send(shellId: string, commandId: string, data: Buffer, end: boolean): Promise<void> {
    await this.transport.post(buildSendRequest({ ...this.base(), shellId, commandId, data, end }));
  }

  // Feeds `input` to the command's stdin, one Send at a time. The next
  // input chunk is read only after the server acknowledged the last Send
  // (back-pressure). Every Send but the last carries exactly
  // SEND_CHUNK_BYTES; the last one has End="true". A fault on a Send (the
  // command has exited, for example) stops the feed; Receive then reports
  // what the command printed and its exit code. An error from `input`
  // (a local read error) is returned, not thrown, so the caller can close
  // stdin before it rethrows.
  private async feed(shellId: string, commandId: string, input: AsyncIterable<Buffer>, signal?: AbortSignal): Promise<FeedResult> {
    const iterator = input[Symbol.asyncIterator]();
    let pending: Buffer[] = [];
    let pendingBytes = 0;
    const take = (n: number): Buffer => {
      const all = pending.length === 1 ? (pending[0] as Buffer) : Buffer.concat(pending, pendingBytes);
      const head = all.subarray(0, n);
      const rest = all.subarray(n);
      pending = rest.length > 0 ? [rest] : [];
      pendingBytes = rest.length;
      return head;
    };
    let finished = false;
    try {
      for (;;) {
        if (signal?.aborted) return { kind: 'aborted' };
        let next: IteratorResult<Buffer>;
        try {
          next = await iterator.next();
        } catch (error) {
          finished = true;
          return { kind: 'inputFailed', error };
        }
        if (next.done) {
          finished = true;
          break;
        }
        const chunk = Buffer.isBuffer(next.value) ? next.value : Buffer.from(next.value as Uint8Array);
        if (chunk.length === 0) continue;
        pending.push(chunk);
        pendingBytes += chunk.length;
        // Strictly more than one chunk: the bytes after it prove this Send
        // is not the last one.
        while (pendingBytes > SEND_CHUNK_BYTES) {
          if (signal?.aborted) return { kind: 'aborted' };
          await this.send(shellId, commandId, take(SEND_CHUNK_BYTES), false);
        }
      }
      if (signal?.aborted) return { kind: 'aborted' };
      await this.send(shellId, commandId, take(pendingBytes), true);
      return { kind: 'done' };
    } catch (err) {
      if (err instanceof WinRMFaultError) return { kind: 'failed', error: err };
      throw err;
    } finally {
      if (!finished) await iterator.return?.(undefined);
    }
  }

  // After an abort: close stdin, so a script that reads it can clean up
  // and exit by itself, and wait up to graceMs for that. Errors are
  // ignored; Signal terminate follows in the caller's finally block.
  private async closeStdinAndWait(shellId: string, commandId: string, graceMs: number): Promise<void> {
    try {
      await this.send(shellId, commandId, Buffer.alloc(0), true);
      const deadline = AbortSignal.timeout(graceMs);
      for (;;) {
        const poll = await this.poll(shellId, commandId, deadline);
        if (poll.done) return;
      }
    } catch {
      // The command may already be gone, or the grace time ran out.
    }
  }

  private async runInShell(shellId: string, cmd: string, args: string[], signal?: AbortSignal): Promise<CommandResult> {
    const commandId = parseCommandResponse(await this.transport.post(this.commandRequest(shellId, cmd, args)));
    try {
      return await this.collect(shellId, commandId, signal);
    } finally {
      await this.transport.post(buildSignalRequest({ ...this.base(), shellId, commandId })).catch(() => undefined);
    }
  }

  async runCommand(cmd: string, args: string[] = [], opts?: { cwd?: string; signal?: AbortSignal }): Promise<CommandResult> {
    this.throwIfClosed();
    throwIfAborted(opts?.signal);
    const shellId = await this.createShell(opts?.cwd);
    try {
      return await this.runInShell(shellId, cmd, args, opts?.signal);
    } finally {
      await this.deleteShell(shellId).catch(() => undefined);
    }
  }

  // -EncodedCommand: the script travels as base64 UTF-16LE, so its
  // pipes, quotes and non-ASCII text never reach cmd.exe. The structured
  // queries below go through here too.
  async runPowerShell(script: string): Promise<CommandResult> {
    const result = await this.runCommand('powershell.exe', powerShellArgs(script));
    return { ...result, stderr: stripCliXml(result.stderr) };
  }

  async *runCommandStream(cmd: string, args: string[] = [], opts?: { cwd?: string; signal?: AbortSignal }): AsyncIterable<OutputChunk> {
    this.throwIfClosed();
    throwIfAborted(opts?.signal);
    const shellId = await this.createShell(opts?.cwd);
    try {
      const commandId = parseCommandResponse(await this.transport.post(this.commandRequest(shellId, cmd, args)));
      // One decoder per stream: a UTF-8 character split across two
      // Receives comes out whole.
      const out = new StringDecoder('utf8');
      const err = new StringDecoder('utf8');
      try {
        for (;;) {
          const poll = await this.poll(shellId, commandId, opts?.signal);
          const stdout = out.write(poll.stdout) + (poll.done ? out.end() : '');
          const stderr = err.write(poll.stderr) + (poll.done ? err.end() : '');
          if (stdout.length > 0) yield { stream: 'stdout', data: stdout };
          if (stderr.length > 0) yield { stream: 'stderr', data: stderr };
          // The iterator's final result carries the exit code: a
          // caller that drives next() itself reads { exitCode } from the
          // `done` result; for await ignores it. null: the server sent none.
          if (poll.done) return { exitCode: poll.exitCode } satisfies StreamEnd;
        }
      } finally {
        await this.transport.post(buildSignalRequest({ ...this.base(), shellId, commandId })).catch(() => undefined);
      }
    } finally {
      await this.deleteShell(shellId).catch(() => undefined);
    }
  }

  runPowerShellStream(script: string): AsyncIterable<OutputChunk> {
    return this.runCommandStream('powershell.exe', powerShellArgs(script));
  }

  // Runs a command whose stdin is `input`. Sends come first, one at
  // a time, then Receive collects the output. The transport carries one
  // request at a time (one SecurityContext, ordered sequence numbers), and
  // a Receive on a command that prints nothing blocks for the whole
  // OperationTimeout, so Send and Receive do not interleave.
  async *runCommandWithInput(
    cmd: string,
    args: string[],
    input: AsyncIterable<Buffer>,
    opts?: InputCommandOptions,
  ): AsyncIterable<InputCommandChunk> {
    this.throwIfClosed();
    const signal = opts?.signal;
    throwIfAborted(signal);
    const shellId = await this.createShell(opts?.cwd);
    try {
      const commandId = parseCommandResponse(await this.transport.post(this.commandRequest(shellId, cmd, args, false)));
      try {
        const fed = await this.feed(shellId, commandId, input, signal);
        if (fed.kind === 'aborted' || fed.kind === 'inputFailed') {
          await this.closeStdinAndWait(shellId, commandId, opts?.abortGraceMs ?? DEFAULT_ABORT_GRACE_MS);
          if (fed.kind === 'inputFailed') throw fed.error;
          throw new WinRMAbortError('WinRM command was aborted', { cause: signal?.reason });
        }
        for (;;) {
          const poll = await this.poll(shellId, commandId, signal);
          if (poll.stdout.length > 0) yield { stream: 'stdout', data: poll.stdout.toString('utf8') };
          if (poll.stderr.length > 0) yield { stream: 'stderr', data: poll.stderr.toString('utf8') };
          if (poll.done) {
            yield { stream: 'exit', exitCode: poll.exitCode ?? -1, inputComplete: fed.kind === 'done' };
            return;
          }
        }
      } finally {
        await this.transport.post(buildSignalRequest({ ...this.base(), shellId, commandId })).catch(() => undefined);
      }
    } finally {
      await this.deleteShell(shellId).catch(() => undefined);
    }
  }

  // The PowerShell form: stderr is held back and comes out once, CLIXML
  // stripped, just before the exit chunk.
  async *runPowerShellWithInput(script: string, input: AsyncIterable<Buffer>, opts?: InputCommandOptions): AsyncIterable<InputCommandChunk> {
    let stderr = '';
    for await (const chunk of this.runCommandWithInput('powershell.exe', powerShellArgs(script), input, opts)) {
      if (chunk.stream === 'stderr') {
        if (stderr.length < MAX_STDERR_BYTES) stderr += chunk.data.slice(0, MAX_STDERR_BYTES - stderr.length);
        continue;
      }
      if (chunk.stream === 'exit' && stderr !== '') yield { stream: 'stderr', data: stripCliXml(stderr) };
      yield chunk;
    }
  }

  private async runQuery(script: string, what: string): Promise<string> {
    const result = await this.runPowerShell(script);
    if (result.exitCode !== 0) {
      throw new WinRMError(`WinRM ${what} query failed with exit code ${result.exitCode}: ${result.stderr || result.stdout}`);
    }
    return result.stdout;
  }

  async readEventLog(q: EventLogQuery): Promise<EventRecord[]> {
    return mapEventRecords(await this.runQuery(buildEventLogScript(q), 'event log'));
  }

  async listServices(): Promise<ServiceInfo[]> {
    return mapServices(await this.runQuery(buildServicesScript(), 'service'));
  }

  async listProcesses(): Promise<ProcessInfo[]> {
    return mapProcesses(await this.runQuery(buildProcessesScript(), 'process'));
  }

  private throwIfClosed(): void {
    if (this.closed) throw new WinRMError('WinRM session is closed');
  }

  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    for (const shellId of [...this.openShells]) {
      await this.deleteShell(shellId).catch(() => undefined);
    }
    await this.transport.close();
  }
}
