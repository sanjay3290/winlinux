// Fake module sessions and deps for facade unit tests. Each fake records
// what the facade asked for; nothing here touches the network.
import type { AuthProvider, AuthTarget, Credentials, Mechanism, SecurityContext } from '@winlinux/auth';
import type { WinRMConnectOptions, WinRMSession, CommandResult, OutputChunk, ProcessInfo, ServiceInfo, InputCommandChunk, InputCommandOptions } from '@winlinux/winrm';
import type { DirEntry, FileStat, SMBConnectOptions, SMBSession } from '@winlinux/smb2';
import type { ClientDeps } from '../../dist/client.js';

export interface Deferred<T> {
  promise: Promise<T>;
  resolve: (value: T) => void;
  reject: (err: unknown) => void;
}

export function deferred<T>(): Deferred<T> {
  let resolve!: (value: T) => void;
  let reject!: (err: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

export const OK: CommandResult = { stdout: 'ok', stderr: '', exitCode: 0 };

export class FakeWinrm implements WinRMSession {
  closed = 0;
  // Every command line this session was asked to run, buffered or streamed,
  // with the working directory it was given.
  runs: Array<{ cmd: string; args: string[]; cwd?: string }> = [];
  runImpl: (cmd: string, args: string[], cwd?: string) => Promise<CommandResult> = async () => OK;
  closeImpl: () => Promise<void> = async () => undefined;
  runCommand(cmd: string, args: string[] = [], opts?: { cwd?: string }): Promise<CommandResult> {
    this.runs.push({ cmd, args, cwd: opts?.cwd });
    return this.runImpl(cmd, args, opts?.cwd);
  }
  runPowerShell(script: string): Promise<CommandResult> {
    return this.runCommand('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script]);
  }
  async *runCommandStream(cmd = '', args: string[] = [], opts?: { cwd?: string }): AsyncIterable<OutputChunk> {
    this.runs.push({ cmd, args, cwd: opts?.cwd });
    yield { stream: 'stdout', data: 'x' };
  }
  runPowerShellStream(script: string): AsyncIterable<OutputChunk> {
    return this.runCommandStream('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script]);
  }
  // Commands that read stdin. The default drains the input and
  // exits 0; scripts records each PowerShell script.
  scripts: string[] = [];
  inputImpl: (script: string, input: AsyncIterable<Buffer>, opts?: InputCommandOptions) => AsyncIterable<InputCommandChunk> = async function* (
    _script,
    input,
  ) {
    for await (const _chunk of input) void _chunk;
    yield { stream: 'exit', exitCode: 0, inputComplete: true };
  };
  runCommandWithInput(cmd: string, args: string[], input: AsyncIterable<Buffer>, opts?: InputCommandOptions): AsyncIterable<InputCommandChunk> {
    this.runs.push({ cmd, args, cwd: opts?.cwd });
    return this.inputImpl(args.join(' '), input, opts);
  }
  runPowerShellWithInput(script: string, input: AsyncIterable<Buffer>, opts?: InputCommandOptions): AsyncIterable<InputCommandChunk> {
    this.scripts.push(script);
    return this.inputImpl(script, input, opts);
  }
  async readEventLog() {
    return [];
  }
  servicesImpl: () => Promise<ServiceInfo[]> = async () => [];
  processesImpl: () => Promise<ProcessInfo[]> = async () => [];
  listServices(): Promise<ServiceInfo[]> {
    return this.servicesImpl();
  }
  listProcesses(): Promise<ProcessInfo[]> {
    return this.processesImpl();
  }
  close(): Promise<void> {
    this.closed += 1;
    return this.closeImpl();
  }
}

export class FakeSmb implements SMBSession {
  closed = 0;
  security = { dialect: '3.1.1', signingAlgorithm: 'AES-GMAC', cipher: 'AES-128-GCM', encryptData: false, signing: true };
  listImpl: (share: string, dirPath?: string) => Promise<DirEntry[]> = async () => [];
  async listShares() {
    return [];
  }
  list(share: string, dirPath?: string) {
    return this.listImpl(share, dirPath);
  }
  // File operations: every call is recorded; statImpl decides what
  // exists. The default answers a plain file for every path.
  ops: Array<{ op: string; share: string; path: string; to?: string; data?: string }> = [];
  statImpl: (share: string, path: string) => Promise<FileStat> = async () => ({
    sizeBytes: 5n,
    mtime: new Date('2026-10-09T10:00:00.000Z'),
    atime: new Date('2026-10-09T11:00:00.000Z'),
    isDirectory: false,
    readonly: false,
  });
  mkdirImpl: (share: string, path: string) => Promise<void> = async () => undefined;
  stat(share: string, path: string): Promise<FileStat> {
    this.ops.push({ op: 'stat', share, path });
    return this.statImpl(share, path);
  }
  async readFile(share: string, path: string): Promise<Buffer> {
    this.ops.push({ op: 'readFile', share, path });
    return Buffer.from('fake-content');
  }
  async writeFile(share: string, path: string, data: Buffer | string) {
    this.ops.push({ op: 'writeFile', share, path, data: data.toString() });
  }
  async deleteFile(share: string, path: string) {
    this.ops.push({ op: 'deleteFile', share, path });
  }
  async deleteDirectory(share: string, path: string) {
    this.ops.push({ op: 'deleteDirectory', share, path });
  }
  async rename(share: string, path: string, to: string) {
    this.ops.push({ op: 'rename', share, path, to });
  }
  uploads: Array<{ localPath: string; share: string; remotePath: string }> = [];
  downloadImpl: (share: string, remotePath: string, localPath: string) => Promise<void> = async () => undefined;
  async upload(localPath: string, share: string, remotePath: string) {
    this.uploads.push({ localPath, share, remotePath });
  }
  download(share: string, remotePath: string, localPath: string) {
    return this.downloadImpl(share, remotePath, localPath);
  }
  async delete() {}
  mkdir(share: string, path: string) {
    this.ops.push({ op: 'mkdir', share, path });
    return this.mkdirImpl(share, path);
  }
  async close() {
    this.closed += 1;
  }
}

export class NullProvider implements AuthProvider {
  constructor(readonly mechanism: Mechanism) {}
  createContext(_target: AuthTarget, _credentials: Credentials): SecurityContext {
    throw new Error('fake deps never create contexts');
  }
}

// Deps whose connect functions are driven by the test.
export interface FakeDeps extends ClientDeps {
  winrmOpens: WinRMConnectOptions[];
  smbOpens: SMBConnectOptions[];
  mechanisms: Mechanism[];
}

export function fakeDeps(opts: {
  winrm?: (o: WinRMConnectOptions) => Promise<WinRMSession>;
  smb?: (o: SMBConnectOptions) => Promise<SMBSession>;
  closeTimeoutMs?: number;
}): FakeDeps {
  const deps: FakeDeps = {
    winrmOpens: [],
    smbOpens: [],
    mechanisms: [],
    winrmConnect: async (o) => {
      deps.winrmOpens.push(o);
      return (opts.winrm ?? (async () => new FakeWinrm()))(o);
    },
    smbConnect: async (o) => {
      deps.smbOpens.push(o);
      return (opts.smb ?? (async () => new FakeSmb()))(o);
    },
    createAuthProvider: (m) => {
      deps.mechanisms.push(m);
      return new NullProvider(m);
    },
    closeTimeoutMs: opts.closeTimeoutMs,
  };
  return deps;
}
