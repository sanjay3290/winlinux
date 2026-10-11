// Recursive transfer helpers for `get -r` / `put -r`: tree walks,
// name and path safety, and a small worker pool. The facade (client.ts)
// drives them over its one SMB session.
import path from 'node:path';
import { lstat, readdir } from 'node:fs/promises';
import { SmbError, type DirEntry } from '@winlinux/smb2';
import { WinLinuxError, WinLinuxUsageError } from './errors.js';
import { hasControls, terminalSafe } from './terminal.js';

export const MAX_PARALLEL = 8;

export interface TreeFileEvent {
  path: string; // relative to the copied root, `/`-separated
  index: number; // 1-based, in start order
  total: number;
  sizeBytes: number;
}

export interface TreeSkipEvent {
  path: string;
  reason: 'symlink' | 'reparse point' | 'special file';
}

export interface TreeTransferOptions {
  parallel?: number; // files in flight on the one SMB session; default 1, max 8
  signal?: AbortSignal; // abort: no new file starts; the copy stops after the files in flight
  onFile?: (event: TreeFileEvent) => void; // a file starts
  onFileDone?: (event: TreeFileEvent) => void; // a file is complete
  onSkip?: (event: TreeSkipEvent) => void;
}

export interface TreeTransferSummary {
  files: number;
  directories: number;
  bytes: number;
  skipped: number;
  share: string;
  remotePath: string; // the remote root of the copy, share-relative
  localPath: string; // the local root of the copy
}

// The copy stopped on an AbortSignal. Files already copied stay.
export class WinLinuxAbortError extends WinLinuxError {
  readonly files: number;
  readonly total: number;
  constructor(files: number, total: number) {
    super(`interrupted after ${files} of ${total} files`);
    this.files = files;
    this.total = total;
  }
}

const WINDOWS_INVALID = /[<>:"|?*\x00-\x1f]/;
const WINDOWS_RESERVED = /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(\..*)?$/i;

function invalidOnWindows(name: string): boolean {
  return WINDOWS_INVALID.test(name) || WINDOWS_RESERVED.test(name) || /[. ]$/.test(name);
}

// A name from a remote listing. A server could send `..`, a separator or an
// absolute name; none of them may steer a write. Nor may control
// characters reach a local name or the terminal, on any platform.
// On a Windows client the name must also be one Windows can hold.
export function checkRemoteName(name: string, platform: NodeJS.Platform = process.platform): void {
  if (hasControls(name)) {
    throw new SmbError(`unsafe remote name refused (control characters): "${terminalSafe(name)}"`);
  }
  if (name === '' || name === '.' || name === '..' || /[/\\\0]/.test(name)) {
    throw new SmbError(`unsafe remote name refused: ${JSON.stringify(name)}`);
  }
  if (platform === 'win32' && invalidOnWindows(name)) {
    throw new SmbError(`remote name is not valid on this system: ${JSON.stringify(name)}`);
  }
}

// A local name for `put -r`: the server is Windows, so the name must be one
// Windows can hold (and a `\` would split into a path there).
export function checkLocalName(name: string): void {
  if (name.includes('\\') || invalidOnWindows(name)) {
    throw new WinLinuxUsageError(`put -r: local name is not valid on Windows: ${JSON.stringify(name)}`);
  }
}

// Joins `parts` under `root` and proves the result stays inside it.
export function safeJoin(root: string, parts: string[]): string {
  const base = path.resolve(root);
  const target = path.resolve(base, ...parts);
  const back = path.relative(base, target);
  if (back !== '' && (back === '..' || back.startsWith(`..${path.sep}`) || path.isAbsolute(back))) {
    throw new SmbError(`refusing to write outside ${root}: ${parts.join('/')}`);
  }
  return target;
}

export function checkParallel(parallel: number | undefined): number {
  if (parallel === undefined) return 1;
  if (!Number.isInteger(parallel) || parallel < 1 || parallel > MAX_PARALLEL) {
    throw new WinLinuxUsageError(`parallel must be an integer from 1 to ${MAX_PARALLEL}`);
  }
  return parallel;
}

export function joinRemote(root: string, rel: string): string {
  if (!root) return rel;
  return rel ? `${root}/${rel}` : root;
}

export function trimRemote(remotePath: string): string {
  return remotePath.split(/[\\/]/).filter(Boolean).join('/');
}

export interface TreePlan {
  dirs: string[]; // relative, parents before children; '' is the root
  files: Array<{ rel: string; size: number }>;
  skipped: TreeSkipEvent[];
}

const byName = (a: { name: string }, b: { name: string }) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0);

// Breadth-first walk of a remote directory. Reparse points (symbolic links,
// junctions) are skipped, never followed.
export async function walkRemote(list: (dir: string) => Promise<DirEntry[]>, root: string): Promise<TreePlan> {
  const plan: TreePlan = { dirs: [''], files: [], skipped: [] };
  for (let i = 0; i < plan.dirs.length; i++) {
    const dir = plan.dirs[i] as string;
    const entries = [...(await list(joinRemote(root, dir)))].sort(byName);
    for (const entry of entries) {
      checkRemoteName(entry.name);
      const rel = dir ? `${dir}/${entry.name}` : entry.name;
      if (entry.isReparsePoint) plan.skipped.push({ path: rel, reason: 'reparse point' });
      else if (entry.isDirectory) plan.dirs.push(rel);
      else plan.files.push({ rel, size: Number(entry.sizeBytes) });
    }
  }
  return plan;
}

// Breadth-first walk of a local directory. Symbolic links, devices, FIFOs
// and sockets are skipped; links are never followed.
export async function walkLocal(root: string): Promise<TreePlan> {
  const plan: TreePlan = { dirs: [''], files: [], skipped: [] };
  for (let i = 0; i < plan.dirs.length; i++) {
    const dir = plan.dirs[i] as string;
    const entries = (await readdir(path.join(root, ...dir.split('/').filter(Boolean)), { withFileTypes: true })).sort(byName);
    for (const entry of entries) {
      checkLocalName(entry.name);
      const rel = dir ? `${dir}/${entry.name}` : entry.name;
      if (entry.isSymbolicLink()) plan.skipped.push({ path: rel, reason: 'symlink' });
      else if (entry.isDirectory()) plan.dirs.push(rel);
      else if (entry.isFile()) plan.files.push({ rel, size: (await lstat(path.join(root, ...rel.split('/')))).size });
      else plan.skipped.push({ path: rel, reason: 'special file' });
    }
  }
  return plan;
}

// Runs `work` over `items` with at most `parallel` in flight. The first
// failure stops new work; the ones in flight finish, then it is thrown. An
// aborted signal also stops new work (the caller decides what that means).
export async function runPool<T>(
  items: readonly T[],
  parallel: number,
  signal: AbortSignal | undefined,
  work: (item: T, index: number) => Promise<void>,
): Promise<void> {
  let next = 0;
  let failed = false;
  let failure: unknown;
  const worker = async () => {
    while (!failed && !signal?.aborted && next < items.length) {
      const index = next++;
      try {
        await work(items[index] as T, index);
      } catch (err) {
        if (!failed) {
          failed = true;
          failure = err;
        }
      }
    }
  };
  await Promise.all(Array.from({ length: Math.min(parallel, items.length) }, worker));
  if (failed) throw failure;
}
