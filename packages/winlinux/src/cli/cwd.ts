// Working directory tracking for the interactive shell.
// Every line runs in a fresh WinRS shell, so `cd` is handled here: the
// target is resolved against the tracked directory with cmd.exe path rules,
// and later lines open their shell with that directory (rsp:WorkingDirectory).

// True when the line's first word is cmd's `cd` (or `chdir`), in any case.
export function isCd(word: string | undefined): boolean {
  return word !== undefined && /^(cd|chdir)$/i.test(word);
}

// Arguments after `cd`: drops the `/d` switch and joins the rest, so both
// `cd "C:\Program Files"` and `cd C:\Program Files` name the same directory.
// Returns undefined for a bare `cd` (print the working directory).
export function cdTarget(args: string[]): string | undefined {
  const rest = args[0] !== undefined && /^\/d$/i.test(args[0]) ? args.slice(1) : args;
  const target = rest.join(' ').trim();
  return target === '' ? undefined : target;
}

// Resolves `target` against `cwd` the way cmd.exe does: drive letters,
// rooted paths, `.` and `..`, both separators. The result is absolute and
// uses backslashes, with a trailing one only at a drive root (`C:\`).
// `cwd` must be absolute (a drive root or below).
export function resolveCd(cwd: string, target: string): string {
  const drive = (p: string) => (/^[A-Za-z]:/.test(p) ? p[0]!.toUpperCase() : undefined);
  const cwdDrive = drive(cwd) ?? 'C';
  let base: string;
  let path = target.trim();
  if (path.startsWith('\\\\') || path.startsWith('//')) {
    // UNC: cmd rejects it as a working directory; pass it on for the remote message.
    return '\\\\' + segments(path.slice(2)).join('\\');
  }
  const targetDrive = drive(path);
  if (targetDrive !== undefined) {
    path = path.slice(2);
    if (path === '') return `${targetDrive}:\\`;
    // `D:dir` is relative to D:'s current directory, which is only known for the current drive.
    base = /^[\\/]/.test(path) ? `${targetDrive}:\\` : targetDrive === cwdDrive ? cwd : `${targetDrive}:\\`;
  } else if (/^[\\/]/.test(path)) {
    base = `${cwdDrive}:\\`;
  } else {
    base = cwd;
  }
  const parts = segments(base.slice(2));
  for (const part of segments(path)) {
    if (part === '..') parts.pop();
    else parts.push(part);
  }
  return `${base[0]!.toUpperCase()}:\\${parts.join('\\')}`;
}

function segments(path: string): string[] {
  return path.split(/[\\/]+/).filter((s) => s !== '' && s !== '.');
}

// Windows paths compare case-insensitively; `C:\` and `C:` are the same root.
export function sameDirectory(a: string, b: string): boolean {
  const norm = (p: string) => p.trim().replace(/[\\/]+$/, '').toLowerCase();
  return norm(a) === norm(b);
}
