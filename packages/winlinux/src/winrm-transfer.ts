// File copy over WinRM, for networks that block SMB (TCP 445).
//
// get: one PowerShell command opens the file read-only, writes it to
// stdout as base64 lines and ends with `sha256:<hex>`. The client decodes
// the lines as Receives arrive (a Receive can end anywhere in a line).
// put: one PowerShell command reads base64 lines from stdin ($input, fed
// by rsp:Send), writes `<dest>.winlinux-<rand>.part` next to the
// destination, hashes it, compares with the client's hash and moves it
// over the destination. A last stdin line `end` marks a complete upload;
// without it (stdin closed early on Ctrl+C or a local read error) the
// script removes its temp file and the destination stays as it was.
//
// User text reaches the scripts only inside single-quoted PowerShell
// literals (psQuote). The share and path are resolved on the server.
import { createReadStream } from 'node:fs';
import { createHash } from 'node:crypto';
import { psQuote } from '@winlinux/winrm';
import { WinLinuxTransferError, WinLinuxUsageError } from './errors.js';

// Base64 lines carry this many file bytes (a multiple of 3, so no line
// but the last has padding). 48 KiB -> 64 KiB of text per line.
export const LINE_BYTES = 48 * 1024;
// A line longer than this is refused: no server line comes near it, and
// the decoder must not buffer without bound.
export const MAX_LINE_CHARS = 1024 * 1024;
// stdout of put and stderr of both scripts: kept for the error message.
const MAX_TEXT = 64 * 1024;

// A PowerShell single-quoted literal of `value`. One helper, shared with
// the event log query in @winlinux/winrm, so the two cannot drift.
export { psQuote };

// The share-relative path as segments. `/` and `\` both separate; empty
// and `.` segments are dropped. `..` is refused, and so are characters
// that would let a segment name a drive, an alternate data stream or a
// device (`:`), or that Windows never allows in a name.
export function remoteSegments(remotePath: string): string[] {
  const segments = remotePath.split(/[\\/]/).filter((s) => s !== '' && s !== '.');
  if (segments.length === 0) throw new WinLinuxUsageError(`remote path names no file: ${JSON.stringify(remotePath)}`);
  for (const segment of segments) {
    if (segment === '..') throw new WinLinuxUsageError(`remote path must not contain '..': ${remotePath}`);
    if (/[:<>"|?*\x00-\x1f]/.test(segment)) {
      throw new WinLinuxUsageError(`remote path has a character Windows does not allow in a name: ${JSON.stringify(remotePath)}`);
    }
  }
  return segments;
}

export function checkTransferShare(share: string): void {
  if (/[\x00-\x1f]/.test(share)) throw new WinLinuxUsageError(`share name has a control character: ${JSON.stringify(share)}`);
}

// Shared head of both scripts: resolve <share>/<path> to a local path on
// the server and prove it stays under the share's root. A drive admin
// share (C$, D$) maps to its drive root without Get-SmbShare, which needs
// the Server service; any other share is looked up by exact name (no
// wildcard match, unlike Get-SmbShare -Name).
function resolvePrelude(share: string, segments: string[]): string {
  return [
    `$share = ${psQuote(share)}`,
    `$rel = ${psQuote(segments.join('\\'))}`,
    "if ($share -match '^[A-Za-z]\\$$') { $root = $share.Substring(0, 1) + ':\\' }",
    'else {',
    '  $found = @(Get-SmbShare | Where-Object { $_.Name -eq $share })',
    "  if ($found.Count -eq 0) { throw ('no such share: ' + $share) }",
    '  $root = $found[0].Path',
    '}',
    '$root = [IO.Path]::GetFullPath($root)',
    '$full = [IO.Path]::GetFullPath([IO.Path]::Combine($root, $rel))',
    "$prefix = $root.TrimEnd('\\') + '\\'",
    "if (-not $full.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) { throw ('path leaves the share: ' + $rel) }",
  ].join('\n');
}

// Error contract of both scripts: exit 1, or exit 3 for a SHA-256
// mismatch, with two lines on stderr:
//   winlinux: [<kind>] <message>   kind: notfound, noshare, denied, inuse,
//                                  isdir or error; the message names
//                                  <share>/<path>, never the server's
//                                  local path
//   winlinux-raw: <message>        the .NET text as it was (for -v)
// `exit` in catch still runs finally.
function wrap(kind: 'get' | 'put', body: string, cleanup = ''): string {
  return [
    `# winlinux-transfer:${kind}`,
    "$ErrorActionPreference = 'Stop'",
    "$ProgressPreference = 'SilentlyContinue'",
    '$code = 1',
    '$temp = $null',
    '$full = $null',
    '$root = $null',
    'try {',
    body,
    '} catch {',
    '  $e = $_.Exception',
    // "Exception calling "Open" with "4" argument(s)" wraps the real one.
    '  while ($e -is [Management.Automation.MethodInvocationException] -and $e.InnerException) { $e = $e.InnerException }',
    '  $raw = $e.Message',
    "  $kind = 'error'",
    "  if ($raw -like 'no such share: *') { $kind = 'noshare' }",
    "  elseif ($raw -like 'is a directory: *') { $kind = 'isdir' }",
    "  elseif ($raw -like 'no such directory: *') { $kind = 'notfound' }",
    "  elseif ($e -is [IO.FileNotFoundException] -or $e -is [IO.DirectoryNotFoundException] -or $e -is [Management.Automation.ItemNotFoundException]) { $kind = 'notfound' }",
    "  elseif ($e -is [UnauthorizedAccessException] -or $e -is [Security.SecurityException]) { $kind = 'denied' }",
    // ERROR_SHARING_VIOLATION (32) and ERROR_LOCK_VIOLATION (33).
    "  elseif ($e -is [IO.IOException] -and (($e.HResult -band 0xFFFF) -eq 32 -or ($e.HResult -band 0xFFFF) -eq 33)) { $kind = 'inuse' }",
    '  $msg = $raw',
    "  if ($full) { $msg = $msg.Replace($full, $share + '/' + $rel.Replace('\\', '/')) }",
    "  if ($root) { $msg = $msg.Replace($root.TrimEnd('\\') + '\\', $share + '/').Replace($root.TrimEnd('\\'), $share) }",
    "  [Console]::Error.WriteLine('winlinux: [' + $kind + '] ' + $msg)",
    "  [Console]::Error.WriteLine('winlinux-raw: ' + $raw)",
    '  exit $code',
    '} finally {',
    cleanup,
    '}',
    'exit 0',
  ].join('\n');
}

const HEX = "[BitConverter]::ToString($sha.Hash).Replace('-', '').ToLowerInvariant()";

export function buildGetScript(share: string, segments: string[]): string {
  return wrap(
    'get',
    [
      resolvePrelude(share, segments),
      "if ([IO.Directory]::Exists($full)) { throw ('is a directory: ' + $rel) }",
      '$fs = [IO.File]::Open($full, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)',
      'try {',
      '  $sha = [Security.Cryptography.SHA256]::Create()',
      '  $out = [Console]::OpenStandardOutput()',
      `  $buf = New-Object byte[] ${LINE_BYTES}`,
      '  while (($n = $fs.Read($buf, 0, $buf.Length)) -gt 0) {',
      '    [void]$sha.TransformBlock($buf, 0, $n, $null, 0)',
      '    $line = [Text.Encoding]::ASCII.GetBytes([Convert]::ToBase64String($buf, 0, $n) + "`n")',
      '    $out.Write($line, 0, $line.Length)',
      '  }',
      '  [void]$sha.TransformFinalBlock($buf, 0, 0)',
      `  $tail = [Text.Encoding]::ASCII.GetBytes('sha256:' + ${HEX} + "\`n")`,
      '  $out.Write($tail, 0, $tail.Length)',
      '  $out.Flush()',
      '} finally {',
      '  $fs.Dispose()',
      '}',
    ].join('\n'),
  );
}

export function buildPutScript(share: string, segments: string[], sha256: string, tempSuffix: string): string {
  if (!/^[0-9a-f]{64}$/.test(sha256)) throw new Error('buildPutScript: sha256 must be 64 lowercase hex digits');
  if (!/^\.winlinux-[0-9a-f]+\.part$/.test(tempSuffix)) throw new Error('buildPutScript: bad temp suffix');
  return wrap(
    'put',
    [
      resolvePrelude(share, segments),
      `$expected = ${psQuote(sha256)}`,
      '$dir = [IO.Path]::GetDirectoryName($full)',
      "if (-not [IO.Directory]::Exists($dir)) { throw ('no such directory: ' + $dir) }",
      "if ([IO.Directory]::Exists($full)) { throw ('is a directory: ' + $rel) }",
      `$temp = $full + ${psQuote(tempSuffix)}`,
      '$sha = [Security.Cryptography.SHA256]::Create()',
      '$complete = $false',
      '$fs = [IO.File]::Open($temp, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)',
      'try {',
      '  foreach ($line in $input) {',
      "    if ($line -ceq 'end') { $complete = $true; break }",
      '    if ($line.Length -eq 0) { continue }',
      '    $bytes = [Convert]::FromBase64String($line)',
      '    [void]$sha.TransformBlock($bytes, 0, $bytes.Length, $null, 0)',
      '    $fs.Write($bytes, 0, $bytes.Length)',
      '  }',
      '} finally {',
      '  $fs.Dispose()',
      '}',
      "if (-not $complete) { throw 'upload interrupted; the destination is unchanged' }",
      '[void]$sha.TransformFinalBlock((New-Object byte[] 0), 0, 0)',
      `$actual = ${HEX}`,
      "if ($actual -ne $expected) { $code = 3; throw ('sha256 mismatch: the client sent ' + $expected + ', the server wrote ' + $actual) }",
      // .NET, not Move-Item: -Destination would read [ and ] as wildcards.
      'if ([IO.File]::Exists($full)) { [IO.File]::Replace($temp, $full, [NullString]::Value) } else { [IO.File]::Move($temp, $full) }',
      '$temp = $null',
      "[Console]::Out.WriteLine('sha256:' + $actual)",
    ].join('\n'),
    '  if ($temp -and [IO.File]::Exists($temp)) { Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue }',
  );
}

// Decodes the get script's stdout: base64 lines, then `sha256:<hex>`.
// push() takes the text of one Receive and returns the bytes of every
// line it completes; a partial line waits for the next Receive.
export class Base64LineDecoder {
  private tail = '';
  private hash: string | undefined;

  push(text: string): Buffer[] {
    const out: Buffer[] = [];
    let data = this.tail + text;
    let start = 0;
    for (;;) {
      const nl = data.indexOf('\n', start);
      if (nl < 0) break;
      const line = data.slice(start, nl).replace(/\r$/, '');
      start = nl + 1;
      const bytes = this.line(line);
      if (bytes && bytes.length > 0) out.push(bytes);
    }
    data = data.slice(start);
    if (data.length > MAX_LINE_CHARS) throw this.protocol(`a line longer than ${MAX_LINE_CHARS} characters`);
    this.tail = data;
    return out;
  }

  private line(line: string): Buffer | undefined {
    if (this.hash !== undefined) {
      if (line === '') return undefined;
      throw this.protocol('data after the sha256 line');
    }
    const m = /^sha256:([0-9a-f]{64})$/.exec(line);
    if (m) {
      this.hash = m[1];
      return undefined;
    }
    if (line === '') return undefined;
    if (line.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(line)) throw this.protocol('a line that is not base64');
    return Buffer.from(line, 'base64');
  }

  // The server's hash. Throws when the output stopped before it.
  end(): string {
    if (this.tail.replace(/\r$/, '') !== '') this.push('\n');
    if (this.hash === undefined) throw this.protocol('the output ended without a sha256 line');
    return this.hash;
  }

  private protocol(what: string): WinLinuxTransferError {
    return new WinLinuxTransferError(`get over WinRM: the server sent ${what}`, 'get', 'protocol');
  }
}

// SHA-256 of a local file, streamed.
export async function sha256File(localPath: string): Promise<{ sha256: string; size: number }> {
  const hash = createHash('sha256');
  let size = 0;
  for await (const chunk of createReadStream(localPath, { highWaterMark: LINE_BYTES * 4 })) {
    hash.update(chunk as Buffer);
    size += (chunk as Buffer).length;
  }
  return { sha256: hash.digest('hex'), size };
}

// The put script's stdin: the file as base64 lines, then `end`. Read
// lazily, one line per pull, so the Send back-pressure reaches the disk.
// `onBytes` counts the file bytes that left as lines.
export async function* uploadLines(localPath: string, onBytes?: (n: number) => void): AsyncGenerator<Buffer> {
  const stream = createReadStream(localPath, { highWaterMark: LINE_BYTES });
  let carry = Buffer.alloc(0);
  for await (const raw of stream) {
    const chunk = carry.length > 0 ? Buffer.concat([carry, raw as Buffer]) : (raw as Buffer);
    // Whole 3-byte groups only, so every line but the last is unpadded.
    const usable = chunk.length - (chunk.length % 3);
    carry = Buffer.from(chunk.subarray(usable));
    if (usable === 0) continue;
    onBytes?.(usable);
    yield Buffer.from(`${chunk.subarray(0, usable).toString('base64')}\n`, 'ascii');
  }
  if (carry.length > 0) {
    onBytes?.(carry.length);
    yield Buffer.from(`${carry.toString('base64')}\n`, 'ascii');
  }
  yield Buffer.from('end\n', 'ascii');
}

// Keeps the first MAX_TEXT characters of a stream of text.
export class TextCap {
  text = '';
  add(more: string): void {
    if (this.text.length < MAX_TEXT) this.text += more.slice(0, MAX_TEXT - this.text.length);
  }
}

// The message a failed script left on stderr, without the prefix it adds.
export function scriptMessage(stderr: string, exitCode: number): string {
  return scriptFailure(stderr, exitCode).message;
}

export type ScriptFailureKind = 'notfound' | 'noshare' | 'denied' | 'inuse' | 'isdir' | 'error';

export interface ScriptFailure {
  kind: ScriptFailureKind;
  message: string; // names <share>/<path>, not the server's local path
  raw?: string; // the .NET text as it was
}

const KINDS = new Set<string>(['notfound', 'noshare', 'denied', 'inuse', 'isdir', 'error']);

// Parses the scripts' stderr contract (see wrap()).
export function scriptFailure(stderr: string, exitCode: number): ScriptFailure {
  let kind: ScriptFailureKind = 'error';
  let message: string | undefined;
  let raw: string | undefined;
  for (const line of stderr.split(/\r?\n/)) {
    const m = /^winlinux: \[(\w+)\] (.*)$/.exec(line);
    if (m && message === undefined) {
      kind = KINDS.has(m[1] as string) ? (m[1] as ScriptFailureKind) : 'error';
      message = m[2] as string;
      continue;
    }
    if (line.startsWith('winlinux-raw: ') && raw === undefined) raw = line.slice('winlinux-raw: '.length);
  }
  if (message === undefined) {
    const text = stderr.trim().replace(/^winlinux: /, '');
    message = text === '' ? `the remote script exited with code ${exitCode}` : text;
  }
  return raw === undefined ? { kind, message } : { kind, message, raw };
}
