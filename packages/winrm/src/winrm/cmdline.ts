// How a command and its arguments reach the program on the server.
//
// With WINRS_SKIP_CMD_SHELL=FALSE, WinRS joins rsp:Command and every
// rsp:Arguments element with spaces and runs the line through cmd.exe,
// which then starts the program; the program splits its command line
// again by the CommandLineToArgvW rules. So each argument crosses two
// parsers. This module quotes one argument so that both parsers hand it
// through unchanged, and encodes a PowerShell script so it crosses
// neither.

// cmd.exe's special characters. `^` escapes any one of them when cmd is
// not inside a quoted span; escaping `"` as well keeps cmd out of quote
// mode for the whole line, so every `^` is an escape and the text cmd
// hands to the program is exactly the CommandLineToArgvW-quoted
// argument. `%` and `!` are the variable-expansion markers: an escaped
// `%NAME^%` names no variable, so cmd leaves it alone and the program
// sees the literal `%NAME%`.
const CMD_META = /[()%!^"<>&|]/g;

// CommandLineToArgvW: quotes are needed for an empty argument and for
// whitespace or a quote. Backslashes are literal except in front of a
// quote (or the closing quote), where each one must be doubled.
function quoteArgv(arg: string): string {
  if (arg.length > 0 && !/[\s"]/.test(arg)) return arg;
  let out = '"';
  let backslashes = 0;
  for (const ch of arg) {
    if (ch === '\\') {
      backslashes += 1;
      continue;
    }
    if (ch === '"') {
      out += '\\'.repeat(backslashes * 2 + 1) + '"';
    } else {
      out += '\\'.repeat(backslashes) + ch;
    }
    backslashes = 0;
  }
  return `${out}${'\\'.repeat(backslashes * 2)}"`;
}

// One command-line word that cmd.exe and then the program both read back
// as exactly `arg`. Returns `arg` itself when nothing needs quoting, so
// plain words (`/c`, `-n`, `127.0.0.1`) go out as they are.
export function quoteCmdArg(arg: string): string {
  return quoteArgv(arg).replace(CMD_META, '^$&');
}

// The powershell.exe argument list for a script. `-EncodedCommand` takes
// the script as base64 of its UTF-16LE bytes (the same thing pywinrm's
// run_ps sends), so `|`, `&`, quotes and non-ASCII text never meet
// cmd.exe. The base64 alphabet has no cmd metacharacter.
export function powerShellArgs(script: string): string[] {
  return ['-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(script, 'utf16le').toString('base64')];
}

// The script back out of a powershell.exe argument list built by
// powerShellArgs (tests and the fake Windows endpoint).
export function decodePowerShellArgs(args: string[]): string | undefined {
  const i = args.indexOf('-EncodedCommand');
  const b64 = i >= 0 ? args[i + 1] : undefined;
  return b64 === undefined ? undefined : Buffer.from(b64, 'base64').toString('utf16le');
}
