// What Windows does with the command line WinRS builds: cmd.exe
// reads the joined line first (WINRS_SKIP_CMD_SHELL=FALSE), then the
// program splits what cmd hands it by the CommandLineToArgvW rules. The
// fake Windows endpoint runs every Command through this, so a quoting bug
// in the client shows up offline as the wrong argv.

// cmd.exe phase 2 for one line, as far as it concerns an argument list:
// a `"` toggles quote mode; outside it `^` escapes the next character and
// a special character would start a pipe, redirection or a second
// command. The simulator refuses those instead of interpreting them, so a
// test sees exactly where cmd would have cut the line.
export function cmdPass(line: string): string {
  let out = '';
  let quoted = false;
  for (let i = 0; i < line.length; i += 1) {
    const ch = line[i] as string;
    if (ch === '"') {
      quoted = !quoted;
      out += ch;
    } else if (!quoted && ch === '^') {
      i += 1;
      out += line[i] ?? '';
    } else if (!quoted && /[&|<>()]/.test(ch)) {
      throw new Error(`cmd.exe would interpret '${ch}' at offset ${i} of: ${line}`);
    } else {
      out += ch;
    }
  }
  return out;
}

// CommandLineToArgvW: whitespace separates outside quotes, a `"` toggles
// quote mode, 2n backslashes before a quote are n literal backslashes,
// 2n+1 are n backslashes and a literal quote, and backslashes elsewhere
// are literal.
export function commandLineToArgv(line: string): string[] {
  const argv: string[] = [];
  let current = '';
  let inArg = false;
  let quoted = false;
  let i = 0;
  while (i < line.length) {
    const ch = line[i] as string;
    if (ch === '\\') {
      let n = 0;
      while (line[i + n] === '\\') n += 1;
      if (line[i + n] === '"') {
        current += '\\'.repeat(Math.floor(n / 2));
        if (n % 2 === 1) current += '"';
        else quoted = !quoted;
        i += n + 1;
      } else {
        current += '\\'.repeat(n);
        i += n;
      }
      inArg = true;
    } else if (ch === '"') {
      quoted = !quoted;
      inArg = true;
      i += 1;
    } else if (!quoted && /\s/.test(ch)) {
      if (inArg) argv.push(current);
      current = '';
      inArg = false;
      i += 1;
    } else {
      current += ch;
      inArg = true;
      i += 1;
    }
  }
  if (inArg) argv.push(current);
  return argv;
}

// The argv a program started by WinRS sees for a Command request.
export function windowsArgv(command: string, args: string[]): string[] {
  return commandLineToArgv(cmdPass([command, ...args].join(' ')));
}
