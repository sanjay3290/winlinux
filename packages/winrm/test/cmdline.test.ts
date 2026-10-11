// Command-line quoting and PowerShell encoding. The quoting is
// checked against a simulator of what Windows does with the line (cmd.exe
// pass, then the CommandLineToArgvW split); the encoding is decoded back
// in the test. The fake Windows endpoint uses the same simulator, so the
// live scenarios in live-harness.test.ts cover the session end to end.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { decodePowerShellArgs, powerShellArgs, quoteCmdArg } from '../src/winrm/cmdline.js';
import { cmdPass, commandLineToArgv, windowsArgv } from './helpers/cmdline-sim.js';
import { connect } from '../src/winrm/index.js';
import { createAuthProvider } from '@winlinux/auth';
import { CREDENTIALS } from './helpers/stub-auth.js';
import { startFakeWindows } from './helpers/fake-windows.js';

const AWKWARD = [
  'plain',
  '',
  'two words',
  'tab\there',
  'say "hi"',
  'a & whoami',
  'x | y',
  '<in >out',
  '100%',
  '%COMPUTERNAME%',
  '!delayed!',
  'caret^here',
  '(paren) & more',
  'C:\\Program Files\\',
  'back\\slash "quoted\\" end',
  'ends with backslashes\\\\',
  'ünïcödé ✓',
];

// What the program on the server sees for a runCommand(cmd, args) call.
const seen = (cmd: string, args: string[]): string[] => windowsArgv(quoteCmdArg(cmd), args.map(quoteCmdArg));

describe('quoteCmdArg', () => {
  it('leaves plain words alone', () => {
    for (const word of ['/c', '-n', '120', '127.0.0.1', 'hostname', 'C:\\Windows\\Temp']) {
      assert.equal(quoteCmdArg(word), word);
    }
  });

  it('every awkward argument comes back as exactly one argv element', () => {
    for (const arg of AWKWARD) {
      assert.deepEqual(seen('prog', [arg]), ['prog', arg], `argument ${JSON.stringify(arg)}`);
    }
    assert.deepEqual(seen('prog', AWKWARD), ['prog', ...AWKWARD]);
  });

  it('escapes every cmd.exe metacharacter so cmd never sees a pipe, a redirection or a quote', () => {
    const line = ['prog', ...AWKWARD.map(quoteCmdArg)].join(' ');
    assert.doesNotMatch(line, /(^|[^^])[&|<>()]/);
    // Without the escapes the simulator (like cmd.exe) would split the line.
    assert.throws(() => cmdPass('echo a & whoami'), /would interpret '&'/);
    assert.throws(() => cmdPass('"a" | b'), /would interpret '\|'/);
  });

  it('quotes the program path too', () => {
    assert.deepEqual(seen('C:\\Program Files\\App\\app.exe', ['-v']), ['C:\\Program Files\\App\\app.exe', '-v']);
  });

  it('the simulator itself splits a hand-written Windows line by the documented rules', () => {
    assert.deepEqual(commandLineToArgv('a "b c" d\\"e "f\\\\" g\\\\\\"h'), ['a', 'b c', 'd"e', 'f\\', 'g\\"h']);
    assert.equal(cmdPass('^"a ^& b^"'), '"a & b"');
    assert.equal(cmdPass('"a & b"'), '"a & b"');
  });
});

describe('powerShellArgs', () => {
  it('sends the script as -EncodedCommand base64 of UTF-16LE and the test decodes it back', () => {
    const script = `Get-Service | Where-Object { $_.Name -eq 'wuauserv' } | Select-Object "Name" # ünïcödé ✓`;
    const args = powerShellArgs(script);
    assert.deepEqual(args.slice(0, 3), ['-NoProfile', '-NonInteractive', '-EncodedCommand']);
    const b64 = args[3] ?? '';
    assert.match(b64, /^[A-Za-z0-9+/=]+$/);
    assert.equal(Buffer.from(b64, 'base64').toString('utf16le'), script);
    assert.equal(decodePowerShellArgs(args), script);
    // The encoded argument needs no quoting, so the line stays as built.
    assert.deepEqual(args.map(quoteCmdArg), args);
    assert.deepEqual(seen('powershell.exe', args), ['powershell.exe', ...args]);
  });

  it('decodePowerShellArgs returns undefined for a -Command list', () => {
    assert.equal(decodePowerShellArgs(['-NoProfile', '-Command', 'Get-Date']), undefined);
  });
});

describe('session quoting against the fake Windows endpoint', () => {
  it('a quoted argument with spaces, quotes and & arrives as one argument', async () => {
    const server = await startFakeWindows({ tls: true, username: CREDENTIALS.username, password: CREDENTIALS.password ?? '' });
    try {
      const session = await connect({
        host: '127.0.0.1',
        port: server.port,
        tls: true,
        tlsVerify: false,
        authProvider: createAuthProvider('basic'),
        credentials: CREDENTIALS,
      });
      try {
        const r = await session.runCommand('fake-argv', ['one two', 'say "hi"', 'a & whoami']);
        assert.equal(r.exitCode, 0);
        assert.deepEqual(JSON.parse(r.stdout), ['one two', 'say "hi"', 'a & whoami']);
      } finally {
        await session.close();
      }
    } finally {
      await server.close();
    }
  });
});
