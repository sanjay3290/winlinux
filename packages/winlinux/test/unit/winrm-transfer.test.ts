// File copy over WinRM, pure parts: PowerShell quoting, remote
// path rules, the base64 line decoder, the auto rule and --via parsing.
// The facade runs against fake sessions here; winrm-copy.test.ts runs the
// real WinRM session against the transfer mock.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { connect as smbConnect, SmbAccessDeniedError, SmbAuthError, SmbConnectionError, SmbNotFoundError } from '@winlinux/smb2';
import type { InputCommandChunk } from '@winlinux/winrm';
import { createClient } from '../../dist/client.js';
import { EXIT, WinLinuxAuthError, WinLinuxConnectionError, WinLinuxTransferError, WinLinuxUsageError, exitCodeFor, isTcpUnreachable } from '../../dist/errors.js';
import { Base64LineDecoder, LINE_BYTES, MAX_LINE_CHARS, buildGetScript, buildPutScript, psQuote, remoteSegments, scriptFailure, uploadLines } from '../../dist/winrm-transfer.js';
import { HELP, SHELL_HELP, execute, fallbackNotice, parseVia, type Io } from '../../dist/cli/app.js';
import { psQuote as winrmPsQuote } from '@winlinux/winrm';
import { FakeSmb, FakeWinrm, fakeDeps } from '../helpers/fakes.js';
import { countingListener } from '../helpers/listeners.js';
import { assigned, psUnquote, withoutLiterals } from '../helpers/transfer-mock.js';

const OPTS = { username: 'u', password: 'p', auth: 'ntlm' as const };
const HASH = 'a'.repeat(64);

function tempDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'winlinux-winrm-transfer-'));
}

function systemError(code: string): Error & { code: string } {
  const err = new Error(`connect ${code} 127.0.0.1:445`) as Error & { code: string };
  err.code = code;
  return err;
}

// The error smb2's connect() throws when the TCP connect fails.
function tcpFailure(cause: Error): SmbConnectionError {
  const wrapped = new SmbConnectionError(`cannot connect to h:445: ${cause.message}`);
  (wrapped as { cause?: unknown }).cause = cause;
  return wrapped;
}

function capture(): { io: Io; out: () => string; err: () => string } {
  let out = '';
  let err = '';
  const io = {
    env: {},
    stdin: process.stdin,
    stdout: { write: (t: string) => ((out += t), true) },
    stderr: { write: (t: string) => ((err += t), true) },
  } as unknown as Io;
  return { io, out: () => out, err: () => err };
}

describe('PowerShell quoting', () => {
  const NAMES = ["it's", 'two  spaces', 'Ünïcödé-日本語', 'smart \u2018quote\u2019 and \u201a\u201b', "''", "a'; Remove-Item C:\\ -Recurse; '", '$(Get-Date) `n $env:PATH', ''];

  it('psQuote doubles every single-quote character and round-trips', () => {
    for (const name of NAMES) {
      const quoted = psQuote(name);
      assert.equal(psUnquote(quoted).value, name, quoted);
      assert.equal(psUnquote(quoted).end, quoted.length, `${quoted}: the literal ends at its last quote`);
    }
    assert.equal(psQuote("it's"), "'it''s'");
    assert.equal(psQuote('\u2019'), "'\u2019\u2019'");
  });

  it('psQuote is the one helper from @winlinux/winrm', () => {
    assert.equal(psQuote, winrmPsQuote);
  });

  it('the scripts carry share, path and hash as quoted literals only', () => {
    for (const name of NAMES.filter((n) => n.length > 3)) {
      const segments = remoteSegments(`dir with space/${name.replace(/[:\\/]/g, '_')}.txt`);
      for (const script of [buildGetScript(name, segments), buildPutScript(name, segments, HASH, '.winlinux-0123ab.part')]) {
        assert.equal(assigned(script, '$share = '), name);
        assert.equal(assigned(script, '$rel = '), segments.join('\\'));
        // With the literals cut out, no user text is left in the code.
        const code = withoutLiterals(script);
        for (const part of [name, ...segments]) {
          if (part.length > 3) assert.ok(!code.includes(part), `${JSON.stringify(part)} appears outside a literal`);
        }
      }
    }
    const put = buildPutScript('C$', ['x'], HASH, '.winlinux-0123ab.part');
    assert.equal(assigned(put, '$expected = '), HASH);
    assert.equal(assigned(put, '$temp = $full + '), '.winlinux-0123ab.part');
    assert.throws(() => buildPutScript('C$', ['x'], "'; evil", '.winlinux-1.part'), /sha256/);
    assert.throws(() => buildPutScript('C$', ['x'], HASH, "x'"), /suffix/);
  });

  it('the scripts read the file with FileShare.Read and write a temp file next to the destination', () => {
    const get = buildGetScript('C$', ['a.txt']);
    assert.match(get, /\[IO\.FileAccess\]::Read, \[IO\.FileShare\]::Read\)/);
    assert.match(get, /'sha256:' \+/);
    const put = buildPutScript('C$', ['a.txt'], HASH, '.winlinux-0a.part');
    assert.match(put, /foreach \(\$line in \$input\)/);
    assert.match(put, /\[IO\.FileMode\]::CreateNew/);
    assert.match(put, /\$code = 3; throw \('sha256 mismatch/);
    assert.match(put, /finally \{\n {2}if \(\$temp -and \[IO\.File\]::Exists\(\$temp\)\) \{ Remove-Item -LiteralPath \$temp/);
    // Drive admin shares map to the drive root; others by exact name.
    assert.match(get, /if \(\$share -match '\^\[A-Za-z\]\\\$\$'\) \{ \$root = \$share\.Substring\(0, 1\) \+ ':\\' \}/);
    assert.match(get, /Get-SmbShare \| Where-Object \{ \$_\.Name -eq \$share \}/);
  });
});

describe('remote path rules', () => {
  it('splits on / and \\, drops empty and . segments', () => {
    assert.deepEqual(remoteSegments('a/b\\c.txt'), ['a', 'b', 'c.txt']);
    assert.deepEqual(remoteSegments('/a//./b/'), ['a', 'b']);
    assert.deepEqual(remoteSegments("Ünï cödé/it's.txt"), ['Ünï cödé', "it's.txt"]);
  });

  it('refuses .., drive and stream syntax, control characters and an empty path', () => {
    for (const bad of ['../x', 'a/../../b', 'a\\..\\b', '..']) assert.throws(() => remoteSegments(bad), (e: unknown) => e instanceof WinLinuxUsageError && /'\.\.'/.test(e.message), bad);
    for (const bad of ['C:/x', 'a/file.txt:stream', 'a\u0000b', 'a\nb', 'a?b']) assert.throws(() => remoteSegments(bad), WinLinuxUsageError, JSON.stringify(bad));
    for (const bad of ['', '/', './.']) assert.throws(() => remoteSegments(bad), WinLinuxUsageError, JSON.stringify(bad));
  });
});

describe('Base64LineDecoder', () => {
  const data = Buffer.from(Array.from({ length: 1000 }, (_, i) => (i * 7) % 256));
  const lines = [data.subarray(0, 300), data.subarray(300, 301), data.subarray(301, 1000)];
  const text = lines.map((l) => `${l.toString('base64')}\n`).join('') + `sha256:${HASH}\n`;

  it('decodes lines split at every position, mid-line and mid-quad', () => {
    for (let cut = 1; cut < text.length; cut += 1) {
      const decoder = new Base64LineDecoder();
      const out = [...decoder.push(text.slice(0, cut)), ...decoder.push(text.slice(cut))];
      assert.ok(Buffer.concat(out).equals(data), `cut at ${cut}`);
      assert.equal(decoder.end(), HASH);
    }
  });

  it('decodes one character per Receive, and CRLF line ends', () => {
    const decoder = new Base64LineDecoder();
    const out: Buffer[] = [];
    for (const ch of text.replaceAll('\n', '\r\n')) out.push(...decoder.push(ch));
    assert.ok(Buffer.concat(out).equals(data));
    assert.equal(decoder.end(), HASH);
  });

  it('a 0-byte file is the hash line alone; a trailer without newline still counts', () => {
    const decoder = new Base64LineDecoder();
    assert.deepEqual(decoder.push(`sha256:${HASH}`), []);
    assert.equal(decoder.end(), HASH);
  });

  it('refuses a missing hash line, data after it, non-base64 and an endless line', () => {
    const protocol = (e: unknown) => e instanceof WinLinuxTransferError && e.reason === 'protocol' && e.direction === 'get';
    const noHash = new Base64LineDecoder();
    noHash.push('AAAA\n');
    assert.throws(() => noHash.end(), protocol);
    assert.throws(() => new Base64LineDecoder().push(`sha256:${HASH}\nAAAA\n`), protocol);
    assert.throws(() => new Base64LineDecoder().push('not base64!\n'), protocol);
    assert.throws(() => new Base64LineDecoder().push('AAA\n'), protocol);
    assert.throws(() => new Base64LineDecoder().push('A'.repeat(MAX_LINE_CHARS + 4)), protocol);
  });
});

describe('uploadLines', () => {
  it('sends the file as unpadded base64 lines of LINE_BYTES, then end', async () => {
    const dir = tempDir();
    try {
      const file = path.join(dir, 'f.bin');
      const data = Buffer.alloc(LINE_BYTES * 2 + 5, 9);
      fs.writeFileSync(file, data);
      const lines: string[] = [];
      for await (const chunk of uploadLines(file)) lines.push(chunk.toString('ascii'));
      assert.equal(lines.at(-1), 'end\n');
      assert.ok(lines.slice(0, -2).every((l) => !l.includes('=')), 'only the last data line has padding');
      assert.ok(Buffer.concat(lines.slice(0, -1).map((l) => Buffer.from(l.trim(), 'base64'))).equals(data));
      const empty = path.join(dir, 'empty');
      fs.writeFileSync(empty, '');
      const only: string[] = [];
      for await (const chunk of uploadLines(empty)) only.push(chunk.toString('ascii'));
      assert.deepEqual(only, ['end\n']);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

// A FakeWinrm whose transfer scripts answer from `get` (stdout text) or
// `put` (exit code and stderr).
function scripted(get: string, exitCode = 0, stderr = ''): FakeWinrm {
  const session = new FakeWinrm();
  session.inputImpl = async function* (_script, input): AsyncIterable<InputCommandChunk> {
    for await (const _chunk of input) void _chunk;
    if (get) yield { stream: 'stdout', data: get };
    if (stderr) yield { stream: 'stderr', data: stderr };
    yield { stream: 'exit', exitCode, inputComplete: true };
  };
  return session;
}

describe('hash checks', () => {
  it('get: a hash mismatch is WinLinuxTransferError (exit 5); the .part file is gone, the old file stays', async () => {
    const dir = tempDir();
    const dest = path.join(dir, 'report.csv');
    fs.writeFileSync(dest, 'original');
    const body = Buffer.from('new content');
    const session = scripted(`${body.toString('base64')}\nsha256:${HASH}\n`);
    const client = createClient('h', { ...OPTS, transfer: { via: 'winrm' } }, fakeDeps({ winrm: async () => session }));
    try {
      const err = await client.get('C$', 'report.csv', dest).catch((e: unknown) => e);
      assert.ok(err instanceof WinLinuxTransferError, String(err));
      assert.equal(err.reason, 'mismatch');
      assert.match(err.message, /sha256 mismatch/);
      assert.equal(exitCodeFor(err), EXIT.file);
      assert.deepEqual(fs.readdirSync(dir), ['report.csv']);
      assert.equal(fs.readFileSync(dest, 'utf8'), 'original');
    } finally {
      await client.close();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('put: the server reports a mismatch with exit 3; the error says so (exit 5)', async () => {
    const dir = tempDir();
    const src = path.join(dir, 'up.txt');
    fs.writeFileSync(src, 'hello');
    const session = scripted('', 3, `winlinux: sha256 mismatch: the client sent ${HASH}, the server wrote ${'b'.repeat(64)}\n`);
    const client = createClient('h', { ...OPTS, transfer: { via: 'winrm' } }, fakeDeps({ winrm: async () => session }));
    try {
      const err = await client.put(src, 'C$', 'up.txt').catch((e: unknown) => e);
      assert.ok(err instanceof WinLinuxTransferError, String(err));
      assert.equal(err.reason, 'mismatch');
      assert.equal(err.direction, 'put');
      assert.match(err.message, /^put C\$\/up\.txt over WinRM: sha256 mismatch/);
      assert.equal(exitCodeFor(err), EXIT.file);
      // The client's hash went into the script.
      const script = session.scripts[0] ?? '';
      assert.equal(assigned(script, '$expected = '), '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824');
    } finally {
      await client.close();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('put: a script that exits 0 without confirming the hash is a protocol error', async () => {
    const dir = tempDir();
    const src = path.join(dir, 'up.txt');
    fs.writeFileSync(src, 'hello');
    const client = createClient('h', { ...OPTS, transfer: { via: 'winrm' } }, fakeDeps({ winrm: async () => scripted('') }));
    try {
      await assert.rejects(client.put(src, 'C$', 'up.txt'), (e: unknown) => e instanceof WinLinuxTransferError && e.reason === 'protocol');
    } finally {
      await client.close();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('a remote failure is WinLinuxTransferError reason remote, with the server message', async () => {
    const dir = tempDir();
    const client = createClient('h', { ...OPTS, transfer: { via: 'winrm' } }, fakeDeps({ winrm: async () => scripted('', 1, "winlinux: Could not find file 'C:\\x.txt'.\n") }));
    try {
      const err = await client.get('C$', 'x.txt', path.join(dir, 'x.txt')).catch((e: unknown) => e);
      assert.ok(err instanceof WinLinuxTransferError && err.reason === 'remote', String(err));
      assert.equal(err.message, "get C$/x.txt over WinRM failed: Could not find file 'C:\\x.txt'.");
      assert.deepEqual(fs.readdirSync(dir), []);
    } finally {
      await client.close();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('transfer.via auto', () => {
  const fileAt = (dir: string) => {
    const src = path.join(dir, 'up.txt');
    fs.writeFileSync(src, 'hello');
    return src;
  };

  for (const [what, cause] of [
    ['TCP refused', systemError('ECONNREFUSED')],
    ['a connect timeout', new Error('connect_timeout')],
    ['an unreachable host', systemError('EHOSTUNREACH')],
  ] as const) {
    it(`falls back to WinRM on ${what}, tells onFallback once, and caches the decision`, async () => {
      const dir = tempDir();
      const events: Array<{ smbPort: number }> = [];
      const winrm = new FakeWinrm();
      const deps = fakeDeps({ winrm: async () => winrm, smb: async () => Promise.reject(tcpFailure(cause)) });
      const client = createClient('h', { ...OPTS, smb: { port: 4450 }, transfer: { via: 'auto', onFallback: (e) => events.push(e) } }, deps);
      try {
        // FakeWinrm confirms nothing, so the put fails after it ran over WinRM.
        await assert.rejects(client.put(fileAt(dir), 'C$', 'a.txt'), WinLinuxTransferError);
        await assert.rejects(client.put(fileAt(dir), 'C$', 'b.txt'), WinLinuxTransferError);
        assert.equal(deps.smbOpens.length, 1, 'one SMB probe for the client life');
        assert.equal(deps.smbOpens[0]?.connectTimeoutMs, 5000, 'the SMB TCP connect is bounded to 5 s');
        assert.equal(winrm.scripts.length, 2);
        assert.deepEqual(events.map((e) => e.smbPort), [4450]);
        assert.equal(fallbackNotice(4450), 'winlinux: SMB port 4450 unreachable; copying over WinRM\n');
      } finally {
        await client.close();
        fs.rmSync(dir, { recursive: true, force: true });
      }
    });
  }

  for (const [what, err, cls] of [
    ['an auth error', new SmbAuthError('logon failure', 0xc000006d), WinLinuxAuthError],
    ['access denied at session setup', new SmbAccessDeniedError('access denied', 0xc0000022), WinLinuxAuthError],
    ['a reset after the connect', tcpFailure(systemError('ECONNRESET')), WinLinuxConnectionError],
  ] as const) {
    it(`does not fall back on ${what}`, async () => {
      const dir = tempDir();
      const events: unknown[] = [];
      const winrm = new FakeWinrm();
      const deps = fakeDeps({ winrm: async () => winrm, smb: async () => Promise.reject(err) });
      const client = createClient('h', { ...OPTS, transfer: { via: 'auto', onFallback: (e) => events.push(e) } }, deps);
      try {
        await assert.rejects(client.put(fileAt(dir), 'C$', 'a.txt'), cls);
        await assert.rejects(client.get('C$', 'a.txt', path.join(dir, 'a.txt')), cls);
        assert.equal(winrm.scripts.length, 0);
        assert.equal(deps.winrmOpens.length, 0, 'WinRM never opened');
        assert.deepEqual(events, []);
      } finally {
        await client.close();
        fs.rmSync(dir, { recursive: true, force: true });
      }
    });
  }

  it('does not fall back on a file error once SMB is up, and keeps SMB', async () => {
    const dir = tempDir();
    const smb = new FakeSmb();
    smb.downloadImpl = async () => {
      throw new SmbNotFoundError('no such file', 0xc0000034);
    };
    const winrm = new FakeWinrm();
    const deps = fakeDeps({ winrm: async () => winrm, smb: async () => smb });
    const client = createClient('h', { ...OPTS, transfer: { via: 'auto' } }, deps);
    try {
      await assert.rejects(client.get('C$', 'a.txt', path.join(dir, 'a.txt')), SmbNotFoundError);
      await client.put(fileAt(dir), 'C$', 'b.txt');
      assert.equal(smb.uploads.length, 1);
      assert.equal(winrm.scripts.length, 0);
      assert.equal(deps.winrmOpens.length, 0);
    } finally {
      await client.close();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('isTcpUnreachable: real ECONNREFUSED from smb2 yes; a silent port, auth and WinRM errors no', async () => {
    const refused = await smbConnect({ host: '127.0.0.1', port: 1, authProvider: {} as never, credentials: { username: 'u' } }).catch((e: unknown) => e);
    const ctx = { protocol: 'smb' as const, host: '127.0.0.1', port: 1, mechanism: 'ntlm' as const, redact: (t: string) => t };
    const { mapSmbOpenError } = await import('../../dist/errors.js');
    assert.equal(isTcpUnreachable(mapSmbOpenError(refused, ctx)), true, String(refused));
    // A port that accepts the connect and then never answers is reachable.
    const silent = await countingListener('silent');
    try {
      const stalled = await smbConnect({ host: '127.0.0.1', port: silent.port, requestTimeoutMs: 200, authProvider: {} as never, credentials: { username: 'u' } }).catch((e: unknown) => e);
      const mapped = mapSmbOpenError(stalled, { ...ctx, port: silent.port });
      assert.ok(mapped instanceof WinLinuxConnectionError, String(mapped));
      assert.equal(isTcpUnreachable(mapped), false, String(stalled));
    } finally {
      await silent.close();
    }
    assert.equal(isTcpUnreachable(new WinLinuxConnectionError('x', 'winrm', 'h', 5985, { cause: tcpFailure(systemError('ECONNREFUSED')) })), false);
    assert.equal(isTcpUnreachable(new WinLinuxAuthError('x', 'smb', 'ntlm')), false);
    assert.equal(isTcpUnreachable(new WinLinuxConnectionError('x', 'smb', 'h', 445, { cause: new Error('connect_timeout') })), false, 'the cause must be smb2 connect error');
  });

  it("the library default is 'smb': an unreachable port 445 is a connection error, no WinRM", async () => {
    const dir = tempDir();
    const deps = fakeDeps({ smb: async () => Promise.reject(tcpFailure(systemError('ECONNREFUSED'))) });
    const client = createClient('h', OPTS, deps);
    try {
      await assert.rejects(client.put(fileAt(dir), 'C$', 'a.txt'), WinLinuxConnectionError);
      assert.equal(deps.winrmOpens.length, 0);
      await assert.rejects(client.put(fileAt(dir), 'C$', 'a.txt', { via: 'bogus' as never }), WinLinuxUsageError);
      assert.throws(() => createClient('h', { ...OPTS, transfer: { via: 'ftp' as never } }, deps), /transfer\.via must be smb, winrm or auto/);
    } finally {
      await client.close();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('--via', () => {
  it('parses auto (default), smb and winrm; refuses other values', () => {
    assert.equal(parseVia({}), 'auto');
    assert.equal(parseVia({ via: 'smb' }), 'smb');
    assert.equal(parseVia({ via: 'winrm' }), 'winrm');
    assert.equal(parseVia({ via: 'auto', recursive: true }), 'auto');
    assert.throws(() => parseVia({ via: 'WinRM' }), /--via must be auto, smb or winrm/);
    assert.throws(() => parseVia({ via: 'winrm', recursive: true }), (e: unknown) => e instanceof WinLinuxUsageError && /not supported yet/.test(e.message));
  });

  it('belongs to get and put only', async () => {
    const client = createClient('h', OPTS, fakeDeps({}));
    try {
      for (const command of ['ls', 'stat', 'run', 'mkdir'] as const) {
        const args = command === 'run' ? ['hostname'] : ['S/x'];
        await assert.rejects(execute(client, command, args, { via: 'winrm' }, capture().io), /--via applies to get and put only/);
      }
      await assert.rejects(execute(client, 'get', ['S/d'], { via: 'winrm', recursive: true }, capture().io), /not supported yet/);
      await assert.rejects(execute(client, 'put', ['.', 'S/d'], { via: 'winrm', recursive: true }, capture().io), /not supported yet/);
    } finally {
      await client.close();
    }
    assert.match(HELP, /--via <auto\|smb\|winrm>/);
    assert.match(SHELL_HELP, /get \[-r\] \[--parallel <n>\] \[--via <auto\|smb\|winrm>\]/);
  });

  it('get --via winrm prints the same line as over SMB', async () => {
    const dir = tempDir();
    const body = Buffer.from('payload');
    const { createHash } = await import('node:crypto');
    const hex = createHash('sha256').update(body).digest('hex');
    const session = scripted(`${body.toString('base64')}\nsha256:${hex}\n`);
    const client = createClient('h', OPTS, fakeDeps({ winrm: async () => session }));
    try {
      const dest = path.join(dir, 'p.txt');
      const plain = capture();
      assert.equal(await execute(client, 'get', ['C$/p.txt', dest], { via: 'winrm' }, plain.io), 0);
      assert.equal(plain.out(), `downloaded C$/p.txt -> ${dest} (7 bytes)\n`);
      const json = capture();
      assert.equal(await execute(client, 'get', ['C$/p.txt', dest], { via: 'winrm', json: true }, json.io), 0);
      assert.deepEqual(JSON.parse(json.out()), { share: 'C$', remotePath: 'p.txt', localPath: dest, sizeBytes: '7' });
      assert.equal(fs.readFileSync(dest, 'utf8'), 'payload');
    } finally {
      await client.close();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('script failure contract', () => {
  it('parses the kind, the clean message and the raw text', () => {
    const f = scriptFailure("winlinux: [notfound] Could not find file 'Data/nope.txt'.\nwinlinux-raw: Could not find file 'C:\\share\\nope.txt'.\n", 1);
    assert.deepEqual(f, { kind: 'notfound', message: "Could not find file 'Data/nope.txt'.", raw: "Could not find file 'C:\\share\\nope.txt'." });
    for (const kind of ['noshare', 'denied', 'inuse', 'isdir', 'error']) {
      assert.equal(scriptFailure(`winlinux: [${kind}] m\n`, 1).kind, kind);
    }
  });

  it('an unknown kind or the old format falls back to error with the text', () => {
    assert.deepEqual(scriptFailure('winlinux: [weird] m\n', 1), { kind: 'error', message: 'm' });
    assert.deepEqual(scriptFailure('winlinux: something broke\n', 1), { kind: 'error', message: 'something broke' });
    assert.deepEqual(scriptFailure('', 7), { kind: 'error', message: 'the remote script exited with code 7' });
  });

  it('both scripts classify .NET exceptions and hide the server path', () => {
    for (const script of [buildGetScript('Data', ['a.txt']), buildPutScript('Data', ['a.txt'], 'a'.repeat(64), '.winlinux-ab.part')]) {
      assert.match(script, /\[IO\.FileNotFoundException\]/);
      assert.match(script, /\[UnauthorizedAccessException\]/);
      assert.match(script, /HResult -band 0xFFFF\) -eq 32/);
      assert.match(script, /MethodInvocationException/);
      assert.match(script, /\$msg\.Replace\(\$full, \$share \+ '\/'/);
      assert.match(script, /'winlinux: \[' \+ \$kind \+ '\] ' \+ \$msg/);
      assert.match(script, /'winlinux-raw: ' \+ \$raw/);
    }
  });
});
