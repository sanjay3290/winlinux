// Server text on the terminal: event messages, file, share, service
// and process names reach the screen with C0, DEL and C1 controls made
// visible (\xNN), so a hostile server cannot clear the screen, move the
// cursor or set the window title. --json stays raw: JSON escapes C0 itself.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { PassThrough } from 'node:stream';
import { SmbError, SmbNotFoundError, type DirEntry } from '@winlinux/smb2';
import { createClient } from '../../dist/client.js';
import { execute, printError, type Io } from '../../dist/cli/app.js';
import { formatEvents, formatLs, formatProcesses, formatServices, formatShares, formatStat } from '../../dist/cli/output.js';
import { checkRemoteName } from '../../dist/tree.js';
import { FakeSmb, fakeDeps } from '../helpers/fakes.js';

// Clear screen, set the window title (OSC ... BEL), a bare CR, DEL and a C1 CSI.
const HOSTILE = '\x1b[2Jcleared\x1b]0;owned\x07 back\rCR del\x7f c1\x9b31m';
const SHOWN = '\\x1b[2Jcleared\\x1b]0;owned\\x07 back\\x0dCR del\\x7f c1\\x9b31m';
// Any control a terminal acts on, except tab and the newline that ends a line.
const CONTROL = /[\x00-\x08\x0b-\x1f\x7f-\x9f]/;

function lines(text: string): string[] {
  return text.split('\n');
}

function assertInert(text: string): void {
  for (const line of lines(text)) assert.ok(!CONTROL.test(line), `control character in ${JSON.stringify(line)}`);
}

function capture(tty = false): { io: Io; out: () => string; err: () => string } {
  const stdout = new PassThrough();
  const stderr = Object.assign(new PassThrough(), { isTTY: tty });
  let out = '';
  let err = '';
  stdout.on('data', (d: Buffer) => (out += d.toString()));
  stderr.on('data', (d: Buffer) => (err += d.toString()));
  return { io: { env: {}, stdin: process.stdin, stdout, stderr }, out: () => out, err: () => err };
}

const entry = (name: string): DirEntry => ({ name, isDirectory: false, sizeBytes: 1n, mtime: new Date(0), isReparsePoint: false });

describe('server text in tables and listings', () => {
  it('event log: provider and message show their controls as \\xNN', () => {
    const text = formatEvents([{ timeCreated: '2026-10-11T00:00:00Z', level: 'Error', id: 7, provider: `prov${HOSTILE}`, message: `${HOSTILE}\nsecond line` }]);
    assertInert(text);
    assert.ok(text.includes(`prov${SHOWN}`), text);
    assert.ok(text.includes(SHOWN), text);
    assert.ok(!text.includes('second line'), 'still only the first line of the message');
  });

  it('shares, services, processes and stat', () => {
    for (const text of [
      formatShares([{ name: `s${HOSTILE}`, type: 'disk', comment: HOSTILE }]),
      formatServices([{ name: `svc${HOSTILE}`, displayName: HOSTILE, status: 'Running', startType: 'Automatic' }]),
      formatProcesses([{ id: 4, name: `p${HOSTILE}`, cpuSeconds: 1, workingSetBytes: 2, startTime: null }]),
      formatStat('S', `dir/${HOSTILE}`, { isDirectory: false, sizeBytes: 1n, mtime: new Date(0), atime: new Date(0), readonly: false }),
    ]) {
      assertInert(text);
      assert.ok(text.includes(SHOWN), text);
    }
  });

  it('ls names', () => {
    const text = formatLs([entry(`f${HOSTILE}`), entry('tab\there')]);
    assertInert(text);
    assert.ok(text.includes(`f${SHOWN}\n`), text);
    assert.ok(text.includes('tab\there\n'), 'a tab is left alone');
  });

  it('--json keeps the raw strings; the table escapes them', async () => {
    const smb = new FakeSmb();
    smb.listImpl = async () => [entry(`f${HOSTILE}`)];
    const client = createClient('h', { username: 'u', password: 'p', auth: 'ntlm' }, fakeDeps({ smb: async () => smb }));
    try {
      const json = capture();
      assert.equal(await execute(client, 'ls', ['S'], { json: true }, json.io), 0);
      assert.equal(JSON.parse(json.out())[0].name, `f${HOSTILE}`);
      const table = capture();
      assert.equal(await execute(client, 'ls', ['S'], {}, table.io), 0);
      assertInert(table.out());
      assert.ok(table.out().includes(`f${SHOWN}`));
    } finally {
      await client.close();
    }
  });
});

describe('progress lines and errors', () => {
  it('put -r progress and summary lines on a TTY show local names with controls escaped', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'winlinux-terminal-'));
    const name = 'c1\x9b31m-del\x7f.txt'; // a Linux name can hold both; Windows allows them too
    fs.mkdirSync(path.join(dir, 'up'));
    fs.writeFileSync(path.join(dir, 'up', name), 'abc');
    const smb = new FakeSmb();
    smb.statImpl = async (_s, p) => {
      throw new SmbNotFoundError(`no such file or directory: stat S/${p}`, 0xc0000034);
    };
    const client = createClient('h', { username: 'u', password: 'p', auth: 'ntlm' }, fakeDeps({ smb: async () => smb }));
    try {
      const tty = capture(true);
      assert.equal(await execute(client, 'put', [path.join(dir, 'up'), 'S/dest'], { recursive: true }, tty.io), 0);
      // The progress line's own \r\x1b[K is ours; the name's controls are not.
      const shown = tty.err().replaceAll('\r\x1b[K', '');
      assertInert(shown);
      assert.ok(shown.includes('c1\\x9b31m-del\\x7f.txt'), shown);
    } finally {
      await client.close();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('error messages keep their newlines and show other controls escaped', () => {
    const io = capture();
    const err = new SmbError(`share comment says ${HOSTILE}\nsee the server log`);
    const cause = new Error(`cause ${HOSTILE}`);
    (err as { cause?: unknown }).cause = cause;
    printError(err, io.io, { username: 'u' }, { json: false, verbose: true });
    const text = io.err();
    assertInert(text);
    assert.ok(text.includes(`share comment says ${SHOWN}\nsee the server log`), text);
    assert.ok(text.includes(`cause ${SHOWN}`), text);
  });
});

describe('remote names with control characters', () => {
  for (const platform of ['linux', 'darwin', 'win32'] as const) {
    it(`${platform}: refused, and the message shows them escaped`, () => {
      for (const bad of ['a\x1bb', 'a\x07b', 'a\rb', 'a\nb', 'a\tb', 'a\x7fb', 'a\x9bb', 'a\x85b']) {
        assert.throws(
          () => checkRemoteName(bad, platform),
          (error: unknown) => {
            assert.ok(error instanceof SmbError, String(error));
            assert.ok(!CONTROL.test(error.message.replaceAll('\n', '')) && !error.message.includes('\n'), JSON.stringify(error.message));
            return true;
          },
          JSON.stringify(bad),
        );
      }
      checkRemoteName('plain é 日本.txt', platform);
    });
  }
});
