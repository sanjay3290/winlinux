// The no-echo prompt switches the terminal to raw mode before it prints
// "Password: ". In the other order a key typed as soon as the prompt
// appears could be echoed by the terminal; the pty suite caught that race.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { promptPassword, PromptInterrupted } from '../../dist/cli/password.js';

function fakeTty() {
  const events: string[] = [];
  const stdin = Object.assign(new EventEmitter(), {
    isRaw: false,
    setRawMode(on: boolean) {
      events.push(`raw ${on}`);
      this.isRaw = on;
      return this;
    },
    setEncoding: () => undefined,
    resume: () => events.push('resume'),
    pause: () => events.push('pause'),
  });
  const stderr = { write: (text: string) => events.push(`write ${JSON.stringify(text)}`) };
  return { stdin: stdin as unknown as NodeJS.ReadStream, stderr: stderr as unknown as NodeJS.WritableStream, events, emit: (s: string) => stdin.emit('data', s) };
}

describe('promptPassword', () => {
  it('enters raw mode before writing the prompt, and restores it after', async () => {
    const tty = fakeTty();
    const answer = promptPassword(tty.stdin, tty.stderr);
    assert.deepEqual(tty.events.slice(0, 2), ['raw true', 'write "Password: "']);
    tty.emit('s3cr\u007fret\r');
    assert.equal(await answer, 's3cret');
    assert.deepEqual(tty.events.slice(-3), ['raw false', 'pause', 'write "\\n"']);
  });

  it('Ctrl+C restores the mode and rejects with PromptInterrupted', async () => {
    const tty = fakeTty();
    const answer = promptPassword(tty.stdin, tty.stderr);
    tty.emit('ab\u0003');
    await assert.rejects(answer, PromptInterrupted);
    assert.ok(tty.events.includes('raw false'));
  });
});
