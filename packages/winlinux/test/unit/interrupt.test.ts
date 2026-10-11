// First Ctrl+C in a subcommand: `run` waits for the aborted
// command's Signal and Delete; every other command closes at once, so a
// stalled `get` still removes its .part file.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { interruptSubcommand } from '../../dist/cli/app.js';
import type { WinLinuxClient } from '../../dist/types.js';

function fakeClient(): { client: WinLinuxClient; closes: () => number } {
  let closes = 0;
  const client = { close: async () => void (closes += 1) } as unknown as WinLinuxClient;
  return { client, closes: () => closes };
}

const tick = () => new Promise((resolve) => setImmediate(resolve));

describe('interruptSubcommand', () => {
  it('closes at once for a stalled get', async () => {
    const { client, closes } = fakeClient();
    const abort = new AbortController();
    const stalled = new Promise<number>(() => undefined);
    const done = interruptSubcommand('get', client, stalled, abort);
    await tick();
    assert.equal(closes(), 1, 'close() runs without waiting for the transfer');
    await done;
  });

  it('aborts run and closes only after the run settles', async () => {
    const { client, closes } = fakeClient();
    const abort = new AbortController();
    let settle!: () => void;
    const running = new Promise<number>((_resolve, reject) => (settle = () => reject(new Error('aborted'))));
    const done = interruptSubcommand('run', client, running, abort);
    assert.equal(abort.signal.aborted, true);
    await tick();
    assert.equal(closes(), 0, 'Signal and Delete go out before close()');
    settle();
    await done;
    assert.equal(closes(), 1);
  });
});
