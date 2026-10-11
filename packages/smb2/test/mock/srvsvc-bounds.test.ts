// SRVSVC response framing: a fragment length of 0 or one smaller
// than the RESPONSE header, an auth trailer longer than the fragment, or a
// stub over 16 MiB fails listShares() with SmbError. A fragment length of 0
// used to loop forever on the same bytes.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { connect } from "../../src/index.js";
import { SmbError } from "../../src/errors.js";
import { StubAuthProvider } from "../helpers/stub-provider.js";
import { MockSmbServer, type MockOptions } from "./server.js";

// A RESPONSE PDU (raw writes): 16-byte header, alloc hint, context, cancel
// count, then the stub. `fragLength` and `authLength` may lie.
function response(callId: number, stub: Buffer, opts: { first?: boolean; last?: boolean; fragLength?: number; authLength?: number } = {}): Buffer {
  const out = Buffer.alloc(24 + stub.length);
  out[0] = 5;
  out[2] = 2; // RESPONSE
  out[3] = (opts.first === false ? 0 : 0x01) | (opts.last === false ? 0 : 0x02); // FIRST_FRAG, LAST_FRAG
  out.writeUInt32LE(0x10, 4);
  out.writeUInt16LE(opts.fragLength ?? out.length, 8);
  out.writeUInt16LE(opts.authLength ?? 0, 10);
  out.writeUInt32LE(callId, 12);
  out.writeUInt32LE(stub.length, 16);
  stub.copy(out, 24);
  return out;
}

// NetrShareEnum level 1 with no shares: Level, switch, container ref,
// EntriesRead 0, NULL array, TotalEntries 0, NULL resume handle, status 0.
const EMPTY_ENUM = Buffer.from([1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

async function listWith(enumPdus: MockOptions["enumPdus"]): Promise<unknown> {
  const server = new MockSmbServer({ challenge: Buffer.from("mock-challenge"), enumPdus });
  const port = await server.listen();
  try {
    const session = await connect({
      host: "127.0.0.1",
      port,
      authProvider: new StubAuthProvider({ challenge: Buffer.from("mock-challenge") }),
      credentials: { username: "u" },
      requestTimeoutMs: 3000,
    });
    try {
      return await session.listShares();
    } finally {
      await session.close().catch(() => undefined);
    }
  } finally {
    await server.close();
  }
}

const refused = (pattern: RegExp) => (error: unknown) => {
  assert.ok(error instanceof SmbError, `expected SmbError, got ${String(error)}`);
  assert.match(error.message, pattern);
  return true;
};

describe("SRVSVC response framing", () => {
  it("still joins a response split into two fragments", async () => {
    const shares = await listWith((callId) => [
      response(callId, EMPTY_ENUM.subarray(0, 12), { last: false }),
      response(callId, EMPTY_ENUM.subarray(12), { first: false }),
    ]);
    assert.deepEqual(shares, []);
  });

  for (const [name, fragLength] of [["0", 0], ["10, inside the common header", 10], ["20, inside the RESPONSE header", 20]] as const) {
    it(`a fragment length of ${name} is refused`, async () => {
      await assert.rejects(listWith((callId) => [response(callId, EMPTY_ENUM, { fragLength })]), refused(/DCE\/RPC fragment length/));
    });
  }

  it("a fragment length of 0 on a fragment that is not the last is refused, not looped on", async () => {
    await assert.rejects(listWith((callId) => [response(callId, EMPTY_ENUM, { fragLength: 0, last: false })]), refused(/DCE\/RPC fragment length/));
  });

  it("an auth trailer longer than the fragment is refused", async () => {
    await assert.rejects(listWith((callId) => [response(callId, EMPTY_ENUM, { authLength: 200 })]), refused(/DCE\/RPC fragment length/));
  });

  it("a stub over 16 MiB is refused", async () => {
    const chunk = Buffer.alloc(65535 - 24);
    const count = Math.ceil((16 * 1024 * 1024) / chunk.length) + 1;
    await assert.rejects(
      listWith((callId) => Array.from({ length: count }, (_, i) => response(callId, chunk, { first: i === 0, last: i === count - 1 }))),
      refused(/SRVSVC response stub is over the 16777216-byte limit/),
    );
  });
});
