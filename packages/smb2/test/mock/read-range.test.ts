// readRange against the scripted mock server: exact bytes across
// several READs of a file above the readFile cap, short reads at end of
// file, nothing past it, a file that shrank while open, the share mode of
// the CREATE, the cap, and the handle closing after an abort.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import PacketType from "../../src/protocol/smb2/PacketType.js";
import { connect, MAX_BUFFERED_FILE_BYTES, type SMBSession } from "../../src/index.js";
import { SmbAbortError, SmbFileTooLargeError, SmbNotFoundError } from "../../src/errors.js";
import { StubAuthProvider } from "../helpers/stub-provider.js";
import { MockSmbServer, type MockOptions } from "./server.js";

const MiB = 1024 * 1024;
const READ_CHUNK = 64 * 1024;

function patternBytes(length: number): Buffer {
  const out = Buffer.alloc(length);
  for (let index = 0; index < length; index++) out[index] = (index * 7 + (index >>> 10)) % 251;
  return out;
}

// 65 MiB: above the 64 MiB readFile cap, so only readRange can read it.
const BIG = patternBytes(65 * MiB);
const SMALL = Buffer.from("0123456789abcdef");

async function startServer(opts: MockOptions = {}): Promise<{ server: MockSmbServer; port: number }> {
  const server = new MockSmbServer({
    challenge: Buffer.from("mock-challenge"),
    files: new Map([
      ["big.log", { data: BIG, isDirectory: false }],
      ["small.txt", { data: SMALL, isDirectory: false }],
      ["empty.txt", { data: Buffer.alloc(0), isDirectory: false }],
    ]),
    ...opts,
  });
  return { server, port: await server.listen() };
}

const open = (port: number): Promise<SMBSession> =>
  connect({
    host: "127.0.0.1",
    port,
    authProvider: new StubAuthProvider({ challenge: Buffer.from("mock-challenge") }),
    credentials: { username: "u" },
    requestTimeoutMs: 5000,
  });

const count = (server: MockSmbServer, type: number) => server.seen.filter((request) => request.type === type).length;

async function waitFor(condition: () => boolean, what: string): Promise<void> {
  const deadline = Date.now() + 2000;
  while (!condition()) {
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`);
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}

describe("readRange", () => {
  it("returns the exact bytes of a range that spans several READs, in a file above the readFile cap", async () => {
    const { server, port } = await startServer();
    try {
      const session = await open(port);
      await assert.rejects(session.readFile("share", "big.log"), SmbFileTooLargeError);
      const offset = 64 * MiB - 100; // crosses the 64 MiB boundary
      const length = MiB;
      const reads = count(server, PacketType.Read);
      const data = await session.readRange("share", "big.log", offset, length);
      assert.equal(data.length, length);
      assert.ok(data.equals(BIG.subarray(offset, offset + length)));
      assert.equal(count(server, PacketType.Read) - reads, Math.ceil(length / READ_CHUNK), "one READ per 64 KiB");
      // A bigint offset reads the same bytes.
      assert.ok((await session.readRange("share", "big.log", BigInt(offset), 4096)).equals(BIG.subarray(offset, offset + 4096)));
      // The head of the file, as a log reader reads it first.
      assert.ok((await session.readRange("share", "big.log", 0, 8192)).equals(BIG.subarray(0, 8192)));
      await session.close();
    } finally {
      await server.close();
    }
  });

  it("returns the remaining bytes at end of file, and an empty Buffer past it without a READ", async () => {
    const { server, port } = await startServer();
    try {
      const session = await open(port);
      assert.ok((await session.readRange("share", "small.txt", 10, 100)).equals(SMALL.subarray(10)));
      const reads = count(server, PacketType.Read);
      assert.equal((await session.readRange("share", "small.txt", 16, 100)).length, 0, "at end of file");
      assert.equal((await session.readRange("share", "small.txt", 1000, 100)).length, 0, "past end of file");
      assert.equal((await session.readRange("share", "empty.txt", 0, 100)).length, 0, "an empty file");
      assert.equal((await session.readRange("share", "small.txt", 3, 0)).length, 0, "a zero-length range");
      assert.equal(count(server, PacketType.Read), reads, "no READ for a range that starts at or past the end");
      assert.equal(count(server, PacketType.Create), count(server, PacketType.Close), "every handle closed");
      await session.close();
    } finally {
      await server.close();
    }
  });

  it("returns what is left of a file that shrank after the open (STATUS_END_OF_FILE on a READ)", async () => {
    const { server, port } = await startServer({ shrinkAfterOpen: new Map([["big.log", 64 * 1024 + 500]]) });
    try {
      const session = await open(port);
      const data = await session.readRange("share", "big.log", 0, 3 * READ_CHUNK);
      assert.equal(data.length, 64 * 1024 + 500, "two READs: a full one and a short one; the third hits END_OF_FILE");
      assert.ok(data.equals(BIG.subarray(0, 64 * 1024 + 500)));
      assert.equal((await session.readRange("share", "big.log", 2 * READ_CHUNK, 100)).length, 0, "past the new end");
      await session.close();
    } finally {
      await server.close();
    }
  });

  it("opens the file read-only with share access read, write and delete", async () => {
    const { server, port } = await startServer();
    try {
      const session = await open(port);
      await session.readRange("share", "small.txt", 0, 4);
      const create = server.creates.find((c) => c.name === "small.txt");
      assert.ok(create);
      assert.equal(create.desiredAccess, 0x1, "FILE_READ_DATA only");
      assert.equal(create.shareAccess, 0x7, "FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE");
      await session.close();
    } finally {
      await server.close();
    }
  });

  it("refuses a length above the buffer cap before any request, and bad offsets and lengths", async () => {
    const { server, port } = await startServer();
    try {
      const session = await open(port);
      const seen = server.seen.length;
      await assert.rejects(session.readRange("share", "big.log", 0, MAX_BUFFERED_FILE_BYTES + 1), SmbFileTooLargeError);
      await assert.rejects(session.readRange("share", "big.log", -1, 10), RangeError);
      await assert.rejects(session.readRange("share", "big.log", -1n, 10), RangeError);
      await assert.rejects(session.readRange("share", "big.log", 1.5, 10), RangeError);
      await assert.rejects(session.readRange("share", "big.log", 0, -10), RangeError);
      assert.equal(server.seen.length, seen, "nothing went out");
      assert.equal((await session.readRange("share", "big.log", 0, MAX_BUFFERED_FILE_BYTES)).length, MAX_BUFFERED_FILE_BYTES, "the cap itself is allowed");
      await session.close();
    } finally {
      await server.close();
    }
  });

  it("maps a missing file to SmbNotFoundError, and closes the handle after an abort mid-range", async () => {
    const { server, port } = await startServer({
      createErrors: new Map([["missing.log", 0xc0000034]]),
      responseDelayMs: (type, nth) => (type === PacketType.Read && nth === 2 ? 300 : 0),
    });
    try {
      const session = await open(port);
      await assert.rejects(session.readRange("share", "missing.log", 0, 10), SmbNotFoundError);
      const controller = new AbortController();
      const reading = session.readRange("share", "big.log", 0, 4 * READ_CHUNK, { signal: controller.signal });
      reading.catch(() => undefined);
      await waitFor(() => count(server, PacketType.Read) === 2, "the second READ");
      const closes = count(server, PacketType.Close);
      controller.abort();
      await assert.rejects(reading, (error: unknown) => {
        assert.ok(error instanceof SmbAbortError);
        assert.equal(error.message, "read share/big.log at 0 was aborted");
        return true;
      });
      await waitFor(() => count(server, PacketType.Close) === closes + 1, "the CLOSE after the abort");
      assert.equal(count(server, PacketType.Read), 2, "no further READ");
      assert.ok((await session.readRange("share", "small.txt", 0, 4)).equals(SMALL.subarray(0, 4)), "the session stays usable");
      await session.close();
    } finally {
      await server.close();
    }
  });
});
