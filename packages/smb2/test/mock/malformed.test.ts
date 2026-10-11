// Malformed responses from a server: a frame the client cannot parse
// fails every pending request with SmbError and drops the connection. It
// must never throw out of the socket "data" handler, which would be an
// uncaught exception that ends the whole process.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import PacketType from "../../src/protocol/smb2/PacketType.js";
import { connect } from "../../src/index.js";
import { SmbError } from "../../src/errors.js";
import { StubAuthProvider } from "../helpers/stub-provider.js";
import { MockSmbServer, type MockOptions } from "./server.js";

// NetBIOS header (4) + SMB2 header (64) + QUERY_DIRECTORY fixed body (8).
const QUERY_DIRECTORY_BUFFER = 4 + 64 + 8;

async function startServer(opts: MockOptions): Promise<{ server: MockSmbServer; port: number }> {
  const server = new MockSmbServer({
    challenge: Buffer.from("mock-challenge"),
    dirEntries: [
      { name: "file.txt", isDirectory: false, size: 5 },
      { name: "mydir", isDirectory: true, size: 0 },
    ],
    files: new Map([["file.txt", { data: Buffer.from("hello"), isDirectory: false }]]),
    ...opts,
  });
  return { server, port: await server.listen() };
}

const open = (port: number) =>
  connect({
    host: "127.0.0.1",
    port,
    authProvider: new StubAuthProvider({ challenge: Buffer.from("mock-challenge") }),
    credentials: { username: "u" },
    requestTimeoutMs: 3000,
  });

async function waitFor(condition: () => boolean, what: string): Promise<void> {
  const deadline = Date.now() + 2000;
  while (!condition()) {
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`);
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}

const malformed = (error: unknown) => {
  assert.ok(error instanceof SmbError, `expected SmbError, got ${String(error)}`);
  assert.match(error.message, /malformed response from server/);
  return true;
};

// Replaces the response to the first request of `type` (and only that one).
function once(type: number, rewrite: (framed: Buffer) => Buffer): MockOptions["mangle"] {
  let done = false;
  return (command, framed) => {
    if (command !== type || done) return framed;
    done = true;
    return rewrite(Buffer.from(framed));
  };
}

const cases: Array<[string, number, (framed: Buffer) => Buffer, (port: number) => Promise<unknown>]> = [
  [
    "a QUERY_DIRECTORY NextEntryOffset past the end of the buffer",
    PacketType.QueryDirectory,
    (framed) => {
      framed.writeUInt32LE(0x00100000, QUERY_DIRECTORY_BUFFER);
      return framed;
    },
    async (port) => (await open(port)).list("share"),
  ],
  [
    "a QUERY_DIRECTORY FileNameLength past the end of the entry",
    PacketType.QueryDirectory,
    (framed) => {
      framed.writeUInt32LE(0x10000, QUERY_DIRECTORY_BUFFER + 60);
      return framed;
    },
    async (port) => (await open(port)).list("share"),
  ],
  [
    "a response shorter than the SMB2 header",
    PacketType.Create,
    (framed) => {
      const short = framed.subarray(0, 4 + 20);
      short.writeUInt32BE(20, 0);
      return short;
    },
    async (port) => (await open(port)).readFile("share", "file.txt"),
  ],
  [
    "a frame whose NetBIOS message type is not zero",
    PacketType.Create,
    (framed) => {
      framed[0] = 0x01;
      return framed;
    },
    async (port) => (await open(port)).readFile("share", "file.txt"),
  ],
];

describe("malformed responses", () => {
  for (const [name, type, rewrite, run] of cases) {
    it(`${name}: the request rejects with SmbError and the connection is dropped`, async () => {
      const { server, port } = await startServer({ mangle: once(type, rewrite) });
      try {
        await assert.rejects(run(port), malformed);
        await waitFor(() => server.connectionsClosed === 1, "the client to drop the connection");
      } finally {
        await server.close();
      }
    });
  }

  // The Command is checked against the request before any parsing,
  // so an unknown command code is refused without reaching the parser.
  it("a response with an unknown command code is refused, and nothing throws", async () => {
    const { server, port } = await startServer({
      mangle: once(PacketType.Create, (framed) => {
        framed.writeUInt16LE(0x00ff, 4 + 12);
        return framed;
      }),
    });
    try {
      await assert.rejects((await open(port)).readFile("share", "file.txt"), (error: unknown) => {
        assert.ok(error instanceof SmbError, `expected SmbError, got ${String(error)}`);
        assert.match(error.message, /response command does not match the request/);
        return true;
      });
    } finally {
      await server.close();
    }
  });

  it("a later request on the dropped connection fails at once, not after the request timeout", async () => {
    const { server, port } = await startServer({
      mangle: once(PacketType.QueryDirectory, (framed) => {
        framed.writeUInt32LE(0x00100000, QUERY_DIRECTORY_BUFFER);
        return framed;
      }),
    });
    try {
      const session = await open(port);
      await assert.rejects(session.list("share"), malformed);
      const started = Date.now();
      await assert.rejects(session.readFile("share", "file.txt"));
      assert.ok(Date.now() - started < 1000);
    } finally {
      await server.close();
    }
  });
});
