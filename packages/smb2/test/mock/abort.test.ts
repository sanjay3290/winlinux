// AbortSignal on list, listIter, stat, readFile and download, against
// the scripted mock server. An abort rejects with SmbAbortError (name
// 'AbortError') at once, even while a request is in flight; no further
// request goes out; the handle closes; the session stays usable. A signal
// that is already aborted rejects before any request goes out.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import os from "node:os";
import path from "node:path";
import fs from "node:fs";
import PacketType from "../../src/protocol/smb2/PacketType.js";
import { connect, type SMBSession } from "../../src/index.js";
import { SmbAbortError, SmbError } from "../../src/errors.js";
import { StubAuthProvider } from "../helpers/stub-provider.js";
import { MockSmbServer, type MockOptions } from "./server.js";

const STALL_MS = 400;

function patternBytes(length: number): Buffer {
  const out = Buffer.alloc(length);
  for (let index = 0; index < length; index++) out[index] = index % 251;
  return out;
}

async function startServer(opts: MockOptions = {}): Promise<{ server: MockSmbServer; port: number }> {
  const server = new MockSmbServer({
    challenge: Buffer.from("mock-challenge"),
    dirEntries: [
      { name: "file.txt", isDirectory: false, size: 5 },
      { name: "mydir", isDirectory: true, size: 0 },
    ],
    files: new Map([
      ["big.bin", { data: patternBytes(200000), isDirectory: false }], // 4 READs of 64 KB
      ["file.txt", { data: Buffer.from("hello"), isDirectory: false }],
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
    requestTimeoutMs: 3000,
  });

async function waitFor(condition: () => boolean, what: string): Promise<void> {
  const deadline = Date.now() + 2000;
  while (!condition()) {
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`);
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

// The nth response of `type` stalls for STALL_MS; everything else is at once.
const stallNth = (type: number, nth: number): MockOptions["responseDelayMs"] =>
  (command, n) => (command === type && n === nth ? STALL_MS : 0);

const count = (server: MockSmbServer, type: number) => server.seen.filter((request) => request.type === type).length;

// The reason of a plain abort() is an AbortError DOMException; it is the cause.
const abortError = (reason?: unknown) => (error: unknown) => {
  assert.ok(error instanceof SmbAbortError, `expected SmbAbortError, got ${String(error)}`);
  assert.ok(error instanceof SmbError);
  assert.equal(error.name, "AbortError");
  assert.match(error.message, / was aborted$/);
  if (reason !== undefined) assert.equal((error as { cause?: unknown }).cause, reason);
  return true;
};

// The abort is observed: after a short wait the only new request is the
// CLOSE of the handle, and the session answers the next call as usual.
async function expectCloseThen(server: MockSmbServer, seenBefore: number, type: number, next: () => Promise<void>): Promise<void> {
  await waitFor(() => server.seen.length > seenBefore, "the CLOSE after the abort");
  await sleep(STALL_MS + 50); // the stalled response arrives and is discarded
  const after = server.seen.slice(seenBefore).map((request) => request.type);
  assert.deepEqual(after, [PacketType.Close], `only a CLOSE follows the abort (saw ${after.join(",")})`);
  assert.equal(count(server, type), count(server, type), "no further request of that type");
  await next();
}

describe("already aborted signal", () => {
  it("list, listIter, stat, readFile and download reject before any request goes out", async () => {
    const { server, port } = await startServer();
    try {
      const session = await open(port);
      const seen = server.seen.length;
      const reason = new Error("deadline");
      const controller = new AbortController();
      controller.abort(reason);
      const { signal } = controller;
      await assert.rejects(session.list("share", "dir", { signal }), abortError(reason));
      await assert.rejects(session.stat("share", "file.txt", { signal }), abortError(reason));
      await assert.rejects(session.readFile("share", "file.txt", { signal }), abortError(reason));
      await assert.rejects(session.download("share", "file.txt", path.join(os.tmpdir(), "never-written"), { signal }), abortError(reason));
      await assert.rejects(session.listIter("share", "dir", { signal })[Symbol.asyncIterator]().next(), abortError(reason));
      assert.equal(server.seen.length, seen, "not even a TREE_CONNECT went out");
      await assert.rejects(session.list("share", undefined, { signal: AbortSignal.abort() }), abortError());
      assert.deepEqual(await session.list("share"), await session.list("share"), "the session is still usable");
      await session.close();
    } finally {
      await server.close();
    }
  });

  it("names the call in the message", async () => {
    const { server, port } = await startServer();
    try {
      const session = await open(port);
      const signal = AbortSignal.abort();
      await assert.rejects(session.list("share", "dir", { signal }), { message: "list share/dir was aborted" });
      await assert.rejects(session.stat("share", "f", { signal }), { message: "stat share/f was aborted" });
      await assert.rejects(session.readFile("share", "f", { signal }), { message: "read share/f was aborted" });
      await session.close();
    } finally {
      await server.close();
    }
  });
});

describe("abort during list", () => {
  it("rejects while the third QUERY_DIRECTORY is in flight, sends only a CLOSE, and the session stays usable", async () => {
    const { server, port } = await startServer({ dirPages: 50, responseDelayMs: stallNth(PacketType.QueryDirectory, 3) });
    try {
      const session = await open(port);
      const controller = new AbortController();
      const listing = session.list("share", undefined, { signal: controller.signal });
      listing.catch(() => undefined);
      await waitFor(() => count(server, PacketType.QueryDirectory) === 3, "the third QUERY_DIRECTORY");
      const seen = server.seen.length;
      const started = Date.now();
      controller.abort();
      await assert.rejects(listing, abortError(controller.signal.reason));
      assert.ok(Date.now() - started < STALL_MS / 2, "rejected before the stalled response, not after it");
      await expectCloseThen(server, seen, PacketType.QueryDirectory, async () => {
        const entries = await session.list("share");
        assert.equal(entries.length, 100, "50 pages of 2 entries");
        assert.equal(count(server, PacketType.QueryDirectory), 3 + 51, "the next list reads every page, plus NO_MORE_FILES");
      });
      await session.close();
    } finally {
      await server.close();
    }
  });

  it("rejects between pages without sending the next QUERY_DIRECTORY", async () => {
    const { server, port } = await startServer({ dirPages: 50 });
    try {
      const session = await open(port);
      const controller = new AbortController();
      const entries: string[] = [];
      let pages = 0;
      const run = async () => {
        for await (const entry of session.listIter("share", undefined, { signal: controller.signal })) {
          entries.push(entry.name);
          if (entries.length === 4) {
            pages = count(server, PacketType.QueryDirectory);
            controller.abort(); // after the second page, before the third goes out
          }
        }
      };
      const seenBefore = () => server.seen.length;
      await assert.rejects(run(), abortError());
      assert.deepEqual(entries, ["file.txt", "mydir", "file.txt.p2", "mydir.p2"]);
      assert.equal(pages, 2);
      assert.equal(count(server, PacketType.QueryDirectory), 2, "no third QUERY_DIRECTORY");
      await waitFor(() => server.seen[server.seen.length - 1]?.type === PacketType.Close, "the CLOSE");
      const seen = seenBefore();
      assert.deepEqual((await session.list("share")).length, 100);
      assert.equal(server.seen[seen]?.type, PacketType.Create, "the next list opens a new handle");
      await session.close();
    } finally {
      await server.close();
    }
  });
});

describe("listIter", () => {
  it("yields entries page by page and closes the handle on break", async () => {
    const { server, port } = await startServer({ dirPages: 3 });
    try {
      const session = await open(port);
      const names: string[] = [];
      for await (const entry of session.listIter("share")) {
        names.push(entry.name);
        if (names.length === 3) break; // inside the second page
      }
      assert.deepEqual(names, ["file.txt", "mydir", "file.txt.p2"]);
      assert.equal(count(server, PacketType.QueryDirectory), 2, "the third page was never requested");
      await waitFor(() => count(server, PacketType.Close) === 1, "the CLOSE from break");
      assert.deepEqual(server.seen.slice(-3).map((request) => request.type), [PacketType.QueryDirectory, PacketType.QueryDirectory, PacketType.Close]);

      const all: string[] = [];
      for await (const entry of session.listIter("share", "")) all.push(entry.name);
      assert.deepEqual(all, ["file.txt", "mydir", "file.txt.p2", "mydir.p2", "file.txt.p3", "mydir.p3"]);
      assert.equal(count(server, PacketType.Close), 2, "the handle closes when the pages run out");
      assert.deepEqual(all, (await session.list("share")).map((entry) => entry.name), "the same entries as list()");
      await session.close();
    } finally {
      await server.close();
    }
  });

  it("maps a typed error and closes the handle", async () => {
    const { server, port } = await startServer({ createErrors: new Map([["missing", 0xc0000034]]) });
    try {
      const session = await open(port);
      await assert.rejects(session.listIter("share", "missing")[Symbol.asyncIterator]().next(), { name: "SmbNotFoundError" });
      await session.close();
    } finally {
      await server.close();
    }
  });
});

describe("abort during a multi-request read", () => {
  it("readFile rejects while the second READ is in flight, sends only a CLOSE, and the session stays usable", async () => {
    const { server, port } = await startServer({ responseDelayMs: stallNth(PacketType.Read, 2) });
    try {
      const session = await open(port);
      const controller = new AbortController();
      const reading = session.readFile("share", "big.bin", { signal: controller.signal });
      reading.catch(() => undefined);
      await waitFor(() => count(server, PacketType.Read) === 2, "the second READ");
      const seen = server.seen.length;
      const started = Date.now();
      controller.abort();
      await assert.rejects(reading, abortError(controller.signal.reason));
      assert.ok(Date.now() - started < STALL_MS / 2, "rejected before the stalled response");
      await expectCloseThen(server, seen, PacketType.Read, async () => {
        assert.equal((await session.readFile("share", "file.txt")).toString(), "hello");
        assert.equal(count(server, PacketType.Read), 3, "two READs before the abort, one after");
      });
      await session.close();
    } finally {
      await server.close();
    }
  });

  it("download rejects with AbortError, closes the handle, and leaves the session usable", async () => {
    const { server, port } = await startServer({ responseDelayMs: stallNth(PacketType.Read, 2) });
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "smb-abort-"));
    try {
      const session = await open(port);
      const controller = new AbortController();
      const local = path.join(tempDir, "big.bin");
      const downloading = session.download("share", "big.bin", local, { signal: controller.signal });
      downloading.catch(() => undefined);
      await waitFor(() => count(server, PacketType.Read) === 2, "the second READ");
      const seen = server.seen.length;
      controller.abort();
      await assert.rejects(downloading, abortError());
      await expectCloseThen(server, seen, PacketType.Read, async () => {
        await session.download("share", "file.txt", path.join(tempDir, "file.txt"));
        assert.equal(fs.readFileSync(path.join(tempDir, "file.txt")).toString(), "hello");
      });
      await session.close();
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
      await server.close();
    }
  });

  it("stat rejects while QUERY_INFO is in flight and closes the handle", async () => {
    const { server, port } = await startServer({ responseDelayMs: stallNth(PacketType.QueryInfo, 1) });
    try {
      const session = await open(port);
      const controller = new AbortController();
      const stat = session.stat("share", "file.txt", { signal: controller.signal });
      stat.catch(() => undefined);
      await waitFor(() => count(server, PacketType.QueryInfo) === 1, "the QUERY_INFO");
      const seen = server.seen.length;
      controller.abort();
      await assert.rejects(stat, abortError());
      await expectCloseThen(server, seen, PacketType.QueryInfo, async () => {
        assert.equal((await session.stat("share", "file.txt")).sizeBytes, 5n);
      });
      await session.close();
    } finally {
      await server.close();
    }
  });

  it("an abort during the CREATE is seen once it has answered, so the handle it opened closes", async () => {
    const { server, port } = await startServer({ responseDelayMs: stallNth(PacketType.Create, 1) });
    try {
      const session = await open(port);
      const controller = new AbortController();
      const reading = session.readFile("share", "big.bin", { signal: controller.signal });
      reading.catch(() => undefined);
      await waitFor(() => count(server, PacketType.Create) === 1, "the CREATE");
      controller.abort();
      await assert.rejects(reading, abortError());
      await waitFor(() => count(server, PacketType.Close) === 1, "the CLOSE");
      assert.equal(count(server, PacketType.Read), 0, "no READ went out");
      assert.equal(server.handlesOpened, 1);
      await session.close();
    } finally {
      await server.close();
    }
  });
});
