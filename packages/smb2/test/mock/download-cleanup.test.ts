// An aborted or failed download leaves no partial file, against the
// scripted mock server: the call rejects with the original error, and the
// local path does not exist afterwards. A successful download is unchanged.
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

const BIG = patternBytes(200000); // 4 READs of 64 KB

async function startServer(opts: MockOptions = {}): Promise<{ server: MockSmbServer; port: number }> {
  const server = new MockSmbServer({
    challenge: Buffer.from("mock-challenge"),
    files: new Map([
      ["big.bin", { data: BIG, isDirectory: false }],
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

const count = (server: MockSmbServer, type: number) => server.seen.filter((request) => request.type === type).length;

describe("download leaves no partial file", () => {
  it("an abort during the second READ rejects with SmbAbortError and the local path does not exist", async () => {
    const { server, port } = await startServer({ responseDelayMs: (type, nth) => (type === PacketType.Read && nth === 2 ? STALL_MS : 0) });
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "smb-partial-"));
    try {
      const session = await open(port);
      const controller = new AbortController();
      const local = path.join(tempDir, "big.bin");
      const downloading = session.download("share", "big.bin", local, { signal: controller.signal });
      downloading.catch(() => undefined);
      await waitFor(() => count(server, PacketType.Read) === 2, "the second READ");
      controller.abort();
      await assert.rejects(downloading, (error: unknown) => {
        assert.ok(error instanceof SmbAbortError, `expected SmbAbortError, got ${String(error)}`);
        return true;
      });
      assert.equal(fs.existsSync(local), false, "no partial file at the local path");
      assert.deepEqual(fs.readdirSync(tempDir), [], "nothing else left behind");
      await waitFor(() => count(server, PacketType.Close) >= 1, "the CLOSE");
      await session.close();
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
      await server.close();
    }
  });

  it("a READ error mid-transfer rejects with SmbError and leaves no file", async () => {
    // The file shrank after the CREATE: the second READ fails with
    // STATUS_END_OF_FILE, which createReadStream reports as an error.
    const { server, port } = await startServer({ shrinkAfterOpen: new Map([["big.bin", 65536]]) });
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "smb-partial-"));
    try {
      const session = await open(port);
      const local = path.join(tempDir, "big.bin");
      await assert.rejects(session.download("share", "big.bin", local), (error: unknown) => {
        assert.ok(error instanceof SmbError, `expected SmbError, got ${String(error)}`);
        assert.ok(!(error instanceof SmbAbortError));
        assert.match(error.message, /download share\/big\.bin to /);
        return true;
      });
      assert.equal(count(server, PacketType.Read), 2, "the first READ succeeded, the second failed");
      assert.equal(fs.existsSync(local), false, "no partial file at the local path");
      // The session is still usable and a good download is unchanged.
      await session.download("share", "file.txt", path.join(tempDir, "file.txt"));
      assert.equal(fs.readFileSync(path.join(tempDir, "file.txt")).toString(), "hello");
      await session.close();
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
      await server.close();
    }
  });

  it("a failed CREATE leaves an existing local file untouched", async () => {
    const { server, port } = await startServer();
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "smb-partial-"));
    try {
      const session = await open(port);
      const local = path.join(tempDir, "report.docx");
      fs.writeFileSync(local, "keep me");
      await assert.rejects(session.download("share", "missing.txt", local), SmbError);
      assert.equal(count(server, PacketType.Read), 0, "no READ went out");
      assert.equal(fs.readFileSync(local, "utf8"), "keep me", "the existing file is untouched");
      await session.close();
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
      await server.close();
    }
  });

  it("a successful download writes the whole file", async () => {
    const { server, port } = await startServer();
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "smb-partial-"));
    try {
      const session = await open(port);
      const local = path.join(tempDir, "big.bin");
      await session.download("share", "big.bin", local);
      assert.ok(fs.readFileSync(local).equals(BIG));
      assert.equal(count(server, PacketType.Read), 4);
      await session.close();
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
      await server.close();
    }
  });
});
