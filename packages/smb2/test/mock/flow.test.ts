// Mock-server tests: the full public API against a scripted localhost SMB2
// server. Covers connect->setup->tree->read->close, signed flows, tampered
// signatures, multi-credit reads, and error statuses -> typed errors.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import os from "node:os";
import path from "node:path";
import fs from "node:fs";
import PacketType from "../../src/protocol/smb2/PacketType.js";
import Client from "../../src/client/Client.js";
import { connect } from "../../src/index.js";
import {
  SmbAccessDeniedError,
  SmbAlreadyExistsError,
  SmbDirectoryNotEmptyError,
  SmbEncryptionRequiredError,
  SmbError,
  SmbIsADirectoryError,
  SmbNotADirectoryError,
  SmbNotFoundError,
  SmbSigningError,
} from "../../src/errors.js";
import { StubAuthProvider } from "../helpers/stub-provider.js";
import { MockSmbServer, type MockOptions } from "./server.js";

// Hand-built NetrShareEnum level-1 response stub (raw writes, no SUT
// code): shares MockShare/disk and IPC$/ipc.
function mockEnumStub(): Buffer {
  const parts: Buffer[] = [];
  const u32 = (value: number) => {
    const out = Buffer.alloc(4);
    out.writeUInt32LE(value >>> 0);
    parts.push(out);
  };
  const cvString = (text: string) => {
    u32(text.length + 1);
    u32(0);
    u32(text.length + 1);
    const chars = Buffer.from(text + "\0", "utf16le");
    parts.push(chars);
    if (chars.length % 4 !== 0) parts.push(Buffer.alloc(4 - (chars.length % 4)));
  };
  u32(1); // InfoStruct.Level
  u32(1); // union switch
  u32(0x100); // Level1 container
  u32(2); // EntriesRead
  u32(0x104); // Buffer array
  u32(2); // conformant max_count
  u32(0x108); u32(0); u32(0x10c);
  u32(0x110); u32(3); u32(0);
  cvString("MockShare");
  cvString("mock disk");
  cvString("IPC$");
  u32(2); // TotalEntries
  u32(0x200); // ResumeHandle pointer
  u32(0); // resume value
  u32(0); // status
  return Buffer.concat(parts);
}

function patternBytes(length: number): Buffer {
  const out = Buffer.alloc(length);
  for (let index = 0; index < length; index++) out[index] = index % 251;
  return out;
}

const sessionKey = Buffer.from("0123456789abcdef");

async function waitFor(condition: () => boolean, what: string): Promise<void> {
  const deadline = Date.now() + 2000;
  while (!condition()) {
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`);
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}

async function startServer(opts: MockOptions = {}): Promise<{ server: MockSmbServer; port: number }> {
  const server = new MockSmbServer({
    challenge: Buffer.from("mock-challenge"),
    enumStub: mockEnumStub(),
    dirEntries: [
      { name: "file.txt", isDirectory: false, size: 5 },
      { name: "mydir", isDirectory: true, size: 0 },
    ],
    files: new Map([
      ["big.bin", { data: patternBytes(200000), isDirectory: false }],
      ["file.txt", { data: Buffer.from("hello"), isDirectory: false }],
      ["ro.txt", { data: Buffer.from("ro"), isDirectory: false, attrs: 0x81 }],
      ["mydir", { data: Buffer.alloc(0), isDirectory: true }],
      ["del.txt", { data: Buffer.from("bye"), isDirectory: false }],
      ["deldir", { data: Buffer.alloc(0), isDirectory: true }],
      ["dl.bin", { data: Buffer.from("download-me"), isDirectory: false }],
    ]),
    ...opts,
  });
  const port = await server.listen();
  return { server, port };
}

function stubProvider(key = true): StubAuthProvider {
  return new StubAuthProvider({
    challenge: Buffer.from("mock-challenge"),
    sessionKey: key ? sessionKey : undefined,
  });
}

describe("mock server flow", () => {
  it("runs the full public API over one connection", async () => {
    const { server, port } = await startServer();
    try {
      const session = await connect({
        host: "127.0.0.1",
        port,
        authProvider: stubProvider(),
        credentials: { username: "u", password: "p", domain: "d" },
        requestTimeoutMs: 3000,
      });

      const data = await session.readFile("share", "big.bin");
      assert.deepEqual(data, patternBytes(200000));

      const fileStat = await session.stat("share", "file.txt");
      assert.equal(fileStat.sizeBytes, 5n);
      assert.equal(fileStat.isDirectory, false);
      assert.equal(fileStat.readonly, false);
      assert.deepEqual(fileStat.mtime, new Date(Date.UTC(2024, 0, 2, 3, 4, 5)));

      // stat on a directory exercises the plain-open-fails, DIRECTORY-flag
      // retry path against the strict mock.
      const dirStat = await session.stat("share", "mydir");
      assert.equal(dirStat.isDirectory, true);
      const mydirCreates = server.creates.filter((create) => create.name === "mydir");
      assert.equal(mydirCreates.length, 2);
      assert.equal(mydirCreates[0].options & 1, 0);
      assert.equal(mydirCreates[1].options & 1, 1);

      const roStat = await session.stat("share", "ro.txt");
      assert.equal(roStat.readonly, true);

      const entries = await session.list("share");
      assert.deepEqual(entries.map((entry) => entry.name).sort(), ["file.txt", "mydir"]);
      assert.equal(entries.find((entry) => entry.name === "mydir")!.isDirectory, true);
      assert.equal(entries.find((entry) => entry.name === "file.txt")!.sizeBytes, 5n);

      await session.writeFile("share", "out.txt", "written!");
      assert.equal(server.writtenBytes("out.txt").toString(), "written!");

      await session.mkdir("share", "newdir");
      await assert.rejects(session.mkdir("share", "file.txt"), SmbAlreadyExistsError);

      await session.delete("share", "del.txt");
      await session.delete("share", "deldir");

      const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "smb-mock-"));
      try {
        const local = path.join(tempDir, "up.bin");
        fs.writeFileSync(local, patternBytes(100000));
        await session.upload(local, "share", "upload.bin");
        assert.deepEqual(server.writtenBytes("upload.bin"), patternBytes(100000));
        const down = path.join(tempDir, "down.bin");
        await session.download("share", "dl.bin", down);
        assert.equal(fs.readFileSync(down).toString(), "download-me");
      } finally {
        fs.rmSync(tempDir, { recursive: true, force: true });
      }

      const shares = await session.listShares();
      assert.deepEqual(shares, [
        { name: "MockShare", type: "disk", comment: "mock disk" },
        { name: "IPC$", type: "ipc", comment: "" },
      ]);
      assert.equal(server.dceWrites.length, 2);
      assert.equal(server.dceWrites[0][2], 11); // BIND
      assert.equal(server.dceWrites[1][2], 0); // REQUEST
      assert.equal(server.dceWrites[1].readUInt16LE(22), 15); // NetrShareEnum

      await session.close();
      await waitFor(() => server.connectionsClosed === 1, "server-side close");

      // One connection carried the whole suite: auth tokens in order, the
      // expected commands, tree disconnect + logoff at the end.
      assert.equal(server.connections, 1);
      assert.deepEqual(
        server.setupBuffers.map((buffer) => buffer.toString()),
        ["stub-token-1", "stub-token-2"],
      );
      const types = server.seen.map((request) => request.type);
      assert.deepEqual(types.slice(0, 4), [
        PacketType.Negotiate,
        PacketType.SessionSetup,
        PacketType.SessionSetup,
        PacketType.TreeConnect,
      ]);
      assert.deepEqual(types.slice(-2), [PacketType.TreeDisconnect, PacketType.LogOff]);
      for (const want of [PacketType.Read, PacketType.Write, PacketType.QueryInfo, PacketType.QueryDirectory]) {
        assert.ok(types.includes(want), `expected a ${want} request`);
      }
      const reads = server.seen.filter((request) => request.type === PacketType.Read);
      assert.equal(reads.length, 4 + 1 + 2); // 200KB file in 64KB chunks + dl.bin + 2 pipe reads
      assert.ok(reads.every((request) => request.creditCharge === 1));
      assert.ok(server.seen.every((request) => !request.signed)); // unsigned suite
    } finally {
      await server.close();
    }
  });

  it("signs every post-setup request when the server requires it", async () => {
    const { server, port } = await startServer({
      securityMode: 0x03,
      sessionKey,
      signResponses: true,
    });
    try {
      const session = await connect({
        host: "127.0.0.1",
        port,
        authProvider: stubProvider(),
        credentials: { username: "u" },
        requestTimeoutMs: 3000,
      });
      const data = await session.readFile("share", "file.txt");
      assert.equal(data.toString(), "hello");
      await session.close();
      await waitFor(() => server.connectionsClosed === 1, "server-side close");

      assert.deepEqual(
        server.seen.slice(0, 3).map((request) => request.signed),
        [false, false, false],
      );
      const rest = server.seen.slice(3);
      assert.ok(rest.length > 0);
      assert.ok(rest.every((request) => request.signed), "all post-setup requests signed");
      assert.ok(
        rest.every((request) => request.signatureValid === true),
        "all signatures verify with the stub sessionKey",
      );
    } finally {
      await server.close();
    }
  });

  it("signs with the first 16 bytes of a 32-byte Kerberos session key", async () => {
    const gssKey = Buffer.concat([sessionKey, Buffer.from("kerberos-tail-16")]);
    const { server, port } = await startServer({
      securityMode: 0x03,
      sessionKey, // the server holds the MS-SMB2 16-byte key
      signResponses: true,
    });
    try {
      const session = await connect({
        host: "127.0.0.1",
        port,
        authProvider: new StubAuthProvider({
          mechanism: "kerberos",
          challenge: Buffer.from("mock-challenge"),
          sessionKey: gssKey,
        }),
        credentials: { username: "u" },
        signing: "required",
        requestTimeoutMs: 3000,
      });
      assert.equal((await session.readFile("share", "file.txt")).toString(), "hello");
      await session.close();
      const rest = server.seen.slice(3);
      assert.ok(rest.length > 0);
      assert.ok(
        rest.every((request) => request.signed && request.signatureValid === true),
        "every post-setup request verifies with the first 16 bytes",
      );
    } finally {
      await server.close();
    }
  });

  it("rejects responses with tampered signatures", async () => {
    const { server, port } = await startServer({
      securityMode: 0x03,
      sessionKey,
      signResponses: true,
      tamperSignatures: true,
    });
    try {
      const session = await connect({
        host: "127.0.0.1",
        port,
        authProvider: stubProvider(),
        credentials: { username: "u" },
        requestTimeoutMs: 3000,
      });
      await assert.rejects(session.readFile("share", "file.txt"), SmbSigningError);
      await assert.rejects(session.close(), SmbSigningError);
      await waitFor(() => server.connectionsClosed === 1, "server-side close");
    } finally {
      await server.close();
    }
  });

  for (const kind of ["missing", "directory"] as const) {
    it(`upload with a ${kind} local path sends no CREATE and keeps the remote bytes`, async () => {
      const { server, port } = await startServer({
        files: new Map([["keep.txt", { data: Buffer.from("original"), isDirectory: false }]]),
      });
      const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "smb-mock-"));
      try {
        const session = await connect({
          host: "127.0.0.1",
          port,
          authProvider: stubProvider(false),
          credentials: { username: "u" },
          requestTimeoutMs: 3000,
        });
        const local = kind === "missing" ? path.join(tempDir, "absent.bin") : tempDir;
        await assert.rejects(session.upload(local, "share", "keep.txt"), {
          code: kind === "missing" ? "ENOENT" : "EISDIR",
        });
        assert.deepEqual(server.creates, []);
        assert.equal(server.writtenBytes("keep.txt").length, 0);
        assert.equal((await session.readFile("share", "keep.txt")).toString(), "original");
        await session.close();
      } finally {
        fs.rmSync(tempDir, { recursive: true, force: true });
        await server.close();
      }
    });
  }

  it("maps error statuses to typed errors", async () => {
    const { server, port } = await startServer({
      createErrors: new Map([
        ["denied.txt", 0xc0000022],
        ["missing.txt", 0xc0000034],
      ]),
    });
    try {
      const session = await connect({
        host: "127.0.0.1",
        port,
        authProvider: stubProvider(false),
        credentials: { username: "u" },
        requestTimeoutMs: 3000,
      });
      await assert.rejects(session.readFile("share", "denied.txt"), SmbAccessDeniedError);
      await assert.rejects(session.readFile("share", "missing.txt"), SmbNotFoundError);
      await session.close();
    } finally {
      await server.close();
    }
  });

  // SMB 3.1.1 against the mock's independent crypto: preauth
  // integrity, SP800-108 keys, AES-GMAC signing, AES-128-GCM/CCM
  // encryption per session and per share, and the refusals.
  describe("SMB 3.1.1", () => {
    const open = (port: number) =>
      connect({ host: "127.0.0.1", port, authProvider: stubProvider(), credentials: { username: "u" }, requestTimeoutMs: 3000 });
    const postSetup = (server: MockSmbServer) =>
      server.seen.filter((r) => r.type !== PacketType.Negotiate && r.type !== PacketType.SessionSetup);

    it("session encryption with AES-128-GCM: every request after setup is encrypted and the API works", async () => {
      const { server, port } = await startServer({ securityMode: 0x01, sessionKey, smb3: { cipher: 2, encryptData: true } });
      try {
        const session = await open(port);
        assert.deepEqual(session.security, { dialect: "3.1.1", signingAlgorithm: "AES-GMAC", cipher: "AES-128-GCM", encryptData: true, signing: true });
        assert.deepEqual(await session.readFile("share", "big.bin"), patternBytes(200000));
        await session.writeFile("share", "new.txt", "encrypted hello");
        assert.equal(server.writtenBytes("new.txt").toString(), "encrypted hello");
        assert.equal((await session.list("share")).length, 2);
        assert.deepEqual((await session.listShares()).map((share) => share.name), ["MockShare", "IPC$"]);
        await session.close();
        const after = postSetup(server);
        assert.ok(after.length > 10);
        assert.deepEqual(after.filter((r) => !r.encrypted).map((r) => r.type), [], "no plaintext request after setup");
        assert.ok(after.every((r) => !r.signed), "encrypted requests are not also signed");
        assert.equal(server.decryptFailures, 0);
      } finally {
        await server.close();
      }
    });

    it("share encryption with AES-128-CCM: only the marked share is encrypted; the rest is GMAC-signed", async () => {
      const { server, port } = await startServer({ securityMode: 0x03, sessionKey, signResponses: true, smb3: { cipher: 1, encryptShares: ["secure"] } });
      try {
        const session = await open(port);
        assert.deepEqual(session.security, { dialect: "3.1.1", signingAlgorithm: "AES-GMAC", cipher: "AES-128-CCM", encryptData: false, signing: true });
        assert.equal((await session.readFile("share", "file.txt")).toString(), "hello");
        assert.equal((await session.readFile("secure", "file.txt")).toString(), "hello");
        await session.listShares();
        await session.close();
        const byShare = (name: string) => postSetup(server).filter((r) => server.shareOfTree.get(r.treeId) === name && r.type !== PacketType.TreeConnect);
        assert.ok(byShare("secure").length >= 3);
        assert.ok(byShare("secure").every((r) => r.encrypted), "every request on the encrypted share is encrypted");
        for (const name of ["share", "IPC$"]) {
          assert.ok(byShare(name).length >= 2, name);
          assert.ok(byShare(name).every((r) => !r.encrypted && r.signed && r.signatureValid === true), `${name}: signed with AES-GMAC`);
        }
        // TREE_CONNECT itself goes signed: the share flag arrives in its response.
        const connects = server.seen.filter((r) => r.type === PacketType.TreeConnect);
        assert.ok(connects.every((r) => !r.encrypted && r.signatureValid === true));
      } finally {
        await server.close();
      }
    });

    it("refuses a plaintext response on an encrypted session", async () => {
      const { server, port } = await startServer({ securityMode: 0x01, sessionKey, smb3: { cipher: 2, encryptData: true, forcePlaintext: true } });
      try {
        const session = await open(port);
        await assert.rejects(session.readFile("share", "file.txt"), (error: unknown) => {
          assert.ok(error instanceof SmbSigningError);
          assert.match(error.message, /plaintext response on an encrypted session or share refused/);
          return true;
        });
      } finally {
        await server.close();
      }
    });

    it("an encrypted response that does not authenticate fails the request and drops the connection", async () => {
      const { server, port } = await startServer({ securityMode: 0x01, sessionKey, smb3: { cipher: 2, encryptData: true, tamperEncrypted: true } });
      try {
        const session = await open(port);
        await assert.rejects(session.readFile("share", "file.txt"), (error: unknown) => {
          assert.ok(error instanceof SmbSigningError);
          assert.match(error.message, /an encrypted SMB response did not decrypt/);
          return true;
        });
      } finally {
        await server.close();
      }
    });

    it("a tampered AES-GMAC response signature is rejected", async () => {
      const { server, port } = await startServer({ securityMode: 0x03, sessionKey, signResponses: true, tamperSignatures: true, smb3: { cipher: 2 } });
      try {
        const session = await open(port);
        await assert.rejects(session.readFile("share", "file.txt"), /response signature verification failed/);
      } finally {
        await server.close();
      }
    });

    it("an unsigned final SESSION_SETUP response is refused for 3.1.1", async () => {
      const { server, port } = await startServer({ securityMode: 0x01, sessionKey, smb3: { cipher: 2, unsignedFinal: true } });
      try {
        await assert.rejects(open(port), (error: unknown) => {
          assert.ok(error instanceof SmbSigningError);
          assert.match(error.message, /did not sign the final SESSION_SETUP response/);
          return true;
        });
      } finally {
        await server.close();
      }
    });

    it("a session that must be encrypted with no cipher negotiated fails clear", async () => {
      const { server, port } = await startServer({ securityMode: 0x01, sessionKey, smb3: { cipher: 0, encryptData: true } });
      try {
        await assert.rejects(open(port), (error: unknown) => {
          assert.ok(error instanceof SmbEncryptionRequiredError);
          assert.match(error.message, /requires SMB encryption for this session, but no cipher was negotiated \(dialect 3\.1\.1\)/);
          return true;
        });
      } finally {
        await server.close();
      }
    });

    it("a share that must be encrypted with no cipher negotiated fails clear and is disconnected", async () => {
      const { server, port } = await startServer({ securityMode: 0x01, sessionKey, signResponses: true, smb3: { cipher: 0, encryptShares: ["secure"] } });
      try {
        const session = await open(port);
        await assert.rejects(session.readFile("secure", "file.txt"), (error: unknown) => {
          assert.ok(error instanceof SmbError);
          assert.match(error.message, /the share requires SMB encryption but this connection negotiated none/);
          return true;
        });
        assert.equal(server.seen.filter((r) => r.type === PacketType.TreeDisconnect).length, 1);
        assert.equal((await session.readFile("share", "file.txt")).toString(), "hello", "the session stays usable");
        await session.close();
      } finally {
        await server.close();
      }
    });

    it("waits past async STATUS_PENDING interim responses (a pipe READ served out of process)", async () => {
      const { server, port } = await startServer({ securityMode: 0x01, sessionKey, interimPending: true, smb3: { cipher: 2, encryptData: true } });
      try {
        const session = await open(port);
        assert.deepEqual((await session.listShares()).map((share) => share.name), ["MockShare", "IPC$"]);
        assert.deepEqual(await session.readFile("share", "big.bin"), patternBytes(200000));
        await session.close();
      } finally {
        await server.close();
      }
    });

    it("maxDialect 2.1 keeps the SMB 2.1 exchange", async () => {
      const { server, port } = await startServer({ securityMode: 0x01, sessionKey, signResponses: true });
      try {
        const session = await connect({ host: "127.0.0.1", port, authProvider: stubProvider(), credentials: { username: "u" }, requestTimeoutMs: 3000, maxDialect: "2.1" });
        assert.deepEqual(session.security, { dialect: "2.1", signingAlgorithm: "HMAC-SHA256", cipher: "none", encryptData: false, signing: true });
        await session.close();
      } finally {
        await server.close();
      }
    });
  });

  // The shape checks of deleteFile, deleteDirectory and rename, and the
  // RenameInformation bytes that go out.
  it("deleteFile, deleteDirectory and rename check the shape and send the right SET_INFO", async () => {
    const { server, port } = await startServer({
      files: new Map([
        ["file.txt", { data: Buffer.from("hello"), isDirectory: false }],
        ["mydir", { data: Buffer.alloc(0), isDirectory: true }],
        ["full", { data: Buffer.alloc(0), isDirectory: true }],
        ["sub\\inner.txt", { data: Buffer.from("x"), isDirectory: false }],
      ]),
      setInfoErrors: new Map([["full", 0xc0000101]]), // STATUS_DIRECTORY_NOT_EMPTY
    });
    try {
      const session = await connect({
        host: "127.0.0.1",
        port,
        authProvider: stubProvider(false),
        credentials: { username: "u" },
        requestTimeoutMs: 3000,
      });
      await assert.rejects(session.deleteFile("share", "mydir"), (error: unknown) => {
        assert.ok(error instanceof SmbIsADirectoryError);
        assert.equal(error.message, "is a directory: share/mydir; use rmdir");
        return true;
      });
      await assert.rejects(session.deleteDirectory("share", "file.txt"), (error: unknown) => {
        assert.ok(error instanceof SmbNotADirectoryError);
        assert.equal(error.message, "not a directory: share/file.txt; use delete");
        return true;
      });
      assert.equal(server.setInfos.length, 0, "no SET_INFO before the shape checks pass");

      await assert.rejects(session.deleteDirectory("share", "full"), (error: unknown) => {
        assert.ok(error instanceof SmbDirectoryNotEmptyError);
        assert.equal(error.message, "directory not empty: rmdir share/full (status 0xc0000101)");
        return true;
      });
      // The failed SET_INFO must not leak the handle: on a real server an
      // open handle keeps the directory alive until logoff, so a later
      // delete-on-close silently does nothing (seen against Samba).
      const closes = server.seen.filter((r) => r.type === PacketType.Close).length;
      assert.equal(closes, server.handlesOpened, "every handle is closed after the failure");
      await session.deleteDirectory("share", "mydir");
      await session.deleteFile("share", "file.txt");
      const dispositions = server.setInfos.filter((s) => s.infoClass === 13);
      assert.deepEqual(dispositions.map((s) => [s.name, s.buffer[0]]), [["full", 1], ["mydir", 1], ["file.txt", 1]]);

      await session.rename("share", "sub/inner.txt", "sub/renamed.txt");
      await session.rename("share", "mydir", "other/dir");
      const renames = server.setInfos.filter((s) => s.infoClass === 10);
      assert.deepEqual(
        renames.map((s) => ({
          name: s.name,
          replace: s.buffer[0],
          target: s.buffer.subarray(20, 20 + s.buffer.readUInt32LE(16)).toString("ucs2"),
        })),
        [
          { name: "sub\\inner.txt", replace: 0, target: "sub\\renamed.txt" },
          { name: "mydir", replace: 0, target: "other\\dir" },
        ],
      );
      await session.close();
    } finally {
      await server.close();
    }
  });

  // Windows refuses a TREE_CONNECT to an `-EncryptData $true` share on
  // SMB 2.x with a bare STATUS_ACCESS_DENIED. The session asks SRVSVC
  // NetrShareGetInfo level 1005 whether the share requires encryption and
  // reports that; any other outcome keeps the plain access-denied error.
  describe("tree connect access denied", () => {
    const denied = new Map([
      ["enc", 0xc0000022],
      ["acl", 0xc0000022],
      ["gone", 0xc0000022],
    ]);

    it("names SMB encryption when the share's shi1005_flags say so, and the session stays usable", async () => {
      const { server, port } = await startServer({
        treeConnectErrors: denied,
        shareFlags: new Map([["enc", 0x8000 | 0x800]]),
      });
      try {
        const session = await connect({
          host: "127.0.0.1",
          port,
          authProvider: stubProvider(false),
          credentials: { username: "u" },
          requestTimeoutMs: 3000,
        });
        await assert.rejects(session.list("enc"), (error: unknown) => {
          assert.ok(error instanceof SmbEncryptionRequiredError);
          assert.ok(error instanceof SmbAccessDeniedError);
          assert.equal(error.name, "SmbEncryptionRequiredError");
          assert.equal(error.status, 0xc0000022);
          assert.equal(
            error.message,
            "share enc requires SMB encryption, which this connection did not negotiate (dialect 2.1, cipher none) (status 0xc0000022)",
          );
          return true;
        });
        assert.deepEqual(server.shareInfoQueries, ["enc"]);
        assert.deepEqual(server.treeConnects, ["enc", "IPC$"]);
        assert.equal(server.seen.filter((r) => r.type === PacketType.TreeDisconnect).length, 1);
        // The probe left the session intact.
        const entries = await session.list("share");
        assert.equal(entries.length, 2);
        await session.close();
      } finally {
        await server.close();
      }
    });

    it("keeps a plain access-denied error when the flag is clear, the share is unknown, or the probe is refused", async () => {
      const { server, port } = await startServer({
        treeConnectErrors: denied,
        shareFlags: new Map([["acl", 0x800]]),
      });
      try {
        const session = await connect({
          host: "127.0.0.1",
          port,
          authProvider: stubProvider(false),
          credentials: { username: "u" },
          requestTimeoutMs: 3000,
        });
        for (const share of ["acl", "gone"]) {
          await assert.rejects(session.list(share), (error: unknown) => {
            assert.ok(error instanceof SmbAccessDeniedError);
            assert.ok(!(error instanceof SmbEncryptionRequiredError));
            assert.equal(error.message, `access denied: tree connect to ${share} (status 0xc0000022)`);
            return true;
          });
        }
        assert.deepEqual(server.shareInfoQueries, ["acl", "gone"]);
        await session.close();
      } finally {
        await server.close();
      }
    });

    it("keeps the access-denied error when IPC$ itself is refused", async () => {
      const { server, port } = await startServer({
        treeConnectErrors: new Map([...denied, ["IPC$", 0xc0000022]]),
        shareFlags: new Map([["enc", 0x8000]]),
      });
      try {
        const session = await connect({
          host: "127.0.0.1",
          port,
          authProvider: stubProvider(false),
          credentials: { username: "u" },
          requestTimeoutMs: 3000,
        });
        await assert.rejects(session.list("enc"), (error: unknown) => {
          assert.ok(error instanceof SmbAccessDeniedError);
          assert.ok(!(error instanceof SmbEncryptionRequiredError));
          return true;
        });
        assert.deepEqual(server.shareInfoQueries, []);
        await session.close();
      } finally {
        await server.close();
      }
    });
  });

  // Regression: a request that failed with an error status left its
  // request-timeout timer armed, which held the process open for up to
  // requestTimeoutMs after any SMB error.
  it("clears the request timer when a request fails", async () => {
    const { server, port } = await startServer({
      createErrors: new Map([["missing.txt", 0xc0000034]]),
    });
    try {
      const client = new Client("127.0.0.1", { port, requestTimeout: 3000 });
      const session = await client.authenticate({
        authProvider: stubProvider(false),
        credentials: { username: "u" },
      });
      const tree = await session.connectTree("share");
      await assert.rejects(tree.request({ type: PacketType.Create }, {
        buffer: Buffer.from("missing.txt", "ucs2"),
        createDisposition: 1,
        createOptions: 0,
      }));
      assert.equal(client.requestTimeoutIdMap.size, 0);
      await client.close();
    } finally {
      await server.close();
    }
  });

  it("reads 200KB in one multi-credit READ", async () => {
    const { server, port } = await startServer();
    try {
      const client = new Client("127.0.0.1", { port, requestTimeout: 3000 });
      const session = await client.authenticate({
        authProvider: stubProvider(false),
        credentials: { username: "u" },
      });
      const tree = await session.connectTree("share");
      const created = await tree.request({ type: PacketType.Create }, {
        buffer: Buffer.from("big.bin", "ucs2"),
        createDisposition: 1,
        createOptions: 0,
      });
      const response = await tree.request({ type: PacketType.Read, creditCharge: 4 }, {
        fileId: created.body.fileId,
        length: 200000,
        offset: 0,
      });
      assert.equal((response.body.buffer as Buffer).length, 200000);
      assert.deepEqual(response.body.buffer, patternBytes(200000));
      const reads = server.seen.filter((request) => request.type === PacketType.Read);
      assert.equal(reads.length, 1);
      assert.equal(reads[0].creditCharge, 4);
      await client.close();
    } finally {
      await server.close();
    }
  });

  it("refuses to sign when the provider has no session key", async () => {
    const { server, port } = await startServer({ securityMode: 0x03 });
    try {
      await assert.rejects(
        connect({
          host: "127.0.0.1",
          port,
          authProvider: stubProvider(false),
          credentials: { username: "u" },
          requestTimeoutMs: 3000,
        }),
        SmbSigningError,
      );
    } finally {
      await server.close();
    }
  });

  it("keeps socket errors off stderr and hands them to an error listener", async () => {
    const { server, port } = await startServer();
    const origConsoleError = console.error;
    const origStderrWrite = process.stderr.write;
    const written: unknown[] = [];
    try {
      // Silent case: no listener, so the client must print nothing.
      const quiet = new Client("127.0.0.1", { port, requestTimeout: 3000 });
      await quiet.connect();
      console.error = (...args: unknown[]) => { written.push(args); };
      process.stderr.write = ((chunk: unknown) => { written.push(chunk); return true; }) as typeof process.stderr.write;
      const quietClosed = new Promise((resolve) => quiet.socket.once("close", resolve));
      quiet.socket.destroy(new Error("mock socket failure"));
      await quietClosed;
      console.error = origConsoleError;
      process.stderr.write = origStderrWrite;
      assert.deepEqual(written, []);
      assert.equal(quiet.connected, false);

      // A caller that listens still receives the error.
      const loud = new Client("127.0.0.1", { port, requestTimeout: 3000 });
      await loud.connect();
      const received = new Promise<Error>((resolve) => loud.once("error", resolve));
      loud.socket.destroy(new Error("second failure"));
      assert.equal((await received).message, "second failure");
    } finally {
      console.error = origConsoleError;
      process.stderr.write = origStderrWrite;
      await server.close();
    }
  });
});
