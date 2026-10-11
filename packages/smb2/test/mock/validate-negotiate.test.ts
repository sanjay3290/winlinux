// FSCTL_VALIDATE_NEGOTIATE_INFO: below SMB 3.1.1 the preauth hash
// does not protect the NEGOTIATE, so after the first TREE_CONNECT the client
// sends its NEGOTIATE values in a signed IOCTL and checks the server's
// answer against the NEGOTIATE response. A mismatch or an unsigned answer
// ends the connection.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import HeaderFlag from "../../src/protocol/smb2/HeaderFlag.js";
import PacketType from "../../src/protocol/smb2/PacketType.js";
import { connect } from "../../src/index.js";
import { SmbDialectError, SmbSigningError } from "../../src/errors.js";
import { StubAuthProvider } from "../helpers/stub-provider.js";
import { MockSmbServer, type MockOptions } from "./server.js";

const sessionKey = Buffer.from("0123456789abcdef");

async function startServer(opts: MockOptions): Promise<{ server: MockSmbServer; port: number }> {
  const server = new MockSmbServer({
    challenge: Buffer.from("mock-challenge"),
    files: new Map([["file.txt", { data: Buffer.from("hello"), isDirectory: false }]]),
    sessionKey,
    signResponses: true,
    ...opts,
  });
  return { server, port: await server.listen() };
}

const open = (port: number, extra: { signing?: "auto" | "required"; maxDialect?: "2.1" | "3.1.1"; key?: boolean } = {}) =>
  connect({
    host: "127.0.0.1",
    port,
    authProvider: new StubAuthProvider({ challenge: Buffer.from("mock-challenge"), sessionKey: extra.key === false ? undefined : sessionKey }),
    credentials: { username: "u" },
    requestTimeoutMs: 3000,
    ...(extra.signing ? { signing: extra.signing } : {}),
    ...(extra.maxDialect ? { maxDialect: extra.maxDialect } : {}),
  });

async function waitFor(condition: () => boolean, what: string): Promise<void> {
  const deadline = Date.now() + 2000;
  while (!condition()) {
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`);
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}

const ioctls = (server: MockSmbServer) => server.seen.filter((r) => r.type === PacketType.InputOutputControl);

const dialects: Array<[string, MockOptions, { maxDialect?: "2.1" }]> = [
  ["SMB 2.1", { securityMode: 0x01 }, { maxDialect: "2.1" }],
  ["SMB 3.0.2", { securityMode: 0x01, smb3: { cipher: 1, dialect: 0x0302 } }, {}],
];

describe("FSCTL_VALIDATE_NEGOTIATE_INFO below SMB 3.1.1", () => {
  for (const [name, opts, extra] of dialects) {
    describe(name, () => {
      it("sends the NEGOTIATE values once, signed, after the first TREE_CONNECT", async () => {
        const { server, port } = await startServer(opts);
        try {
          const session = await open(port, extra);
          assert.equal((await session.readFile("share", "file.txt")).toString(), "hello");
          assert.equal((await session.readFile("other", "file.txt")).toString(), "hello");
          const seen = ioctls(server);
          assert.equal(seen.length, 1, "one validation per connection");
          assert.equal(seen[0]!.signed && seen[0]!.signatureValid, true, "the IOCTL is signed");
          // It went out right after the first TREE_CONNECT.
          const types = server.seen.map((r) => r.type);
          assert.equal(types[types.indexOf(PacketType.TreeConnect) + 1], PacketType.InputOutputControl);
          const sent = server.negotiateRequest!;
          assert.deepEqual(server.validateRequests, [
            { capabilities: sent.capabilities, guid: sent.guid, securityMode: sent.securityMode, dialects: sent.dialects },
          ]);
          await session.close();
        } finally {
          await server.close();
        }
      });

      for (const [field, answer] of [
        ["dialect", { dialect: 0x0202 }],
        ["security mode", { securityMode: 0x03 }],
        ["capabilities", { capabilities: 0x7f }],
        ["server GUID", { guid: Buffer.alloc(16, 0xee) }],
      ] as const) {
        it(`an answer with another ${field} ends the connection`, async () => {
          const { server, port } = await startServer({ ...opts, validateNegotiate: answer });
          try {
            const session = await open(port, extra);
            await assert.rejects(session.readFile("share", "file.txt"), (error: unknown) => {
              assert.ok(error instanceof SmbDialectError, `expected SmbDialectError, got ${String(error)}`);
              assert.match(error.message, new RegExp(`VALIDATE_NEGOTIATE_INFO .*${field}`));
              return true;
            });
            await waitFor(() => server.connectionsClosed === 1, "the client to drop the connection");
            assert.equal(server.seen.filter((r) => r.type === PacketType.Create).length, 0, "nothing ran on the tree");
          } finally {
            await server.close();
          }
        });
      }

      it("an unsigned answer ends the connection", async () => {
        const { server, port } = await startServer({
          ...opts,
          mangle: (type, framed) => {
            if (type !== PacketType.InputOutputControl) return framed;
            const copy = Buffer.from(framed);
            copy.writeUInt32LE(copy.readUInt32LE(4 + 16) & ~HeaderFlag.Signed, 4 + 16);
            return copy;
          },
        });
        try {
          const session = await open(port, extra);
          await assert.rejects(session.readFile("share", "file.txt"), (error: unknown) => {
            assert.ok(error instanceof SmbSigningError, `expected SmbSigningError, got ${String(error)}`);
            assert.match(error.message, /VALIDATE_NEGOTIATE_INFO/);
            return true;
          });
          await waitFor(() => server.connectionsClosed === 1, "the client to drop the connection");
        } finally {
          await server.close();
        }
      });
    });
  }

  it("SMB 3.0.2: a server that refuses the IOCTL ends the connection", async () => {
    const { server, port } = await startServer({ securityMode: 0x01, smb3: { cipher: 1, dialect: 0x0302 }, validateNegotiate: { status: 0xc00000bb } });
    try {
      const session = await open(port);
      await assert.rejects(session.readFile("share", "file.txt"), (error: unknown) => {
        assert.ok(error instanceof SmbDialectError, `expected SmbDialectError, got ${String(error)}`);
        assert.match(error.message, /refused FSCTL_VALIDATE_NEGOTIATE_INFO/);
        return true;
      });
    } finally {
      await server.close();
    }
  });

  it("SMB 2.1: a signed STATUS_NOT_SUPPORTED (a server older than the IOCTL) is accepted", async () => {
    const { server, port } = await startServer({ securityMode: 0x01, validateNegotiate: { status: 0xc00000bb } });
    try {
      const session = await open(port, { maxDialect: "2.1" });
      assert.equal((await session.readFile("share", "file.txt")).toString(), "hello");
      await session.close();
    } finally {
      await server.close();
    }
  });

  it("SMB 3.1.1 sends no validation: the preauth hash covers the NEGOTIATE", async () => {
    const { server, port } = await startServer({ securityMode: 0x01, smb3: { cipher: 2 } });
    try {
      const session = await open(port);
      assert.equal((await session.readFile("share", "file.txt")).toString(), "hello");
      assert.equal(ioctls(server).length, 0);
      await session.close();
    } finally {
      await server.close();
    }
  });

  it("no validation without signing: no session key, nothing to sign it with", async () => {
    const { server, port } = await startServer({ securityMode: 0x01, signResponses: false });
    try {
      const session = await open(port, { maxDialect: "2.1", key: false });
      assert.equal((await session.readFile("share", "file.txt")).toString(), "hello");
      assert.equal(ioctls(server).length, 0);
      assert.equal((session.security as { signing?: boolean }).signing, false);
      await session.close();
    } finally {
      await server.close();
    }
  });
});

describe("client NEGOTIATE SecurityMode", () => {
  for (const [mode, expected] of [["auto", 0x01], ["required", 0x03]] as const) {
    it(`signing ${mode}: SecurityMode 0x0${expected}, and security.signing reports signing in effect`, async () => {
      const { server, port } = await startServer({ securityMode: 0x03, smb3: { cipher: 2 } });
      try {
        const session = await open(port, { signing: mode });
        assert.equal(server.negotiateRequest?.securityMode, expected);
        assert.equal((session.security as { signing?: boolean }).signing, true);
        await session.close();
      } finally {
        await server.close();
      }
    });
  }
});
