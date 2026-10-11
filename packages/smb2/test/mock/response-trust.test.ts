// The client judges each response against the request it answers,
// never against the response's own unauthenticated header: the Signed flag,
// SessionId, TreeId and Command of a plaintext response are all on-path
// attacker controlled. Unsolicited responses are discarded, not cached.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import Smb2Packet from "../../src/protocol/smb2/Packet.js";
import HeaderFlag from "../../src/protocol/smb2/HeaderFlag.js";
import PacketType from "../../src/protocol/smb2/PacketType.js";
import { connect } from "../../src/index.js";
import { SmbError, SmbSigningError } from "../../src/errors.js";
import { StubAuthProvider } from "../helpers/stub-provider.js";
import { MOCK_SESSION_ID, MockSmbServer, type MockOptions } from "./server.js";

const sessionKey = Buffer.from("0123456789abcdef");

// Offsets in a framed response: NetBIOS header (4) + SMB2 header field.
const FLAGS = 4 + 16;
const COMMAND = 4 + 12;
const TREE_ID = 4 + 36;
const SESSION_ID = 4 + 40;
// READ response: header (64) + StructureSize..Reserved2 (16), then the data.
const READ_DATA = 4 + 64 + 16;
// TREE_CONNECT response: ShareType, Reserved, then ShareFlags at body offset 4.
const SHARE_FLAGS = 4 + 64 + 4;

async function startServer(opts: MockOptions): Promise<{ server: MockSmbServer; port: number }> {
  const server = new MockSmbServer({
    challenge: Buffer.from("mock-challenge"),
    files: new Map([["file.txt", { data: Buffer.from("hello"), isDirectory: false }]]),
    sessionKey,
    ...opts,
  });
  return { server, port: await server.listen() };
}

const open = (port: number, maxDialect: "2.1" | "3.1.1" = "3.1.1", signing: "auto" | "required" = "required") =>
  connect({
    host: "127.0.0.1",
    port,
    authProvider: new StubAuthProvider({ challenge: Buffer.from("mock-challenge"), sessionKey }),
    credentials: { username: "u" },
    requestTimeoutMs: 3000,
    maxDialect,
    signing,
  });

const refused = (pattern: RegExp) => (error: unknown) => {
  assert.ok(error instanceof SmbSigningError, `expected SmbSigningError, got ${String(error)}`);
  assert.match(error.message, pattern);
  return true;
};

const postSetup = (type: number) => type !== PacketType.Negotiate && type !== PacketType.SessionSetup;

// Rewrites every response of the given commands.
function on(types: number[], rewrite: (framed: Buffer) => void): MockOptions["mangle"] {
  return (type, framed) => {
    if (!types.includes(type)) return framed;
    const copy = Buffer.from(framed);
    rewrite(copy);
    return copy;
  };
}

const clearSigned = (framed: Buffer) => framed.writeUInt32LE(framed.readUInt32LE(FLAGS) & ~HeaderFlag.Signed, FLAGS);

const signedServers: Array<[string, "2.1" | "3.1.1", MockOptions]> = [
  ["SMB 2.1, HMAC-SHA256", "2.1", { securityMode: 0x03, signResponses: true }],
  ["SMB 3.1.1, AES-GMAC", "3.1.1", { securityMode: 0x03, signResponses: true, smb3: { cipher: 2 } }],
];

describe("signed sessions refuse what the response header claims", () => {
  for (const [name, maxDialect, opts] of signedServers) {
    describe(name, () => {
      it("still reads a file when every response is signed", async () => {
        const { server, port } = await startServer(opts);
        try {
          const session = await open(port, maxDialect);
          assert.equal((await session.readFile("share", "file.txt")).toString(), "hello");
          await session.close();
        } finally {
          await server.close();
        }
      });

      it("refuses a READ response with the Signed flag cleared and forged data", async () => {
        const { server, port } = await startServer({
          ...opts,
          mangle: on([PacketType.Read], (framed) => {
            clearSigned(framed);
            framed.write("EVIL!", READ_DATA, "latin1");
          }),
        });
        try {
          const session = await open(port, maxDialect);
          await assert.rejects(session.readFile("share", "file.txt"), refused(/unsigned response to a signed request refused/));
        } finally {
          await server.close();
        }
      });

      it("refuses a signed response that names a session the request was not sent on", async () => {
        const { server, port } = await startServer({
          ...opts,
          mangle: on([PacketType.Read], (framed) => framed.write("ffffffffffffffff", SESSION_ID, "hex")),
        });
        try {
          const session = await open(port, maxDialect);
          await assert.rejects(session.readFile("share", "file.txt"), refused(/response session does not match the request/));
        } finally {
          await server.close();
        }
      });

      it("refuses an unsigned response with SessionId 0", async () => {
        const { server, port } = await startServer({
          ...opts,
          mangle: on([PacketType.Read], (framed) => {
            clearSigned(framed);
            framed.fill(0, SESSION_ID, SESSION_ID + 8);
          }),
        });
        try {
          const session = await open(port, maxDialect);
          await assert.rejects(session.readFile("share", "file.txt"), refused(/does not match the request|unsigned response/));
        } finally {
          await server.close();
        }
      });

      it("refuses an unsigned WRITE success", async () => {
        const { server, port } = await startServer({ ...opts, mangle: on([PacketType.Write], clearSigned) });
        try {
          const session = await open(port, maxDialect);
          await assert.rejects(session.writeFile("share", "new.txt", Buffer.from("data")), refused(/unsigned response to a signed request refused/));
        } finally {
          await server.close();
        }
      });
    });
  }

  it("refuses a TREE_CONNECT response with ENCRYPT_DATA and the Signed flag cleared", async () => {
    const { server, port } = await startServer({
      securityMode: 0x03,
      signResponses: true,
      smb3: { cipher: 2, encryptShares: ["share"] },
      mangle: on([PacketType.TreeConnect], (framed) => {
        clearSigned(framed);
        framed.writeUInt32LE(framed.readUInt32LE(SHARE_FLAGS) & ~0x8000, SHARE_FLAGS);
      }),
    });
    try {
      const session = await open(port);
      await assert.rejects(session.readFile("share", "file.txt"), refused(/unsigned response to a signed request refused/));
      assert.equal(server.seen.filter((r) => r.type === PacketType.Read).length, 0, "no plaintext READ went out");
    } finally {
      await server.close();
    }
  });

  it("still accepts an unsigned async STATUS_PENDING interim response on a signed session", async () => {
    const { server, port } = await startServer({ securityMode: 0x03, signResponses: true, interimPending: true, smb3: { cipher: 2 } });
    try {
      const session = await open(port);
      assert.equal((await session.readFile("share", "file.txt")).toString(), "hello");
      await session.close();
    } finally {
      await server.close();
    }
  });

  it("still fails with the server's status when STATUS_USER_SESSION_DELETED comes back unsigned", async () => {
    const { server, port } = await startServer({
      securityMode: 0x03,
      signResponses: true,
      smb3: { cipher: 2 },
      createErrors: new Map([["file.txt", 0xc0000203]]),
      mangle: on([PacketType.Create], clearSigned),
    });
    try {
      const session = await open(port);
      await assert.rejects(session.readFile("share", "file.txt"), (error: unknown) => {
        assert.ok(error instanceof SmbError && !(error instanceof SmbSigningError), `got ${String(error)}`);
        assert.equal(error.status, 0xc0000203);
        return true;
      });
    } finally {
      await server.close();
    }
  });
});

describe("encrypted requests need encrypted responses for the same session", () => {
  it("refuses a plaintext response with SessionId 0 on an encrypted session", async () => {
    const { server, port } = await startServer({
      securityMode: 0x01,
      smb3: { cipher: 2, encryptData: true, forcePlaintext: true },
      mangle: (type, framed) => {
        if (!postSetup(type)) return framed;
        const copy = Buffer.from(framed);
        copy.fill(0, SESSION_ID, SESSION_ID + 8);
        return copy;
      },
    });
    try {
      const session = await open(port, "3.1.1", "auto");
      await assert.rejects(session.readFile("share", "file.txt"), refused(/does not match the request|plaintext response/));
    } finally {
      await server.close();
    }
  });

  it("refuses a plaintext response relabelled as SESSION_SETUP on an encrypted session", async () => {
    const { server, port } = await startServer({
      securityMode: 0x01,
      smb3: { cipher: 2, encryptData: true, forcePlaintext: true },
      mangle: (type, framed) => {
        if (!postSetup(type)) return framed;
        const copy = Buffer.from(framed);
        copy.writeUInt16LE(PacketType.SessionSetup, COMMAND);
        return copy;
      },
    });
    try {
      const session = await open(port, "3.1.1", "auto");
      await assert.rejects(session.readFile("share", "file.txt"), refused(/response command does not match the request|plaintext response/));
    } finally {
      await server.close();
    }
  });

  it("refuses a plaintext response that names another TreeId on an encrypted share", async () => {
    const { server, port } = await startServer({
      securityMode: 0x01,
      signResponses: true,
      smb3: { cipher: 2, encryptShares: ["share"], forcePlaintext: true },
      mangle: on([PacketType.Create, PacketType.Read, PacketType.Close], (framed) => framed.writeUInt32LE(99, TREE_ID)),
    });
    try {
      const session = await open(port, "3.1.1", "auto");
      await assert.rejects(session.readFile("share", "file.txt"), refused(/plaintext response on an encrypted session or share refused/));
    } finally {
      await server.close();
    }
  });

  it("refuses an encrypted response whose inner SessionId differs from its TRANSFORM header", async () => {
    const { server, port } = await startServer({
      securityMode: 0x01,
      smb3: { cipher: 2, encryptData: true },
      mangleMessage: (type, message) => {
        if (type === PacketType.Read) message.write("1111111111111111", 40, "hex");
        return message;
      },
    });
    try {
      const session = await open(port, "3.1.1", "auto");
      await assert.rejects(session.readFile("share", "file.txt"), refused(/does not match/));
    } finally {
      await server.close();
    }
  });
});

describe("unsolicited responses are discarded", () => {
  // A READ response for MessageId `messageId`, unsigned, built before any
  // key exists (raw serializer, no client code).
  const forgedRead = (messageId: bigint) =>
    Smb2Packet.prefixMessage(
      Smb2Packet.serializeMessage(
        { type: PacketType.Read, flags: HeaderFlag.Response, messageId, sessionId: MOCK_SESSION_ID, treeId: 1, status: 0, credit: 1 },
        { structureSize: 17, dataOffset: 80, buffer: Buffer.from("EVIL!") },
      ),
    );

  for (const [name, maxDialect, opts] of signedServers) {
    it(`${name}: a READ response injected before sign-in does not answer the later READ`, async () => {
      // Learn the READ's MessageId from an untouched run.
      const probe = await startServer(opts);
      let readId: bigint;
      try {
        const session = await open(probe.port, maxDialect);
        assert.equal((await session.readFile("share", "file.txt")).toString(), "hello");
        await session.close();
        readId = probe.server.seen.find((r) => r.type === PacketType.Read)!.messageId;
      } finally {
        await probe.server.close();
      }

      const { server, port } = await startServer({
        ...opts,
        mangle: (type, framed) => (type === PacketType.Negotiate ? Buffer.concat([framed, forgedRead(readId)]) : framed),
      });
      try {
        const session = await open(port, maxDialect);
        assert.equal((await session.readFile("share", "file.txt")).toString(), "hello");
        await session.close();
      } finally {
        await server.close();
      }
    });
  }
});
