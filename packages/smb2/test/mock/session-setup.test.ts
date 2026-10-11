// The final SESSION_SETUP response: on every SMB 3.x session with a
// session key it must be signed and verify, so a forged final response
// cannot finish the sign-in; and a guest or anonymous session is refused
// when real credentials were given or signing is required.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { connect } from "../../src/index.js";
import type { Credentials } from "../../src/auth-contract.js";
import { SmbAuthError, SmbSigningError } from "../../src/errors.js";
import { StubAuthProvider } from "../helpers/stub-provider.js";
import { MockSmbServer, type MockOptions } from "./server.js";

const sessionKey = Buffer.from("0123456789abcdef");
const IS_GUEST = 0x0001;
const IS_NULL = 0x0002;

async function startServer(opts: MockOptions): Promise<{ server: MockSmbServer; port: number }> {
  const server = new MockSmbServer({
    challenge: Buffer.from("mock-challenge"),
    files: new Map([["file.txt", { data: Buffer.from("hello"), isDirectory: false }]]),
    sessionKey,
    ...opts,
  });
  return { server, port: await server.listen() };
}

const open = (
  port: number,
  credentials: Credentials = { username: "u" },
  extra: { signing?: "auto" | "required"; maxDialect?: "2.1" | "3.1.1" } = {},
) =>
  connect({
    host: "127.0.0.1",
    port,
    authProvider: new StubAuthProvider({ challenge: Buffer.from("mock-challenge"), sessionKey }),
    credentials,
    requestTimeoutMs: 3000,
    ...extra,
  });

const fails = (ErrorType: typeof SmbAuthError, pattern: RegExp) => (error: unknown) => {
  assert.ok(error instanceof ErrorType, `expected ${ErrorType.name}, got ${String(error)}`);
  assert.match(error.message, pattern);
  return true;
};

describe("final SESSION_SETUP signature on SMB 3.0 and 3.0.2", () => {
  for (const [name, dialect] of [["3.0", 0x0300], ["3.0.2", 0x0302]] as const) {
    it(`SMB ${name}: an unsigned final SESSION_SETUP response is refused`, async () => {
      const { server, port } = await startServer({ securityMode: 0x01, smb3: { cipher: 0, dialect, unsignedFinal: true } });
      try {
        await assert.rejects(open(port), fails(SmbSigningError, new RegExp(`did not sign the final SESSION_SETUP response \\(required for SMB ${name.replace(".", "\\.")}\\)`)));
      } finally {
        await server.close();
      }
    });

    it(`SMB ${name}: an unsigned final response is refused with signing required too`, async () => {
      const { server, port } = await startServer({ securityMode: 0x03, signResponses: true, smb3: { cipher: 0, dialect, unsignedFinal: true } });
      try {
        await assert.rejects(open(port, { username: "u" }, { signing: "required" }), fails(SmbSigningError, /did not sign the final SESSION_SETUP response/));
      } finally {
        await server.close();
      }
    });

    it(`SMB ${name}: a signed final response passes and the session works (AES-CMAC, AES-128-CCM)`, async () => {
      const { server, port } = await startServer({ securityMode: 0x03, signResponses: true, smb3: { cipher: 1, dialect, encryptShares: ["secure"] } });
      try {
        const session = await open(port, { username: "u" }, { signing: "required" });
        assert.equal(session.security.dialect, name);
        assert.equal(session.security.signingAlgorithm, "AES-CMAC");
        assert.equal((await session.readFile("share", "file.txt")).toString(), "hello");
        assert.equal((await session.readFile("secure", "file.txt")).toString(), "hello");
        assert.ok(server.seen.some((r) => r.encrypted), "the secure share was encrypted");
        await session.close();
      } finally {
        await server.close();
      }
    });
  }
});

describe("guest and anonymous sessions", () => {
  const password: Credentials = { username: "u", password: "p" };

  for (const [flag, label] of [[IS_GUEST, "IS_GUEST"], [IS_NULL, "IS_NULL"]] as const) {
    it(`${label} after real credentials is refused (SMB 3.1.1)`, async () => {
      const { server, port } = await startServer({ securityMode: 0x01, signResponses: true, sessionFlags: flag, smb3: { cipher: 0 } });
      try {
        await assert.rejects(open(port, password), fails(SmbAuthError, /signed the session in as (guest|anonymous), not as the given account/));
      } finally {
        await server.close();
      }
    });
  }

  it("IS_GUEST after real credentials is refused on SMB 2.1 too", async () => {
    const { server, port } = await startServer({ securityMode: 0x01, signResponses: true, sessionFlags: IS_GUEST });
    try {
      await assert.rejects(open(port, password, { maxDialect: "2.1" }), fails(SmbAuthError, /as guest, not as the given account/));
    } finally {
      await server.close();
    }
  });

  it("IS_GUEST is refused when the client requires signing", async () => {
    const { server, port } = await startServer({ securityMode: 0x01, signResponses: true, sessionFlags: IS_GUEST, smb3: { cipher: 0 } });
    try {
      await assert.rejects(open(port, { username: "guest" }, { signing: "required" }), fails(SmbSigningError, /signing is required but the server signed the session in as guest/));
    } finally {
      await server.close();
    }
  });

  it("IS_GUEST is refused when the server requires signing", async () => {
    const { server, port } = await startServer({ securityMode: 0x03, signResponses: true, sessionFlags: IS_GUEST, smb3: { cipher: 0 } });
    try {
      await assert.rejects(open(port, { username: "guest" }), fails(SmbSigningError, /signing is required but the server signed the session in as guest/));
    } finally {
      await server.close();
    }
  });

  it("a guest session without a password and with no signing requirement still works", async () => {
    const { server, port } = await startServer({ securityMode: 0, sessionFlags: IS_GUEST, smb3: { cipher: 0, unsignedFinal: true } });
    try {
      const session = await open(port, { username: "guest" });
      assert.equal((await session.readFile("share", "file.txt")).toString(), "hello");
      await session.close();
    } finally {
      await server.close();
    }
  });
});
