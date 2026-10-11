// Auth-loop tests: the SESSION_SETUP exchange against a stub AuthProvider,
// with a fake transport (no network). Proves tokens land in the security
// buffer, the exchange repeats on one connection, and the stub sessionKey
// drives signing.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import Session from "../../src/client/Session.js";
import type Client from "../../src/client/Client.js";
import StatusCode from "../../src/protocol/smb2/StatusCode.js";
import PacketType from "../../src/protocol/smb2/PacketType.js";
import Dialect from "../../src/protocol/smb2/Dialect.js";
import { StubAuthProvider } from "../helpers/stub-provider.js";
import type { AuthProvider, SecurityContext, StepResult } from "../../src/auth-contract.js";
import {
  SmbAccessDeniedError,
  SmbAuthError,
  SmbDialectError,
  SmbSigningError,
} from "../../src/errors.js";

interface ScriptedResponse {
  header: { status: number; sessionId?: string };
  body: Record<string, unknown>;
}

function makeTransport(scripted: ScriptedResponse[]) {
  const requests: Array<{ header: object; body: Record<string, unknown> }> = [];
  const keys = new Map<string, Buffer>();
  let signingEnabled = false;
  const queue = [...scripted];
  const client = {
    host: "mockhost",
    setSessionKey: (id: string, key: Buffer) => keys.set(id, key),
    clearSessionKey: (id: string) => void keys.delete(id),
    enableSigning: () => void (signingEnabled = true),
    request: async (header: object, body: Record<string, unknown> = {}) => {
      requests.push({ header, body });
      const next = queue.shift();
      if (!next) throw new Error("transport: no more scripted responses");
      if (
        next.header.status !== StatusCode.Success &&
        next.header.status !== StatusCode.MoreProcessingRequired
      ) {
        throw { header: next.header, body: next.body };
      }
      return next;
    },
  };
  return { client: client as unknown as Client, requests, keys, wasSigningEnabled: () => signingEnabled };
}

const sessionId = "0a0b0c0d0e0f1011";
const negotiate = (securityMode: number, dialect = Dialect.Smb210): ScriptedResponse => ({
  header: { status: StatusCode.Success },
  body: { securityMode, dialectRevision: dialect },
});

// Kerberos-style context: one AP-REQ out, then it completes only when the
// server's AP-REP (sent with STATUS_SUCCESS) is fed back. A step after
// completion throws, like the real Kerberos context.
class KerberosStyleContext implements SecurityContext {
  steps: Array<Buffer | undefined> = [];
  complete = false;
  readonly negotiatedMechanism = "kerberos" as const;
  constructor(private readonly apRep: Buffer, private readonly key?: Buffer) {}
  // Like @winlinux/auth with @winlinux/krb-session-key: the full GSS key,
  // only once the AP-REP completed the context.
  get sessionKey(): Buffer | undefined {
    return this.complete && this.key ? Buffer.from(this.key) : undefined;
  }
  async step(inputToken?: Buffer): Promise<StepResult> {
    if (this.complete) throw new Error("kerberos-style: handshake is already complete");
    this.steps.push(inputToken);
    if (this.steps.length === 1) return { output: Buffer.from("ap-req"), complete: false };
    if (!inputToken || !inputToken.equals(this.apRep)) throw new Error("kerberos-style: wrong AP-REP");
    this.complete = true;
    return { output: null, complete: true };
  }
}

function kerberosStyleProvider(apRep: Buffer, key?: Buffer) {
  const contexts: KerberosStyleContext[] = [];
  const provider: AuthProvider = {
    mechanism: "kerberos",
    createContext: () => {
      const ctx = new KerberosStyleContext(apRep, key);
      contexts.push(ctx);
      return ctx;
    },
  };
  return { provider, contexts };
}

describe("SESSION_SETUP auth loop", () => {
  it("feeds the final STATUS_SUCCESS token to a Kerberos-style context", async () => {
    const apRep = Buffer.from("ap-rep-mutual-auth");
    const { client, requests, wasSigningEnabled } = makeTransport([
      negotiate(0x01),
      { header: { status: StatusCode.Success, sessionId }, body: { buffer: apRep } },
    ]);
    const { provider, contexts } = kerberosStyleProvider(apRep);
    const session = new Session(client);
    await session.authenticateWithProvider({ authProvider: provider, credentials: { username: "u" } });

    assert.equal(session.authenticated, true);
    assert.equal(requests.length, 2, "no extra SESSION_SETUP after STATUS_SUCCESS");
    assert.deepEqual(requests[1].body.buffer, Buffer.from("ap-req"));
    assert.deepEqual(contexts[0].steps, [undefined, apRep]);
    assert.equal(contexts[0].complete, true);
    assert.equal(wasSigningEnabled(), false, "no session key, signing only enabled");
  });

  it("does not step a context that is already complete on STATUS_SUCCESS", async () => {
    const acceptCompleted = Buffer.from("a1073005a0030a0100", "hex");
    const { client } = makeTransport([
      negotiate(0x01),
      { header: { status: StatusCode.MoreProcessingRequired, sessionId }, body: { buffer: Buffer.from("challenge") } },
      { header: { status: StatusCode.Success, sessionId }, body: { buffer: acceptCompleted } },
    ]);
    const provider = new StubAuthProvider({ sessionKey: Buffer.from("0123456789abcdef") });
    const session = new Session(client);
    await session.authenticateWithProvider({ authProvider: provider, credentials: { username: "u" } });
    assert.equal(session.authenticated, true);
    assert.equal(provider.contexts[0].steps.length, 2, "the final blob is not fed to a complete context");
  });

  it("still fails with SmbAuthError when the final token does not complete the context", async () => {
    const { client } = makeTransport([
      negotiate(0x01),
      { header: { status: StatusCode.Success, sessionId }, body: { buffer: Buffer.alloc(0) } },
    ]);
    const { provider } = kerberosStyleProvider(Buffer.from("ap-rep"));
    const session = new Session(client);
    await assert.rejects(
      session.authenticateWithProvider({ authProvider: provider, credentials: { username: "u" } }),
      (error: unknown) => error instanceof SmbAuthError && /not complete/.test(error.message),
    );
  });

  it("names Kerberos session keys and the addon when signing is required and no key exists", async () => {
    const apRep = Buffer.from("ap-rep");
    const { client } = makeTransport([
      negotiate(0x03),
      { header: { status: StatusCode.Success, sessionId }, body: { buffer: apRep } },
    ]);
    const { provider, contexts } = kerberosStyleProvider(apRep);
    const session = new Session(client);
    await assert.rejects(
      session.authenticateWithProvider({ authProvider: provider, credentials: { username: "u" } }),
      (error: unknown) =>
        error instanceof SmbSigningError &&
        /Kerberos provider supplies no session key/.test(error.message) &&
        /@winlinux\/krb-session-key/.test(error.message) &&
        !/#\d/.test(error.message),
    );
    assert.equal(contexts[0].complete, true, "auth itself succeeded; only signing is missing");
  });

  it("signs with the first 16 bytes of a 32-byte Kerberos session key (MS-SMB2 3.2.5.3.1)", async () => {
    const apRep = Buffer.from("ap-rep");
    const gssKey = Buffer.from("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "hex");
    const { client, keys, wasSigningEnabled } = makeTransport([
      negotiate(0x03),
      { header: { status: StatusCode.Success, sessionId }, body: { buffer: apRep } },
    ]);
    const { provider } = kerberosStyleProvider(apRep, gssKey);
    const session = new Session(client);
    await session.authenticateWithProvider({
      authProvider: provider,
      credentials: { username: "u" },
      signing: "required",
    });
    assert.equal(session.authenticated, true);
    assert.deepEqual(keys.get(sessionId), gssKey.subarray(0, 16));
    assert.equal(wasSigningEnabled(), true);
  });

  it("zeroes the GSS key copy it read after deriving the 16-byte signing key", async () => {
    const apRep = Buffer.from("ap-rep");
    const gssKey = Buffer.alloc(32, 0xab);
    const reads: Buffer[] = [];
    const { client, keys } = makeTransport([
      negotiate(0x03),
      { header: { status: StatusCode.Success, sessionId }, body: { buffer: apRep } },
    ]);
    const { provider } = kerberosStyleProvider(apRep, gssKey);
    const wrapped: AuthProvider = {
      mechanism: "kerberos",
      createContext: (t, c) => {
        const ctx = provider.createContext(t, c);
        return new Proxy(ctx, {
          get(target, prop) {
            if (prop !== "sessionKey") return Reflect.get(target, prop, target);
            const k = target.sessionKey;
            if (k) reads.push(k);
            return k;
          },
        });
      },
    };
    await new Session(client).authenticateWithProvider({ authProvider: wrapped, credentials: { username: "u" } });
    assert.deepEqual(keys.get(sessionId), Buffer.alloc(16, 0xab), "signing key is intact");
    assert.equal(reads.length, 1);
    assert.deepEqual(reads[0], Buffer.alloc(32), "the copy smb2 read is zeroed");
  });

  it("right-pads a GSS session key shorter than 16 bytes with zeros", async () => {
    const apRep = Buffer.from("ap-rep");
    const { client, keys } = makeTransport([
      negotiate(0x03),
      { header: { status: StatusCode.Success, sessionId }, body: { buffer: apRep } },
    ]);
    const { provider } = kerberosStyleProvider(apRep, Buffer.from("0102030405060708", "hex"));
    const session = new Session(client);
    await session.authenticateWithProvider({ authProvider: provider, credentials: { username: "u" } });
    assert.deepEqual(keys.get(sessionId), Buffer.from("01020304050607080000000000000000", "hex"));
  });

  it("maps an auth KerberosCredentialError to SmbAuthError", async () => {
    const { client } = makeTransport([negotiate(0x03)]);
    const provider: AuthProvider = {
      mechanism: "negotiate",
      createContext: () => ({
        complete: false,
        step: async () => {
          throw Object.assign(new Error("Kerberos rejected the credentials: Preauthentication failed"), {
            name: "KerberosCredentialError",
          });
        },
      }),
    };
    await assert.rejects(
      new Session(client).authenticateWithProvider({ authProvider: provider, credentials: { username: "u" } }),
      (error: unknown) => error instanceof SmbAuthError && /Preauthentication failed/.test((error as Error).message),
    );
  });

  it("sends stub tokens and registers the stub sessionKey for signing", async () => {
    const token1 = Buffer.from("stub-token-1");
    const challenge = Buffer.from("server-challenge");
    const token2 = Buffer.from("stub-token-2");
    const sessionKey = Buffer.from("0123456789abcdef");
    const { client, requests, keys, wasSigningEnabled } = makeTransport([
      negotiate(0x01),
      { header: { status: StatusCode.MoreProcessingRequired, sessionId }, body: { buffer: challenge } },
      { header: { status: StatusCode.Success, sessionId }, body: { buffer: Buffer.alloc(0) } },
    ]);
    const provider = new StubAuthProvider({ challenge, sessionKey });
    const session = new Session(client);
    await session.authenticateWithProvider({
      authProvider: provider,
      credentials: { username: "u", password: "p", domain: "d" },
    });

    assert.equal(session.authenticated, true);
    // One connection, three requests in order.
    assert.equal(requests.length, 3);
    assert.equal((requests[0].header as { type: number }).type, PacketType.Negotiate);
    assert.equal((requests[1].header as { type: number }).type, PacketType.SessionSetup);
    assert.equal((requests[2].header as { type: number }).type, PacketType.SessionSetup);
    // Tokens land in the security buffer; the challenge feeds back in.
    assert.deepEqual(requests[1].body.buffer, token1);
    assert.deepEqual(requests[2].body.buffer, token2);
    assert.equal(provider.contexts.length, 1);
    assert.deepEqual(provider.contexts[0].steps, [undefined, challenge]);
    assert.deepEqual(provider.created[0].target, { host: "mockhost", service: "cifs" });
    // Stub sessionKey drives signing.
    assert.deepEqual(keys.get(sessionId), sessionKey);
    assert.equal(wasSigningEnabled(), true);
    assert.equal(provider.contexts[0].disposed, true);
  });

  it("stays unsigned when the server offers no signing", async () => {
    const { client, wasSigningEnabled } = makeTransport([
      negotiate(0x00),
      { header: { status: StatusCode.Success, sessionId }, body: { buffer: Buffer.alloc(0) } },
    ]);
    const session = new Session(client);
    await session.authenticateWithProvider({
      authProvider: new StubAuthProvider({ tokens: [Buffer.from("only")] }),
      credentials: { username: "u" },
    });
    assert.equal(session.authenticated, true);
    assert.equal(wasSigningEnabled(), false);
  });

  it("fails clear when the server picks a dialect that was not offered", async () => {
    // With maxDialect "2.1" only 2.0.2 and 2.1 are offered; a 3.1.1 answer is refused.
    const { client, requests } = makeTransport([negotiate(0x01, Dialect.Smb311)]);
    const session = new Session(client);
    await assert.rejects(
      session.authenticateWithProvider({
        authProvider: new StubAuthProvider(),
        credentials: { username: "u" },
        maxDialect: "2.1",
      }),
      (error: unknown) =>
        error instanceof SmbDialectError && error.message === "server negotiated dialect 0x0311, which was not offered (offered 2.0.2, 2.1)",
    );
    assert.deepEqual(requests[0]?.body.dialects, [0x0202, 0x0210]);
    assert.equal(requests[0]?.body.capabilities, undefined, "no SMB3 capability bit with maxDialect 2.1");

    const { client: client2, requests: requests2 } = makeTransport([negotiate(0x01, 0x0400 as Dialect)]);
    await assert.rejects(
      new Session(client2).authenticateWithProvider({ authProvider: new StubAuthProvider(), credentials: { username: "u" } }),
      /server negotiated dialect 0x0400, which was not offered \(offered 2\.0\.2, 2\.1, 3\.0, 3\.0\.2, 3\.1\.1\)/,
    );
    assert.deepEqual(requests2[0]?.body.dialects, [0x0202, 0x0210, 0x0300, 0x0302, 0x0311]);
    assert.equal(requests2[0]?.body.capabilities, 0x40, "SMB2_GLOBAL_CAP_ENCRYPTION for the 3.0.x dialects");
  });

  it("fails clear when signing is required but the provider has no key", async () => {
    const { client } = makeTransport([
      negotiate(0x03),
      { header: { status: StatusCode.Success, sessionId }, body: { buffer: Buffer.alloc(0) } },
    ]);
    const session = new Session(client);
    await assert.rejects(
      session.authenticateWithProvider({
        authProvider: new StubAuthProvider({ tokens: [Buffer.from("only")] }),
        credentials: { username: "u" },
      }),
      (error: unknown) => error instanceof SmbSigningError && /session key/.test(error.message),
    );
  });

  it("fails clear when signing mode is required but the server offers none", async () => {
    const { client } = makeTransport([negotiate(0x00)]);
    const session = new Session(client);
    await assert.rejects(
      session.authenticateWithProvider({
        authProvider: new StubAuthProvider(),
        credentials: { username: "u" },
        signing: "required",
      }),
      SmbSigningError,
    );
  });

  it("maps a logon failure to a typed auth error", async () => {
    const { client } = makeTransport([
      negotiate(0x00),
      { header: { status: 0xc000006d, sessionId }, body: {} },
    ]);
    const session = new Session(client);
    await assert.rejects(
      session.authenticateWithProvider({
        authProvider: new StubAuthProvider(),
        credentials: { username: "u" },
      }),
      (error: unknown) => error instanceof Error && /authentication failed/.test(error.message),
    );
  });

  it("maps access denied during setup to SmbAccessDeniedError", async () => {
    const { client } = makeTransport([
      negotiate(0x00),
      { header: { status: 0xc0000022, sessionId }, body: {} },
    ]);
    const session = new Session(client);
    await assert.rejects(
      session.authenticateWithProvider({
        authProvider: new StubAuthProvider(),
        credentials: { username: "u" },
      }),
      SmbAccessDeniedError,
    );
  });
});
