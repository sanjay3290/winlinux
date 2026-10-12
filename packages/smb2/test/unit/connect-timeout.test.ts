// A TCP connect that does not finish in connectTimeoutMs rejects with an
// SmbConnectionError whose cause has code ETIMEDOUT, as ENOTFOUND and
// ECONNREFUSED causes do, so callers read all three the same way.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { Socket } from "node:net";
import { connect, SmbConnectionError } from "../../src/index.js";
import { StubAuthProvider } from "../helpers/stub-provider.js";

describe("connect timeout", () => {
  it("rejects with SmbConnectionError, cause code ETIMEDOUT and message connect_timeout", async () => {
    // A connect that never completes, without depending on the network.
    const original = Socket.prototype.connect;
    Socket.prototype.connect = function (this: Socket) {
      return this;
    } as typeof Socket.prototype.connect;
    try {
      await assert.rejects(
        connect({
          host: "smb.example.test",
          port: 445,
          authProvider: new StubAuthProvider({ challenge: Buffer.from("c") }),
          credentials: { username: "u" },
          connectTimeoutMs: 50,
        }),
        (error: unknown) => {
          assert.ok(error instanceof SmbConnectionError, String(error));
          const cause = (error as { cause?: Error & { code?: string } }).cause;
          assert.equal(cause?.message, "connect_timeout");
          assert.equal(cause?.code, "ETIMEDOUT");
          return true;
        },
      );
    } finally {
      Socket.prototype.connect = original;
    }
  });
});
