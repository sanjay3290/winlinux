// Signing tests against the checked-in CPython oracle vector.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { computeSignature, signMessage, verifySignature } from "../../src/signing.js";
import { treeConnect } from "../fixtures/golden-packets.js";
import { oracleKey, oracleSignature } from "../fixtures/signing-oracle.js";

const key = Buffer.from(oracleKey, "hex");
const message = Buffer.from(treeConnect, "hex");

describe("SMB2 packet signing", () => {
  it("matches the independent Python oracle vector", () => {
    assert.equal(computeSignature(message, key).toString("hex"), oracleSignature);
  });

  it("signMessage patches only the signature field", () => {
    const signed = signMessage(message, key);
    assert.equal(signed.subarray(48, 64).toString("hex"), oracleSignature);
    assert.equal(signed.subarray(0, 48).toString("hex"), message.subarray(0, 48).toString("hex"));
    assert.equal(signed.subarray(64).toString("hex"), message.subarray(64).toString("hex"));
    assert.equal(message.subarray(48, 64).toString("hex"), "0".repeat(32)); // input untouched
  });

  it("verifySignature accepts a good signature and rejects tampering", () => {
    assert.equal(verifySignature(signMessage(message, key), key), true);
    const tampered = signMessage(message, key);
    tampered[100] ^= 0xff;
    assert.equal(verifySignature(tampered, key), false);
    assert.equal(verifySignature(signMessage(message, key), Buffer.alloc(16, 7)), false);
    assert.equal(verifySignature(Buffer.alloc(10), key), false);
  });
});
