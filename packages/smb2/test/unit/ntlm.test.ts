// NTLM test-provider unit tests: hash primitive, challenge parsing, and a
// deterministic authenticate-message build. Wire correctness against a real
// server is proven by the live suite.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  buildAuthenticate,
  encodeNegotiate,
  md4,
  parseChallenge,
} from "../helpers/ntlm-provider.js";

describe("NTLM test provider", () => {
  it("computes MD4 (js-md4 works under ESM)", () => {
    assert.equal(md4(Buffer.alloc(0)).toString("hex"), "31d6cfe0d16ae931b73c59d7e0c089c0");
    assert.equal(md4(Buffer.from("password", "utf16le")).toString("hex"), "8846f7eaee8fb117ad06bdd830b7586c");
  });

  it("builds an NTLMv2-only negotiate message", () => {
    const message = encodeNegotiate("ws1", "corp");
    assert.equal(message.length, 32 + 3 + 4);
    assert.equal(message.subarray(0, 8).toString("hex"), "4e544c4d53535000");
    assert.equal(message.readUInt32LE(8), 1);
    // Unicode | NTLM session security | always sign | extended session
    // security | target info | version. No NTLMv1 path exists.
    assert.equal(message.readUInt32LE(12), 0x02888201);
    assert.equal(message.readUInt16LE(16), 4); // domain length
    assert.equal(message.readUInt32LE(20), 35); // domain offset
    assert.equal(message.readUInt16LE(24), 3); // workstation length
    assert.equal(message.readUInt32LE(28), 32); // workstation offset
    assert.equal(message.subarray(32, 35).toString("ascii"), "WS1");
    assert.equal(message.subarray(35).toString("ascii"), "CORP");
  });

  it("parses a challenge message", () => {
    const targetInfo = Buffer.from("0100020003000400050006000000", "hex");
    const challenge = Buffer.alloc(48 + targetInfo.length);
    challenge.write("NTLMSSP", 0, 7, "ascii");
    challenge.writeUInt32LE(2, 8);
    challenge.writeUInt16LE(0, 12);
    challenge.writeUInt16LE(0, 14);
    challenge.writeUInt32LE(48, 16);
    challenge.writeUInt32LE(0x8207b207, 20);
    Buffer.from("0123456789abcdef", "hex").copy(challenge, 24);
    challenge.writeUInt16LE(targetInfo.length, 40);
    challenge.writeUInt16LE(targetInfo.length, 42);
    challenge.writeUInt32LE(48, 44);
    targetInfo.copy(challenge, 48);

    const parsed = parseChallenge(challenge);
    assert.equal(parsed.flags, 0x8207b207);
    assert.equal(parsed.serverChallenge.toString("hex"), "0123456789abcdef");
    assert.deepEqual(parsed.targetInfo, targetInfo);
  });

  it("builds a deterministic NTLMv2 authenticate message", () => {
    const targetInfo = Buffer.from("07000800010203040506070800000000", "hex");
    const first = buildAuthenticate({
      username: "user",
      domain: "WORKGROUP",
      workstation: "CLIENT",
      password: "secret",
      challenge: { flags: 0x8207b207, serverChallenge: Buffer.from("0123456789abcdef", "hex"), targetInfo },
      clientChallenge: Buffer.from("f0f1f2f3f4f5f6f7", "hex"),
      timestamp: 133000000000000000n,
    });
    const second = buildAuthenticate({
      username: "user",
      domain: "WORKGROUP",
      workstation: "CLIENT",
      password: "secret",
      challenge: { flags: 0x8207b207, serverChallenge: Buffer.from("0123456789abcdef", "hex"), targetInfo },
      clientChallenge: Buffer.from("f0f1f2f3f4f5f6f7", "hex"),
      timestamp: 133000000000000000n,
    });
    assert.deepEqual(first.message, second.message);
    assert.deepEqual(first.sessionKey, second.sessionKey);
    assert.equal(first.sessionKey.length, 16);

    const message = first.message;
    assert.equal(message.subarray(0, 8).toString("ascii"), "NTLMSSP\0");
    assert.equal(message.readUInt32LE(8), 3);
    assert.equal(message.readUInt32LE(60), 0x8007b207); // echoed flags minus VERSION
    // The server challenge is bound into the NT proof: flipping the challenge
    // changes both the NT response and the session key.
    const other = buildAuthenticate({
      username: "user",
      domain: "WORKGROUP",
      workstation: "CLIENT",
      password: "secret",
      challenge: { flags: 0x8207b207, serverChallenge: Buffer.from("ffffffffffffffff", "hex"), targetInfo },
      clientChallenge: Buffer.from("f0f1f2f3f4f5f6f7", "hex"),
      timestamp: 133000000000000000n,
    });
    assert.notDeepEqual(other.message, first.message);
    assert.notDeepEqual(other.sessionKey, first.sessionKey);
  });
});
