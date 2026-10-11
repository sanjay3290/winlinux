// Offline replay of real Samba exchanges captured by test/live/capture.ts
//. No Docker: a local TCP server serves the recorded Samba frames
// back. The client must produce byte-identical requests (so its SMB2
// signatures match what Samba accepted) and must verify Samba's own response
// signatures.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { buildAuthenticate, parseChallenge } from "../helpers/ntlm-provider.js";
import {
  ReplayServer,
  signatureValid,
  frameCommand,
  frameStatus,
  isSigned,
  runCaptureFlow,
  type CaptureFixture,
} from "../helpers/capture.js";

// dist-test/test/mock -> <package>/test/fixtures/live
const fixtureDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../../test/fixtures/live");

function load(signing: "required" | "disabled"): CaptureFixture {
  return JSON.parse(fs.readFileSync(path.join(fixtureDir, `samba-signing-${signing}.json`), "utf8")) as CaptureFixture;
}

const NEGOTIATE = 0x0000;
const SESSION_SETUP = 0x0001;
const STATUS_MORE_PROCESSING_REQUIRED = 0xc0000016;

// Re-derives the NTLMv2 session key from the captured CHALLENGE and the
// fixed client inputs recorded with the capture.
function sessionKeyFor(fixture: CaptureFixture): Buffer {
  const challengeFrame = fixture.frames
    .map((f) => ({ dir: f.dir, buf: Buffer.from(f.hex, "hex") }))
    .find((f) => f.dir === "s2c" && frameCommand(f.buf) === SESSION_SETUP && frameStatus(f.buf) === STATUS_MORE_PROCESSING_REQUIRED)!;
  const offset = challengeFrame.buf.readUInt16LE(64 + 4);
  const length = challengeFrame.buf.readUInt16LE(64 + 6);
  const challenge = parseChallenge(challengeFrame.buf.subarray(offset, offset + length));
  return buildAuthenticate({
    username: fixture.credentials.username,
    domain: fixture.credentials.domain,
    workstation: fixture.workstation,
    password: fixture.credentials.password,
    challenge,
    clientChallenge: Buffer.from(fixture.clientChallenge, "hex"),
    timestamp: BigInt(fixture.timestamp),
  }).sessionKey;
}

for (const signing of ["required", "disabled"] as const) {
  describe(`replay of live Samba capture (server signing = ${signing})`, () => {
    const fixture = load(signing);
    const frames = fixture.frames.map((f) => ({ dir: f.dir, buf: Buffer.from(f.hex, "hex") }));
    const sessionKey = sessionKeyFor(fixture);

    it("holds a real Samba NEGOTIATE response for SMB 2.1", () => {
      const negotiate = frames.find((f) => f.dir === "s2c" && frameCommand(f.buf) === NEGOTIATE)!;
      assert.ok(negotiate);
      assert.equal(negotiate.buf.readUInt16LE(64 + 4), 0x0210);
      const securityMode = negotiate.buf.readUInt16LE(64 + 2);
      assert.equal(securityMode & 0x01, 0x01);
      assert.equal(securityMode & 0x02, signing === "required" ? 0x02 : 0);
    });

    it("signs every frame after SESSION_SETUP", () => {
      const setupDone = frames.findIndex(
        (f) => f.dir === "s2c" && frameCommand(f.buf) === SESSION_SETUP && frameStatus(f.buf) === 0,
      );
      assert.ok(setupDone > 0);
      const postSetup = frames.slice(setupDone + 1);
      assert.ok(postSetup.length > 10);
      for (const f of postSetup) assert.ok(isSigned(f.buf), `unsigned ${f.dir} command 0x${frameCommand(f.buf).toString(16)}`);
    });

    it("verifies both sides' recorded signatures under the derived session key", () => {
      // Samba accepted the client's signatures and signed its replies with
      // the same key, so this proves our NTLMv2 key derivation matches Samba.
      const signed = frames.filter((f) => isSigned(f.buf));
      assert.ok(signed.some((f) => f.dir === "c2s") && signed.some((f) => f.dir === "s2c"));
      for (const f of signed) {
        assert.ok(signatureValid(f.buf, sessionKey), `bad ${f.dir} signature on command 0x${frameCommand(f.buf).toString(16)}`);
      }
    });

    it("replays the whole session request for request", async () => {
      const server = new ReplayServer(fixture.frames, sessionKey);
      await server.start();
      try {
        const result = await runCaptureFlow({
          host: fixture.host,
          port: server.port,
          share: "testshare",
          credentials: fixture.credentials,
          signing: signing === "required" ? "required" : "auto",
          timestamp: BigInt(fixture.timestamp),
        });
        assert.deepEqual(server.mismatches, []);
        assert.ok(server.consumedAll, "client stopped before the end of the capture");
        assert.deepEqual(result, fixture.result);
        assert.ok(result.shares.some((share) => share.name === "testshare" && share.type === "disk"));
      } finally {
        await server.stop();
      }
    });

    it("fails the replay when one Samba signature byte changes", async () => {
      // Flip one signature byte in the first signed response after setup.
      const tampered = fixture.frames.map((f) => ({ ...f }));
      const index = frames.findIndex(
        (f, i) => f.dir === "s2c" && isSigned(f.buf) && i > 0 && frameCommand(f.buf) !== SESSION_SETUP,
      );
      assert.ok(index > 0);
      const buf = Buffer.from(tampered[index].hex, "hex");
      buf[48] ^= 0xff;
      tampered[index].hex = buf.toString("hex");
      const server = new ReplayServer(tampered, sessionKey);
      await server.start();
      try {
        await assert.rejects(
          runCaptureFlow({
            host: fixture.host,
            port: server.port,
            share: "testshare",
            credentials: fixture.credentials,
            signing: signing === "required" ? "required" : "auto",
            timestamp: BigInt(fixture.timestamp),
          }),
          /signature/,
        );
      } finally {
        await server.stop();
      }
    });
  });
}

