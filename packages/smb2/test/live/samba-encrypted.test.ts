// Live SMB 3.x encryption and signing against real Samba in Docker.
// Run with `npm run test:live` (needs Docker; destroyed after the run).
//
// - dperson/samba (Samba 4.12), `smb encrypt = required`: SMB 3.1.1 with
//   AES-128-GCM, and with `server max protocol = SMB3_02`, SMB 3.0.2 with
//   AES-128-CCM. Every frame after SESSION_SETUP is a TRANSFORM_HEADER.
// - Samba 4.17 from Debian bookworm (built from samba-bookworm/): AES-GMAC
//   signing and a share with `smb encrypt = required` next to a plain one;
//   only the encrypted share's traffic is transformed.
//
// Env: SMB_LIVE_ENC_PORT (base port, default 14460), SMB_LIVE_BOOKWORM_BASE
// (base image for the bookworm build, default debian:bookworm-slim).
import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { connect, type SMBSession } from "../../src/index.js";
import { NtlmTestProvider } from "../helpers/ntlm-provider.js";
import { RecordingProxy, frameCommand, frameStatus } from "../helpers/capture.js";
import { DOMAIN, IMAGE, PASS, SHARE, USER, docker, removeContainer, waitForSmb } from "./samba-docker.js";

const BASE_PORT = Number(process.env.SMB_LIVE_ENC_PORT ?? "14460");
const BOOKWORM_BASE = process.env.SMB_LIVE_BOOKWORM_BASE ?? "debian:bookworm-slim";
const BOOKWORM_IMAGE = "winlinux-samba-bookworm:test";
// dist-test/test/live -> <package>/test/live/samba-bookworm
const BOOKWORM_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../../test/live/samba-bookworm");

const SESSION_SETUP = 0x0001;
const TREE_CONNECT = 0x0003;
const isTransform = (hex: string) => hex.startsWith("fd534d42");

async function open(port: number): Promise<SMBSession> {
  return await connect({
    host: "127.0.0.1",
    port,
    authProvider: new NtlmTestProvider(),
    credentials: { username: USER, password: PASS, domain: DOMAIN },
    requestTimeoutMs: 30000,
  });
}

async function roundTrip(session: SMBSession, share: string, bytes: number): Promise<void> {
  const data = crypto.randomBytes(bytes);
  await session.writeFile(share, "enc-roundtrip.bin", data);
  const back = await session.readFile(share, "enc-roundtrip.bin");
  assert.equal(crypto.createHash("sha256").update(back).digest("hex"), crypto.createHash("sha256").update(data).digest("hex"));
  assert.ok((await session.list(share)).some((e) => e.name === "enc-roundtrip.bin"));
  await session.delete(share, "enc-roundtrip.bin");
}

// Frames after the final SESSION_SETUP response.
function afterSetup(proxy: RecordingProxy) {
  const done = proxy.frames.findIndex((f) => f.dir === "s2c" && !isTransform(f.hex) && frameCommand(Buffer.from(f.hex, "hex")) === SESSION_SETUP && frameStatus(Buffer.from(f.hex, "hex")) === 0);
  assert.ok(done > 0, "saw the final SESSION_SETUP response");
  return proxy.frames.slice(done + 1);
}

for (const [label, extra, expected, offset] of [
  ["SMB 3.1.1, AES-128-GCM", [], { dialect: "3.1.1", signingAlgorithm: "AES-CMAC", cipher: "AES-128-GCM", encryptData: true, signing: true }, 0],
  ["SMB 3.0.2, AES-128-CCM", ["-g", "server max protocol = SMB3_02"], { dialect: "3.0.2", signingAlgorithm: "AES-CMAC", cipher: "AES-128-CCM", encryptData: true, signing: true }, 1],
] as const) {
  describe(`live samba 4.12, smb encrypt = required (${label})`, () => {
    const port = BASE_PORT + offset;
    const container = `winlinux-smb-enc-${offset}-${process.pid}`;
    before(async () => {
      await removeContainer(container);
      await docker(
        "run", "-d", "--rm", "--name", container, "-p", `127.0.0.1:${port}:445`, IMAGE,
        "-u", `${USER};${PASS}`, "-s", `${SHARE};/share;yes;no;no;${USER}`, "-p",
        "-g", "smb encrypt = required", ...extra, "-w", DOMAIN,
      );
      await waitForSmb(port, 90000);
    }, { timeout: 180000 });
    after(async () => removeContainer(container), { timeout: 60000 });

    it("negotiates encryption and every frame after setup is encrypted", { timeout: 300000 }, async () => {
      const proxy = new RecordingProxy(port);
      await proxy.start();
      try {
        const session = await open(proxy.port);
        try {
          assert.deepEqual(session.security, expected);
          const shares = await session.listShares();
          assert.ok(shares.some((s) => s.name === SHARE), JSON.stringify(shares));
          await roundTrip(session, SHARE, 10 * 1024 * 1024 + 7);
        } finally {
          await session.close();
        }
        const frames = afterSetup(proxy);
        assert.ok(frames.length > 20);
        assert.deepEqual(frames.filter((f) => !isTransform(f.hex)).map((f) => `${f.dir} ${f.hex.slice(0, 40)}`), []);
      } finally {
        await proxy.stop();
      }
    });
  });
}

describe("live samba 4.17 (Debian bookworm): AES-GMAC signing and share-level encryption", () => {
  const port = BASE_PORT + 2;
  const container = `winlinux-smb-enc-bookworm-${process.pid}`;
  before(async () => {
    const proxyArgs = ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"]
      .filter((name) => process.env[name])
      .flatMap((name) => ["--build-arg", `${name}=${process.env[name]}`]);
    await docker("build", "-q", "--network", "host", "--build-arg", `BASE=${BOOKWORM_BASE}`, ...proxyArgs, "-t", BOOKWORM_IMAGE, BOOKWORM_DIR);
    await removeContainer(container);
    await docker("run", "-d", "--rm", "--name", container, "-p", `127.0.0.1:${port}:445`, "-e", "EXTRA_GLOBAL=server signing = required", BOOKWORM_IMAGE);
    await waitForSmb(port, 90000);
  }, { timeout: 600000 });
  after(async () => removeContainer(container), { timeout: 60000 });

  it("signs with AES-GMAC on the plain share and encrypts only the encrypted share", { timeout: 300000 }, async () => {
    const proxy = new RecordingProxy(port);
    await proxy.start();
    try {
      const session = await open(proxy.port);
      try {
        assert.deepEqual(session.security, { dialect: "3.1.1", signingAlgorithm: "AES-GMAC", cipher: "AES-128-GCM", encryptData: false, signing: true });
        assert.deepEqual((await session.listShares()).map((s) => s.name).sort(), ["IPC$", "enc", "plain"]);
        await roundTrip(session, "plain", 4 * 1024 * 1024 + 3);
        await roundTrip(session, "enc", 4 * 1024 * 1024 + 3);
      } finally {
        await session.close();
      }
      const frames = afterSetup(proxy);
      const encrypted = frames.filter((f) => isTransform(f.hex));
      const plain = frames.filter((f) => !isTransform(f.hex));
      assert.ok(encrypted.length > 10, "the enc share's traffic is encrypted");
      assert.ok(plain.length > 10, "the plain share and IPC$ stay signed, not encrypted");
      // Every plaintext frame after setup is signed (SMB2_FLAGS_SIGNED),
      // except async STATUS_PENDING interim responses, which servers send
      // unsigned and the client only skips (MS-SMB2 3.3.4.2).
      const interim = (b: Buffer) => frameStatus(b) === 0x103 && (b.readUInt32LE(16) & 0x2) !== 0;
      for (const f of plain.filter((f) => !interim(Buffer.from(f.hex, "hex")))) { const b = Buffer.from(f.hex, "hex"); assert.ok(b.readUInt32LE(16) & 0x8, `unsigned ${f.dir} frame: command 0x${frameCommand(b).toString(16)} status 0x${frameStatus(b).toString(16)} flags 0x${b.readUInt32LE(16).toString(16)}`); }
      // The TREE_CONNECT to enc goes signed; its response flags the share.
      const connects = plain.filter((f) => frameCommand(Buffer.from(f.hex, "hex")) === TREE_CONNECT && f.dir === "s2c");
      assert.ok(connects.some((f) => Buffer.from(f.hex, "hex").readUInt32LE(64 + 4) & 0x8000), "one TREE_CONNECT response carries SMB2_SHAREFLAG_ENCRYPT_DATA");
    } finally {
      await proxy.stop();
    }
  });

  it("negotiates AES-128-CCM on 3.1.1 when the server allows only CCM", { timeout: 300000 }, async () => {
    const ccmContainer = `${container}-ccm`;
    const ccmPort = BASE_PORT + 3;
    await removeContainer(ccmContainer);
    await docker("run", "-d", "--rm", "--name", ccmContainer, "-p", `127.0.0.1:${ccmPort}:445`, "-e", "EXTRA_GLOBAL=server smb3 encryption algorithms = AES-128-CCM", BOOKWORM_IMAGE);
    try {
      await waitForSmb(ccmPort, 90000);
      const session = await open(ccmPort);
      try {
        assert.equal(session.security.cipher, "AES-128-CCM");
        assert.equal(session.security.dialect, "3.1.1");
        await roundTrip(session, "enc", 1024 * 1024 + 1);
      } finally {
        await session.close();
      }
    } finally {
      await removeContainer(ccmContainer);
    }
  });
});
