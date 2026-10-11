// Live integration tests against dperson/samba (Docker). One suite with
// `server signing = required`, one with it disabled. Run with
// `npm run test:live` (needs Docker; fails fast with a clear error without
// it). Destroyed after the run.
import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import os from "node:os";
import path from "node:path";
import fs from "node:fs";
import crypto from "node:crypto";
import { connect } from "../../src/index.js";
import { SmbAuthError, SmbNotFoundError, SmbSigningError } from "../../src/errors.js";
import { NtlmTestProvider, filetimeNow } from "../helpers/ntlm-provider.js";
import {
  CAPTURE_TEXT,
  RecordingProxy,
  frameCommand,
  frameStatus,
  isSigned,
  runCaptureFlow,
} from "../helpers/capture.js";
import {
  DOMAIN,
  PASS,
  PORT_DISABLED,
  PORT_REQUIRED,
  PREFIX,
  SHARE,
  USER,
  docker,
  removeContainer,
  sambaVersion,
  startSamba,
  type SigningMode,
} from "./samba-docker.js";

const SESSION_SETUP = 0x0001;
const NEGOTIATE = 0x0000;
const BIG_FILE_BYTES = 100 * 1024 * 1024;

function liveSuite(signing: SigningMode, port: number, container: string): void {
  describe(`live samba (server signing = ${signing})`, () => {
    before(async () => {
      await startSamba(signing, port, container);
      console.log(`[live ${signing}] ${await sambaVersion(container)}, image arch ${(await docker("image", "inspect", "dperson/samba:latest", "--format", "{{.Architecture}}")).trim()}`);
      await docker(
        "exec", container, "sh", "-c",
        "head -c 200000 /dev/zero | tr '\\0' 'A' > /share/big.bin && echo hello-live > /share/hello.txt && mkdir -p /share/sub",
      );
    }, { timeout: 180000 });

    after(async () => {
      await removeContainer(container);
    }, { timeout: 60000 });

    it("runs the full API against real Samba", { timeout: 120000 }, async () => {
      const session = await connect({
        host: "127.0.0.1",
        port,
        authProvider: new NtlmTestProvider(),
        credentials: { username: USER, password: PASS, domain: DOMAIN },
        signing: signing === "required" ? "required" : "auto",
        requestTimeoutMs: 15000,
      });
      try {
        const shares = await session.listShares();
        const testshare = shares.find((share) => share.name === SHARE);
        assert.ok(testshare, `expected share ${SHARE} in ${JSON.stringify(shares)}`);
        assert.equal(testshare.type, "disk");
        console.log(`[live ${signing}] listShares: ${shares.map((share) => `${share.name}(${share.type})`).join(", ")}`);

        // Server-side view of this open session: protocol and signing.
        const status = await docker("exec", container, "smbstatus", "-b");
        const row = status.split("\n").find((line) => line.includes(USER));
        assert.ok(row, `expected a ${USER} session in smbstatus:\n${status}`);
        console.log(`[live ${signing}] smbstatus: ${row.trim().replace(/\s+/g, " ")}`);
        if (signing === "required") {
          assert.match(row, /HMAC-SHA256|AES-128-CMAC/, "server must report the session as signed");
        }

        await session.mkdir("testshare", "testdir");
        await session.writeFile("testshare", "testdir/note.txt", "live-write");

        const fileStat = await session.stat("testshare", "testdir/note.txt");
        assert.equal(fileStat.sizeBytes, 10n);
        assert.equal(fileStat.isDirectory, false);

        const hello = await session.readFile("testshare", "hello.txt");
        assert.equal(hello.toString().trim(), "hello-live");

        const big = await session.readFile("testshare", "big.bin");
        assert.equal(big.length, 200000);
        assert.ok(big.every((byte) => byte === 65));

        const entries = await session.list("testshare");
        const names = entries.map((entry) => entry.name);
        for (const want of ["hello.txt", "big.bin", "sub", "testdir"]) {
          assert.ok(names.includes(want), `expected ${want} in ${names.join(",")}`);
        }
        assert.equal(entries.find((entry) => entry.name === "sub")!.isDirectory, true);

        const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "smb-live-"));
        try {
          const local = path.join(tempDir, "up.bin");
          const payload = Buffer.alloc(100000, 0x42);
          fs.writeFileSync(local, payload);
          await session.upload(local, "testshare", "upload.bin");
          const roundtrip = await session.readFile("testshare", "upload.bin");
          assert.deepEqual(roundtrip, payload);
          const down = path.join(tempDir, "down.bin");
          await session.download("testshare", "big.bin", down);
          assert.equal(fs.statSync(down).size, 200000);
        } finally {
          fs.rmSync(tempDir, { recursive: true, force: true });
        }

        await session.delete("testshare", "testdir/note.txt");
        await session.delete("testshare", "testdir");
        await session.delete("testshare", "upload.bin");
      } finally {
        await session.close();
      }
    });

    it("records the exchange and logs the negotiated dialect", { timeout: 120000 }, async () => {
      const proxy = new RecordingProxy(port);
      await proxy.start();
      try {
        const result = await runCaptureFlow({
          host: "127.0.0.1",
          port: proxy.port,
          share: SHARE,
          credentials: { username: USER, password: PASS, domain: DOMAIN },
          signing: signing === "required" ? "required" : "auto",
          timestamp: filetimeNow(),
        });
        assert.ok(result.shares.some((share) => share.name === SHARE && share.type === "disk"));
        assert.equal(result.readBack, CAPTURE_TEXT);
      } finally {
        await proxy.stop();
      }

      const frames = proxy.frames.map((f) => ({ dir: f.dir, buf: Buffer.from(f.hex, "hex") }));
      const negotiate = frames.find((f) => f.dir === "s2c" && frameCommand(f.buf) === NEGOTIATE)!;
      assert.ok(negotiate, "no NEGOTIATE response captured");
      const securityMode = negotiate.buf.readUInt16LE(64 + 2);
      const dialect = negotiate.buf.readUInt16LE(64 + 4);
      console.log(`[live ${signing}] negotiated dialect=0x${dialect.toString(16).padStart(4, "0")} securityMode=0x${securityMode.toString(16)} frames=${frames.length}`);
      assert.ok(dialect === 0x0202 || dialect === 0x0210, `unexpected dialect 0x${dialect.toString(16)}`);

      // Everything after the final SESSION_SETUP success must be signed when
      // the server requires signing.
      const setupDone = frames.findIndex(
        (f) => f.dir === "s2c" && frameCommand(f.buf) === SESSION_SETUP && frameStatus(f.buf) === 0,
      );
      assert.ok(setupDone > 0, "no successful SESSION_SETUP captured");
      const postSetup = frames.slice(setupDone + 1);
      const signedCount = postSetup.filter((f) => isSigned(f.buf)).length;
      console.log(`[live ${signing}] post-setup frames signed: ${signedCount}/${postSetup.length}`);
      if (signing === "required") {
        assert.equal(securityMode & 0x02, 0x02, "server must advertise SIGNING_REQUIRED");
        assert.equal(signedCount, postSetup.length, "every post-setup frame must be signed");
      } else {
        assert.equal(securityMode & 0x02, 0, "server must not require signing");
      }
    });

    it("maps a missing file to SmbNotFoundError", { timeout: 60000 }, async () => {
      const session = await connect({
        host: "127.0.0.1",
        port,
        authProvider: new NtlmTestProvider(),
        credentials: { username: USER, password: PASS, domain: DOMAIN },
        signing: signing === "required" ? "required" : "auto",
        requestTimeoutMs: 15000,
      });
      try {
        await assert.rejects(session.stat(SHARE, "no-such-file.txt"), SmbNotFoundError);
        await assert.rejects(session.readFile(SHARE, "no-such-dir/x.txt"), SmbNotFoundError);
      } finally {
        await session.close();
      }
    });

    it("puts and gets a 100 MB file with equal SHA-256", { timeout: 900000 }, async () => {
      const session = await connect({
        host: "127.0.0.1",
        port,
        authProvider: new NtlmTestProvider(),
        credentials: { username: USER, password: PASS, domain: DOMAIN },
        signing: signing === "required" ? "required" : "auto",
        requestTimeoutMs: 60000,
      });
      const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "smb-live-big-"));
      try {
        const local = path.join(tempDir, "big-up.bin");
        const payload = crypto.randomBytes(BIG_FILE_BYTES);
        fs.writeFileSync(local, payload);
        const want = crypto.createHash("sha256").update(payload).digest("hex");
        const megabytes = BIG_FILE_BYTES / (1024 * 1024);

        let started = process.hrtime.bigint();
        await session.upload(local, SHARE, "big-100mb.bin");
        const putSeconds = Number(process.hrtime.bigint() - started) / 1e9;

        const remoteStat = await session.stat(SHARE, "big-100mb.bin");
        assert.equal(remoteStat.sizeBytes, BigInt(BIG_FILE_BYTES));

        const down = path.join(tempDir, "big-down.bin");
        started = process.hrtime.bigint();
        await session.download(SHARE, "big-100mb.bin", down);
        const getSeconds = Number(process.hrtime.bigint() - started) / 1e9;

        const got = crypto.createHash("sha256").update(fs.readFileSync(down)).digest("hex");
        assert.equal(got, want);
        const serverSide = (await docker("exec", container, "sha256sum", "/share/big-100mb.bin")).split(" ")[0];
        assert.equal(serverSide, want);
        console.log(
          `[live ${signing}] 100 MB sha256=${want} put ${putSeconds.toFixed(2)}s (${(megabytes / putSeconds).toFixed(1)} MB/s) ` +
          `get ${getSeconds.toFixed(2)}s (${(megabytes / getSeconds).toFixed(1)} MB/s)`,
        );
        await session.delete(SHARE, "big-100mb.bin");
      } finally {
        fs.rmSync(tempDir, { recursive: true, force: true });
        await session.close();
      }
    });

    it("rejects a wrong password with SmbAuthError", { timeout: 60000 }, async () => {
      await assert.rejects(
        connect({
          host: "127.0.0.1",
          port,
          authProvider: new NtlmTestProvider(),
          credentials: { username: USER, password: "wrong", domain: DOMAIN },
          requestTimeoutMs: 15000,
        }),
        SmbAuthError,
      );
    });

    if (signing === "required") {
      it("refuses to connect without a provider session key", { timeout: 60000 }, async () => {
        await assert.rejects(
          connect({
            host: "127.0.0.1",
            port,
            authProvider: new NtlmTestProvider({ includeSessionKey: false }),
            credentials: { username: USER, password: PASS, domain: DOMAIN },
            requestTimeoutMs: 15000,
          }),
          SmbSigningError,
        );
      });
    }
  });
}

liveSuite("required", PORT_REQUIRED, `${PREFIX}-required`);
liveSuite("disabled", PORT_DISABLED, `${PREFIX}-disabled`);
