// Live SMB scenarios against a real Windows Server.
// Not part of `npm test` or the Samba `test:live` (not named *.test.ts).
// Run with: npm run test:live:windows -w @winlinux/smb2
// Setup: packages/winrm/test/live/README.md. Exits 2 when the env is
// incomplete, 1 when a scenario fails, 0 when all pass.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { NtlmAuthProvider } from "@winlinux/auth";
import { connect, type SMBSession } from "../../src/index.js";
import Client from "../../src/client/Client.js";
import Dialect from "../../src/protocol/smb2/Dialect.js";
import PacketType from "../../src/protocol/smb2/PacketType.js";
import { generateGuid } from "../../src/protocol/util.js";

const HELP = [
  "test:live:windows needs a Windows Server with SMB file sharing on and one test share.",
  "Required:",
  "  SMB_HOST     host name or IP of the Windows server",
  "  SMB_SHARE    name of the test share (the account needs write access)",
  "  SMB_USER     local admin test account",
  "  SMB_PASS     its password",
  "Optional:",
  "  SMB_DOMAIN   NTLM domain (default: empty, for a local account)",
  "  SMB_PORT     TCP port (default: 445)",
  "See packages/winrm/test/live/README.md for the VM setup.",
].join("\n");

const missing = ["SMB_HOST", "SMB_SHARE", "SMB_USER", "SMB_PASS"].filter((name) => !process.env[name]);
const port = Number(process.env.SMB_PORT || 445);
const problems = missing.map((name) => `${name} is not set`);
if (!Number.isInteger(port) || port < 1 || port > 65535) problems.push(`SMB_PORT must be a TCP port, got '${process.env.SMB_PORT}'`);
if (problems.length > 0) {
  console.error(`test:live:windows cannot run:\n  - ${problems.join("\n  - ")}\n\n${HELP}`);
  process.exit(2);
}

const HOST = process.env.SMB_HOST as string;
const SHARE = process.env.SMB_SHARE as string;
const credentials = {
  username: process.env.SMB_USER as string,
  password: process.env.SMB_PASS as string,
  domain: process.env.SMB_DOMAIN ?? "",
};
console.log(`test:live:windows: host=${HOST}:${port} share=${SHARE} user=${credentials.domain ? `${credentials.domain}\\` : ""}${credentials.username}`);

async function withSession<T>(fn: (session: SMBSession) => Promise<T>): Promise<T> {
  const session = await connect({
    host: HOST,
    port,
    authProvider: new NtlmAuthProvider(),
    credentials,
    requestTimeoutMs: 30_000,
  });
  try {
    return await fn(session);
  } finally {
    await session.close();
  }
}

const sha256 = (data: Buffer) => crypto.createHash("sha256").update(data).digest("hex");

describe(`SMB live against Windows ${HOST}`, () => {
  it("SMB: negotiate offers 2.0.2/2.1 and logs the dialect Windows picks", { timeout: 60_000 }, async () => {
    // A separate NEGOTIATE on its own connection, identical to the one the
    // session sends (src/client/Session.ts), to read the dialect it gets.
    const client = new Client(HOST, { port, requestTimeout: 30_000 });
    try {
      await client.connect();
      const response = await client.request(
        { type: PacketType.Negotiate },
        { dialects: [Dialect.Smb202, Dialect.Smb210], clientGuid: generateGuid() },
      );
      const dialect = response.body.dialectRevision as number;
      const securityMode = response.body.securityMode as number;
      console.log(`# negotiated dialect 0x${dialect.toString(16)}, securityMode 0x${securityMode.toString(16)} (0x2 = signing required)`);
      assert.ok(dialect === Dialect.Smb202 || dialect === Dialect.Smb210, `unexpected dialect 0x${dialect.toString(16)}`);
    } finally {
      await client.close();
    }
    // And the full logon on that dialect works.
    await withSession(async () => undefined);
  });

  it("SMB: listShares returns the test share", { timeout: 60_000 }, async () => {
    const shares = await withSession((session) => session.listShares());
    console.log(`# shares: ${shares.map((share) => `${share.name}(${share.type})`).join(", ")}`);
    const found = shares.find((share) => share.name.toLowerCase() === SHARE.toLowerCase());
    assert.ok(found, `share ${SHARE} not in ${JSON.stringify(shares)}`);
    assert.equal(found.type, "disk");
  });

  it("SMB: put then get a file with equal SHA-256", { timeout: 300_000 }, async () => {
    const payload = crypto.randomBytes(3 * 1024 * 1024 + 17);
    const remote = `winlinux-live-${crypto.randomBytes(4).toString("hex")}.bin`;
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "winlinux-smb-win-"));
    try {
      const up = path.join(dir, "up.bin");
      const down = path.join(dir, "down.bin");
      fs.writeFileSync(up, payload);
      await withSession(async (session) => {
        await session.upload(up, SHARE, remote);
        try {
          await session.download(SHARE, remote, down);
        } finally {
          await session.delete(SHARE, remote);
        }
      });
      const got = fs.readFileSync(down);
      console.log(`# ${payload.length} bytes, sha256 ${sha256(payload)}`);
      assert.equal(got.length, payload.length);
      assert.equal(sha256(got), sha256(payload));
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
