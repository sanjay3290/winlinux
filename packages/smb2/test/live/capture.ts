// One-shot capture tool, not a test. Starts dperson/samba twice (server
// signing required and disabled), runs the fixed capture flow through a
// recording proxy, and writes test/fixtures/live/samba-signing-<mode>.json.
// The offline replay test (test/mock/live-replay.test.ts) reads those files.
// Usage: npm run capture:live -w @winlinux/smb2
// Env: SMB_LIVE_PREFIX, SMB_LIVE_PORT_REQUIRED, SMB_LIVE_PORT_DISABLED.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { filetimeNow } from "../helpers/ntlm-provider.js";
import {
  CAPTURE_CLIENT_CHALLENGE,
  CAPTURE_TEXT,
  CAPTURE_WORKSTATION,
  RecordingProxy,
  runCaptureFlow,
  type CaptureFixture,
} from "../helpers/capture.js";
import {
  DOMAIN,
  PASS,
  PORT_DISABLED,
  PORT_REQUIRED,
  PREFIX,
  SHARE,
  USER,
  removeContainer,
  sambaVersion,
  startSamba,
  type SigningMode,
} from "./samba-docker.js";

// dist-test/test/live/capture.js -> <package>/test/fixtures/live
const outDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../../test/fixtures/live");

async function capture(signing: SigningMode, port: number): Promise<void> {
  const container = `${PREFIX}-capture-${signing}`;
  try {
    await startSamba(signing, port, container);
    const version = await sambaVersion(container);
    const proxy = new RecordingProxy(port);
    await proxy.start();
    const timestamp = filetimeNow();
    const credentials = { username: USER, password: PASS, domain: DOMAIN };
    let result;
    try {
      result = await runCaptureFlow({
        host: "127.0.0.1",
        port: proxy.port,
        share: SHARE,
        credentials,
        signing: signing === "required" ? "required" : "auto",
        timestamp,
      });
    } finally {
      await proxy.stop();
    }
    if (result.readBack !== CAPTURE_TEXT) throw new Error(`read back ${JSON.stringify(result.readBack)}`);
    const fixture: CaptureFixture = {
      description:
        `dperson/samba (${version}) with 'server signing = ${signing}': NEGOTIATE, NTLMv2 SESSION_SETUP, ` +
        `SRVSVC NetShareEnum over IPC$, write/read/delete ${SHARE}/capture.txt, close. Captured by test/live/capture.ts.`,
      sambaVersion: version,
      signing,
      host: "127.0.0.1",
      credentials,
      workstation: CAPTURE_WORKSTATION,
      clientChallenge: CAPTURE_CLIENT_CHALLENGE,
      timestamp: timestamp.toString(),
      result,
      frames: proxy.frames,
    };
    fs.mkdirSync(outDir, { recursive: true });
    const file = path.join(outDir, `samba-signing-${signing}.json`);
    fs.writeFileSync(file, JSON.stringify(fixture, null, 2) + "\n");
    console.log(`wrote ${file}: ${proxy.frames.length} frames`);
  } finally {
    await removeContainer(container);
  }
}

try {
  await capture("required", PORT_REQUIRED);
  await capture("disabled", PORT_DISABLED);
} catch (error) {
  console.error(`capture failed: ${(error as Error).message}`);
  process.exit(1);
}
