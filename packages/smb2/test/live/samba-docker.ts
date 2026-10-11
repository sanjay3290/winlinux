// Docker helpers for the live Samba runs (dperson/samba). Shared by the live
// suite and the capture tool. Names and ports come from env so parallel runs
// on one host cannot collide; the defaults are the original values.
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { connect } from "../../src/index.js";
import { SmbAuthError } from "../../src/errors.js";
import { NtlmTestProvider } from "../helpers/ntlm-provider.js";

export const IMAGE = "dperson/samba:latest";
export const USER = "testuser";
export const PASS = "testpass123"; // test-only container account
export const SHARE = "testshare";
export const DOMAIN = "WORKGROUP";

export const PREFIX = process.env.SMB_LIVE_PREFIX ?? "winlinux-smb-live";
export const PORT_REQUIRED = Number(process.env.SMB_LIVE_PORT_REQUIRED ?? "14445");
export const PORT_DISABLED = Number(process.env.SMB_LIVE_PORT_DISABLED ?? "14446");

export type SigningMode = "required" | "disabled";

const execFileAsync = promisify(execFile);

export async function docker(...args: string[]): Promise<string> {
  try {
    const { stdout } = await execFileAsync("docker", args, { encoding: "utf8" });
    return stdout;
  } catch (error) {
    const stderr = (error as { stderr?: string }).stderr ?? (error as Error).message;
    throw new Error(`docker ${args.join(" ")} failed: ${stderr}`);
  }
}

// The docker proxy accepts TCP before smbd is up, so poll with a real
// (bad-password) logon until the server answers with LOGON_FAILURE.
export async function waitForSmb(port: number, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    try {
      await connect({
        host: "127.0.0.1",
        port,
        authProvider: new NtlmTestProvider(),
        credentials: { username: USER, password: "wrong", domain: DOMAIN },
        requestTimeoutMs: 3000,
      });
    } catch (error) {
      if (error instanceof SmbAuthError) return; // server speaks SMB
      if (Date.now() > deadline) {
        throw new Error(`timed out waiting for SMB on 127.0.0.1:${port}: ${(error as Error).message}`);
      }
      await new Promise((resolve) => setTimeout(resolve, 1000));
      continue;
    }
    throw new Error("bad-password logon unexpectedly succeeded");
  }
}

export async function removeContainer(container: string): Promise<void> {
  try {
    await docker("rm", "-f", container);
  } catch {
    // did not exist; ignore
  }
}

export async function startSamba(signing: SigningMode, port: number, container: string): Promise<void> {
  await removeContainer(container);
  await docker(
    "run", "-d", "--rm", "--name", container,
    "-p", `127.0.0.1:${port}:445`,
    IMAGE,
    "-u", `${USER};${PASS}`,
    "-s", `${SHARE};/share;yes;no;no;${USER}`,
    "-p",
    "-g", `server signing = ${signing}`,
    "-w", DOMAIN,
  );
  await waitForSmb(port, 90000);
}

export async function sambaVersion(container: string): Promise<string> {
  return (await docker("exec", container, "smbd", "--version")).trim();
}
