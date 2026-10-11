// The Windows SMB live runner must refuse to run, with exit 2 and a list of
// what it needs, when its env is missing. It must never pass silently.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

describe("test:live:windows env check", () => {
  it("exits 2 and names every missing SMB_* variable", () => {
    const env: NodeJS.ProcessEnv = {};
    for (const [key, value] of Object.entries(process.env)) if (!key.startsWith("SMB_")) env[key] = value;
    const script = fileURLToPath(new URL("../live/windows-live.js", import.meta.url));
    const result = spawnSync(process.execPath, [script], { env, encoding: "utf8" });
    assert.equal(result.status, 2, result.stderr);
    for (const name of ["SMB_HOST", "SMB_SHARE", "SMB_USER", "SMB_PASS"]) {
      assert.match(result.stderr, new RegExp(`${name} is not set`));
    }
  });
});
