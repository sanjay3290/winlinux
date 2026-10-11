#!/usr/bin/env bash
# Proves that the packed @winlinux/krb-session-key tarball installs without
# compiling anything and that its prebuilt addon loads.
#   usage: prove-prebuild.sh <path-to-tarball.tgz>
# Run with the compiler absent or disabled (for example CC=/usr/bin/false).
set -euxo pipefail

tarball=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
dir=$(mktemp -d)
cd "$dir"
npm init -y >/dev/null
npm install --loglevel=warn "$tarball"

pkg=node_modules/@winlinux/krb-session-key
ls "$pkg"
# Nothing was compiled: no build/ directory, only the shipped prebuilds.
test ! -d "$pkg/build"
ls "$pkg/prebuilds/$(node -p 'process.platform + "-" + process.arch')/"*.node

PKG_PATH="$dir/$pkg" node --input-type=module -e '
  import { createRequire } from "node:module";
  import { readFileSync } from "node:fs";
  import { load } from "@winlinux/krb-session-key";
  const require = createRequire(import.meta.url);
  const resolved = require("node-gyp-build").path(process.env.PKG_PATH);
  if (!/[\\/]prebuilds[\\/]/.test(resolved)) throw new Error("not loaded from prebuilds/: " + resolved);
  load();
  if (process.platform === "linux" && !readFileSync("/proc/self/maps", "utf8").includes("libgssapi_krb5")) {
    throw new Error("load() did not map libgssapi_krb5");
  }
  console.log("prebuild OK:", process.platform, process.arch, "node", process.versions.node, "->", resolved);
'
