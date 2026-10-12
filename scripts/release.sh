#!/usr/bin/env bash
# The local release: check, build, test, pack, smoke test and publish
# the five packages from the maintainer's machine.
#
#   npm run release:dry                   # everything, with `npm publish --dry-run`
#   npm run release -- --publish 1.1.0    # the real publish (npm login first)
#   bash scripts/release.sh [--dry-run] [<version>] [options]
#
# Without --publish nothing is published: the last step runs
# `npm publish --dry-run`. <version> defaults to the version in
# package.json; with --publish it is required and must equal it.
#
# Options:
#   --publish <version>   publish for real, with `npm publish --access public`
#   --dry-run             the default; accepted for clarity
#   --skip-linux-check    skip `npm run check:linux` (prints a warning)
#   --reuse-prebuilds     keep packages/krb-session-key/prebuilds/ as it is
#                         and only prove it (for example after adding a
#                         darwin-x64 binary built on an Intel Mac)
#
# Steps, in order. The first failure stops the run and names the step.
#   1. preflight: tools, Node >= 22, on main, clean tree, HEAD == origin/main,
#      every package.json at <version>, exact internal pins; with --publish,
#      `npm whoami` must work
#   2. npm ci, npm run build, npm test, npm audit --audit-level=low
#   3. npm run check:linux (Docker)
#   4. the addon prebuilds: scripts/prebuild-local.sh --prove (all six
#      targets on macOS); the run needs every binary
#   5. npm pack of all five packages, and a check of each tarball
#   6. smoke test: install the tarballs into an empty directory on this host,
#      then in node:22-slim containers (linux/amd64 and linux/arm64) with no
#      compiler: `npx winlinux --version`, `import { connect }`, the
#      CommonJS `await import()`, and kerberosSessionKeyAvailable() true
#   7. publish in dependency order: @winlinux/krb-session-key,
#      @winlinux/auth, @winlinux/smb2, @winlinux/winrm, winlinux. A package
#      whose exact version is already on the registry is skipped, so a
#      failed run can be repeated.
#
# No --provenance: npm provenance needs a CI OIDC identity (GitHub Actions),
# and this runs on a workstation.
set -euo pipefail

repo=$(cd "$(dirname "$0")/.." && pwd)
cd "$repo"

order=(@winlinux/krb-session-key @winlinux/auth @winlinux/smb2 @winlinux/winrm winlinux)
dirs=(krb-session-key auth smb2 winrm winlinux)
addon_targets=(darwin-arm64 darwin-x64 linux-x64 linux-arm64)
publish=0
version=
skip_linux=0
reuse_prebuilds=0

usage() { sed -n 2,40p "$0" >&2; exit 2; }
while [ $# -gt 0 ]; do
  case "$1" in
    --publish) [ $# -ge 2 ] || usage; publish=1; version=$2; shift ;;
    --dry-run) ;;
    --skip-linux-check) skip_linux=1 ;;
    --reuse-prebuilds) reuse_prebuilds=1 ;;
    -h|--help) usage ;;
    -*) echo "release: unknown option $1" >&2; usage ;;
    *) [ -z "$version" ] || usage; version=$1 ;;
  esac
  shift
done

step=preflight
fail() { echo >&2; echo "release: $*" >&2; exit 1; }
banner() { step=$1; echo; echo "==== release: $1"; }
work=$(mktemp -d "${TMPDIR:-/tmp}/winlinux-release.XXXXXX")
on_exit() {
  local rc=$?
  rm -rf "$work"
  [ "$rc" = 0 ] || echo "release: FAILED at step '$step' (exit $rc). The steps after it did not run." >&2
}
trap on_exit EXIT

# --- 1. preflight -----------------------------------------------------------
banner preflight
[ -z "${npm_config_dry_run:-}" ] || [ "${npm_config_dry_run}" = false ] \
  || fail "npm's --dry-run flag reached this script and would turn npm ci into a no-op; use 'npm run release:dry'"
for t in git node npm tar; do command -v "$t" >/dev/null || fail "$t is not installed"; done
command -v docker >/dev/null && docker info >/dev/null 2>&1 \
  || fail "Docker must be running (check:linux, the Linux prebuilds and the container smoke test use it)"
node_major=$(node -p 'process.versions.node.split(".")[0]')
[ "$node_major" -ge 22 ] || fail "Node.js 22 or later is needed (this is $(node -v))"
pkg_version=$(node -p 'require("./packages/winlinux/package.json").version')
if [ "$publish" = 1 ]; then
  [ -n "$version" ] || fail "--publish needs the version, for example --publish $pkg_version"
fi
version=${version:-$pkg_version}
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "'$version' is not a version like 1.2.3"

branch=$(git rev-parse --abbrev-ref HEAD)
[ "$branch" = main ] || fail "releases come from main; this checkout is on '$branch'"
[ -z "$(git status --porcelain)" ] || { git status --short >&2; fail "the working tree is not clean"; }
git fetch --quiet origin main || fail "git fetch origin main failed"
[ "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)" ] \
  || fail "HEAD ($(git rev-parse --short HEAD)) is not origin/main ($(git rev-parse --short origin/main)); pull or push first"

VERSION=$version node -e '
  const fs = require("fs"); const v = process.env.VERSION; const bad = [];
  const files = ["package.json", ...process.argv.slice(1).map((d) => `packages/${d}/package.json`)];
  for (const f of files) {
    const j = JSON.parse(fs.readFileSync(f, "utf8"));
    if (j.version !== v) bad.push(`${f}: version ${j.version}`);
    for (const k of ["dependencies", "optionalDependencies"])
      for (const [d, r] of Object.entries(j[k] ?? {}))
        if (d.startsWith("@winlinux/") && r !== v) bad.push(`${f}: ${k}.${d} is ${r}`);
  }
  if (bad.length) { console.error(bad.join("\n")); process.exit(1); }
' "${dirs[@]}" || fail "not every package.json is at $version (see above)"
echo "version $version in every package.json; on main at $(git rev-parse --short HEAD), clean, equal to origin/main"

if [ "$publish" = 1 ]; then
  who=$(npm whoami 2>/dev/null) || fail "npm whoami failed: run 'npm login' first"
  echo "npm user: $who (publishing for real)"
else
  echo "dry run: nothing is published"
fi

# --- 2. build, test, audit --------------------------------------------------
banner "npm ci";              npm ci --no-audit --no-fund
banner "npm run build";       npm run build
banner "npm test";            npm test
banner "npm audit";           npm audit --audit-level=low

# --- 3. Linux check ---------------------------------------------------------
if [ "$skip_linux" = 1 ]; then
  step="check:linux"
  echo
  echo "!!!! WARNING: --skip-linux-check: the Linux build and tests did NOT run." >&2
  echo "!!!! This release is tested on $(uname -s) only." >&2
else
  banner "npm run check:linux"; npm run check:linux
fi

# --- 4. addon prebuilds -----------------------------------------------------
banner "addon prebuilds"
prebuilds=packages/krb-session-key/prebuilds
if [ "$reuse_prebuilds" = 1 ]; then
  bash scripts/prebuild-local.sh --prove-only | tee "$work/prebuild.log"
else
  rm -rf "$prebuilds"
  bash scripts/prebuild-local.sh --prove | tee "$work/prebuild.log"
fi
for t in "${addon_targets[@]}"; do
  ls "$prebuilds/$t/"*.node >/dev/null 2>&1 || fail "no $t prebuild in $prebuilds (the release needs darwin-arm64, darwin-x64, linux-x64 and linux-arm64; build darwin on a Mac)"
done
for libc in glibc musl; do
  for a in x64 arm64; do
    [ -f "$prebuilds/linux-$a/@winlinux+krb-session-key.$libc.node" ] || fail "no linux-$a $libc prebuild"
  done
done
if grep -q "NOT PROVEN" "$work/prebuild.log"; then
  echo
  echo "!!!! WARNING: $(grep -m1 'NOT PROVEN on this machine' "$work/prebuild.log" | sed 's/^ *//')" >&2
  echo "!!!! Those binaries are built and checked, but no install on that platform loaded them." >&2
fi

# --- 5. pack and check ------------------------------------------------------
banner "npm pack"
mkdir -p "$work/pack"
for w in "${order[@]}"; do npm pack -w "$w" --pack-destination "$work/pack" --silent >/dev/null; done
tarball() { # $1 package name -> tarball path
  local n=${1#@}; n=${n//\//-}; echo "$work/pack/$n-$version.tgz"
}
for w in "${order[@]}"; do
  t=$(tarball "$w"); [ -f "$t" ] || fail "npm pack made no $(basename "$t")"
  tar tzf "$t" | sort > "$work/list"
  for f in package/package.json package/LICENSE package/README.md; do
    grep -qx "$f" "$work/list" || fail "$(basename "$t") has no ${f#package/}"
  done
  grep -q '^package/dist/' "$work/list" || fail "$(basename "$t") has no dist/"
  if grep -E '^package/(test|dist/test|node_modules|build)/|\.map$' "$work/list"; then fail "$(basename "$t") ships tests, build output or source maps (above)"; fi
  if grep -E '^package/src/' "$work/list" | grep -v '^package/src/native/'; then fail "$(basename "$t") ships TypeScript sources (above)"; fi
  v=$(tar xzf "$t" -O package/package.json | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>console.log(JSON.parse(s).version))')
  [ "$v" = "$version" ] || fail "$(basename "$t") has version $v"
done
addon=$(tarball @winlinux/krb-session-key)
for t in "${addon_targets[@]}"; do
  tar tzf "$addon" | grep -q "^package/prebuilds/$t/.*\.node$" || fail "the addon tarball has no $t prebuild"
done
tar tzf "$(tarball winlinux)" | grep -qx 'package/bin/winlinux.js' || fail "the winlinux tarball has no bin/winlinux.js"
echo "tarballs (all checked):"
for w in "${order[@]}"; do
  t=$(tarball "$w")
  printf '  %-40s %8s bytes  %3s files\n' "$(basename "$t")" "$(wc -c < "$t" | tr -d ' ')" "$(tar tzf "$t" | wc -l | tr -d ' ')"
done
echo "addon prebuilds in the tarball:"
tar tzf "$addon" | grep '^package/prebuilds/' | sed 's|^package/|  |'

# --- 6. smoke tests ---------------------------------------------------------
banner "smoke test"
mkdir -p "$work/smoke"
cat > "$work/smoke/smoke.mjs" <<'EOF'
// ESM consumer: the README quick start import, plus the addon check.
import { connect } from 'winlinux';
import { kerberosSessionKeyAvailable } from '@winlinux/auth';
import { existsSync } from 'node:fs';
if (typeof connect !== 'function') throw new Error('connect is not a function');
const client = await connect('server.example.test', { username: 'alice', password: 'x' });
await client.close();
const target = `${process.platform}-${process.arch}`;
const prebuilt = existsSync(`node_modules/@winlinux/krb-session-key/prebuilds/${target}`);
const addon = await kerberosSessionKeyAvailable();
if (prebuilt && existsSync('node_modules/@winlinux/krb-session-key/build')) throw new Error('the addon was compiled; the prebuild did not load at install');
if (prebuilt && !addon) throw new Error(`a ${target} prebuild exists but kerberosSessionKeyAvailable() is false`);
console.log(`esm ok: import { connect }; kerberosSessionKeyAvailable() ${addon} (${target}, prebuild ${prebuilt ? 'present' : 'absent'})`);
EOF
cat > "$work/smoke/smoke.cjs" <<'EOF'
// CommonJS consumer: the README CommonJS example.
async function main() {
  const { connect } = await import('winlinux');
  if (typeof connect !== 'function') throw new Error('connect is not a function');
  console.log('cjs ok: await import("winlinux")');
}
main().catch((err) => { console.error(err); process.exit(1); });
EOF
cat > "$work/smoke/run.sh" <<'EOF'
# usage: run.sh <pack dir> <smoke dir> <version>
set -eu
app=$(mktemp -d)
cd "$app"
npm init -y >/dev/null
npm install --no-audit --no-fund --loglevel=error "$1"/*.tgz
v=$(npx --no-install winlinux --version)
[ "$v" = "$3" ] || { echo "npx winlinux --version printed '$v', expected '$3'" >&2; exit 1; }
echo "npx winlinux --version: $v"
cp "$2/smoke.mjs" "$2/smoke.cjs" .
node smoke.mjs
node smoke.cjs
rm -rf "$app"
EOF
echo "-- host: $(uname -s) $(uname -m), node $(node -v), compiler disabled"
CC=/usr/bin/false CXX=/usr/bin/false bash "$work/smoke/run.sh" "$work/pack" "$work/smoke" "$version"
for platform in linux/amd64 linux/arm64; do
  echo "-- node:22-slim $platform: no compiler, only libgssapi-krb5-2"
  # shellcheck disable=SC2086
  docker run --rm --platform "$platform" ${RELEASE_DOCKER_ARGS:-} \
    -v "$work/pack:/pack:ro" -v "$work/smoke:/smoke:ro" \
    -e HTTPS_PROXY -e HTTP_PROXY -e NO_PROXY -e npm_config_registry -e VERSION="$version" \
    node:22-slim bash -euo pipefail -c '
      export DEBIAN_FRONTEND=noninteractive
      apt-get update -qq && apt-get install -y -qq --no-install-recommends libgssapi-krb5-2 >/dev/null
      ! command -v cc; ! command -v gcc; ! command -v c++; ! command -v make
      test ! -e /usr/include/gssapi
      bash /smoke/run.sh /pack /smoke "$VERSION"
    '
done

# --- 7. publish -------------------------------------------------------------
if [ "$publish" = 1 ]; then banner "npm publish"; else banner "npm publish --dry-run"; fi
published=()
skipped=()
for w in "${order[@]}"; do
  t=$(tarball "$w")
  if out=$(npm view "$w@$version" version 2>&1); then
    if [ "$out" = "$version" ]; then echo "$w@$version is already on the registry: skipped"; skipped+=("$w"); continue; fi
  elif ! grep -q E404 <<<"$out"; then
    echo "$out" >&2; fail "npm view $w@$version failed (not a 404)"
  fi
  if [ "$publish" = 1 ]; then
    npm publish "$t" --access public
    published+=("$w@$version")
  else
    npm publish "$t" --access public --dry-run
  fi
done

step=done
echo
echo "==== release: OK"
if [ "$publish" = 1 ]; then
  echo "published: ${published[*]:-none}"
  [ ${#skipped[@]} -eq 0 ] || echo "already on the registry: ${skipped[*]}"
  echo
  echo "Next:"
  echo "  npm view winlinux@$version version            # the registry has it"
  echo "  git tag v$version && git push origin v$version"
else
  echo "dry run of $version passed; nothing was published."
  [ ${#skipped[@]} -eq 0 ] || echo "already on the registry: ${skipped[*]}"
  echo "To publish: npm run release -- --publish $version"
fi
