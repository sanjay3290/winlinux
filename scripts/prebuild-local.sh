#!/usr/bin/env bash
# Builds the @winlinux/krb-session-key prebuilt binaries locally, the way
# .github/workflows/prebuild.yml builds them in CI.
#
#   npm run prebuild:local -- [--prove] [target ...]
#   bash scripts/prebuild-local.sh [--prove] [target ...]
#
# Targets. The default on macOS is all six; on Linux, the four linux ones.
#   darwin-arm64     macOS with the host toolchain (Xcode CLT)
#   darwin-x64       same; on Apple silicon it is cross-compiled (clang
#                    -arch x86_64 against the macOS SDK)
#   darwin           the darwin target of the host's own arch
#   linux-x64        glibc, built in node:22-bullseye (glibc 2.31 floor) in Docker
#   linux-arm64      same, arm64 (QEMU on an x64 host, native on Apple silicon)
#   linux-x64-musl   Alpine/musl, built in node:22-alpine in Docker
#   linux-arm64-musl
#
# Output: packages/krb-session-key/prebuilds/<platform>-<arch>/*.node, which
# `npm pack -w @winlinux/krb-session-key` then ships (the `files` list has
# `prebuilds`). The glibc and musl binaries of one arch share a directory
# (`@winlinux+krb-session-key.glibc.node` and `.musl.node`); node-gyp-build
# picks by the libc of the running Node.
#
# Each Linux build streams the working tree (tracked and untracked files,
# nothing ignored) into a fresh container as a tar on stdin, so it works
# from a git worktree too. The container runs `npm ci --ignore-scripts`,
# then prebuildify, and checks the binary: it must not link krb5 (the GSSAPI
# library is dlopened at run time) and a glibc build must not need a symbol
# newer than GLIBC_FLOOR. Each darwin build must be a Mach-O of the right
# arch that links only GSS.framework and the system libraries.
#
#   --prove        after building, pack the package and prove a compiler-free
#                  install of the tarball on each target just built
#                  (.github/scripts/prove-prebuild.sh). Linux: in a slim image
#                  with no compiler, no Kerberos headers, only the run-time
#                  GSSAPI library (libgssapi-krb5-2, which pulls in
#                  libkrb5-3, or Alpine krb5-libs). Darwin: on the host with
#                  CC=/usr/bin/false. darwin-x64 on Apple silicon needs an
#                  x86_64 Node (PREBUILD_NODE_X64, run under Rosetta);
#                  without one it is reported as NOT PROVEN.
#   --prove-only   skip the builds and prove the binaries already in prebuilds/
#   PREBUILD_NODE_X64      path to an x86_64 `node` binary (for darwin-x64 proof)
#   PREBUILD_DOCKER_ARGS   extra `docker run` arguments (for example a proxy CA)
#
# The last lines list every target as built / proven / NOT PROVEN. Exit
# code: non-zero when a build or a proof fails. A target that cannot be
# proven on this machine (darwin-x64 without an x86_64 Node) does not fail
# the run, but the summary says so.
set -euo pipefail

repo=$(cd "$(dirname "$0")/.." && pwd)
pkg='@winlinux/krb-session-key'
pkg_dir=packages/krb-session-key
out="$repo/$pkg_dir/prebuilds"
glibc_floor=2.31
prove=0
build=1
targets=()
host_os=$(uname -s)
host_arch=$(node -p process.arch)
for a in "$@"; do
  case "$a" in
    --prove) prove=1 ;;
    --prove-only) prove=1; build=0 ;;
    darwin) targets+=("darwin-$host_arch") ;;
    darwin-arm64|darwin-x64|linux-x64|linux-arm64|linux-x64-musl|linux-arm64-musl) targets+=("$a") ;;
    *) echo "prebuild-local: unknown argument '$a'" >&2; sed -n 2,47p "$0" >&2; exit 2 ;;
  esac
done
if [ ${#targets[@]} -eq 0 ]; then
  targets=(linux-x64 linux-arm64 linux-x64-musl linux-arm64-musl)
  [ "$host_os" = Darwin ] && targets=(darwin-arm64 darwin-x64 "${targets[@]}")
fi
# A cross-built darwin target leaves its binary in build/Release, which the
# loader tries first. Build the host arch last so build/Release ends up
# loadable on this machine.
ordered=()
for t in "${targets[@]}"; do case "$t" in darwin-*) [ "$t" = "darwin-$host_arch" ] || ordered+=("$t") ;; *) ordered+=("$t") ;; esac; done
for t in "${targets[@]}"; do [ "$t" = "darwin-$host_arch" ] && ordered+=("$t"); done
targets=("${ordered[@]}")

built=()
proven=()
not_proven=()

need_docker() {
  command -v docker >/dev/null || { echo "prebuild-local: docker is not installed" >&2; exit 2; }
  docker info >/dev/null 2>&1 || { echo "prebuild-local: the docker daemon is not running" >&2; exit 2; }
}

# Tracked and untracked files that are not ignored, as a tar stream. Nothing
# built on the host (node_modules, dist, build, prebuilds) comes along.
source_tar() {
  local f
  git -C "$repo" ls-files -z --cached --others --exclude-standard \
    | while IFS= read -r -d '' f; do
        if [ -e "$repo/$f" ] || [ -L "$repo/$f" ]; then printf '%s\0' "$f"; fi
      done \
    | COPYFILE_DISABLE=1 tar -C "$repo" --null -T - -cf -
}

# The build inside a Linux container. $1 image, $2 docker platform, $3 arch,
# $4 libc (glibc|musl).
linux_build() {
  local image=$1 platform=$2 arch=$3 libc=$4
  need_docker
  git -C "$repo" ls-files --cached >/dev/null
  mkdir -p "$out/linux-$arch"
  rm -f "$out/linux-$arch/"*".$libc.node"
  echo "== prebuild linux-$arch ($libc) in $image"
  # shellcheck disable=SC2086
  source_tar | docker run -i --rm --platform "$platform" ${PREBUILD_DOCKER_ARGS:-} \
    -v "$out/linux-$arch:/out" \
    -e HTTPS_PROXY -e HTTP_PROXY -e NO_PROXY -e npm_config_registry \
    -e PACKAGE="$pkg" -e PACKAGE_DIR="$pkg_dir" -e ARCH="$arch" -e LIBC="$libc" \
    -e GLIBC_FLOOR="$glibc_floor" -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" \
    "$image" sh -eu -c '
      mkdir /work
      # Read the whole tar stream first, so stdin is free for the steps below.
      tar -C /work -xf -
      uname -m
      test "$(node -p process.arch)" = "$ARCH"
      if [ "$LIBC" = musl ]; then
        apk add --no-cache -q build-base python3 krb5-dev file binutils </dev/null
      else
        export DEBIAN_FRONTEND=noninteractive
        ldd --version | sed -n 1p
        apt-get update -qq </dev/null
        apt-get install -y -qq --no-install-recommends build-essential python3 libkrb5-dev file binutils </dev/null >/dev/null
      fi
      cd /work
      rm -rf "$PACKAGE_DIR/prebuilds" "$PACKAGE_DIR/build"
      npm ci --ignore-scripts --no-audit --no-fund </dev/null
      npm run prebuildify:linux -w "$PACKAGE" </dev/null
      bin=$(ls "$PACKAGE_DIR"/prebuilds/linux-$ARCH/*.node)
      ls -l "$bin"; file "$bin"
      case "$bin" in *.$LIBC.node) ;; *) echo "expected a .$LIBC.node binary, got $bin" >&2; exit 1 ;; esac
      # The binary must not link krb5 (dlopen at run time).
      if objdump -p "$bin" | grep -E "NEEDED.*(gssapi|krb5)"; then echo "binary links krb5" >&2; exit 1; fi
      if [ "$LIBC" = glibc ]; then
        need=$(objdump -T "$bin" | grep -oE "GLIBC_[0-9.]+" | sed "s/GLIBC_//" | sort -Vu | tail -1)
        test -n "$need"
        echo "highest glibc symbol version required: $need (floor $GLIBC_FLOOR)"
        test "$(printf "%s\n%s\n" "$need" "$GLIBC_FLOOR" | sort -V | tail -1)" = "$GLIBC_FLOOR"
      fi
      cp "$bin" /out/
      chown "$HOST_UID:$HOST_GID" /out/*.node
    '
  ls -l "$out/linux-$arch/"
}

# $1 arch (arm64|x64). Uses the host toolchain; another arch is a cross build.
darwin_build() {
  local arch=$1 macho
  [ "$host_os" = Darwin ] || { echo "prebuild-local: darwin-$arch needs macOS" >&2; exit 2; }
  macho=$arch; [ "$arch" = x64 ] && macho=x86_64
  echo "== prebuild darwin-$arch with the host toolchain (host is darwin-$host_arch)"
  [ -d "$repo/node_modules" ] || (cd "$repo" && npm ci --ignore-scripts --no-audit --no-fund)
  rm -rf "${out:?}/darwin-$arch"
  (cd "$repo" && npm run prebuildify -w "$pkg" -- --arch "$arch")
  local bin; bin=$(ls "$out/darwin-$arch"/*.node)
  ls -l "$bin"; file "$bin"
  test "$(lipo -archs "$bin")" = "$macho" || { echo "prebuild-local: $bin is not $macho only: $(lipo -archs "$bin")" >&2; exit 1; }
  # Only GSS.framework and the system libraries; nothing from Homebrew.
  if otool -L "$bin" | tail -n +2 | grep -vE '^\s+(/System/Library/Frameworks/|/usr/lib/)'; then
    echo "prebuild-local: $bin links a library outside the OS" >&2; exit 1
  fi
  otool -L "$bin" | tail -n +2
}

# An x86_64 node binary for the darwin-x64 proof on Apple silicon, or nothing.
x64_node() {
  local n=${PREBUILD_NODE_X64:-}
  [ -n "$n" ] && [ -x "$n" ] || return 0
  if [ "$(arch -x86_64 "$n" -p process.arch 2>/dev/null)" = x64 ]; then echo "$n"; fi
}

# A compiler-free install of the packed tarball. $1 target.
prove_target() {
  local t=$1 pack rc=0
  pack=$(mktemp -d)
  (cd "$repo" && npm pack -w "$pkg" --pack-destination "$pack" >/dev/null)
  echo "== prove $t: $(ls "$pack")"
  case "$t" in
    darwin-*)
      local arch=${t#darwin-}
      if [ "$arch" = "$host_arch" ]; then
        CC=/usr/bin/false CXX=/usr/bin/false bash "$repo/.github/scripts/prove-prebuild.sh" "$pack"/*.tgz || rc=$?
      else
        local n; n=$(x64_node)
        if [ "$arch" != x64 ] || [ -z "$n" ]; then
          echo "prebuild-local: NOT PROVEN $t: no $arch Node on this machine (set PREBUILD_NODE_X64 to an x86_64 node binary, or prove it on an Intel Mac)" >&2
          not_proven+=("$t"); rm -rf "$pack"; return 0
        fi
        arch -x86_64 env PATH="$(dirname "$n"):$PATH" CC=/usr/bin/false CXX=/usr/bin/false \
          bash "$repo/.github/scripts/prove-prebuild.sh" "$pack"/*.tgz || rc=$?
      fi ;;
    linux-*)
      local arch=${t#linux-}; arch=${arch%-musl}
      local platform=linux/amd64; [ "$arch" = arm64 ] && platform=linux/arm64
      local image=node:22-bookworm-slim setup='apt-get update -qq && apt-get install -y -qq --no-install-recommends libgssapi-krb5-2 >/dev/null'
      case "$t" in *-musl) image=node:22-alpine; setup='apk add --no-cache -q krb5-libs bash' ;; esac
      # shellcheck disable=SC2086
      docker run --rm --platform "$platform" ${PREBUILD_DOCKER_ARGS:-} \
        -v "$pack:/pack:ro" -v "$repo/.github/scripts:/scripts:ro" \
        -e HTTPS_PROXY -e HTTP_PROXY -e NO_PROXY -e npm_config_registry -e ARCH="$arch" -e SETUP="$setup" \
        "$image" sh -eu -c '
          test "$(node -p process.arch)" = "$ARCH"
          sh -c "$SETUP"
          ! command -v cc; ! command -v gcc; ! command -v c++; ! command -v make
          test ! -e /usr/include/gssapi
          bash /scripts/prove-prebuild.sh /pack/*.tgz
        ' || rc=$?
      ;;
  esac
  rm -rf "$pack"
  [ "$rc" = 0 ] || { echo "prebuild-local: proof FAILED for $t" >&2; exit "$rc"; }
  proven+=("$t")
}

for t in "${targets[@]}"; do
  [ "$build" = 1 ] || break
  case "$t" in
    darwin-*) darwin_build "${t#darwin-}" ;;
    linux-x64) linux_build node:22-bullseye linux/amd64 x64 glibc ;;
    linux-arm64) linux_build node:22-bullseye linux/arm64 arm64 glibc ;;
    linux-x64-musl) linux_build node:22-alpine linux/amd64 x64 musl ;;
    linux-arm64-musl) linux_build node:22-alpine linux/arm64 arm64 musl ;;
  esac
  built+=("$t")
done
# Only a cross build ran: build/Release holds a binary this machine cannot
# load. Remove it; the loader then uses the host prebuild or the next
# `npm rebuild -w @winlinux/krb-session-key` compiles one.
case " ${built[*]:-} " in
  *" darwin-$host_arch "*) ;;
  *" darwin-"*) rm -rf "${repo:?}/$pkg_dir/build"; echo "prebuild-local: removed $pkg_dir/build (it held the cross-built binary)" ;;
esac
if [ "$prove" = 1 ]; then
  for t in "${targets[@]}"; do prove_target "$t"; done
fi

echo
echo "prebuild-local: summary"
echo "  built this run: ${built[*]:-none}"
[ "$prove" = 1 ] && echo "  proven (compiler-free install loads the prebuild): ${proven[*]:-none}"
[ ${#not_proven[@]} -gt 0 ] && echo "  NOT PROVEN on this machine: ${not_proven[*]}"
echo "  binaries in $pkg_dir/prebuilds:"
(cd "$out" 2>/dev/null && find . -name '*.node' -type f | sed 's|^\./|    |' | sort) || echo "    none"
