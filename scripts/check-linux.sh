#!/usr/bin/env bash
# The Linux check, in Docker: the same commands as the CI workflow, on a
# local copy of the working tree, before you push.
#
#   npm run check:linux          # or: bash scripts/check-linux.sh
#
# It copies the working tree (tracked and untracked files, nothing ignored:
# no node_modules, dist, build or prebuilds) into a fresh node:22-bookworm
# container with the addon's build prerequisites (libkrb5-dev, g++, make,
# python3), then runs the same commands as .github/workflows/ci.yml:
#
#   npm ci && npm run build && npx --no-install winlinux --version
#   && npm test && npm audit --audit-level=low
#
# The file list comes from git on the host, and the files reach the
# container as a tar stream on stdin. Nothing is mounted and no git
# metadata goes into the container, so it works from a plain clone and from
# a git worktree (where .git is a file that points outside the checkout).
# The checkout is only read, never touched, so it also works from
# macOS with a darwin build in node_modules. Exit code: the first failing
# step's, 0 when every step passed.
#
#   CHECK_IMAGE=node:22-bookworm   base image (any Debian-based node image)
#   CHECK_KEEP=1                   keep the container for inspection
#   CHECK_DOCKER_ARGS              extra `docker run` arguments (for example a proxy CA)
set -euo pipefail

repo=$(cd "$(dirname "$0")/.." && pwd)
image=${CHECK_IMAGE:-node:22-bookworm}
rm_flag=--rm
if [ "${CHECK_KEEP:-0}" = 1 ]; then rm_flag=; fi

command -v git >/dev/null || { echo "check-linux: git is not installed" >&2; exit 2; }
command -v docker >/dev/null || { echo "check-linux: docker is not installed" >&2; exit 2; }
docker info >/dev/null 2>&1 || { echo "check-linux: the docker daemon is not running" >&2; exit 2; }
git -C "$repo" rev-parse --is-inside-work-tree >/dev/null 2>&1 \
  || { echo "check-linux: $repo is not a git checkout" >&2; exit 2; }

# Tracked and untracked files that are not ignored: the change under test,
# with or without a commit. A tracked file deleted in the working tree is
# left out. Nothing built on the host comes along.
list_files() {
  local f
  git -C "$repo" ls-files -z --cached --others --exclude-standard \
    | while IFS= read -r -d '' f; do
        if [ -e "$repo/$f" ] || [ -L "$repo/$f" ]; then printf '%s\0' "$f"; fi
      done
}
# Fail before docker starts if git cannot list the files.
git -C "$repo" ls-files --cached >/dev/null

echo "check-linux: $image, source $repo"
# COPYFILE_DISABLE stops macOS tar from adding ._* AppleDouble files.
# shellcheck disable=SC2086
list_files | COPYFILE_DISABLE=1 tar -C "$repo" --null -T - -cf - \
  | docker run -i $rm_flag --platform linux/amd64 ${CHECK_DOCKER_ARGS:-} \
  -e HTTPS_PROXY -e HTTP_PROXY -e NO_PROXY -e npm_config_registry \
  "$image" bash -euo pipefail -c '
    mkdir /work
    # Read the whole tar stream first, so stdin is free for the steps below.
    tar -C /work --warning=no-unknown-keyword -xf -
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq </dev/null
    apt-get install -y -qq --no-install-recommends libkrb5-dev g++ make python3 </dev/null >/dev/null
    cd /work
    echo "== node $(node -v), npm $(npm -v), $(ldd --version | sed -n 1p)"
    echo "== npm ci";        npm ci --no-audit --no-fund </dev/null
    echo "== npm run build"; npm run build </dev/null
    echo "== npx winlinux --version"; npx --no-install winlinux --version </dev/null
    echo "== npm test";      npm test </dev/null
    echo "== npm audit";     npm audit --audit-level=low </dev/null
    echo "check-linux: OK"
  '
