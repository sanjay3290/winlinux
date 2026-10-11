# Releasing winlinux

Five packages ship together, at one version, from this repo:
`@winlinux/krb-session-key`, `@winlinux/auth`, `@winlinux/smb2`,
`@winlinux/winrm`, `winlinux`.

The maintainer releases from a Mac with one command, `scripts/release.sh`.
Releases are not published from CI (see [The workflow files](#the-workflow-files)).

## One-time setup (maintainer)

1. **An npm account** with two-factor authentication on
   (npmjs.com, Account, Two-Factor Authentication, "Authorization and
   writes"). A publish then asks for a one-time password.
2. **Claim the `@winlinux` scope.** A scope is a user name or an
   organization name. Create a free organization named `winlinux`
   (npmjs.com, your avatar, "Add Organization", the free plan for public
   packages). Check it: `npm org ls winlinux` lists you as owner.
3. **The `winlinux` name.** It is free as long as `npm view winlinux`
   returns E404. The first publish claims it.
4. **Log in** on the Mac that publishes: `npm login` (it opens the browser),
   then `npm whoami` prints your user name.
5. **Tools on that Mac:** Node.js 22 or later, Xcode Command Line Tools,
   Docker Desktop running (the Linux check, the Linux prebuilds and the
   container smoke test use it), and git with push access to this repo.

## Version policy

- All five packages move in lockstep: one version, one tag, one release.
- Internal runtime dependencies are **exact** (`"@winlinux/auth": "1.0.0"`,
  not a caret range). The packages share one wire contract
  (`docs/contracts/`) and are tested only against each other at the same
  version. A caret would let npm pair `winlinux@1.0.0` with a later
  `@winlinux/winrm` that it was never tested with. The cost is that every
  release bumps all five, which the lockstep rule requires anyway.
- `@winlinux/krb-session-key` is an `optionalDependencies` entry of
  `@winlinux/auth`, also exact. An install where the addon cannot load or
  build still succeeds and falls back to the `kerberos` package.
- `@winlinux/smb2` and `@winlinux/winrm` depend on `@winlinux/auth` only in
  `devDependencies` (their tests use the real providers). At run time they
  code against their own copies of the contract, so a user who installs one
  of them alone pulls in no auth package. Those dev ranges stay caret.
- `packages/winlinux/test/unit/versions.test.ts` fails `npm test` when a
  version or a pin is out of step.

## Bump the version

On a branch, with a pull request like any other change:

```bash
npm version 0.4.0 --workspaces --include-workspace-root --no-git-tag-version
# Update the exact internal pins and the dev ranges to the new version.
node -e '
const fs=require("fs"), v=require("./package.json").version;
for (const p of ["auth","smb2","winrm","winlinux","krb-session-key"]) {
  const f=`packages/${p}/package.json`, j=JSON.parse(fs.readFileSync(f,"utf8"));
  for (const k of ["dependencies","optionalDependencies"]) for (const d in j[k]??{}) if (d.startsWith("@winlinux/")) j[k][d]=v;
  for (const d in j.devDependencies??{}) if (d.startsWith("@winlinux/")) j.devDependencies[d]="^"+v;
  fs.writeFileSync(f, JSON.stringify(j,null,2)+"\n");
}'
npm install --package-lock-only
```

Add a `## <version>` section to `CHANGELOG.md`, update the expected
`--version` in `packages/winlinux/test/e2e/cli-winrm.test.ts`, and merge.

## Release from GitHub Actions (the normal path)

`.github/workflows/publish.yml` publishes all five packages, with npm
provenance, when a version tag is pushed. It builds the addon prebuilds on
GitHub's darwin and Linux runners, builds and tests everything, packs and
checks every tarball, publishes in dependency order (skipping any version
already on the registry), then installs `winlinux` from the registry and runs
the CLI.

One-time setup:

1. **First release only, token:** on npmjs.com create a *granular access
   token* with **Read and write** on the `@winlinux` scope (organization
   `winlinux`) and on the `winlinux` package, with a short expiry. Store it as
   the `NPM_TOKEN` secret of the `npm` environment (or of the repository):
   `gh secret set NPM_TOKEN --env npm --repo sanjay3290/winlinux`
   (it prompts for the value; never paste a token into a file or a chat).
2. **After the first release, trusted publishing:** for each of the five
   packages, open *Settings > Trusted publishing* on npmjs.com and add a
   GitHub Actions publisher: repository `sanjay3290/winlinux`, workflow
   `publish.yml`, environment `npm`. Then delete the `NPM_TOKEN` secret and
   revoke the token. From then on no secret is stored anywhere.

To release: bump the version (see above), merge to `main`, then

```bash
git checkout main && git pull
git tag vX.Y.Z
git push origin vX.Y.Z
```

Watch the run with `gh run watch --repo sanjay3290/winlinux`. A manual
dispatch of the Publish workflow with `dry_run` checked runs every step and
publishes nothing.

## Release from a workstation (fallback)

Use this only when Actions is unavailable. It publishes without provenance.

### Release 1.0.0

From an up-to-date `main` checkout on the Mac:

```bash
git checkout main && git pull
npm run release:dry                   # 1. everything except the publish
npm run release -- --publish 1.0.0    # 2. the real publish
```

`npm run release:dry` runs every step and ends with `npm publish --dry-run`.
Run it first and read the end of its output. Then run the real publish. It
repeats every check (about 20 minutes) and publishes only if all pass. With
2FA, npm asks for a one-time password (or a browser confirmation) for each
of the five packages.

What `scripts/release.sh` does, in order. The first failure stops the run
and names the step:

1. **Preflight.** It refuses to run unless the checkout is on `main`, the
   tree is clean, `HEAD` equals `origin/main`, and every `package.json`
   (and every internal pin) is at the version given. With `--publish`,
   `npm whoami` must work.
2. `npm ci`, `npm run build`, `npm test`, `npm audit --audit-level=low`.
3. `npm run check:linux`: the same four in `node:22-bookworm` in Docker.
   Only `--skip-linux-check` skips it, with a warning.
4. **Addon prebuilds.** `scripts/prebuild-local.sh --prove` builds
   darwin-arm64, darwin-x64, linux-x64 and linux-arm64 (glibc and musl). It
   proves a compiler-free install of each one it can. The run needs all six
   binaries. On Apple silicon darwin-x64 is cross-compiled and reported as
   NOT PROVEN unless `PREBUILD_NODE_X64` names an x86_64 `node` (see the
   addon README).
5. **Pack** all five packages and check each tarball: `package.json`,
   `LICENSE`, `README.md` and `dist/` present; no tests, TypeScript sources,
   source maps or `build/`; the version; the four prebuild platforms in the
   addon; `bin/winlinux.js` in `winlinux`. It prints the tarball sizes.
6. **Smoke test.** It installs the five tarballs into an empty directory on
   the Mac with the compiler disabled. It then does the same in `node:22-slim`
   containers (linux/amd64 and linux/arm64) with no compiler and only
   `libgssapi-krb5-2`. Each one runs `npx winlinux --version`,
   `import { connect } from 'winlinux'`, `await import('winlinux')` from a
   CommonJS file, and checks that `kerberosSessionKeyAvailable()` is true
   where a prebuild exists.
7. **Publish** in dependency order: `@winlinux/krb-session-key`,
   `@winlinux/auth`, `@winlinux/smb2`, `@winlinux/winrm`, `winlinux`, each
   with `npm publish <tarball> --access public`. It publishes the exact
   tarballs it tested. A package whose version is already on the registry
   is skipped, so after a failure (a network error, a wrong OTP) run the
   same command again.

**No provenance.** `npm publish --provenance` needs an OIDC identity from a
CI system such as GitHub Actions. A release from a workstation cannot have
it, so the packages carry no provenance statement.

Options: `--skip-linux-check` (warns), and `--reuse-prebuilds`, which keeps
`packages/krb-session-key/prebuilds/` as it is and only proves it. Use
`--reuse-prebuilds` to ship a darwin-x64 binary built and proven on an Intel
Mac: copy it into `prebuilds/darwin-x64/` first.

## Verify on the registry

```bash
npm view winlinux@1.0.0 version                     # prints 1.0.0
for p in @winlinux/krb-session-key @winlinux/auth @winlinux/smb2 @winlinux/winrm; do npm view "$p@1.0.0" version; done
npm view @winlinux/krb-session-key@1.0.0 dist.fileCount dist.unpackedSize

cd "$(mktemp -d)" && npm init -y >/dev/null
npm install winlinux@1.0.0
npx winlinux --version                              # prints 1.0.0
node --input-type=module -e "import { connect } from 'winlinux'; console.log(typeof connect)"
```

The registry can lag a minute behind the publish. The package pages are
`https://www.npmjs.com/package/winlinux` and
`https://www.npmjs.com/package/@winlinux/auth` (and so on).

## Tag a workstation release (maintainer)

After the registry shows all five packages:

```bash
git checkout main && git pull
git tag v1.0.0
git push origin v1.0.0
```

Only for a workstation release: the tag marks the commit that was
published. **Warning:** pushing a `v*` tag starts the Publish workflow; it
skips versions that are already on the registry, so it publishes nothing
new. A GitHub release is optional: create it from the tag and paste the
version's section of `CHANGELOG.md`.

## Rollback

- **Never `npm unpublish` after 72 hours.** Within 72 hours of the publish
  npm allows it when no other package depends on the version; after that
  only in narrow cases, and users may already depend on it. An unpublished
  version number can never be used again. Within the first 72 hours,
  unpublish only a version that nobody can have used yet, and unpublish the
  five packages in reverse order (`winlinux` first).
- **Deprecate** a bad version instead. Users then see a warning at install:

  ```bash
  npm deprecate winlinux@1.0.0 "Broken: <reason>. Use 1.0.1."
  for p in @winlinux/krb-session-key @winlinux/auth @winlinux/smb2 @winlinux/winrm; do
    npm deprecate "$p@1.0.0" "Broken: <reason>. Use 1.0.1."
  done
  ```

- **Fix forward:** bump to the next patch version (all five packages),
  release it, and deprecate the bad one. `npm deprecate <pkg>@<version> ""`
  removes a deprecation.
- If the publish stopped halfway (some packages published, some not), do
  not deprecate. Fix the cause and run the same release command again. It
  skips what is already on the registry.

## Pre-merge check (every pull request)

The CI workflow (`.github/workflows/ci.yml`) runs on every pull request. To
run the same checks locally, from the repo root:

```bash
npm ci && npm run build && npm test && npm audit --audit-level=low   # macOS
npm run check:linux                                                  # Linux, in Docker
```

`npm run check:linux` (`scripts/check-linux.sh`) runs the same commands on
a copy of the working tree in a fresh `node:22-bookworm` container with
`libkrb5-dev`, `g++`, `make` and `python3`. Every package must report
`fail 0` and `skipped 0`.

## The workflow files

- `.github/workflows/ci.yml` builds, tests and audits every package on
  Linux and macOS for every pull request and every push to `main`. On Linux
  it also runs the Kerberos round trip against a throwaway local KDC.
- `.github/workflows/prebuild.yml` builds the addon's prebuilt binaries for
  darwin-arm64, darwin-x64, linux-x64 and linux-arm64 and proves a
  compiler-free install of each, when a change touches the addon. It
  uploads workflow artifacts only and publishes nothing.

  It is also called by the Publish workflow.
- `.github/workflows/publish.yml` publishes to npm on a `v*` tag, with
  provenance (see "Release from GitHub Actions" above). Pull requests that
  touch the release workflows run it as a dry run.

`scripts/release.sh` is the workstation fallback: it builds the prebuilds
again with `scripts/prebuild-local.sh` and publishes the tarballs it tested.
