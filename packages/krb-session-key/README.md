# @winlinux/krb-session-key

A small N-API addon: a GSSAPI Kerberos initiator that also returns the
context **session key**. `@winlinux/auth` uses it (an optional dependency)
so that Kerberos can sign SMB2 packets. Without it, Kerberos still
authenticates through the `kerberos` package, but has no session key.

- The handshake (`gss_init_sec_context`), credential acquire, `wrap` and
  `unwrap` run on the libuv thread pool (`napi_async_work`). A KDC round
  trip never blocks the JS thread.
- The key comes from `gss_inquire_sec_context_by_oid(GSS_C_INQ_SSPI_SESSION_KEY)`
  (OID 1.2.840.113554.1.2.2.5.5). It is the full key, for example 32 bytes
  for aes256-cts. SMB2 applies its own rule (the first 16 bytes) in
  `@winlinux/smb2`.
- A context can use its own credential cache (`ccache`). The addon never
  writes `process.env.KRB5CCNAME`.
- macOS links `GSS.framework`. Linux opens `libgssapi_krb5.so.2` with
  `dlopen` at first use, so the addon loads on a host without MIT krb5 and
  fails only when Kerberos is used, with an error that names the package to
  install. `WINLINUX_GSSAPI_LIBRARY` overrides the library path.

- `wrapIov` / `unwrapIov` (`gss_wrap_iov` / `gss_unwrap_iov` with HEADER |
  DATA | PADDING buffers, as pyspnego's `wrap_winrm()`): the RFC 4121 wrap
  token split into the per-message header (trailer rotated in, 60 bytes for
  AES-SHA1) and sealed data of exactly the plaintext length. This is the
  MS-WSMV 2.2.9.1.1.2.2 split that WinRM message encryption over plain HTTP
  needs with Kerberos. Resolved with `dlsym`; `iovSupported()` says whether
  the library has it, and `KrbClient` carries the two methods only then.

Only the initiator (client) side exists. Windows (SSPI) is not supported.

## Install: prebuilt binaries, then a source build

The package ships prebuilt Node-API binaries in `prebuilds/<platform>-<arch>/`
and loads them with [`node-gyp-build`](https://github.com/prebuild/node-gyp-build).
On these platforms an install needs **no compiler and no Kerberos headers**:

| Platform | Prebuild | Run-time requirement |
|---|---|---|
| macOS arm64 (Apple silicon) | `darwin-arm64` | macOS 11 or later (`GSS.framework` is part of macOS) |
| macOS x64 (Intel) | `darwin-x64` | macOS 11 or later |
| Linux x64, glibc | `linux-x64` | glibc 2.31 or later; `libgssapi_krb5.so.2` (`libgssapi-krb5-2` on Debian/Ubuntu, `krb5-libs` on Fedora/RHEL) for Kerberos |
| Linux arm64, glibc | `linux-arm64` | same as Linux x64 |
| Linux x64 / arm64, musl (Alpine) | `linux-x64`, `linux-arm64` (`.musl.node`) | `krb5-libs` for Kerberos |

The binaries pin Node-API version 3 (`NAPI_VERSION=3` in `binding.gyp`), so
one binary per platform serves Node.js 22 and every later major. The Linux
binaries are built on Debian 11 (glibc 2.31) and do not link krb5: the
GSSAPI library is opened with `dlopen` at first use, so one binary serves
every glibc distro that has the run-time library. They are tagged `glibc`;
the musl binaries, built on Alpine, sit next to them tagged `musl`, and
`node-gyp-build` picks by the libc of the running Node.

The loader tries, in order: `build/Release/` (a local source build), then
`prebuilds/<platform>-<arch>/`. The `install` script (`node-gyp-build`) runs
the same lookup and compiles from source **only** when nothing loads: other
platforms (Windows, 32-bit ARM, other libcs), or a platform whose prebuild
fails to load. `npm install --build-from-source` forces a source build.

### Run-time library on Linux

A Linux prebuild needs no compiler and no headers, but Kerberos needs the
MIT Kerberos run-time library `libgssapi_krb5.so.2`. The addon opens it at
the first Kerberos call, so `import` and NTLM work without it. Install:

| Distribution | Package |
|---|---|
| Debian / Ubuntu | `libgssapi-krb5-2` (it pulls in `libkrb5-3`) |
| Fedora / RHEL | `krb5-libs` |
| Alpine | `krb5-libs` |

Each Linux prebuild is proven to install and load in a container that has
this library and nothing else: no compiler, no `libkrb5-dev`
(`node:22-bookworm-slim` with `libgssapi-krb5-2`, `node:22-alpine` with
`krb5-libs`).

### How the prebuilds are made

The prebuilds are produced locally by `npm run prebuild:local`
(`scripts/prebuild-local.sh` at the repo root). On a Mac it runs `prebuildify --napi --strip` with the
host toolchain for `darwin-arm64` and `darwin-x64`; on Apple silicon the x64
binary is cross-compiled (`clang -arch x86_64` against the macOS SDK). It
runs `--tag-libc` builds in Docker for `linux-x64` and `linux-arm64` (glibc
in `node:22-bullseye`, musl in `node:22-alpine`). With `--prove` it packs
the package and proves a compiler-free install of the tarball on each target
(`.github/scripts/prove-prebuild.sh`). The proof of `darwin-x64` needs an
x86_64 Node: on Apple silicon set `PREBUILD_NODE_X64` to an x86_64 `node`
binary (it runs under Rosetta), or run
`npm run prebuild:local -- --prove darwin-x64` on an Intel Mac. Without one,
the script builds `darwin-x64` and reports it as NOT PROVEN. The last lines
of the output list every target as built, proven or not proven.

In a git checkout there are no prebuilds, so `npm ci` builds from source and
needs the prerequisites below.

### Source-build prerequisites

Needed only when no prebuild matches (see above) or in a git checkout.
You need Node.js 22 or later and:

| Platform | Needs |
|---|---|
| macOS | Xcode Command Line Tools (`xcode-select --install`). `GSS.framework` is part of macOS. |
| Debian / Ubuntu | `build-essential`, `python3`, and the MIT Kerberos headers: `apt-get install libkrb5-dev`. At run time: `libgssapi-krb5-2`. |
| Fedora / RHEL | `gcc`, `make`, `python3`, `krb5-devel`. At run time: `krb5-libs`. |

Rebuild after a Node.js or OS change: `npm rebuild @winlinux/krb-session-key`
(a prebuild needs no rebuild: Node-API is ABI-stable).

If neither a prebuild nor the build is available, `@winlinux/auth` falls back
to the `kerberos` package: Kerberos works, but SMB2 signing with Kerberos
does not (smb2 then raises `SmbSigningError` when the server requires
signing). The fallback also cannot take a per-context ccache. For password
Kerberos, `@winlinux/auth` then sets `process.env.KRB5CCNAME` to the
context's temp ccache for the length of `initializeClient` and the first
step (one KDC round trip), under a process-wide lock, and restores it after.
Other code that reads the env in that window sees the temp ccache.

Tested: macOS 27 arm64 (GSS.framework, Heimdal 1.5.1apple1) and Debian 12
in `node:22` (MIT krb5 1.20.1), against a Samba AD DC. The musl prebuilds
load in `node:22-alpine`, but a Kerberos sign-in on Alpine is not tested.
Not tested: Heimdal on Linux, enctypes other than aes256.

## API

```ts
import { KrbClient, gssFactory, load } from '@winlinux/krb-session-key';

load(); // optional: throws now if the addon or the GSS library is missing
const client = await KrbClient.create('cifs@dc1.example.com', {
  ccache: 'FILE:/tmp/my-ccache', // optional; default: KRB5CCNAME / system default
  principal: 'alice@EXAMPLE.COM', // optional
});
let token = await client.step(''); // base64 AP-REQ
// ... send it, then feed the server's AP-REP back:
await client.step(apRepBase64);
client.contextComplete; // true
const key = client.sessionKey(); // Buffer, a fresh copy on each call
client.verifyMic(message, mic); // gss_verify_mic -> boolean
// WinRM message encryption (present when iovSupported()):
const { header, data } = await client.wrapIov(Buffer.from(soap)); // header.length is the MS-WSMV Length-Field
const plain = await client.unwrapIov(header, data);
client.dispose();
```

`gssFactory(service, init)` has the shape of the `GssFactory` seam in
`@winlinux/auth` (`packages/auth/src/auth/kerberos.ts`).

## Tests

`npm test -w @winlinux/krb-session-key` runs the tests that need no KDC
(library loading, the missing-library error, lifecycle, and the RFC 4121
known answers in `test/fixtures/iov-*.json`). The live handshake, the
session key, SMB2 signing and the event-loop proof run in
`npm run test:integration -w @winlinux/auth` (Docker), on the host and in a
Linux `node:22` container.

`npm run test:kdc -w @winlinux/krb-session-key` (Linux, no Docker, no root)
starts a throwaway MIT KDC on localhost (`krb5-kdc`, `krb5-admin-server`,
`krb5-user`, plus a C compiler and `libkrb5-dev` for the acceptor harness
in `test/kdc/acceptor.c`) and proves `wrapIov` / `unwrapIov` against a real
`gss_accept_sec_context` + `gss_unwrap_iov` acceptor for aes128 and aes256.
`WINLINUX_WRITE_FIXTURES=1` refreshes the known-answer fixtures from it.
