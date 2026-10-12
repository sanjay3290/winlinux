# Changelog

All notable changes to winlinux. The five packages (`winlinux`,
`@winlinux/auth`, `@winlinux/winrm`, `@winlinux/smb2`,
`@winlinux/krb-session-key`) share one version and one release.

## 1.1.0 — 2026-10-12

For `@winlinux/smb2` users who read large files: `readRange` reads a byte
range of a file of any size, including one IIS holds open for append;
`list`, `stat`, `readFile`, `download` and `readRange` take an
`AbortSignal`; `listIter` walks a large directory page by page.
`@winlinux/auth` installs with no native build for NTLM-only use.
Kerberos over HTTPS sends the TLS channel binding.

### Features

- **`@winlinux/smb2`: `readRange`.** `readRange(share, path, offset,
  length)` returns `[offset, offset + length)` of a file of any size, with
  share access read, write and delete, so the tail of a log another process
  appends to can be read; fewer bytes at end of file, none past it.
- **`@winlinux/smb2`: `AbortSignal` and `listIter`.** `list`, `stat`,
  `readFile` and `download` take `{ signal }`. On abort the call sends no
  further request, the request in flight rejects at once, the handle closes
  and the call rejects with `SmbAbortError` (`name === 'AbortError'`); the
  session stays usable. `listIter(share, dir)` yields entries per
  `QUERY_DIRECTORY` response, so a caller can stop early with `break`.
- **`get` and `get -r` over SMB stop on Ctrl+C.** The transfer signal
  (`TransferOptions.signal`, the CLI's first Ctrl+C) now reaches smb2's
  `download`, as it already reached the WinRM route: the request in flight
  is cut, the local `.part` file is removed and the call rejects with
  `SmbAbortError` (`get -r`: `WinLinuxAbortError` with the count of files
  done). The CLI exits 130 with no error line. `put` over SMB does not read
  the signal yet.
- **`@winlinux/auth`: the `kerberos` package is an optional dependency.**
  `npm install @winlinux/auth --omit=optional` runs no native build; NTLM
  and Basic work without it. The first step of a Kerberos context then
  fails with an error that says `npm install kerberos`; Negotiate with a
  password falls back to NTLM, and with the ticket cache alone reports the
  Kerberos error. `winlinux` depends on `kerberos` directly, so the CLI
  keeps Kerberos out of the box.
- **`npm run live:gate`: the live checks as one command.** It runs the
  PSRP scenarios over HTTP + NTLM, HTTP + Kerberos, HTTPS + Basic and
  HTTPS + NTLM, and the HTTPS sign-in checks (Kerberos and Negotiate over
  HTTPS, NTLM over HTTPS with `CbtHardeningLevel` Strict) against every
  target of a git-ignored `live-targets.json` (or the `WINRM_*`
  variables), records redacted PSRP fixtures and checks them against the
  deny list, and prints one redacted Markdown table per target. Passwords
  come only from environment variables and never print; a check that
  cannot run is `not run`, never `pass`. Runbook: `docs/live-gate.md`.

### Security hardening

- **Kerberos channel binding over HTTPS.** With
  `@winlinux/krb-session-key`, a Kerberos or Negotiate sign-in to WinRM
  over HTTPS binds its AP-REQ to the server's TLS certificate (RFC 5929
  `tls-server-end-point`, the binding NTLM already sent): the transport
  fetches the certificate with an unauthenticated probe before the first
  token, and the addon passes the binding to `gss_init_sec_context`. A
  server with `CbtHardeningLevel = Strict` checks it. The `kerberos`
  package sends none; `--tls --insecure` stays refused for Kerberos. The
  addon's native code changed, so its prebuilt binaries are rebuilt.
- **The Kerberos token goes on the socket the probe bound.** Over HTTPS
  the first Kerberos or Negotiate token carries the binding of the
  certificate the unauthenticated probe saw. A proxy or load balancer that
  closes the connection after the probe's 401 moves that token to a new
  socket: when the new socket's certificate differs, the sign-in now fails
  with `WinRMAuthError` and is not retried, instead of sending a token
  bound to the wrong peer. The same certificate on a new socket signs in as
  before. The HTTPS agent no longer resumes TLS sessions, because Node
  reports no peer certificate on a resumed socket, which left a
  re-authentication after a dropped connection unbound.

### Fixes

- **`@winlinux/smb2`: an aborted or failed `download` leaves no partial
  file.** When the signal aborts or a READ fails mid-transfer, the
  truncated file at the local path is removed before the call rejects with
  the original error. A successful download is unchanged.
- **`@winlinux/smb2`: a connect timeout has code `ETIMEDOUT`.** The cause
  of an `SmbConnectionError` from a TCP connect that times out now has
  `code: 'ETIMEDOUT'`, like the `ENOTFOUND` and `ECONNREFUSED` causes. Its
  message stays `connect_timeout`.

### Experimental

`winlinux pwsh -c`, `invokePowerShell`, `openPowerShell` and
`openRunspacePool` (PowerShell Remoting, PSRP) are tested against a
scripted PSRP endpoint only. They are not yet verified on a real Windows
Server; their behaviour can change in a minor release.

- **`winlinux pwsh -c <script>` and PowerShell sessions in the library.**
  One PSRP pipeline on the server, with the WinRM sign-in of the client:
  formatted lines on stdout, error, warning, verbose and debug records on
  stderr as PowerShell prints them, or one JSON value with `--json`;
  `--configuration <name>`; exit 4 when the pipeline failed or wrote an
  error record, 130 on Ctrl+C. `client.openPowerShell()` gives a session
  whose pipelines share one runspace; `client.invokePowerShell(script)`
  runs one pipeline. An auth failure latches with the WinRM slot. No host
  is offered yet, so a script that prompts fails on the server. Needs
  PowerShell 3.0 or newer.
- **`@winlinux/winrm`: PSRP runspace pool and pipeline.**
  `openRunspacePool` opens one runspace on the server over the existing
  transport (SESSION_CAPABILITY and INIT_RUNSPACEPOOL in the Create,
  protocol 2.3 claimed, 2.2 or newer accepted), `invoke` and
  `invokeCommand` run a pipeline (CREATE_PIPELINE by Command and Send,
  input values with back-pressure, every output stream as events,
  `Out-String -Stream` on request), `stop` cuts the Receive and sends
  Signal `ctrl_c`, and `close` deletes the shell. A fault on a pipeline
  message fails the pipeline and signals it; a fault on a pool message
  breaks the pool and deletes the shell. No host is offered.
- **`@winlinux/winrm`: CLIXML serializer and deserializer subset.**
  `deserializeClixml` reads the common CLIXML elements into plain values
  and `PSObject` (references, type-name references, cycles, containers,
  enums, error, progress and information records) and turns an unknown
  element into `kind: 'unknown'` instead of throwing; `serializeClixml`
  writes the subset the client sends, with `RefId` and `TNRef` reuse per
  message and the `_xHHHH_` escaping of MS-PSRP 2.2.5.3.2; `toJson` is the
  `--json` view.
- **`@winlinux/winrm`: PSRP message and fragment codec.** `encodeMessage`
  and `decodeMessage` read and write the 40-byte MS-PSRP message header
  (GUIDs in .NET byte order, a UTF-8 byte order mark on server data
  skipped); `encodeFragments` splits a message into fragments of at most
  32768 bytes and `Defragmenter` reassembles them per target, refusing an
  out-of-order fragment, more than 16 messages in progress or a message
  above 64 MiB with the new `PSRemotingError`.
- **`@winlinux/winrm`: WS-Man envelopes for PSRP.** The envelope builder
  takes a resource URI, an optional `wsmv:SessionId` header and
  `MustComply` options; new builders produce the PSRP Create
  (`creationXml`), Command (empty `rsp:Command`, base64 `rsp:Arguments`),
  Receive (`stdout`, with or without a CommandId), Send (`stdin` or `pr`)
  and Signal (`powershell/signal/ctrl_c`) messages, and
  `parsePsrpReceiveResponse` reads a ReceiveResponse without an exit code.
  The WinRS envelopes are byte-identical to before.
- **`@winlinux/winrm` tests: fake PSRP endpoint, fixture recorder, PSRP
  live scenarios.** `npm test` runs the PSRP scenarios against a fake PSRP
  endpoint; `npm run test:live:psrp` runs them against a Windows Server,
  with `WINLINUX_PSRP_RECORD=<dir>` writing redacted fixtures that a
  deny-list test guards. `PSConnectOptions.trace` reports every request,
  response and PSRP message for that recorder.

## 1.0.0 — 2026-10-11

First public release: `npm install winlinux`. SSH-like access to Windows
servers from macOS and Linux: commands and PowerShell, Windows Event Logs,
services and processes over WinRM; file shares over SMB 2 and 3; one
credential set for both.

### Features

- **Library and CLI** (`winlinux`): `connect()` opens nothing; the first
  command opens WinRM (5985, or 5986 with `winrm.tls`) and the first file
  call opens SMB (445). CLI subcommands `run`, `logs`, `services`, `ps`,
  `shares`, `ls`, `get`, `put`, `stat`, `mkdir` (`-p`), `rm` (files only),
  `rmdir` (empty directories only), `mv` (within one share), and an
  interactive shell where `cd` persists across lines. The library adds
  `readFile` / `writeFile` for small files. `--json` output on every
  command. Exit codes 0–6 and 130.
- **Recursive copy**: `get -r` / `put -r` and `getDir()` / `putDir()`, like
  `scp -r`, over one SMB session with `--parallel` up to 8. Symbolic links
  and reparse points are skipped. Ctrl+C stops after the files in flight.
- **Sign-in methods**: Negotiate (default), NTLM, Kerberos and Basic on
  WinRM; Negotiate, NTLM and Kerberos on SMB. Password from
  `WINLINUX_PASSWORD` or a no-echo prompt, never from argv; `-K` uses the
  Kerberos ticket cache.
- **Kerberos keytab sign-in**: `--keytab <file>` (`ConnectOptions.keytab`)
  signs in with no password and no prior `kinit`, for cron jobs, CI runners
  and scripts.
- **Certificate sign-in**: `-a certificate --cert <file> --key <file>` signs
  in to WinRM over HTTPS with a TLS client certificate. An encrypted key
  reads `WINLINUX_KEY_PASSPHRASE` or prompts.
- **CredSSP for the double hop**: `-a credssp` (`auth: 'credssp'`) lets a
  remote command reach a second machine as the user. Strict opt-in; see
  "Double hop and CredSSP" in the README for the risk and the safer
  Kerberos delegation option.
- **Host profiles**: `~/.winlinux/config` in `~/.ssh/config` syntax (`Host`
  blocks, `*` / `?` globs, first match wins). `-F <file>` and `-F none`.
- **Many hosts**: `winlinux run --hosts <list>` runs one command on many
  hosts (aliases, `user@host`, `@group` from the config file) with
  `--parallel` 1–32, live output prefixed `<host> | `, a summary table or one
  `--json` object per host.
- **File copy over WinRM**: `get` and `put` work when TCP 445 is blocked.
  `--via winrm|smb|auto` (CLI default `auto`, library default `smb`). `auto`
  switches to WinRM only when the SMB TCP connect fails. SHA-256 is checked
  on both sides, memory stays bounded, and a failed or interrupted copy
  leaves the destination as it was. Errors use the same classes and
  messages as SMB.
- **WinRM connect timeout**: 10 s by default (`winrm.connectTimeoutMs`,
  `--connect-timeout <s>`, profile key `ConnectTimeout`).
- **WinRM** (`@winlinux/winrm`): WS-Management over HTTP and HTTPS with
  MS-WSMV message encryption over plain HTTP (NTLM, CredSSP, and Kerberos
  with the session-key addon). Streaming output, abort via `AbortSignal`,
  request timeouts, CLIXML-parsed PowerShell errors, event log queries,
  service and process listings, and commands that read stdin.
- **SMB2/3** (`@winlinux/smb2`): browse, read, write, upload and download.
  SMB 3.1.1, 3.0.2 and 3.0 with AES-GMAC or AES-CMAC signing and
  AES-128-GCM / AES-128-CCM encryption. `listShares` through SRVSVC
  `NetShareEnum`. No runtime dependencies.
- **Auth** (`@winlinux/auth`): Basic, NTLM, Kerberos, Negotiate and CredSSP
  behind the `AuthProvider` contract v1.2
  (`docs/contracts/auth-provider.md`).
- **`@winlinux/krb-session-key`**: an optional Node-API addon that exposes
  the GSS session key (SMB signing with Kerberos) and `gss_wrap_iov`
  (WinRM Kerberos over HTTP). Prebuilt binaries for darwin-arm64,
  darwin-x64, linux-x64 and linux-arm64 (glibc 2.31 or later, and musl);
  other platforms build from source.
- **Packaging**: ES modules with a tested CommonJS path,
  `await import('winlinux')`. Each package ships its own README.

### Security hardening

- NTLMv2 only, with MIC, `mechListMIC` verification and channel bindings.
  No NTLMv1 fallback and no console logging in shipped code.
- Kerberos against an IP address is refused before any network traffic;
  `kerberosHostname` / `--krb-hostname` names the SPN host. The name is
  never taken from reverse DNS.
- No NTLM retry after a Kerberos credential rejection, and no retry of the
  same password after an auth failure, so a wrong password costs one
  failed sign-in. `run --hosts` starts no new host after an auth failure.
- Kerberos on WinRM refuses HTTPS with `--insecure`: it sends no channel
  binding yet, so only a verified certificate ties the ticket to the server.
- CredSSP: TSRequest version 6 with the client nonce and the SHA-256
  `pubKeyAuth` binding (CVE-2018-0886); older servers are refused. It needs
  a password and a verified server, refuses `--insecure`, refuses plain
  HTTP unless `--credssp-allow-http`, and announces every delegation on
  stderr.
- SMB: a signed session does not trust flags an unverified response header
  claims, an encrypted request needs an encrypted response, and unsolicited
  responses are discarded. A share
  that requires encryption fails with `SmbEncryptionRequiredError`.
  Server-supplied SRVSVC lengths are bounded.
- The password, its base64 form and the base64 Basic token are redacted
  from every error message, cause and stack the CLI prints. Control
  characters in server text are escaped before they reach the terminal.
- Host profiles cannot hold a password. Keytab and private-key files must
  be `chmod 600`.
- Recursive copies refuse remote names with `..` or separators and never
  write outside the destination.

### Known limits

- **Not verified live:** Kerberos over HTTPS (5986); Windows Server 2016,
  2019 and 2025 (only 2022 is tested); WinRM with
  `CbtHardeningLevel = Strict`; SMB 3.x encryption against Windows Server;
  Kerberos over HTTP from macOS (Heimdal) to a Windows host. Keytab sign-in
  and CredSSP are proven against test servers, not against a real Windows
  domain.
- Windows can report exit code 0 for a remote process that exits at once
  with no output (seen with `cmd /c exit 7` on Windows Server 2022, from
  pywinrm too). The client reports the server's code. A command that prints
  first, such as `cmd /c "echo x& exit 7"`, is reported exactly.
- `get -r` / `put -r` do not run over WinRM yet.
- WinRM file copy is several times slower than SMB.
- The CredSSP inner TLS offers TLS 1.2 AES-GCM suites only.
- SMB 3.x: no FSCTL_VALIDATE_NEGOTIATE_INFO for the 3.0.x dialects (3.1.1
  preauth integrity covers downgrade), no AES-256 ciphers, no compression.
- Interactive shell: `cd` persists; `set`, `pushd` and other cmd.exe state
  is per line.
- The darwin-x64 addon binary is not load-tested on an Intel Mac. If it
  does not load, the install compiles the addon from source (Xcode CLT);
  without that, Kerberos falls back to the `kerberos` package.
- ES modules only; CommonJS code uses `await import('winlinux')`.
  Node.js 22 or later.
- No npm provenance: the packages are not published from CI.
