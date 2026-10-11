# Changelog

All notable changes to winlinux. The five packages (`winlinux`,
`@winlinux/auth`, `@winlinux/winrm`, `@winlinux/smb2`,
`@winlinux/krb-session-key`) share one version and one release.

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
