# winlinux

Connect to Windows servers from Linux and macOS, the way you SSH into a Linux box.
Run commands, read Windows Event Logs, and access SMB file shares from Node.js.

Ships as a **library (SDK)** plus a thin **interactive CLI** on top.

## Why two protocols

Windows has no single SSH-equivalent. This package glues the two native protocols:

| Need | Protocol | Notes |
|------|----------|-------|
| Run commands, read event logs, query state | **WinRM** (WS-Management over HTTP/HTTPS) | PowerShell Remoting runs on this |
| Browse and transfer files on shares | **SMB2/3** | Separate protocol, separate session; `get`/`put` can also run over WinRM when port 445 is blocked |

One credential set serves both: **NTLM**, **Kerberos** and **Negotiate**
(SPNEGO) on WinRM and SMB, plus **Basic**, **CredSSP** and **client
certificates** on WinRM. See [Supported](#supported).

## Install

```bash
npm install winlinux         # the library and the CLI
npx winlinux --help          # the CLI, without a global install
npm install -g winlinux      # `winlinux` on your PATH
```

Requires Node.js 22 or later on macOS or Linux. The packages are ES modules
only; CommonJS code uses `await import('winlinux')` (see
[CommonJS](#commonjs)). `npm install` needs no compiler on the platforms in
[Supported](#supported). Kerberos on Linux also needs the MIT Kerberos
run-time library: `libgssapi-krb5-2` on Debian and Ubuntu, `krb5-libs` on
Fedora, RHEL and Alpine.

## Supported

**Sign-in methods**

| Method | WinRM | SMB | Notes |
|---|---|---|---|
| `negotiate` (default) | yes | yes | Kerberos or NTLM, chosen per protocol |
| `ntlm` | yes | yes | NTLMv2 only, with MIC and channel bindings |
| `kerberos` | yes | yes | Password (`kinit` into a private ccache), ticket cache (`-K`) or keytab (`--keytab`). Needs the server's DNS name. Channel binding over HTTPS with the addon. |
| `basic` | HTTPS only | no | |
| `credssp` | HTTPS (HTTP only with `--credssp-allow-http`) | no | Sends your password to the server; explicit opt-in only. See [Double hop and CredSSP](#double-hop-and-credssp). |
| `certificate` | HTTPS only | no | TLS client certificate mapped to a local account |

Kerberos SMB signing and Kerberos over plain HTTP need the optional
`@winlinux/krb-session-key` addon, which npm installs with `winlinux`.
Without it, SMB uses NTLM and Kerberos on WinRM needs HTTPS.

**Client platforms**

| Platform | Status |
|---|---|
| macOS arm64 (Apple silicon) | Supported; the Kerberos addon ships a prebuilt binary |
| macOS x64 (Intel) | Prebuilt addon binary included, but not load-tested on an Intel Mac |
| Linux x64 and arm64, glibc 2.31 or later | Supported; prebuilt addon binary |
| Linux x64 and arm64, musl (Alpine) | Prebuilt addon binary; Kerberos sign-in not tested |
| Other platforms | The addon compiles from source (C compiler, Kerberos headers). Windows clients are not supported. |

**Servers:** Windows Server with WinRM (5985/5986) and SMB 2.0.2 to 3.1.1.
Verified live against Windows Server 2022 and Samba. See
[Known limits](#known-limits) for what is not verified.

## Architecture

Five npm packages, built and released together from this repository:

```
        +-------------------+
        |  @winlinux/auth   |  NTLM / Kerberos / Negotiate / Basic / CredSSP
        |                   |  (GSSAPI-style security context)
        +---------+---------+
                  | AuthProvider contract
        +---------+---------+
        |                   |
 +------v---------+  +------v---------+
 | @winlinux/winrm|  | @winlinux/smb2 |
 | commands, logs |  | file shares    |
 +------+---------+  +------+---------+
        |                   |
        +---------+---------+
                  |
        +---------v---------+
        |  winlinux         |  Library facade + interactive CLI
        +-------------------+
```

`@winlinux/krb-session-key` is an optional native addon. It gives the auth
package the Kerberos session key that SMB signing and WinRM message
encryption over plain HTTP need. See `docs/contracts/` for the interface
between the auth package and its consumers.

## Quick start

Install with `npm install winlinux` (see [Install](#install)). In this
repository the package is the workspace `packages/winlinux`.

### Library

```ts
import { connect, WinLinuxAuthError } from 'winlinux';

// Opens nothing yet. One credential set serves WinRM and SMB.
const client = await connect('server.corp.example', {
  username: 'alice',
  password: process.env.WINLINUX_PASSWORD,
  domain: 'CORP',
  // auth defaults to 'negotiate'. Over plain HTTP WinRM then uses NTLM
  // with message encryption. Add winrm: { tls: true } for HTTPS on 5986.
});

try {
  const r = await client.run('hostname');                  // first call opens WinRM (5985)
  console.log(r.stdout, r.exitCode);

  const events = await client.readEventLog({ logName: 'System', maxEvents: 5 });
  console.log(events.map((e) => `${e.timeCreated} ${e.level} ${e.message}`));

  const services = await client.listServices();            // { name, displayName, status, startType }
  console.log(services.filter((s) => s.status === 'Running').map((s) => s.name));
  const processes = await client.listProcesses();          // { id, name, cpuSeconds, workingSetBytes, startTime }
  console.log(processes.map((p) => `${p.id} ${p.name}`));

  for await (const chunk of client.runStream('ping', ['-n', '3', 'localhost'])) {
    process.stdout.write(chunk.data);                       // live output
  }

  console.log(await client.listShares());                   // first file call opens SMB (445)
  console.log(await client.ls('C$', 'Windows/Temp'));       // sizeBytes is a bigint
  await client.put('./report.csv', 'C$', 'Windows/Temp/report.csv');
  await client.get('C$', 'Windows/Temp/report.csv', './copy.csv');

  await client.mkdir('C$', 'Windows/Temp/reports/2026', { parents: true });
  await client.mv('C$', 'Windows/Temp/report.csv', 'Windows/Temp/reports/2026/report.csv');
  const info = await client.stat('C$', 'Windows/Temp/reports/2026/report.csv'); // { sizeBytes, mtime, atime, isDirectory, readonly }
  await client.writeFile('C$', 'Windows/Temp/note.txt', `${info.sizeBytes} bytes\n`);   // small files only
  await client.rm('C$', 'Windows/Temp/note.txt');                // files only
  await client.rmdir('C$', 'Windows/Temp/reports/2026');         // empty directories only
  const copied = await client.getDir('C$', 'inetpub/logs', './logs', { parallel: 4 }); // { files, directories, bytes, skipped }
} catch (err) {
  // After an auth failure the client does not retry the same password
  // (account lockout). Call client.setPassword(newPassword) to try again.
  if (err instanceof WinLinuxAuthError) console.error(err.protocol, err.message);
  else throw err;
} finally {
  await client.close();
}
```

Paths are share-relative with `/`. The share name must not hold `/` or `\`.
`put` checks the local file before it opens SMB. `get` writes to a temp file
next to the destination and renames it on success, so a failed download keeps
the old local file.

**Kerberos with a password:** each protocol runs its own `kinit` into its own
temp ccache, so concurrent first calls are safe.

**Kerberos needs the server's DNS name.** The service principal is built from
`host` (`HTTP/<host>`, `cifs/<host>`), and an IP address has no principal in
the KDC. With `auth: 'kerberos'`, or `negotiate` without a password (`-K`),
an IP address is refused at `connect()` with a `WinLinuxUsageError` before
any network traffic. To connect to an IP anyway, set `kerberosHostname`
(`--krb-hostname <fqdn>`) to the server's DNS name: the connection goes to
the IP and the ticket is for that name. winlinux never resolves the name by
reverse DNS, which is spoofable. `negotiate` with a password falls back to
NTLM for an IP address, without contacting the KDC.

**Kerberos file shares and Kerberos over HTTP:** SMB2 signing with Kerberos,
and WinRM message encryption with Kerberos over plain HTTP, need the optional
[`@winlinux/krb-session-key`](packages/krb-session-key/README.md) addon.
The published package carries prebuilt binaries for darwin and linux
x64/arm64 (glibc and musl), so an install needs no compiler. A git clone
builds it from source (Xcode CLT on macOS; `libkrb5-dev` and a compiler on
Linux). With it,
`auth: 'kerberos'` / `-a kerberos` and `-K` reach shares on servers that
require signing and run WinRM over HTTP, and `negotiate` with a password and a
`realm` tries Kerberos for SMB before NTLM. Without it, SMB uses NTLM when a
password exists and Kerberos on WinRM needs HTTPS.
Errors are `WinLinuxUsageError`, `WinLinuxAuthError`, `WinLinuxConnectionError`,
or the module errors (`WinRMFaultError`, `SmbNotFoundError`, ...), re-exported
from `winlinux`.

### CommonJS

The packages are ES modules only. From a CommonJS file (`.cjs`, or a
project without `"type": "module"`), load them with a dynamic `import()`,
which works on every supported Node.js:

```js
// report.cjs
async function main() {
  const { connect } = await import('winlinux');
  const client = await connect('server.corp.example', {
    username: 'alice',
    password: process.env.WINLINUX_PASSWORD,
    domain: 'CORP',
  });
  try {
    const r = await client.run('hostname');
    console.log(r.stdout.trim(), r.exitCode);
  } finally {
    await client.close();
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
```

On Node.js 22.12 and later, `const { connect } = require('winlinux')` also
works, because Node can `require()` an ES module. Node 22.0 to 22.11 throws
`ERR_REQUIRE_ESM` for it; `await import()` works there too. TypeScript
projects that compile to CommonJS need `"module": "node16"` or `"nodenext"`,
so that `await import()` stays a real dynamic import.

### CLI

```bash
export WINLINUX_PASSWORD='...'            # or omit it and type it at the no-echo prompt

npx winlinux 'CORP\alice@server'                          # interactive shell
npx winlinux run    'CORP\alice@server' -- ipconfig /all  # use -- before dash arguments
npx winlinux pwsh   alice@server -c 'Get-Process | Select -First 3'   # one PSRP pipeline, see below
npx winlinux logs   --log System --max 10 --level 2 alice@server
npx winlinux services --status running --name win alice@server   # filtered on the client
npx winlinux ps     --json --name svchost alice@server
npx winlinux shares alice@server
npx winlinux ls     alice@server 'C$/Windows/Temp'
npx winlinux put    alice@server ./report.csv 'C$/Windows/Temp/report.csv'
npx winlinux get    --json alice@server 'C$/Windows/Temp/report.csv' ./copy.csv
npx winlinux stat   alice@server 'C$/Windows/Temp/report.csv'
npx winlinux mkdir  -p alice@server 'C$/Windows/Temp/reports/2026'
npx winlinux mv     alice@server 'C$/Windows/Temp/report.csv' 'C$/Windows/Temp/reports/2026/report.csv'
npx winlinux rm     alice@server 'C$/Windows/Temp/old.csv'      # files only
npx winlinux rmdir  alice@server 'C$/Windows/Temp/empty-dir'    # empty directories only
npx winlinux get -r alice@server 'C$/inetpub/logs' ./logs       # like scp -r
npx winlinux put -r --parallel 4 alice@server ./site 'D$/www'
```

- The interactive shell keeps `cd` across lines (resolved like cmd.exe); other cmd state such as `set` is per line.
  With piped input it exits with the code of the last failing line, counting a non-zero remote exit as 4.
- `--tls` uses HTTPS (5986); `--insecure` skips certificate checks. Kerberos
  on WinRM refuses `--tls --insecure`: a server that does not enforce channel
  binding accepts a ticket relayed by a man in the middle, so the certificate
  must be verified. Over HTTPS the Kerberos ticket carries the TLS channel
  binding (`tls-server-end-point`, with `@winlinux/krb-session-key`; the
  `kerberos` package sends none), which a server with `CbtHardeningLevel =
  Strict` checks against its certificate.
- `-a negotiate|ntlm|kerberos|basic|credssp` picks the mechanism (`credssp`:
  see "Double hop and CredSSP" below); `-K` uses the Kerberos
  ticket cache (no password). Kerberos on WinRM over plain HTTP, and Kerberos
  on SMB with signing, need `@winlinux/krb-session-key`; without it, Kerberos
  on WinRM needs `--tls`.
- Kerberos needs the server's DNS name: `-a kerberos` or `-K` with an IP
  address exits 1 before any connection. `--krb-hostname <fqdn>` names the
  SPN host while connecting to the IP; `-a ntlm` avoids Kerberos.
- `--winrm-port` and `--smb-port` override the ports; `--json` prints one JSON value on stdout.
- `--connect-timeout <s>` (default 10) bounds the WinRM TCP connect, plus the
  TLS handshake over HTTPS. An unreachable host fails with exit 3 after that,
  not after the OS TCP timeout (75 s on macOS). Profile key `ConnectTimeout`.
- `get -r` / `put -r` copy a directory tree over one SMB session, like `scp -r`: an
  existing destination directory receives `<dest>/<name>`, a missing one becomes
  the copy. Symbolic links, devices and reparse points are skipped and reported.
  Each downloaded file lands through a temp file and a rename. A failed file stops
  the copy (exit 5) and the files already copied stay. Ctrl+C stops `get -r` at
  the files in flight and `put -r` after them (exit 130); a second Ctrl+C stops
  at once. `--parallel <n>`
  (1-8) keeps several files in flight. Remote names with `..` or separators are
  refused, and nothing is written outside the destination.
- `rm` refuses a directory and `rmdir` refuses a non-empty one (exit 5); there is
  no recursive delete. `mv` works within one share and never replaces an existing
  target.
- The password is never read from argv. Sources: `-K`, `WINLINUX_PASSWORD`, or a terminal prompt.
  `--keytab <file>` signs in with a Kerberos keytab instead (see below).
- Exit codes: 0 ok, 1 usage, 2 auth, 3 connection, 4 remote command or WinRM error,
  5 file or share error, 6 internal error, 130 interrupted.
- **SMB 3.x:** file commands negotiate SMB 3.1.1 (or 3.0.2 / 3.0, or 2.1 on
  older servers) with AES-GMAC or AES-CMAC signing, and encrypt with
  AES-128-GCM or AES-128-CCM when the server or a share requires it
  (`New-SmbShare -EncryptData $true`, `Set-SmbServerConfiguration
  -EncryptData $true`). `--verbose` prints what was negotiated. A share that
  requires encryption on a connection that negotiated none fails with
  `SmbEncryptionRequiredError` (exit 5). The library option
  `smb: { maxDialect: '2.1' }` limits a connection to SMB 2.x.
- **Known limit:** Windows can report exit code 0 for a remote process that
  exits at once without writing anything (`cmd /c exit 7` read 0 in about
  1 run of 10 on Windows Server 2022, with pywinrm too). winlinux reports
  the code the server sends. A command that prints a line first, such as
  `cmd /c "echo x& exit 7"`, is reported exactly.

#### Host profiles

Put per-host settings in `~/.winlinux/config`, in the `~/.ssh/config` syntax,
and type `winlinux web1` instead of every flag:

```
# ~/.winlinux/config
Host web1 web1.example.test
    HostName web1.example.test
    User svc-ops
    Auth kerberos
    Realm EXAMPLE.TEST
    TLS yes
    WinRMPort 5986

Host *.example.test
    Domain EXAMPLE
    UseTicketCache yes
```

```bash
npx winlinux web1                      # interactive shell as svc-ops
npx winlinux run alice@web1 -- whoami  # user@alias overrides User
npx winlinux run -F none alice@web1.example.test -- whoami   # ignore profiles
```

- Keys: `HostName`, `User`, `Domain`, `Realm`, `Auth`, `TLS`, `Insecure`,
  `WinRMPort`, `SMBPort`, `KrbHostname`, `ConnectTimeout`, `UseTicketCache`, `Keytab`, `Via`,
  `CertFile`, `KeyFile`. Keys are
  case-insensitive; `*` and `?` glob in `Host` patterns. `Group <name>
  <member>...` names a list for `run --hosts @<name>`.
- For each key the first matching `Host` block wins. A flag beats the target
  text (`user@`, `DOMAIN\`), which beats the profile, which beats the default.
- `-F <file>` reads another file; `-F none` ignores profiles. `--verbose`
  prints the file and the blocks that matched.
- No key can hold a password; a `Password` line is an error. The file maps
  your estate, so winlinux warns unless it is `chmod 600`.

#### Many hosts

```bash
npx winlinux run --hosts web1,web2,db1 -- ipconfig /all
npx winlinux run --hosts @web --parallel 8 -- hostname     # Group web web1 web2 in ~/.winlinux/config
npx winlinux run --json --hosts web1,svc@db1.example.test -- whoami
```

- Live output lines are prefixed `<host> | `; a `HOST RESULT TIME` table goes
  to stderr at the end. `--json` prints one object per host instead.
- `--parallel <n>` (1-32, default 4) bounds the hosts in flight.
- One sign-in serves every host. Hosts that need different passwords must run
  in separate calls, or use Kerberos. After one auth failure no new host
  starts, so a wrong password costs one failed sign-in, not one per host.
- Exit code: 0 only if every host ran and exited 0; otherwise the smallest
  per-host code (2 auth, 3 connection, 4 remote command). 130 on Ctrl+C.

#### Certificate sign-in

winlinux can sign in to WinRM over HTTPS with a client certificate instead of
a password. This suits automation against hosts that map a certificate to a
local account.

```bash
npx winlinux run -a certificate --cert c.pem --key k.pem --tls admin@<host> -- whoami
```

- PEM files. An encrypted key reads `WINLINUX_KEY_PASSPHRASE` or asks with a
  no-echo prompt. There is no password prompt.
- HTTPS only (`--tls`); winlinux never sends the certificate over plain HTTP.
- The certificate connection uses TLS 1.2. Windows (HTTP.sys) asks for the
  client certificate after the TLS handshake. In TLS 1.2 that is a
  renegotiation, which Node answers; in TLS 1.3 it is post-handshake
  authentication, which Node does not offer. Every other sign-in
  method keeps TLS 1.3.
  `--insecure` works but warns: you prove your identity to a server you have
  not verified.
- The key file must be `chmod 600`; otherwise winlinux exits 1.
- SMB has no certificate sign-in. Copy files with `--via winrm`.
- Profiles: `Auth certificate`, `CertFile` and `KeyFile`.

Server steps (Windows Server, as an administrator):
1. An HTTPS listener: `winrm quickconfig -transport:https` (needs a server
   certificate for the host name).
2. Allow certificate sign-in: `Set-Item WSMan:\localhost\Service\Auth\Certificate $true`.
3. A client certificate with the Client Authentication EKU and a UPN in the
   subject alternative name, for example `<user>@localhost`, issued by a CA the
   server trusts (import the CA into the machine's Trusted Root store).
4. Map it to a local account:
   `New-Item -Path WSMan:\localhost\ClientCertificate -Subject '<user>@localhost' -URI * -Issuer <CA thumbprint> -Credential (Get-Credential) -Force`.

**Risks.** Certificate mapping works for local accounts only. The private key
is equal to that account's password: keep it at mode 0600, and map it to a
least-privilege account.

#### Unattended use with a keytab

A cron job, a CI runner or a script can sign in with a Kerberos keytab: no
password, no prompt and no prior `kinit`.

```bash
npx winlinux run --keytab ~/.winlinux/svc.keytab -a kerberos --realm <REALM> svc@<host> -- hostname
npx winlinux ls  --keytab ~/.winlinux/svc.keytab --realm <REALM> svc@<host> 'C$/Windows/Temp'
```

winlinux runs `kinit` with the keytab into a private temp ccache (MIT
`kinit -k -t`, Heimdal `kinit --keytab= --use-keytab`) and removes it at
the end. `--keytab` needs a realm (`--realm`, a `DOMAIN\` prefix or
`user@REALM`) and the server's DNS name. It cannot be combined with `-K`,
`-a ntlm` or `-a basic`, and there is no NTLM fallback.

Make a keytab:
- Linux (MIT): `ktutil`, then `addent -password -p svc@<REALM> -k 1 -e aes256-cts-hmac-sha1-96`,
  `wkt svc.keytab`, `quit`.
- On a domain controller: `ktpass /princ svc@<REALM> /mapuser <DOMAIN>\svc /crypto AES256-SHA1 /ptype KRB5_NT_PRINCIPAL /pass * /out svc.keytab`.
  Copy the file over a secure channel.

Then `chmod 600 svc.keytab`. winlinux refuses (exit 1) a keytab that group or
others can read or write.

**Risks.** A keytab is equal to the account password. Anyone who reads the
file can sign in as the account until its password changes. Use a dedicated,
least-privilege service account for each use, keep the file at mode 0600,
and make a new keytab when the password changes. winlinux never logs,
copies or prints the key bytes; `--verbose` prints the path only.

#### Files without port 445

Many networks block SMB (TCP 445) but let WinRM (5985/5986) through. `get`
and `put` can copy a file over WinRM instead:

```bash
npx winlinux get --via winrm alice@<host> 'C$/Windows/Temp/report.csv' ./copy.csv
npx winlinux put --via winrm --tls alice@<host> ./report.csv 'D$/data/report.csv'
npx winlinux get alice@<host> 'Data/report.csv'      # --via auto, the CLI default
```

- `--via smb` uses SMB only. `--via winrm` uses WinRM only and never opens 445.
  `--via auto` (the CLI default) opens SMB first. Only when the TCP connect to
  the SMB port is refused, unreachable or times out (5 s) does it switch to
  WinRM, and it prints one line to stderr:
  `winlinux: SMB port 445 unreachable; copying over WinRM`. The decision holds
  for the rest of the run, so the shell does not retry 445 on every line. An
  auth error or a file error never switches.
- Output, `--json` and exit codes are the same as over SMB. A missing file or
  share, access denied, a file in use and a directory where a file was
  expected give the same error class and message as SMB (`SmbNotFoundError`,
  `SmbAccessDeniedError`, `SmbSharingViolationError`, `SmbIsADirectoryError`),
  naming `<share>/<path>` as you typed it, never the server's local path.
  `-v` adds the server's raw .NET message. Other remote failures and a
  SHA-256 mismatch are `WinLinuxTransferError`. All exit 5.
- `<share>/<path>` keeps its meaning. The server resolves the share to its
  folder: a drive share such as `C$` maps to `C:\`; any other share is looked
  up by its exact name with `Get-SmbShare`. A path with `..` is refused.
- `get -r` and `put -r` do not run over WinRM yet: `--via winrm -r` exits 1,
  and `-r` with `--via auto` uses SMB.
- Library: `transfer: { via: 'winrm' | 'auto', onFallback }` in the connect
  options, or `{ via, signal }` as the last argument of `get` and `put`. The
  library default is `'smb'`.

How it works. `put` runs one PowerShell command and feeds the file to its
stdin as base64 lines with WinRM Send requests, one at a time: the next part
of the file is read only after the server acknowledged the last Send. The
script writes `<dest>.winlinux-<random>.part` next to the destination,
computes SHA-256 as it writes, compares it with the hash the client computed
first, and only then replaces the destination. `get` runs one PowerShell
command that opens the file read-only (other readers allowed, no writers)
and writes it to stdout as base64 lines, then `sha256:<hex>`. The client
decodes the lines as they arrive, writes a local `.part` file, compares the
hash, then renames it. Both sides stream; neither holds the file in memory.
Against the mock, a 100 MB copy each way grows the client's memory by less
than 64 MB.

An interrupted or failed copy never leaves a partial file at the
destination. Ctrl+C closes the remote command's stdin first, so the put
script removes its temp file by itself, then sends Signal and removes the
local `.part` file (exit 130). If the connection dies, or a second Ctrl+C
quits before the server has answered, the server may keep a
`*.winlinux-*.part` file next to the destination; delete it by hand. A
restarted copy starts from the beginning.

**Throughput trade-off.** WinRM copy is slower than SMB:
- The file travels as base64 text (+33 %), and WinRM base64-encodes the
  stdin and stdout streams in SOAP again, so each file byte costs about
  1.8 bytes on the wire.
- Each Send carries about 110 KB of stdin (about 83 KB of the file) and each
  Receive at most one 150 KB envelope. Each is one HTTP round trip with its
  own SOAP envelope, and over plain HTTP its own message encryption.
- Expect it to be several times slower than SMB, more so on links with high
  latency.

There are no measurements against Windows Server yet (HTTP with message
encryption, or HTTPS). The only numbers so far come from the mock on one
machine (loopback, TLS, no Windows, no message encryption): 100 MB put at
about 21 MB/s and get at about 7 MB/s. They show the client's own cost and
say nothing about a real server.

#### Double hop and CredSSP

NTLM and Kerberos sign you in to the server, but the server cannot use that
sign-in to reach a third machine. A command that reads a share on another
server (`Get-ChildItem \\<other-host>\<share>`) then fails with access
denied. This is the "double hop". CredSSP fixes it by sending your password
to the server, encrypted, so the server can sign in as you.

```bash
npx winlinux run -a credssp --tls user@<host> -- powershell -c "Get-ChildItem \\<other-host>\<share>"
```

**Risk.** With CredSSP the server gets your reusable password. A server that
is compromised, or a host that pretends to be the server, gets your account.
Use it only with servers you trust. So winlinux makes it strict opt-in:
- Only `-a credssp` (library: `auth: 'credssp'`) selects it. `negotiate` never
  does, and a host profile cannot set `Auth credssp`.
- It needs a password. It refuses `-K` and `--keytab`.
- It needs a verified server: it refuses `--insecure`, and it refuses plain
  HTTP unless you also pass `--credssp-allow-http` (library:
  `winrm.credsspAllowHttp: true`). Inside CredSSP, `pubKeyAuth` still binds
  the server's TLS key to the sign-in, but over HTTP the outer channel has
  no certificate check. There is no profile key for this flag.
- It works for WinRM commands only. File commands refuse it: "CredSSP is
  WinRM-only; use another mechanism for files".
- Every CredSSP sign-in prints one line to stderr, also with `--json`:
  `winlinux: CredSSP: your password is delegated to <host>`. The library
  never prints; it calls `winrm.onCredSSPDelegation(host)` instead.
- winlinux speaks CredSSP version 6 with the client nonce and the SHA-256
  `pubKeyAuth` hash (the CVE-2018-0886 fix), and refuses servers that only
  speak older versions. The inner sign-in is NTLM, or Kerberos when you set
  `--realm`.

**Server steps.** On the Windows server, in an elevated PowerShell:

```powershell
Enable-WSManCredSSP -Role Server -Force
```

Use an HTTPS listener with a certificate your client trusts, so `--tls`
works without `--insecure`. Turn it off again with
`Disable-WSManCredSSP -Role Server`.

**The safer option: Kerberos resource-based constrained delegation.** Let the
first server act for you on the second server only, with no password sent
anywhere and no change on the client. An AD admin sets it on the second
server's computer object, for example:

```powershell
Set-ADComputer <other-host> -PrincipalsAllowedToDelegateToAccount (Get-ADComputer <host>)
```

Then sign in with Kerberos (`-a kerberos` or `negotiate` with `--realm`) as
usual. Prefer this to CredSSP wherever you control the domain.

### PowerShell remoting (pwsh)

> **Experimental in 1.1.0.** `pwsh -c`, `invokePowerShell`, `openPowerShell`
> and `openRunspacePool` are tested against a scripted PSRP endpoint only,
> not yet on a real Windows Server. Their behaviour can change in a minor
> release. `winlinux run` (WinRS) is the stable way to run commands.

`winlinux pwsh <target> -c '<script>'` runs one pipeline through the
PowerShell Remoting Protocol (PSRP), the protocol behind `Invoke-Command`
and `Enter-PSSession`, inside the WinRM connection and sign-in the other
commands use. The server runs the script in a real runspace and formats
the objects itself (`Out-String -Stream`), so `Get-Process` prints the
table Windows PowerShell prints. Output goes to stdout; error, warning,
verbose and debug records to stderr, with the prefixes PowerShell uses;
`Write-Host` text to stdout. `--json` prints one value,
`{"output": [...], "errors": [...], "state": "Completed"}`, with each
object as its properties plus `"@type"` and `"@toString"`.
`--configuration <name>` picks the session configuration (default
`Microsoft.PowerShell`). Exit 0 when the pipeline completed with no error
record, 4 when it failed or wrote one, 130 on Ctrl+C, which stops the
pipeline on the server before the session closes.

This release runs one pipeline per command: nothing persists from one
`pwsh -c` to the next, and the script gets no host, so `Read-Host` and
`Get-Credential` fail on the server at once instead of waiting. The
interactive session, prompts and reconnect are planned. Needs
PowerShell 3.0 or newer on the server (protocol 2.2 or newer).

Library: `client.openPowerShell()` returns a session whose `invoke(script)`
pipelines share one runspace until `close()`; `client.invokePowerShell(script)`
runs one pipeline in a pool opened for it. Both use the WinRM sign-in of
the client on their own connection and map errors as `run` does. `run`,
`logs`, `services` and `ps` stay on WinRS.

```ts
const ps = await client.openPowerShell();
await ps.invoke('$x = 41').result();
const r = await ps.invoke('$x + 1').result(); // { state: 'Completed', output: [42], errors: [] }
for await (const event of ps.invoke('Get-Process', { outString: { width: 120 } })) {
  if (event.stream === 'output') console.log(event.value);
}
await ps.close();
```

## Known limits

- **Not verified live:** Kerberos over HTTPS (5986), including its channel
  binding (proven against a MIT acceptor only); Windows Server 2016,
  2019 and 2025 (only 2022 is tested); WinRM with
  `CbtHardeningLevel = Strict`; SMB 3.x encryption against Windows Server. Keytab sign-in and the CredSSP double hop are proven against test
  servers, not against a real Windows domain.
- **Exit code of instant-exit commands:** Windows can report exit code 0 for
  a remote process that exits at once without writing anything.
  winlinux reports the code the server sends. A command that prints first,
  such as `cmd /c "echo x& exit 7"`, is reported exactly.
- **ES modules only.** CommonJS code loads the packages with
  `await import()` (see [CommonJS](#commonjs)).
- **Node.js 22 or later.**
- **Kerberos needs the run-time library on Linux.** The Kerberos addon and
  the `kerberos` package open `libgssapi_krb5.so.2` (MIT Kerberos):
  `libgssapi-krb5-2` on Debian and Ubuntu, `krb5-libs` on Fedora, RHEL and
  Alpine. NTLM, Basic and certificate sign-in work without it.
- **No prebuilt addon binary** for platforms outside
  [Supported](#supported): there the addon compiles from source, which needs
  a C compiler and the Kerberos headers (`libkrb5-dev` or `krb5-devel`). If
  that fails, the install still succeeds and Kerberos falls back to the
  `kerberos` package, without SMB signing and without Kerberos over plain
  HTTP.
- **The `kerberos` package** downloads its prebuilt binary from GitHub at
  install time. Without access to GitHub it compiles from source. `winlinux`
  depends on it; for `@winlinux/auth` it is an optional dependency,
  so a library consumer that uses NTLM or Basic only can install with
  `--omit=optional` and skip the native build. Without it, a Kerberos
  sign-in fails with an error that says `npm install kerberos`.
- **Interactive shell:** `cd` persists across lines; `set`, `pushd` and other
  cmd.exe state is per line.

## Development

The five packages are npm workspaces: `packages/auth`, `packages/winrm`,
`packages/smb2`, `packages/krb-session-key` (the optional Kerberos
session-key addon) and `packages/winlinux` (the facade and CLI). From the
repository root:

```bash
npm ci && npm run build && npm test && npm audit --audit-level=low
npm run check:linux        # scripts/check-linux.sh: the same in Docker, node:22-bookworm
```

`npm run check:linux` copies the working tree (committed or not) into a fresh
container with the addon's prerequisites (`libkrb5-dev`, `g++`, `make`,
`python3`) and runs the same four commands there. The GitHub Actions workflow
`.github/workflows/ci.yml` runs them on Linux and macOS for every pull
request. `npm run prebuild:local` (`scripts/prebuild-local.sh`) builds the
addon's prebuilt binaries locally. `docs/RELEASING.md` describes a release.

Live verification: `smb2`, `auth` (Kerberos and NTLM) and the facade pass
against a real Samba server and a Samba AD DC in Docker, and WinRM Kerberos
message encryption over HTTP round-trips against a real MIT KDC. Windows
Server 2022 in an AD domain is verified live; the gaps are in
[Known limits](#known-limits).
