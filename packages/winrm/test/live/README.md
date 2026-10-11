# Live tests against a real Windows Server

These runners prove `@winlinux/winrm` and `@winlinux/smb2` against a real Windows Server.
They are not part of `npm test`. They need a VM, and they read all targets and secrets from the environment.

| Runner | Command | Exit codes |
|---|---|---|
| WinRM | `npm run test:live -w @winlinux/winrm` | 0 all pass, 1 a scenario failed, 2 env incomplete |
| SMB | `npm run test:live:windows -w @winlinux/smb2` | 0 all pass, 1 a scenario failed, 2 env incomplete |

Neither runner skips a scenario. With the env incomplete, a runner prints what it needs and exits 2.
The WinRM runner needs more for one scenario than for the rest: without a Kerberos realm it runs every other scenario, prints `# env incomplete: HTTP + Kerberos ...` with what is missing, and exits 2 (or 1 if another scenario failed).

## Scenarios

WinRM (`scenarios.ts`, one `node:test` test each):

| Test name | Transport | What passes |
|---|---|---|
| HTTPS + Basic: run hostname returns the host name with exit code 0 | HTTPS, Basic | `hostname` output equals `%COMPUTERNAME%`, exit code 0 |
| HTTPS + NTLM: a non-zero exit code is reported exactly (cmd /c "echo x& exit 7" -> x, 7) | HTTPS, NTLM | stdout `x`, exit code 7. The command prints a line first: WinRS can report 0 for a process that exits at once with no output |
| HTTP + NTLM: message encryption works and every SOAP body is sealed | HTTP, NTLM | `hostname` works; at least 5 `wrap()` and 5 `unwrap()` calls |
| HTTP + Kerberos: message encryption with the gss_wrap_iov split, or a refusal that names @winlinux/krb-session-key | HTTP, Kerberos | with `@winlinux/krb-session-key`: `hostname` works over plain HTTP with every body sealed; without it: `connect` fails with a `WinRMProtocolError` that names the addon and HTTPS. Needs `WINRM_REALM` and a KDC (below) |
| Streaming: more than 1 MB of output arrives complete and in order | general | 100,000 numbered lines (1.3 MB), every line intact and in order |
| PowerShell: a script returns CLIXML-parsed output and errors | general | stdout has the output, stderr has the error text, not raw CLIXML |
| Event log: read the last 10 System events | general | 10 events, newest first, each with an id, a provider and a time |
| Abort: breaking out of a long command leaves no orphan shell | general | `ping -n 120` stops early; the shell listing shows no leftover shell |

"general" is the transport that `WINRM_TLS` and `WINRM_MECHANISM` select (default HTTPS + NTLM).
Run the WinRM runner a second time with `WINRM_TLS=0` to run the general scenarios over encrypted HTTP too.

SMB (`packages/smb2/test/live/windows-live.ts`):

| Test name | What passes |
|---|---|
| SMB: negotiate offers 2.0.2/2.1 and logs the dialect Windows picks | dialect is 0x202 or 0x210; the log line shows it and the signing mode |
| SMB: listShares returns the test share | `SMB_SHARE` is in the list with type `disk` |
| SMB: put then get a file with equal SHA-256 | a 3 MB random file uploads, downloads, and hashes equal; the remote copy is deleted |

The offline test `packages/winrm/test/live-harness.test.ts` runs the same WinRM scenario functions against a fake Windows endpoint inside `npm test`.
It also proves that each check can fail (lost exit code, dropped stream chunk, orphan shell, wrong password).

## VM setup

Use Windows Server 2022 or 2025. A local VM (UTM, Parallels) or a cloud VM works. The Mac must reach TCP 5985, 5986 and 445.
Run these commands in an elevated PowerShell on the VM. Replace `<ip-or-name>` with the address the Mac uses.

1. Create the local admin test account:

   ```powershell
   $pw = Read-Host -AsSecureString 'Password for winlinux'
   New-LocalUser -Name winlinux -Password $pw -PasswordNeverExpires
   Add-LocalGroupMember -Group Administrators -Member winlinux
   # A local admin account gets a full token over the network only with this value:
   New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System `
     -Name LocalAccountTokenFilterPolicy -Value 1 -PropertyType DWord -Force
   ```

2. Enable WinRM with the HTTP listener on 5985, and allow Basic (the HTTPS + Basic scenario needs it):

   ```powershell
   winrm quickconfig -quiet
   Set-Item WSMan:\localhost\Service\Auth\Basic -Value $true
   # Keep AllowUnencrypted = false (the default). The HTTP + NTLM scenario depends on it:
   # the server then accepts only encrypted bodies on port 5985.
   Get-Item WSMan:\localhost\Service\AllowUnencrypted
   ```

3. Add the HTTPS listener on 5986 with a self-signed certificate:

   ```powershell
   $cert = New-SelfSignedCertificate -DnsName '<ip-or-name>', $env:COMPUTERNAME -CertStoreLocation Cert:\LocalMachine\My
   New-Item -Path WSMan:\localhost\Listener -Transport HTTPS -Address * -CertificateThumbPrint $cert.Thumbprint -Force
   New-NetFirewallRule -DisplayName 'WinRM HTTPS' -Direction Inbound -Protocol TCP -LocalPort 5986 -Action Allow
   # On a Public network profile, quickconfig limits 5985 to the local subnet. Open it if the Mac is elsewhere:
   New-NetFirewallRule -DisplayName 'WinRM HTTP' -Direction Inbound -Protocol TCP -LocalPort 5985 -Action Allow
   winrm enumerate winrm/config/listener
   ```

4. Turn on SMB file sharing with one test share:

   ```powershell
   New-Item -ItemType Directory -Path C:\winlinux-share -Force
   New-SmbShare -Name winlinux -Path C:\winlinux-share -FullAccess winlinux
   Enable-NetFirewallRule -DisplayGroup 'File and Printer Sharing'
   ```

5. Optional, for the Kerberos scenario: join the VM to an Active Directory domain and use a domain account for `WINRM_USER`.
   The client then needs the realm (`WINRM_REALM`, or `WINRM_DOMAIN`, which is upper-cased) and a KDC for it: `WINRM_KDC=<domain controller>`, or a `[realms]` entry in the client's `krb5.conf` / `KRB5_CONFIG`, or DNS SRV records.
   A workgroup VM has neither; the runner then reports the scenario as env incomplete and runs the rest.

Do not commit any of these values, and never share the password.

## Run

On the Mac, from the repo root:

```bash
npm ci && npm run build

export WINRM_HOST=<ip-or-name> WINRM_USER=winlinux WINRM_TLS_VERIFY=0
read -rs WINRM_PASS && export WINRM_PASS          # keeps the password out of shell history
npm run test:live -w @winlinux/winrm              # general scenarios over HTTPS + NTLM; exit 2 on a workgroup VM (Kerberos env incomplete)
WINRM_TLS=0 npm run test:live -w @winlinux/winrm  # general scenarios over encrypted HTTP + NTLM
# Domain-joined VM, domain account: the Kerberos scenario runs too
WINRM_USER=alice WINRM_REALM=LAB.EXAMPLE WINRM_KDC=dc1.lab.example npm run test:live -w @winlinux/winrm

export SMB_HOST=$WINRM_HOST SMB_SHARE=winlinux SMB_USER=winlinux SMB_PASS=$WINRM_PASS
npm run test:live:windows -w @winlinux/smb2
```

WinRM variables:

| Variable | Required | Default | Meaning |
|---|---|---|---|
| `WINRM_HOST` | yes | | host name or IP of the VM |
| `WINRM_USER` | yes | | test account |
| `WINRM_PASS` | yes | | its password |
| `WINRM_DOMAIN` | no | empty | NTLM domain; empty works for a local account |
| `WINRM_REALM` | for the Kerberos scenario | `WINRM_DOMAIN` upper-cased | Kerberos realm of `WINRM_USER`; without it the Kerberos scenario is env incomplete |
| `WINRM_KDC` | no | none | KDC host for `WINRM_REALM`; the runner writes a `krb5.conf` with it and sets `KRB5_CONFIG` for `kinit` and the GSS library. Without it the client's own `krb5.conf` or DNS must name the KDC |
| `WINRM_MECHANISM` | no | `ntlm` | `basic`, `ntlm`, `kerberos` or `negotiate` for the general scenarios |
| `WINRM_TLS` | no | `1` | `1` general scenarios use HTTPS, `0` HTTP |
| `WINRM_PORT` | no | 5986 / 5985 | port of the listener that `WINRM_TLS` selects; the other listener keeps its default |
| `WINRM_TLS_VERIFY` | no | `1` | `0` accepts the self-signed certificate |

SMB variables: `SMB_HOST`, `SMB_SHARE`, `SMB_USER`, `SMB_PASS` are required. `SMB_DOMAIN` (default empty) and `SMB_PORT` (default 445) are optional.

## Record the result

For each run, keep the command, the environment without the password, the `ok` / `not ok` lines, and the `#` log lines.
The log lines hold the evidence: the host name, the sealed request count, the stream size, the newest event, the shell check method, the SMB dialect, and the file hash.

## Known limits

- Windows can report exit code 0 for a process that exits at once without writing anything (`cmd /c exit 7` read 0 in about 1 run of 10 on Windows Server 2022, with pywinrm too). The exit-code scenario therefore runs `cmd /c "echo x& exit 7"`. A single run that proves the limit itself is not a winlinux failure.
- The abort check lists shells with `Get-WSManInstance -ResourceURI shell -Enumerate`. If Windows refuses that loopback WSMan call inside a remote session, the check counts `winrshost.exe` processes instead. The log line names the method it used. Both methods assume no other client opens shells on the VM during the run.
- The dialect log comes from a separate NEGOTIATE with the same dialect list the session sends. The session itself does not expose the dialect.
- The Kerberos scenario needs a realm and a KDC the client can reach (step 5). On a workgroup VM it is env incomplete, so the WinRM runner exits 2 there even when every other scenario passed. `WINRM_KDC` is not checked for reachability: with a wrong KDC the scenario fails at `kinit` (exit 1).
- The runner does not run `kinit` itself. The `@winlinux/auth` Kerberos provider runs it with the password into a temp ccache, so the client needs a `kinit` binary (MIT or Heimdal).
- Capture of real exchanges into offline fixtures is not implemented yet (the last Part B box).
