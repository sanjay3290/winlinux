# Live gate runbook: `npm run live:gate`

One command runs the maintainer's live checks against one or more Windows Servers and prints one Markdown table per target:

- **PSRP** (rows labelled `[PSRP]`): the PSRP scenarios of `packages/winrm/test/live/psrp-scenarios.ts` over HTTP + NTLM, HTTP + Kerberos, HTTPS + Basic and HTTPS + NTLM (the four runs of `npm run test:live:psrp`).
- **HTTPS-Kerberos** (rows labelled `[HTTPS-Kerberos]`): Kerberos and Negotiate over HTTPS (`hostname` over WinRS and one PSRP pipeline each), and NTLM over HTTPS with `CbtHardeningLevel` Strict.
- The server's OS build, PowerShell version and PSRP protocol version, read through a pipeline.
- PSRP fixtures, recorded and redacted, then checked against the deny list before the table prints.

No check is ever skipped silently. A check that cannot run is reported as `not run` with the reason, and it is never a `pass`.

## What you provide

One server per target, set up as `packages/winrm/test/live/README.md` describes (WinRM listeners on 5985 and 5986, Basic enabled, a local admin test account; optionally a domain and a KDC for Kerberos). Then:

| Check | Needs |
|---|---|
| HTTP + NTLM, HTTPS + NTLM, HTTPS + Basic | the host, the account, the password |
| HTTP + Kerberos, HTTPS + Kerberos, HTTPS + Negotiate | a realm (`realm`, or `domain`, which is upper-cased) and a KDC the client can reach (`kdc`, or the client's `krb5.conf`, or DNS SRV records); `@winlinux/krb-session-key` for HTTP |
| HTTPS + Kerberos, HTTPS + Negotiate | a **verified** HTTPS certificate: `tlsVerify` true and the server certificate trusted by the client (a CA-signed certificate, or `NODE_EXTRA_CA_CERTS=<server-cert.pem>` for a self-signed one). Kerberos over HTTPS refuses an unverified certificate |
| `CbtHardeningLevel` Strict | on the server: `winrm set winrm/config/service/auth '@{CbtHardeningLevel="Strict"}'`. The row passes only when the server reports Strict; at Relaxed it is `not run` |

Without a realm the Kerberos and Negotiate rows are `not run`. A Negotiate row passes only when Negotiate picked Kerberos: a fallback to NTLM fails the row, because it proves nothing about Kerberos. Without `tlsVerify` the HTTPS Kerberos and Negotiate rows are `not run`. Both are reported, with the reason, in the table.

## Targets

**One target** from the env of the live runners:

```bash
export WINRM_HOST=<host> WINRM_USER=<user> WINRM_TLS_VERIFY=0
read -rs WINRM_PASS && export WINRM_PASS          # keeps the password out of shell history
# Domain-joined: also WINRM_DOMAIN=<domain> or WINRM_REALM=<REALM>, and WINRM_KDC=<dc> when DNS does not name the KDC
npm run live:gate
```

**Several targets** (Windows Server 2016, 2019, 2022, 2025, a domain lab) from `live-targets.json` in the directory you run `npm run live:gate` from (the repo root); a relative `WINLINUX_LIVE_TARGETS` or `WINLINUX_PSRP_RECORD` path is relative to it too. The file is git-ignored and holds host names and account names, never passwords. Each entry names the env var that holds its password:

```json
{
  "targets": [
    { "name": "ws2022", "host": "<host>", "user": "<user>", "passwordEnv": "WINRM_PASS_WS2022", "tlsVerify": false },
    { "name": "lab-dc", "host": "<host>", "user": "<user>", "passwordEnv": "WINRM_PASS_LAB", "domain": "<domain>", "kdc": "<dc>", "tlsVerify": true }
  ]
}
```

| Key | Required | Default | Meaning |
|---|---|---|---|
| `name` | yes | | the label in the table and the fixture directory name (letters, digits, `.`, `_`, `-`) |
| `host` | yes | | host name or IP address; it is redacted to `<host>` in the output |
| `user` | yes | | the account; redacted to `<user>` |
| `passwordEnv` | no | `WINRM_PASS` | the env var that holds the password. A `password` key in the file is refused |
| `domain` | no | empty | NTLM domain; also the realm (upper-cased) when `realm` is not set |
| `realm` | no | `domain` upper-cased | Kerberos realm |
| `kdc` | no | none | KDC host; the gate writes a `krb5.conf` for it and sets `KRB5_CONFIG` for the target |
| `httpPort`, `httpsPort` | no | 5985, 5986 | the listeners |
| `tlsVerify` | no | true | false accepts a self-signed certificate (then Kerberos over HTTPS is `not run`) |

`WINLINUX_LIVE_TARGETS=<path>` names another file. A target whose password env var is empty is reported with every row `not run`.

```bash
read -rs WINRM_PASS_WS2022 && export WINRM_PASS_WS2022
read -rs WINRM_PASS_LAB && export WINRM_PASS_LAB
npm run live:gate
```

## Fixtures

The gate records every decrypted request, response and PSRP message of every pool it opens, redacted by `packages/winrm/test/live/redact.ts`, under `WINLINUX_PSRP_RECORD/<target name>/` (or a temp directory it prints when the variable is not set). Before the table prints, it checks every file against the deny list (an IP address, a domain SID, a user profile path, the target's host, domain and user names, the password, and every host, realm, domain, KDC and machine name of the target with its DNS labels). A hit fails the `PSRP fixtures recorded and redacted` row and the run; the gate deletes nothing. Review the files and copy the ones worth keeping under `packages/winrm/test/fixtures/psrp/`, where `test/psrp/fixtures-redacted.test.ts` guards them. The 5 MB scenario alone produces a few hundred files; keep a representative subset.

## Output and exit code

stdout holds the Markdown, one table per target, redacted (`<host>`, `<user>`, `example.test`, `<password>`). The host, realm, domain and KDC names, each of their DNS labels, and the machine name the server reports all become `<host>`, also inside error text; stderr holds progress lines. The password never prints.

| Exit | Meaning |
|---|---|
| 0 | every check of every target passed |
| 1 | a check failed, or a fixture matched the deny list |
| 2 | a check was `not run` (no password, no realm, no `tlsVerify`, no target) |

CI does not reach a Windows Server; the gate is the live check.
