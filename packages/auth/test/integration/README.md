# Auth live integration (Samba AD DC)

Proves `@winlinux/auth` against a real KDC and SMB server on the host
(macOS Heimdal or Linux) and in a Linux `node:22` container (MIT krb5).
Not part of `npm test`. Needs Docker only.

```sh
npm run test:integration -w @winlinux/auth
```

One command does everything:

1. Builds `@winlinux/smb2` and this package (`tsconfig.integration.json`,
   output in `dist-integration/`).
2. Starts `docker-compose.yml` (`nowsci/samba-domain`, realm `EXAMPLE.COM`,
   host `dc1.example.com`, test-only admin password `Passw0rd!`).
3. Waits until a real `kinit` succeeds and SMB accepts an NTLM logon.
4. Starts a `node:22` container on the DC network (installs `krb5-user`,
   builds the packages). It dials `dc1.example.com:88/445`.
5. Phase 1, DC default `server signing = mandatory`: runs `live.test.js`
   on the host (`KRB5_CONFIG` is a temp file whose KDC is
   `tcp/127.0.0.1:<mapped port>`), then in the Linux container.
6. Phase 2: adds `server signing = auto` to `[global]` in the DC's
   `smb.conf` and runs `smbcontrol smbd reload-config`. Signing is then
   offered but not required. Runs `live-unsigned.test.js` on the host,
   then in the Linux container.
7. Removes the containers and network (`compose down -v`).

Nothing changes host config: no `sudo`, no `/etc/hosts`, no `/etc/krb5.conf`.
The host dials `127.0.0.1`, so the tests set the SPN with the `AuthTarget`
`spn` override (`cifs/dc1.example.com`, `HTTP/dc1.example.com`).

## What the tests prove (`live.test.ts`)

The live run needs `@winlinux/krb-session-key` built (`npm ci` builds it;
see its README). Before phase 1 the Linux leg runs the addon's own tests:
`libgssapi_krb5` is mapped only after first use, and a missing library gives
an error that names the package to install.

- Password path: `kinit` into a per-context ccache, then an AP-REQ for
  `cifs/` and `HTTP/`; `klist` of that ccache shows both service tickets.
  `process.env.KRB5CCNAME` never changes, also with two concurrent contexts.
- Ticket-cache path: `useTicketCache: true` with a ccache made by `kinit`.
- SMB2 with Kerberos: `SESSION_SETUP` with the Negotiate provider's token gets
  `STATUS_SUCCESS` and the AP-REP completes the context (`smb2-probe.ts`,
  no signing). The token hex is printed as a test diagnostic.
- NTLM: `@winlinux/smb2` with the auth NTLM provider, signing required,
  lists shares and `sysvol`.
- Server signing required (NEGOTIATE has `SIGNING_REQUIRED`):
  Kerberos (password), Kerberos (ticket cache) and Negotiate (password)
  through `@winlinux/smb2` with `signing: 'required'` authenticate with
  Kerberos, hand smb2 a 32-byte key, list shares, and put then get a
  200 KB file in `netlogon` with an equal SHA-256. A key with one bit
  flipped fails (negative control).
- Event loop: the addon's first step (a TGS round trip to the KDC)
  lets `setImmediate` callbacks run while it is in flight.
- Final SPNEGO token: the DC's NTLM `mechListMIC` in the final
  `NegTokenResp` verifies, and a tampered one fails. Samba sends no
  `mechListMIC` with the Kerberos AP-REP (printed as a diagnostic).
- Wrong password and unknown user: `kinit failed: ...` naming the cause
  (Kerberos), `SmbAuthError` (NTLM).

## What the phase 2 tests prove (`live-unsigned.test.ts`)

- The DC NEGOTIATE response no longer has `SIGNING_REQUIRED` set.
- Kerberos from a `kinit` ccache (`useTicketCache: true`) connects through
  `@winlinux/smb2`, lists shares and lists `sysvol`. The AP-REP from the
  final `STATUS_SUCCESS` completes the context. With the addon the server
  still offers signing, so the session is signed.
- Negotiate with a password picks Kerberos (no NTLM fallback) and does the
  same.

## Environment

| Variable | Default | Use |
|----------|---------|-----|
| `COMPOSE_PROJECT_NAME` | `winlinux-auth-live` | compose project; prefix for names |
| `WINLINUX_DC_CONTAINER` | `<project>-dc` | DC container name |
| `WINLINUX_DC_NETWORK` | `<project>-net` | Docker network |
| `WINLINUX_KDC_PORT` | `127.0.0.1:` (random) | host binding for 88 |
| `WINLINUX_LDAP_PORT` | `127.0.0.1:` (random) | host binding for 389 |
| `WINLINUX_SMB_PORT` | `127.0.0.1:` (random) | host binding for 445 |
| `WINLINUX_LINUX_IMAGE` | `node:22` | image for the Linux leg |

Example with fixed ports: `WINLINUX_KDC_PORT=127.0.0.1:23888`.
Plain `docker compose up` (without the runner) keeps the old defaults
(`winlinux-ad-dc`, ports 88/389/445).

External mode: set `WINLINUX_KDC_HOST`, `WINLINUX_REALM`, `WINLINUX_USER`,
`WINLINUX_PASSWORD`, `WINLINUX_SMB_HOST`, `WINLINUX_SMB_PORT` and
`KRB5_CONFIG` to run only `live.test.js` against a DC you started.
`live-unsigned.test.js` needs a DC that does not require signing; run it
with `node --test` and the same variables.

The image is amd64 only; on arm64 hosts Docker emulates it.
