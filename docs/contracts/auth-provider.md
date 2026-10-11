# Auth Provider Contract (LOCKED v1.2 — 2026-10-10)

This is the seam between `@winlinux/auth` and its consumers
(`@winlinux/winrm`, `@winlinux/smb2`). Consumers code against this interface
and test with a stub; `@winlinux/auth` implements the real providers behind
it. **Locked**: changes go through the change-control section at the bottom.

## Design principle
NTLM and Kerberos are both challenge/response token handshakes (GSSAPI /
SPNEGO). The transport differs — WinRM carries tokens in HTTP `Authorization`
headers; SMB carries them in SMB2 `SESSION_SETUP` security blobs — but token
generation is the same step-wise loop. So the contract exposes a **security
context** that both transports drive the same way, mirroring the GSSAPI
`init_sec_context` loop. Auth wraps raw mechanism tokens in SPNEGO framing
internally, so consumers always see one opaque blob.

## Types (language-neutral; TypeScript shown)

```ts
type Mechanism = 'basic' | 'ntlm' | 'kerberos' | 'negotiate' | 'credssp';

interface Credentials {
  username: string;
  password?: string;        // omit when using a Kerberos ticket cache
  domain?: string;          // NTLM/AD domain or workgroup
  realm?: string;           // Kerberos realm; defaults to domain.toUpperCase()
  useTicketCache?: boolean; // Kerberos: use existing krb5 ccache
  keytab?: string;          // Kerberos: path to a keytab file; kinit gets the
                            // TGT from it (v1.2). Excludes password and
                            // useTicketCache; needs a realm. Kerberos only:
                            // NTLM and Basic refuse it, Negotiate never falls
                            // back to NTLM with it.
}

interface AuthTarget {
  host: string;
  service: 'HTTP' | 'cifs'; // SPN service class: WinRM=HTTP, SMB=cifs
  spn?: string;             // explicit SPN override, e.g. "HTTP/host.domain"
}

interface StepResult {
  output: Buffer | null;    // token to send to the server, or null when done
  complete: boolean;        // handshake finished
}

interface SecurityContext {
  // GSSAPI-style handshake. Call with no arg first, then feed each server
  // challenge token back in until complete === true.
  step(inputToken?: Buffer): Promise<StepResult>;

  readonly complete: boolean;

  // Set for mechanism 'negotiate' once known; else mirrors the provider.
  readonly negotiatedMechanism?: Mechanism;

  // Optional: message confidentiality / integrity. Async because the GSS
  // layer is async. See the Transport encryption rule below for when a
  // consumer must require these.
  wrap?(plaintext: Buffer): Promise<Buffer>;
  unwrap?(ciphertext: Buffer): Promise<Buffer>;

  // Optional: session key for SMB2 message signing.
  readonly sessionKey?: Buffer;

  // Optional: release native handles (GSS contexts).
  dispose?(): Promise<void>;
}

interface AuthProvider {
  readonly mechanism: Mechanism;
  createContext(target: AuthTarget, credentials: Credentials): SecurityContext;
}
```

## Capability matrix (verified)

| Mechanism | wrap/unwrap | sessionKey |
|-----------|-------------|------------|
| basic     | never       | never |
| ntlm      | present (NTLMSSP seal/sign, MS-NLMP 3.4) | present (NTLMv2 user session key) |
| kerberos  | present (GSS wrap/unwrap) | **absent** in the `kerberos` module |
| negotiate | follows the won mechanism | follows the won mechanism |
| credssp   | present (through the inner TLS session: `wrap` returns TLS records, `unwrap` takes them) | never |

`credssp` (v1.2) is WinRM only. Its context runs MS-CSSP: a TLS handshake
carried in the step tokens, then NTLM (or Kerberos when `realm` is set)
framed in SPNEGO inside that TLS session, then `pubKeyAuth`, then the
encrypted `TSCredentials` with the user's password. It needs
`Credentials.password` and refuses `keytab` and `useTicketCache`.
`negotiatedMechanism` is `'credssp'`. `negotiate` never selects it: a
consumer creates a `credssp` provider only on an explicit request.

## Transport encryption rule (reconciliation of WinRM vs Auth)
`wrap`/`unwrap` stay **optional** on the interface because Basic auth can never
provide them. Consumers enforce encryption at the transport instead:

- **WinRM:** if the transport is plain HTTP (port 5985) and the context exposes
  no `wrap`, the WinRM module MUST refuse the connection and require HTTPS
  (5986). Consequence: HTTP+NTLM works with MS-WSMV message encryption;
  HTTP+Kerberos (also Negotiate when it picks Kerberos) works when the
  context has the optional WinRM extension (`wrapWinRM` / `unwrapWinRM`,
  from the `@winlinux/krb-session-key` addon) and is otherwise refused with
  a `WinRMProtocolError` that points to HTTPS; HTTP+Basic must use HTTPS;
  HTTPS works for all.
- **SMB:** SMB2 signing needs `sessionKey`. The `kerberos` module does not
  expose it, so Kerberos SMB signing needs the `@winlinux/krb-session-key`
  addon. SMB requires a present `sessionKey` before it signs.

## Consumption examples (informative, not binding)
- **WinRM (HTTP Negotiate):** send `step()` output as
  `Authorization: Negotiate <base64>`; read the server `WWW-Authenticate`
  token, feed it back via `step(token)`; repeat until `complete`. Encrypt the
  SOAP body with `wrap()` on plain HTTP.
- **SMB2:** put `step()` output in the `SESSION_SETUP` security buffer; feed the
  server response blob back via `step(token)`; use `sessionKey` for signing.
- **Basic:** one `step()` returns base64 `user:pass`; `complete` immediately.

## Change control
Consumers must not depend on anything outside this file. A change to the
contract edits this file, bumps the version, adds a change-log entry, and
updates every consumer's copy of the types in the same change. Do not change
a consumer's copy alone.

### Change log
- **v1.2 — 2026-10-10:** `Mechanism` adds `'credssp'` (MS-CSSP,
  TSRequest version 6 with the client nonce and the SHA-256 `pubKeyAuth`
  binding; servers older than version 6 are refused). Capability matrix row:
  `wrap`/`unwrap` go through the inner TLS session, no `sessionKey`, WinRM
  only. The context needs a password and refuses a keytab and the ticket
  cache. `negotiate` never selects it. No other type or signature changed.
- **v1.2 — 2026-10-10:** `Credentials.keytab?: string`, the path to a
  keytab file, for unattended Kerberos sign-in. The Kerberos context runs
  `kinit` with the keytab into its private temp ccache (MIT `-k -t <file>`,
  Heimdal `--keytab=<file> --use-keytab`) and writes nothing to its stdin. It
  refuses a keytab with a password, with `useTicketCache`, or without a realm,
  and refuses a keytab file that group or others can read or write. NTLM and
  Basic refuse a keytab. Negotiate with a keytab runs Kerberos only (no NTLM
  fallback: there is no password). No other type or signature changed.
- **v1.1 — 2026-09-27:** Capability matrix: NTLM `wrap`/`unwrap` is
  present (it was deferred in v1). `@winlinux/auth` implements NTLMSSP
  seal/sign (MS-NLMP 3.4), proved against the MS-NLMP 4.2.4.4 test vectors.
  Transport rule: HTTP+NTLM encryption is allowed; HTTP+Kerberos is refused
  without the WinRM extension. No interface signature changed.
- **v1 — 2026-09-12:** Locked after the WinRM and Auth analyses were reconciled.
