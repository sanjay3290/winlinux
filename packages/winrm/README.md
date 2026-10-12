# @winlinux/winrm

A WinRM (WS-Management) client for Node.js. Run commands and PowerShell
scripts on Windows servers, stream their output, read event logs, and list
services and processes.

Most users want the [`winlinux`](https://www.npmjs.com/package/winlinux)
package, which adds SMB file shares, a CLI and one credential set for both.

```bash
npm install @winlinux/winrm @winlinux/auth
```

```js
import { connect } from '@winlinux/winrm';
import { createAuthProvider } from '@winlinux/auth';

const winrm = await connect({
  host: 'server.corp.example',
  authProvider: createAuthProvider('negotiate'),
  credentials: { username: 'alice', password: process.env.WINLINUX_PASSWORD, domain: 'CORP' },
});
try {
  const r = await winrm.runCommand('ipconfig', ['/all']);
  console.log(r.exitCode, r.stdout);
  const ps = await winrm.runPowerShell('Get-Service | Select-Object -First 3');
  console.log(ps.stdout);
} finally {
  await winrm.close();
}
```

- HTTP (5985) and HTTPS (5986, `tls: true`).
- Basic, NTLM, Kerberos, Negotiate and CredSSP through an `AuthProvider`, or
  a TLS client certificate (`clientCertificate`) over HTTPS.
- Message encryption over plain HTTP for NTLM, and for Kerberos with the
  optional `@winlinux/krb-session-key` addon.
- Channel binding over HTTPS (RFC 5929 `tls-server-end-point`) for NTLM
  and, with the addon, for Kerberos: the first token is built after an
  unauthenticated probe has fetched the server certificate, and a sign-in
  whose first token lands on a connection with a different certificate
  fails with `WinRMAuthError` instead of binding to the wrong peer.
- PowerShell goes out as `-EncodedCommand`. `runCommand` quotes each
  argument for cmd.exe and the program's own argv split.
- Streaming output, stdin (`runCommandWithInput`), `AbortSignal`, and
  connect and operation timeouts.

ESM only, Node.js 22 or later. MIT license.
