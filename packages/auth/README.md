# @winlinux/auth

Authentication for the winlinux WinRM and SMB2 clients: Basic, NTLM,
Kerberos, Negotiate (SPNEGO) and CredSSP behind one `AuthProvider`
interface.

Most users want the [`winlinux`](https://www.npmjs.com/package/winlinux)
package, which wires this package to WinRM and SMB2. Use this package
directly only to supply an `AuthProvider` to `@winlinux/winrm` or
`@winlinux/smb2`.

```bash
npm install @winlinux/auth
```

```js
import { createAuthProvider } from '@winlinux/auth';

const authProvider = createAuthProvider('negotiate'); // 'basic' | 'ntlm' | 'kerberos' | 'negotiate' | 'credssp'
const credentials = { username: 'alice', password: process.env.WINLINUX_PASSWORD, domain: 'CORP' };
// Pass both to connect() of @winlinux/winrm or @winlinux/smb2.
```

- **NTLM**: NTLMv2 only, with MIC, `mechListMIC` and channel bindings.
- **Kerberos**: a password (`kinit` into a private temp ccache), a keytab
  (`credentials.keytab`) or the ticket cache (`useTicketCache: true`). It
  uses the optional
  [`@winlinux/krb-session-key`](https://www.npmjs.com/package/@winlinux/krb-session-key)
  addon when it loads, and the `kerberos` package otherwise. Only the addon
  gives the session key that SMB2 signing and WinRM encryption over HTTP need.
  `kerberosSessionKeyAvailable()` says whether the addon loaded.
- **CredSSP** sends the password to the server. Only an explicit
  `'credssp'` selects it; `negotiate` never does.

The interface is the auth contract v1.2 (`docs/contracts/auth-provider.md`
in the repository).

ESM only, Node.js 22 or later. MIT license.
