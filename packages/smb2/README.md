# @winlinux/smb2

An SMB 2 and 3 file-share client for Node.js. It is a fork of `node-smb2`
(MIT, see `LICENSE.node-smb2.md`) with pluggable authentication, packet
signing, SMB 3.x encryption and share listing.

Most users want the [`winlinux`](https://www.npmjs.com/package/winlinux)
package, which adds WinRM, a CLI and one credential set for both.

```bash
npm install @winlinux/smb2 @winlinux/auth
```

```js
import { connect } from '@winlinux/smb2';
import { createAuthProvider } from '@winlinux/auth';

const smb = await connect({
  host: 'server.corp.example',
  authProvider: createAuthProvider('ntlm'),
  credentials: { username: 'alice', password: process.env.WINLINUX_PASSWORD, domain: 'CORP' },
});
try {
  console.log(await smb.listShares());
  console.log(await smb.list('C$', 'Windows/Temp'));
  await smb.download('C$', 'Windows/Temp/report.csv', './report.csv');
} finally {
  await smb.close();
}
```

- Dialects: SMB 3.1.1, 3.0.2, 3.0, 2.1 and 2.0.2. `maxDialect: '2.1'` limits
  a connection to SMB 2.x.
- Signing: HMAC-SHA256, AES-CMAC and AES-GMAC. Encryption: AES-128-GCM and
  AES-128-CCM, when the server or a share requires it.
- Kerberos signing needs the session key from the optional
  `@winlinux/krb-session-key` addon.
- No runtime dependencies. The package has no NTLM code of its own: an
  `AuthProvider` (from `@winlinux/auth` or your own) does the sign-in.

ESM only, Node.js 22 or later. MIT license.
