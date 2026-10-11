# Test-only client certificate

Made with openssl for the certificate sign-in tests. Never use them anywhere else.

- `ca-cert.pem`: a test CA (its key was discarded after signing).
- `client-cert.pem`, `client-key.pem`: a client certificate for `CN=test-user`
  with the Client Authentication EKU and a UPN SAN `test-user@localhost`,
  signed by the test CA, valid for 100 years.
- `client-key-encrypted.pem`: the same key as PKCS#8, AES-256-CBC, passphrase
  `Test-Key-Passphrase-Sentinel` (a sentinel test value).
