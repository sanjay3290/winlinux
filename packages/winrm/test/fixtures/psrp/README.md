# Recorded PSRP fixtures

Files here come from `npm run test:live:psrp -w @winlinux/winrm` with
`WINLINUX_PSRP_RECORD=<dir>` set, redacted by `test/live/redact.ts`, and
reviewed by the maintainer before commit. `test/psrp/fixtures-redacted.test.ts`
fails when a file matches the deny list (an IP address, a domain SID, a
user profile path, or the recorder's own host, domain or user name from
`WINRM_HOST`, `WINRM_DOMAIN` and `WINRM_USER`).
