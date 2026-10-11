// The real module bindings for createClient (used by connect() and the CLI).
import { createAuthProvider, kerberosSessionKeyAvailable } from '@winlinux/auth';
import { connect as winrmConnect } from '@winlinux/winrm';
import { connect as smbConnect } from '@winlinux/smb2';
import type { ClientDeps } from './client.js';

export function realDeps(extra: Pick<ClientDeps, 'log'> = {}): ClientDeps {
  return { winrmConnect, smbConnect, createAuthProvider, kerberosSessionKey: kerberosSessionKeyAvailable, ...extra };
}
