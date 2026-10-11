// CLI target and path parsing.
import { WinLinuxUsageError } from '../errors.js';

export interface Target {
  username: string;
  domain?: string;
  host: string;
}

// `[DOMAIN\]user@host`. The host is the text after the last `@`.
// IPv6 goes in brackets. A `:port` suffix is a usage error.
export function parseTarget(text: string, flagDomain?: string): Target {
  const at = text.lastIndexOf('@');
  if (at <= 0 || at === text.length - 1) {
    throw new WinLinuxUsageError(`target must be [DOMAIN\\]user@host: ${text}`);
  }
  let user = text.slice(0, at);
  let host = text.slice(at + 1);

  if (host.startsWith('[')) {
    const end = host.indexOf(']');
    if (end === -1) throw new WinLinuxUsageError(`unclosed '[' in host: ${host}`);
    if (end !== host.length - 1) {
      throw new WinLinuxUsageError(`host must not carry a port (${host}); use --winrm-port or --smb-port`);
    }
    host = host.slice(1, end);
    if (host.length === 0) throw new WinLinuxUsageError('host must not be empty');
  } else if (host.includes(':')) {
    throw new WinLinuxUsageError(
      `host must not carry a port (${host}); use --winrm-port or --smb-port, and put an IPv6 address in brackets`,
    );
  }

  let domain = flagDomain;
  const slash = user.indexOf('\\');
  if (slash !== -1) {
    const targetDomain = user.slice(0, slash);
    user = user.slice(slash + 1);
    if (targetDomain.length === 0) throw new WinLinuxUsageError(`empty domain in target: ${text}`);
    if (flagDomain !== undefined && flagDomain.toLowerCase() !== targetDomain.toLowerCase()) {
      throw new WinLinuxUsageError(`target domain ${targetDomain} differs from --domain ${flagDomain}`);
    }
    domain = targetDomain;
  }
  if (user.length === 0) throw new WinLinuxUsageError(`empty user in target: ${text}`);
  return domain === undefined ? { username: user, host } : { username: user, domain, host };
}

// `<share>[/<path>]` splits at the first `/`.
export function splitSharePath(text: string): { share: string; path?: string } {
  const slash = text.indexOf('/');
  const share = slash === -1 ? text : text.slice(0, slash);
  const rest = slash === -1 ? '' : text.slice(slash + 1);
  if (share.length === 0) throw new WinLinuxUsageError(`expected <share>[/<path>]: ${text}`);
  return rest.length === 0 ? { share } : { share, path: rest };
}
