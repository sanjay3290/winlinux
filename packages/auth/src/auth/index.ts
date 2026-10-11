import type { AuthProvider, Mechanism } from './types.js';
import { BasicAuthProvider } from './basic.js';
import { CredSSPAuthProvider } from './credssp/provider.js';
import { KerberosAuthProvider } from './kerberos.js';
import { NegotiateAuthProvider } from './negotiate.js';
import { NtlmAuthProvider } from './ntlm/provider.js';

export function createAuthProvider(mechanism: Mechanism): AuthProvider {
  switch (mechanism) {
    case 'basic':
      return new BasicAuthProvider();
    case 'ntlm':
      return new NtlmAuthProvider();
    case 'kerberos':
      return new KerberosAuthProvider();
    case 'negotiate':
      return new NegotiateAuthProvider();
    case 'credssp':
      // Only an explicit request selects it; negotiate never does.
      return new CredSSPAuthProvider();
    default:
      throw new Error(`Unknown auth mechanism: ${mechanism as string}`);
  }
}

export type {
  AuthProvider,
  AuthTarget,
  Credentials,
  Mechanism,
  SecurityContext,
  StepResult,
} from './types.js';
export { BasicAuthProvider } from './basic.js';
export { CredSSPAuthProvider, credsspCredentialsError } from './credssp/provider.js';
export type { CredSSPMessageProtection, CredSSPProviderDeps } from './credssp/provider.js';
export {
  KerberosAuthProvider,
  checkKeytabFile,
  kerberosHostError,
  kerberosSessionKeyAvailable,
  keytabCredentialsError,
} from './kerberos.js';
export { NegotiateAuthProvider, KerberosCredentialError } from './negotiate.js';
export { NtlmAuthProvider } from './ntlm/provider.js';
export { hasWinRMMessageProtection } from './winrm-extension.js';
export { channelBindingsHash, packGssChannelBindings } from './channel-bindings.js';
export type { ChannelBoundTarget, GssChannelBindings } from './channel-bindings.js';
export type { WinRMMessageProtection, WinRMSealed } from './winrm-extension.js';
