// Contract types. Mirrors docs/contracts/auth-provider.md (LOCKED v1.2) exactly.
// Do not extend these interfaces; change the contract file first.
export type Mechanism = 'basic' | 'ntlm' | 'kerberos' | 'negotiate' | 'credssp';

export interface Credentials {
  username: string;
  password?: string;
  domain?: string;
  realm?: string;
  useTicketCache?: boolean;
  keytab?: string;
}

export interface AuthTarget {
  host: string;
  service: 'HTTP' | 'cifs';
  spn?: string;
}

export interface StepResult {
  output: Buffer | null;
  complete: boolean;
}

export interface SecurityContext {
  step(inputToken?: Buffer): Promise<StepResult>;
  readonly complete: boolean;
  readonly negotiatedMechanism?: Mechanism;
  wrap?(plaintext: Buffer): Promise<Buffer>;
  unwrap?(ciphertext: Buffer): Promise<Buffer>;
  readonly sessionKey?: Buffer;
  dispose?(): Promise<void>;
}

export interface AuthProvider {
  readonly mechanism: Mechanism;
  createContext(target: AuthTarget, credentials: Credentials): SecurityContext;
}
