// Scripted AuthProvider for unit and mock-server tests. No crypto, no
// network: step() replays fixed tokens and records everything it sees.
import type {
  AuthProvider,
  AuthTarget,
  Credentials,
  Mechanism,
  SecurityContext,
  StepResult,
} from "../../src/auth-contract.js";

export interface StubProviderOptions {
  mechanism?: Mechanism;
  tokens?: Buffer[]; // scripted step() outputs; default two fixed tokens
  challenge?: Buffer; // expected server challenge on the second step()
  sessionKey?: Buffer;
}

export class StubAuthProvider implements AuthProvider {
  readonly mechanism: Mechanism;
  created: Array<{ target: AuthTarget; credentials: Credentials }> = [];
  contexts: StubSecurityContext[] = [];

  constructor(private readonly opts: StubProviderOptions = {}) {
    this.mechanism = opts.mechanism ?? "ntlm";
  }

  createContext(target: AuthTarget, credentials: Credentials): SecurityContext {
    this.created.push({ target, credentials });
    const ctx = new StubSecurityContext(this.opts);
    this.contexts.push(ctx);
    return ctx;
  }
}

export class StubSecurityContext implements SecurityContext {
  steps: Array<Buffer | undefined> = [];
  complete = false;
  disposed = false;
  constructor(private readonly opts: StubProviderOptions = {}) {}

  // A copy on each read, like the real providers (the contract getter).
  get sessionKey(): Buffer | undefined {
    return this.opts.sessionKey ? Buffer.from(this.opts.sessionKey) : undefined;
  }

  async step(inputToken?: Buffer): Promise<StepResult> {
    const index = this.steps.length;
    this.steps.push(inputToken);
    if (index === 1 && this.opts.challenge) {
      const got = inputToken?.toString("hex") ?? "<none>";
      const want = this.opts.challenge.toString("hex");
      if (got !== want) throw new Error(`stub: expected challenge ${want}, got ${got}`);
    }
    const scripted = this.opts.tokens ?? [Buffer.from("stub-token-1"), Buffer.from("stub-token-2")];
    const output = index < scripted.length ? scripted[index] : null;
    this.complete = index + 1 >= scripted.length;
    return { output, complete: this.complete };
  }

  async dispose(): Promise<void> {
    this.disposed = true;
  }
}
