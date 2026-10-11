// One lazy connection slot per protocol.
// States: idle, opening(promise), open(session), authFailed(error), closed.
// A WinLinuxAuthError is latched: later calls on the slot reject with the same
// error and do no network I/O, so repeated logons with a bad password cannot
// trip the account-lockout threshold. reset() clears the latch.
import { WinLinuxAuthError, WinLinuxConnectionError, WinLinuxUsageError } from './errors.js';

export interface Closable {
  close(): Promise<void>;
}

export type SlotState = 'idle' | 'opening' | 'open' | 'authFailed' | 'closed';

export interface SlotHooks<S> {
  open: () => Promise<S>;
  mapOpenError: (err: unknown) => unknown;
  mapOpError: (err: unknown) => unknown;
  onCloseError?: (err: unknown) => void;
  closeTimeoutMs?: number; // default 5000: a dead session must not hang close()
}

export const SESSION_CLOSE_TIMEOUT_MS = 5000;

export class Slot<S extends Closable> {
  private stateValue: SlotState = 'idle';
  private opening: Promise<S> | undefined;
  private session: S | undefined;
  private authFailure: WinLinuxAuthError | undefined;

  constructor(private readonly hooks: SlotHooks<S>) {}

  get state(): SlotState {
    return this.stateValue;
  }

  private acquire(): Promise<S> {
    if (this.stateValue === 'closed') return Promise.reject(new WinLinuxUsageError('client is closed'));
    if (this.stateValue === 'authFailed' && this.authFailure) return Promise.reject(this.authFailure);
    if (this.stateValue === 'open' && this.session) return Promise.resolve(this.session);
    if (!this.opening) {
      this.stateValue = 'opening';
      const opening = this.hooks.open().then(
        (session) => {
          this.session = session;
          if (this.stateValue !== 'closed') this.stateValue = 'open';
          return session;
        },
        (err: unknown) => {
          // Do not cache the failure: the next call starts a fresh open.
          if (this.opening === opening) this.opening = undefined;
          const mapped = this.hooks.mapOpenError(err);
          if (this.stateValue !== 'closed') this.stateValue = 'idle';
          throw this.remember(mapped);
        },
      );
      this.opening = opening;
    }
    return this.opening;
  }

  private remember(mapped: unknown): unknown {
    if (mapped instanceof WinLinuxAuthError && this.stateValue !== 'closed') {
      this.authFailure = mapped;
      this.stateValue = 'authFailed';
    }
    return mapped;
  }

  // Clears the auth-failure latch; the next call opens again.
  reset(): void {
    if (this.stateValue !== 'authFailed') return;
    this.authFailure = undefined;
    this.stateValue = 'idle';
  }

  private closeTimeoutMs(): number {
    return this.hooks.closeTimeoutMs ?? SESSION_CLOSE_TIMEOUT_MS;
  }

  private async settlesWithin(p: Promise<unknown>): Promise<boolean> {
    let timer: NodeJS.Timeout | undefined;
    const timeout = new Promise<false>((resolve) => {
      timer = setTimeout(() => resolve(false), this.closeTimeoutMs());
    });
    try {
      return await Promise.race([p.then(() => true, () => true), timeout]);
    } finally {
      clearTimeout(timer);
    }
  }

  // Bounded best-effort close; errors go to onCloseError.
  private async closeSession(session: S): Promise<void> {
    let timer: NodeJS.Timeout | undefined;
    const timeoutMs = this.closeTimeoutMs();
    const timeout = new Promise<void>((_, reject) => {
      timer = setTimeout(() => reject(new Error(`session close timed out after ${timeoutMs} ms`)), timeoutMs);
    });
    try {
      await Promise.race([session.close(), timeout]);
    } catch (err) {
      this.hooks.onCloseError?.(err);
    } finally {
      clearTimeout(timer);
    }
  }

  private checkNotClosed(): void {
    if (this.stateValue === 'closed') throw new WinLinuxUsageError('client is closed');
  }

  private fail(session: S, err: unknown): unknown {
    const mapped = this.hooks.mapOpError(err);
    if ((mapped instanceof WinLinuxAuthError || mapped instanceof WinLinuxConnectionError) && this.session === session) {
      this.session = undefined;
      this.opening = undefined;
      if (this.stateValue !== 'closed') this.stateValue = 'idle';
      void this.closeSession(session);
    }
    return this.remember(mapped);
  }

  async use<T>(fn: (session: S) => Promise<T>): Promise<T> {
    const session = await this.acquire();
    this.checkNotClosed();
    try {
      return await fn(session);
    } catch (err) {
      throw this.fail(session, err);
    }
  }

  // yield* forwards return() to the module iterator, so ending early sends Signal and Delete.
  // The inner iterator's final value passes through (the WinRM stream's
  // exit code).
  async *stream<T>(fn: (session: S) => AsyncIterable<T>): AsyncGenerator<T, unknown, undefined> {
    const session = await this.acquire();
    this.checkNotClosed();
    try {
      return yield* fn(session);
    } catch (err) {
      throw this.fail(session, err);
    }
  }

  async close(): Promise<void> {
    const opening = this.opening;
    this.stateValue = 'closed';
    if (opening && !(await this.settlesWithin(opening))) {
      // A hung open must not hang close(): give up on it and close the
      // session in the background if it ever arrives.
      this.hooks.onCloseError?.(new Error(`open did not finish within ${this.closeTimeoutMs()} ms; closing it in the background`));
      this.opening = undefined;
      opening.then(
        (late) => {
          if (this.session === late) this.session = undefined;
          void this.closeSession(late);
        },
        () => undefined,
      );
      return;
    }
    const session = this.session;
    this.session = undefined;
    this.opening = undefined;
    if (session) await this.closeSession(session);
  }
}
