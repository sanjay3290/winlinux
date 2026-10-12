export class WinRMError extends Error {
  override name = 'WinRMError';
}

export class WinRMAuthError extends WinRMError {
  override name = 'WinRMAuthError';
}

export class WinRMTransportError extends WinRMError {
  override name = 'WinRMTransportError';
}

// The server answered with a SOAP fault (usually HTTP 500).
export class WinRMFaultError extends WinRMError {
  override name = 'WinRMFaultError';

  constructor(
    message: string,
    readonly faultCode: string | null,
    readonly faultSubcode: string | null,
    readonly reason: string,
    readonly wsmanCode: number | null,
    readonly machine: string | null,
    readonly raw: string,
  ) {
    super(message);
  }
}

// The server answered successfully but the payload was not usable:
// missing shell/command id, Done without an exit code, bad JSON.
export class WinRMProtocolError extends WinRMError {
  override name = 'WinRMProtocolError';
}

// The caller's AbortSignal fired. The name is 'AbortError', as for fetch()
// and other Node APIs. The shell's Signal and Delete still go out.
export class WinRMAbortError extends WinRMError {
  override name = 'AbortError';
}

// PSRP: the runspace pool is Broken, the server's protocol
// version is refused, or a message or fragment is malformed.
export class PSRemotingError extends WinRMError {
  override name = 'PSRemotingError';
}
