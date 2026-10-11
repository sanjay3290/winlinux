// A WinRM mock over TLS built on @winlinux/winrm's own test server
// (packages/winrm/test/helpers/mock-server.ts) and its fixtures.
import { readFileSync } from 'node:fs';
import { actionOf, startMockServer, type MockServer } from '../../../winrm/dist/test/helpers/mock-server.js';

// Same depth from test/helpers (compile) and dist-test/helpers (run).
const FIXTURES = new URL('../../../winrm/dist/test/fixtures/', import.meta.url);

export function fixture(name: string): string {
  return readFileSync(new URL(name, FIXTURES), 'utf8');
}

const SIGNAL_RESPONSE =
  '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body>' +
  '<rsp:SignalResponse xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell"/>' +
  '</s:Body></s:Envelope>';
const DELETE_RESPONSE =
  '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body>' +
  '<x:DeleteResponse xmlns:x="http://schemas.xmlsoap.org/ws/2004/09/transfer"/>' +
  '</s:Body></s:Envelope>';

export function doneReceive(stdoutText: string, exitCode = 0, stderrText = ''): string {
  const b64 = (s: string) => Buffer.from(s).toString('base64');
  const streams = [`<rsp:Stream Name="stdout" CommandId="COMMAND-ID-1">${b64(stdoutText)}</rsp:Stream>`];
  if (stderrText) streams.push(`<rsp:Stream Name="stderr" CommandId="COMMAND-ID-1">${b64(stderrText)}</rsp:Stream>`);
  return (
    '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body>' +
    '<rsp:ReceiveResponse xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell">' +
    streams.join('') +
    '<rsp:CommandState CommandId="COMMAND-ID-1" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done">' +
    `<rsp:ExitCode>${exitCode}</rsp:ExitCode></rsp:CommandState></rsp:ReceiveResponse></s:Body></s:Envelope>`
  );
}

export interface WinrmMockOptions {
  // Receive body; default receive-done.xml (stdout "world", exit code 3).
  // A function gets the Command body that preceded this Receive.
  receive?: string | ((command: string) => string);
  // Answer every request with 401 and no challenge.
  reject401?: boolean;
  // Never answer a Receive: the command runs until the client aborts.
  hangReceive?: boolean;
  // Basic auth: 401 unless the header carries this password.
  password?: string;
}

function basicPassword(header: string | string[] | undefined): string | undefined {
  const value = Array.isArray(header) ? header[0] : header;
  if (!value?.startsWith('Basic ')) return undefined;
  const decoded = Buffer.from(value.slice(6), 'base64').toString('utf8');
  return decoded.slice(decoded.indexOf(':') + 1);
}

// Plain SOAP over HTTPS. Auth headers are accepted as long as one is present.
export function startWinrmMock(opts: WinrmMockOptions = {}): Promise<MockServer> {
  let lastCommand = '';
  return startMockServer(
    (req) => {
      if (opts.reject401 || !req.headers.authorization) return { status: 401 };
      if (opts.password !== undefined && basicPassword(req.headers.authorization) !== opts.password) return { status: 401 };
      const action = actionOf(req.body);
      if (opts.hangReceive && action === 'Receive') return new Promise(() => undefined);
      if (action === 'Command') lastCommand = req.body.toString('utf8');
      const receive = typeof opts.receive === 'function' ? opts.receive(lastCommand) : opts.receive;
      const body =
        action === 'Create'
          ? fixture('create-response.xml')
          : action === 'Command'
            ? fixture('command-response.xml')
            : action === 'Receive'
              ? (receive ?? fixture('receive-done.xml'))
              : action === 'Signal'
                ? SIGNAL_RESPONSE
                : DELETE_RESPONSE;
      return { status: 200, headers: { 'Content-Type': 'application/soap+xml;charset=UTF-8' }, body };
    },
    { tls: { cert: fixture('tls-test-cert.pem'), key: fixture('tls-test-key.pem') } },
  );
}
