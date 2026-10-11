// winlinux -a credssp end to end: the CLI binary against the
// in-process CredSSP endpoint of @winlinux/winrm's tests (TLS in the
// header, NTLMv2, pubKeyAuth, TSCredentials, CredSSP-encrypted SOAP).
// Checks the stderr notice (also with --json) and every CLI refusal.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runCli } from '../helpers/cli.js';
import { actionOf, startMockServer, type MockResponse, type RecordedRequest } from '../../../winrm/dist/test/helpers/mock-server.js';
import { CREDSSP_PASSWORD, credsspEndpoint, type CredSSPEndpoint } from '../../../winrm/dist/test/helpers/credssp-server.js';

const FIXTURES = new URL('../../../winrm/dist/test/fixtures/', import.meta.url);
const fixture = (name: string) => readFileSync(new URL(name, FIXTURES), 'utf8');
const ENV = { WINLINUX_PASSWORD: CREDSSP_PASSWORD };
const TARGET = 'EXAMPLE\\sentinel-user@127.0.0.1';
const NOTICE = 'winlinux: CredSSP: your password is delegated to 127.0.0.1\n';

const SIGNAL_RESPONSE =
  '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body>' +
  '<rsp:SignalResponse xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell"/></s:Body></s:Envelope>';
const DELETE_RESPONSE =
  '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body>' +
  '<x:DeleteResponse xmlns:x="http://schemas.xmlsoap.org/ws/2004/09/transfer"/></s:Body></s:Envelope>';

function receive(stdout: string, exitCode: number): string {
  return (
    '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body>' +
    '<rsp:ReceiveResponse xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell">' +
    `<rsp:Stream Name="stdout" CommandId="COMMAND-ID-1">${Buffer.from(stdout).toString('base64')}</rsp:Stream>` +
    '<rsp:CommandState CommandId="COMMAND-ID-1" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done">' +
    `<rsp:ExitCode>${exitCode}</rsp:ExitCode></rsp:CommandState></rsp:ReceiveResponse></s:Body></s:Envelope>`
  );
}

async function startCredsspWinrm(): Promise<{ port: number; ep: CredSSPEndpoint; close: () => Promise<void> }> {
  const ep = credsspEndpoint();
  const server = await startMockServer(async (req: RecordedRequest): Promise<MockResponse> => {
    const denied = await ep.check(req);
    if (denied) return denied;
    const action = actionOf(Buffer.from(await ep.unwrap(req)));
    const soap =
      action === 'Create' ? fixture('create-response.xml')
      : action === 'Command' ? fixture('command-response.xml')
      : action === 'Receive' ? receive('second hop ok\n', 0)
      : action === 'Signal' ? SIGNAL_RESPONSE
      : DELETE_RESPONSE;
    return ep.wrap(req, soap);
  });
  return {
    port: server.port,
    ep,
    close: async () => {
      ep.close();
      await server.close();
    },
  };
}

describe('cli -a credssp', () => {
  it('runs a command and prints the delegation notice once on stderr', async () => {
    const mock = await startCredsspWinrm();
    try {
      const r = await runCli(['run', '-a', 'credssp', '--credssp-allow-http', '--winrm-port', String(mock.port), TARGET, '--', 'hostname'], ENV);
      assert.equal(r.code, 0, r.stderr);
      assert.equal(r.stdout, 'second hop ok\n');
      assert.equal(r.stderr, NOTICE);
      assert.deepEqual(mock.ep.credentials, [{ domain: 'EXAMPLE', username: 'sentinel-user', password: CREDSSP_PASSWORD }]);
      assert.ok(!r.stdout.includes(CREDSSP_PASSWORD) && !r.stderr.includes(CREDSSP_PASSWORD));
    } finally {
      await mock.close();
    }
  });

  it('--json keeps stdout JSON and the notice on stderr', async () => {
    const mock = await startCredsspWinrm();
    try {
      const r = await runCli(['run', '--json', '-a', 'credssp', '--credssp-allow-http', '--winrm-port', String(mock.port), TARGET, 'hostname'], ENV);
      assert.equal(r.code, 0, r.stderr);
      assert.deepEqual(JSON.parse(r.stdout), { stdout: 'second hop ok\n', stderr: '', exitCode: 0 });
      assert.equal(r.stderr, NOTICE);
    } finally {
      await mock.close();
    }
  });

  it('run --hosts prints one notice per host', async () => {
    const mock = await startCredsspWinrm();
    try {
      const r = await runCli(['run', '-a', 'credssp', '--credssp-allow-http', '--winrm-port', String(mock.port), '--hosts', TARGET, 'hostname'], ENV);
      assert.equal(r.code, 0, r.stderr);
      assert.equal(r.stderr.split('\n').filter((l) => l === NOTICE.trimEnd()).length, 1, r.stderr);
    } finally {
      await mock.close();
    }
  });

  const refusals: Array<[string, string[], RegExp]> = [
    ['plain HTTP without --credssp-allow-http', ['-a', 'credssp'], /CredSSP over plain HTTP is refused: the outer HTTP channel has no certificate check, and CredSSP delegates your password/],
    ['--insecure', ['-a', 'credssp', '--tls', '--insecure'], /CredSSP refuses --insecure/],
    ['--insecure over HTTP', ['-a', 'credssp', '--insecure', '--credssp-allow-http'], /CredSSP refuses --insecure/],
    ['-K', ['-a', 'credssp', '--tls', '-K'], /cannot use the ticket cache \(-K\)/],
    ['--credssp-allow-http without -a credssp', ['--credssp-allow-http'], /--credssp-allow-http applies to -a credssp only/],
  ];
  for (const [what, flags, re] of refusals) {
    it(`refuses ${what} with exit 1 and opens nothing`, async () => {
      const r = await runCli(['run', ...flags, '--winrm-port', '9', TARGET, 'hostname'], ENV);
      assert.equal(r.code, 1, r.stderr);
      assert.match(r.stderr, re);
      assert.ok(!r.stderr.includes('your password is delegated'), 'no notice on a refusal');
    });
  }

  it('refuses a keytab', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'winlinux-credssp-'));
    const keytab = join(dir, 'sentinel.keytab');
    writeFileSync(keytab, 'not a keytab', { mode: 0o600 });
    const r = await runCli(['run', '-a', 'credssp', '--tls', '--keytab', keytab, '--realm', 'EXAMPLE.TEST', '--winrm-port', '9', 'sentinel-user@server.example.test', 'hostname'], {});
    assert.equal(r.code, 1, r.stderr);
    assert.match(r.stderr, /cannot use a keytab/);
  });

  it('refuses file commands: CredSSP is WinRM-only', async () => {
    const r = await runCli(['ls', '-a', 'credssp', '--tls', '--smb-port', '9', TARGET, 'C$'], ENV);
    assert.equal(r.code, 1, r.stderr);
    assert.match(r.stderr, /CredSSP is WinRM-only; use another mechanism for files/);
  });

  it('a profile Auth credssp is refused; -a credssp is the only way in', async () => {
    const home = mkdtempSync(join(tmpdir(), 'winlinux-credssp-home-'));
    mkdirSync(join(home, '.winlinux'));
    writeFileSync(join(home, '.winlinux', 'config'), 'Host box\n  HostName 127.0.0.1\n  Auth credssp\n', { mode: 0o600 });
    const r = await runCli(['run', 'sentinel-user@box', 'hostname'], { ...ENV, HOME: home });
    assert.equal(r.code, 1, r.stderr);
    assert.match(r.stderr, /a profile cannot select it; use -a credssp per command/);
  });

  it('--help lists credssp', async () => {
    const r = await runCli(['--help']);
    assert.match(r.stdout, /credssp/);
    assert.match(r.stdout, /--credssp-allow-http/);
  });
});
