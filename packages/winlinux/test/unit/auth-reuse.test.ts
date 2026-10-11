// Real winrm and smb2 modules; the injected createAuthProvider hands out
// recording providers so the test sees every context the modules create.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { connect as winrmConnect } from '@winlinux/winrm';
import { connect as smbConnect } from '@winlinux/smb2';
import type { AuthProvider, AuthTarget, Credentials, Mechanism, SecurityContext } from '@winlinux/auth';
import { WinLinuxAuthError } from '../../dist/index.js';
import { createClient } from '../../dist/client.js';
import { basicStub } from '../../../winrm/dist/test/helpers/stub-auth.js';
import { StubAuthProvider as SmbStubProvider } from '../../../smb2/dist-test/test/helpers/stub-provider.js';
import { MockSmbServer } from '../../../smb2/dist-test/test/mock/server.js';
import { startWinrmMock } from '../helpers/winrm-mock.js';

interface Recorded {
  service: AuthTarget['service'];
  credentials: Credentials;
  stack: string;
}

class RecordingProvider implements AuthProvider {
  constructor(
    private readonly inner: AuthProvider,
    private readonly log: Recorded[],
  ) {}
  get mechanism(): Mechanism {
    return this.inner.mechanism;
  }
  createContext(target: AuthTarget, credentials: Credentials): SecurityContext {
    this.log.push({ service: target.service, credentials, stack: new Error().stack ?? '' });
    return this.inner.createContext(target, credentials);
  }
}

const PASSWORD = 'auth-reuse-password';

async function setup(smbProvider: () => AuthProvider) {
  const winrmMock = await startWinrmMock();
  const smbMock = new MockSmbServer({
    securityMode: 0,
    dirEntries: [{ name: 'a.txt', isDirectory: false, size: 3 }],
  });
  const smbPort = await smbMock.listen();
  const recorded: Recorded[] = [];
  const requested: Mechanism[] = [];
  const client = createClient(
    '127.0.0.1',
    {
      username: 'user',
      password: PASSWORD,
      auth: 'ntlm',
      winrm: { tls: true, tlsVerify: false, port: winrmMock.port },
      smb: { port: smbPort, requestTimeoutMs: 2000 },
    },
    {
      winrmConnect,
      smbConnect,
      createAuthProvider: (mechanism) => {
        requested.push(mechanism);
        // Each test opens WinRM first, then SMB: the first provider is WinRM's.
        return new RecordingProvider(requested.length === 1 ? basicStub() : smbProvider(), recorded);
      },
    },
  );
  const cleanup = async () => {
    await client.close();
    await Promise.all([winrmMock.close(), smbMock.close()]);
  };
  return { client, recorded, requested, cleanup };
}

describe('auth reuse', () => {
  it('one credential set yields an HTTP and a cifs context', async () => {
    const { client, recorded, requested, cleanup } = await setup(
      () => new SmbStubProvider({ sessionKey: Buffer.alloc(16, 7) }),
    );
    try {
      const result = await client.run('hostname');
      assert.equal(result.stdout, 'world');
      const entries = await client.ls('share');
      assert.deepEqual(entries.map((e) => e.name), ['a.txt']);

      assert.deepEqual(requested, ['ntlm', 'ntlm'], 'one provider per protocol');
      assert.deepEqual(recorded.map((r) => r.service), ['HTTP', 'cifs']);
      assert.equal(recorded[0]?.credentials, recorded[1]?.credentials, 'the same Credentials object');
      assert.equal(recorded[0]?.credentials.password, PASSWORD);
      // Contexts are created inside the modules, never by the facade: the frame
      // that called createContext is module code.
      const caller = (r?: Recorded) => (r?.stack ?? '').split('\n')[2] ?? '';
      assert.match(caller(recorded[0]), /winrm[\\/]dist[\\/]src[\\/]winrm[\\/]transport\.js/);
      assert.match(caller(recorded[1]), /smb2[\\/]dist[\\/]client[\\/]Session\.js/);
    } finally {
      await cleanup();
    }
  });

  it('smb auth failure leaves winrm usable', async () => {
    const failing: AuthProvider = {
      mechanism: 'ntlm',
      createContext: () => ({
        complete: false,
        step: async () => {
          throw new Error('stub provider refuses to step');
        },
      }),
    };
    const { client, cleanup } = await setup(() => failing);
    try {
      assert.equal((await client.run('hostname')).stdout, 'world');
      const err = await client.ls('share').catch((e: unknown) => e);
      assert.ok(err instanceof WinLinuxAuthError, String(err));
      assert.equal(err.protocol, 'smb');
      assert.equal(err.mechanism, 'ntlm');
      assert.equal((await client.run('hostname')).stdout, 'world', 'winrm still works');
    } finally {
      await cleanup();
    }
  });
});
