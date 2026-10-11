import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { connect, WinLinuxUsageError, type ConnectOptions } from '../../dist/index.js';
import { createClient } from '../../dist/client.js';
import { fakeDeps } from '../helpers/fakes.js';
import { NtlmAuthProvider, channelBindingsHash } from '@winlinux/auth';

// A bare NTLM CHALLENGE (raw writes) with NetBIOS names and a timestamp.
function ntlmChallengeWithTimestamp(): Buffer {
  const pair = (id: number, value: Buffer) => {
    const h = Buffer.alloc(4);
    h.writeUInt16LE(id, 0);
    h.writeUInt16LE(value.length, 2);
    return Buffer.concat([h, value]);
  };
  const stamp = Buffer.alloc(8);
  stamp.writeBigUInt64LE(0x01db9999abcdef01n, 0);
  const info = Buffer.concat([
    pair(2, Buffer.from('DOMAIN', 'utf16le')),
    pair(1, Buffer.from('SERVER', 'utf16le')),
    pair(7, stamp),
    pair(0, Buffer.alloc(0)),
  ]);
  const h = Buffer.alloc(56);
  h.write('NTLMSSP\0', 0, 'ascii');
  h.writeUInt32LE(2, 8);
  h.writeUInt32LE(56, 16); // empty TargetName at 56
  h.writeUInt32LE(0xe28a8235, 20); // UNICODE, SIGN, SEAL, NTLM, ALWAYS_SIGN, ESS, TARGET_INFO, VERSION, 128, KEY_EXCH, 56
  Buffer.alloc(8, 1).copy(h, 24);
  h.writeUInt16LE(info.length, 40);
  h.writeUInt16LE(info.length, 42);
  h.writeUInt32LE(56, 44);
  return Buffer.concat([h, info]);
}

// The AV pairs of the NTLMv2 blob in the AUTHENTICATE inside a SPNEGO token.
function authenticateAvPairs(token: Buffer): Map<number, Buffer> {
  const at = token.indexOf(Buffer.concat([Buffer.from('NTLMSSP\0', 'ascii'), Buffer.from([3, 0, 0, 0])]));
  assert.ok(at >= 0, 'an NTLM AUTHENTICATE in the token');
  const type3 = token.subarray(at);
  const ntLen = type3.readUInt16LE(20);
  const ntOff = type3.readUInt32LE(24);
  const list = type3.subarray(ntOff + 16 + 28, ntOff + ntLen);
  const pairs = new Map<number, Buffer>();
  for (let i = 0; i + 4 <= list.length; ) {
    const id = list.readUInt16LE(i);
    const len = list.readUInt16LE(i + 2);
    if (id === 0) break;
    pairs.set(id, list.subarray(i + 4, i + 4 + len));
    i += 4 + len;
  }
  return pairs;
}

async function rejectsUsage(host: string, options: ConnectOptions, pattern: RegExp): Promise<void> {
  await assert.rejects(connect(host, options), (err: unknown) => {
    assert.ok(err instanceof WinLinuxUsageError, `expected WinLinuxUsageError, got ${String(err)}`);
    assert.match((err as Error).message, pattern);
    return true;
  });
}

describe('connect() validation', () => {
  it('rejects empty host or username', async () => {
    await rejectsUsage('', { username: 'u', password: 'p' }, /host/);
    await rejectsUsage('h', { username: '', password: 'p' }, /username/);
  });

  it('requires a password for ntlm and basic', async () => {
    await rejectsUsage('h', { username: 'u', auth: 'ntlm' }, /needs a password/);
    await rejectsUsage('h', { username: 'u', auth: 'basic', useTicketCache: true }, /needs a password/);
    await rejectsUsage('h', { username: 'u', auth: 'ntlm', password: '' }, /needs a password/);
    await connect('h', { username: 'u', auth: 'ntlm', password: 'p' });
  });

  it('requires a password for kerberos and negotiate unless useTicketCache', async () => {
    await rejectsUsage('h', { username: 'u', auth: 'kerberos' }, /useTicketCache/);
    await rejectsUsage('h', { username: 'u' }, /useTicketCache/);
    const a = await connect('h', { username: 'u', auth: 'kerberos', useTicketCache: true });
    const b = await connect('h', { username: 'u', useTicketCache: true });
    await Promise.all([a.close(), b.close()]);
  });

  it('rejects out-of-range ports', async () => {
    await rejectsUsage('h', { username: 'u', password: 'p', winrm: { port: 0 } }, /winrm.port/);
    await rejectsUsage('h', { username: 'u', password: 'p', winrm: { port: 65536 } }, /winrm.port/);
    await rejectsUsage('h', { username: 'u', password: 'p', smb: { port: 1.5 } }, /smb.port/);
  });

  // Kerberos cannot work against an IP address (no principal in the
  // KDC). Refuse at connect() when Kerberos is the only mechanism that can
  // run; negotiate with a password falls back to NTLM and passes.
  it('rejects an IP address host when only Kerberos can run', async () => {
    const message = /^Kerberos needs the server's DNS name, not an IP address \(192\.0\.2\.10\); use the FQDN, --krb-hostname <fqdn>, or -a ntlm$/;
    await rejectsUsage('192.0.2.10', { username: 'u', auth: 'kerberos', password: 'p' }, message);
    await rejectsUsage('192.0.2.10', { username: 'u', auth: 'kerberos', useTicketCache: true }, message);
    await rejectsUsage('192.0.2.10', { username: 'u', useTicketCache: true }, message);
    await rejectsUsage('2001:db8::10', { username: 'u', auth: 'kerberos', password: 'p' }, /\(2001:db8::10\)/);
    const clients = await Promise.all([
      connect('192.0.2.10', { username: 'u', password: 'p' }), // negotiate + password: NTLM fallback
      connect('192.0.2.10', { username: 'u', password: 'p', auth: 'ntlm' }),
      connect('server.example.test', { username: 'u', auth: 'kerberos', useTicketCache: true }),
      connect('192.0.2.10', { username: 'u', auth: 'kerberos', useTicketCache: true, kerberosHostname: 'server.example.test' }),
    ]);
    await Promise.all(clients.map((c) => c.close()));
  });

  it('validates kerberosHostname', async () => {
    await rejectsUsage('h', { username: 'u', password: 'p', kerberosHostname: '' }, /kerberosHostname must not be empty/);
    for (const bad of ['192.0.2.10', 'HTTP/host', 'host example', 'user@host']) {
      await rejectsUsage('h', { username: 'u', password: 'p', kerberosHostname: bad }, /kerberosHostname must be the server's DNS name/);
    }
  });

  it('kerberosHostname names the SPN host while the connection goes to the IP', async () => {
    const targets: Array<{ host: string; service: string; spn?: string }> = [];
    const deps = fakeDeps({});
    deps.createAuthProvider = (mechanism) => ({
      mechanism,
      createContext: (target) => {
        targets.push({ ...target });
        throw new Error('stop here');
      },
    });
    const client = createClient(
      '192.0.2.10',
      // HTTPS: Kerberos over plain HTTP needs the session-key addon.
      { username: 'u', auth: 'kerberos', useTicketCache: true, kerberosHostname: 'files.example.test', winrm: { tls: true } },
      deps,
    );
    await client.run('x');
    await client.ls('C$');
    assert.equal(deps.winrmOpens[0]?.host, '192.0.2.10');
    assert.equal(deps.smbOpens[0]?.host, '192.0.2.10');
    // The modules build the target; the facade's wrapper adds the SPN.
    assert.throws(() => deps.winrmOpens[0]!.authProvider!.createContext({ host: '192.0.2.10', service: 'HTTP' }, { username: 'u' }), /stop here/);
    assert.throws(() => deps.smbOpens[0]!.authProvider.createContext({ host: '192.0.2.10', service: 'cifs' }, { username: 'u' }), /stop here/);
    assert.deepEqual(targets, [
      { host: '192.0.2.10', service: 'HTTP', spn: 'HTTP/files.example.test' },
      { host: '192.0.2.10', service: 'cifs', spn: 'cifs/files.example.test' },
    ]);

    // Without the option the provider is passed through untouched.
    const plain = fakeDeps({});
    const inner = plain.createAuthProvider;
    const seen: unknown[] = [];
    plain.createAuthProvider = (m) => {
      const provider = inner(m);
      seen.push(provider);
      return provider;
    };
    const direct = createClient('server.example.test', { username: 'u', auth: 'kerberos', useTicketCache: true, winrm: { tls: true } }, plain);
    await direct.run('x');
    assert.equal(plain.winrmOpens[0]?.authProvider, seen[0]);
    await Promise.all([client.close(), direct.close()]);
  });

  // The transport sets channelBindings on its own target once TLS is
  // up, after the context exists. The kerberosHostname wrapper must hand the
  // provider that object, not a copy, or NTLM never sees the binding.
  it('NTLM with kerberosHostname sends the channel binding the transport sets later', async () => {
    const deps = fakeDeps({});
    deps.createAuthProvider = () => new NtlmAuthProvider();
    const client = createClient('192.0.2.10', { username: 'u', password: 'p', auth: 'ntlm', kerberosHostname: 'files.example.test', winrm: { tls: true } }, deps);
    await client.run('x');
    const target: { host: string; service: 'HTTP'; channelBindings?: Buffer } = { host: '192.0.2.10', service: 'HTTP' };
    const ctx = deps.winrmOpens[0]!.authProvider!.createContext(target, { username: 'u', password: 'p', domain: 'd' });
    await ctx.step();
    // What WinRMTransport.bindChannel does when the TLS socket answers.
    const binding = Buffer.concat([Buffer.from('tls-server-end-point:', 'ascii'), Buffer.alloc(32, 7)]);
    target.channelBindings = binding;
    const out = await ctx.step(ntlmChallengeWithTimestamp());
    const pairs = authenticateAvPairs(out.output!);
    assert.equal(pairs.get(10)?.toString('hex'), channelBindingsHash(binding).toString('hex'), 'MsvAvChannelBindings');
    assert.equal(pairs.get(9)?.toString('utf16le'), 'HTTP/files.example.test', 'MsvAvTargetName');
    await client.close();
  });

  // Kerberos sends no channel binding yet, so WinRM over
  // HTTPS with --insecure refuses it before any socket. SMB has no TLS and
  // is unchanged; NTLM over unverified TLS is unchanged.
  it('kerberos over HTTPS with tlsVerify false is refused for WinRM only', async () => {
    const deps = fakeDeps({});
    const client = createClient('files.example.test', { username: 'u', auth: 'kerberos', useTicketCache: true, winrm: { tls: true, tlsVerify: false } }, deps);
    await assert.rejects(client.run('x'), (err: unknown) => {
      assert.ok(err instanceof WinLinuxUsageError, `expected WinLinuxUsageError, got ${String(err)}`);
      assert.match((err as Error).message, /Kerberos refuses --insecure \(tlsVerify false\) over HTTPS/);
      return true;
    });
    assert.equal(deps.winrmOpens.length, 0, 'no WinRM connection was opened');
    await client.ls('C$');
    assert.equal(deps.smbOpens.length, 1, 'SMB is not affected');
    await client.close();

    const ntlm = fakeDeps({});
    const plain = createClient('files.example.test', { username: 'u', password: 'p', auth: 'ntlm', winrm: { tls: true, tlsVerify: false } }, ntlm);
    await plain.run('x');
    assert.equal(ntlm.winrmOpens.length, 1, 'NTLM over unverified TLS still opens');
    await plain.close();
  });

  it('rejects an unknown auth mechanism', async () => {
    await rejectsUsage('h', { username: 'u', password: 'p', auth: 'auto' as never }, /auth must be one of/);
  });

  it('builds one frozen Credentials object for both modules', async () => {
    const deps = fakeDeps({});
    const client = createClient('h', { username: 'u', password: 'p', domain: 'D', auth: 'ntlm' }, deps);
    await client.run('x');
    await client.ls('C$');
    assert.equal(deps.winrmOpens[0]?.credentials, deps.smbOpens[0]?.credentials);
    assert.ok(Object.isFrozen(deps.winrmOpens[0]?.credentials));
    assert.deepEqual({ ...deps.winrmOpens[0]?.credentials }, { username: 'u', password: 'p', domain: 'D' });
  });

  it('rejects a share name that holds a path separator', async () => {
    const deps = fakeDeps({});
    const client = createClient('h', { username: 'u', password: 'p' }, deps);
    await assert.rejects(client.ls('A/b', 'c'), WinLinuxUsageError);
    await assert.rejects(client.get('A\\b', 'c', 'd'), WinLinuxUsageError);
    assert.equal(deps.smbOpens.length, 0);
  });
});
