// Kerberos channel binding: the binding a consumer sets on the
// target (channel-bindings.ts) reaches the GSS layer through the GssInit
// seam before the first token is built, so the AP-REQ is bound to the TLS
// server certificate. The `kerberos` package has no such parameter and
// sends none; the context says so through channelBound. No network.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  KerberosAuthProvider,
  createKerberosPackageGssFactory,
  type GssClient,
  type GssInit,
  type KerberosPackage,
} from '../src/auth/kerberos.js';
import { NegotiateAuthProvider } from '../src/auth/negotiate.js';
import type { ChannelBoundTarget } from '../src/auth/channel-bindings.js';
import type { AuthTarget, SecurityContext } from '../src/auth/types.js';

// channelBound is a Kerberos and Negotiate context property, outside the
// SecurityContext contract.
const bound = (ctx: SecurityContext): boolean => (ctx as { channelBound?: boolean }).channelBound === true;

const CERT_HASH = Buffer.from(Array.from({ length: 32 }, (_, i) => i));
const TLS_BINDING = Buffer.concat([Buffer.from('tls-server-end-point:', 'ascii'), CERT_HASH]);
const creds = { username: 'alice', useTicketCache: true };

// A GSS layer that records what it was created with and binds when asked,
// like @winlinux/krb-session-key.
class BindingGss implements GssClient {
  contextComplete = false;
  readonly channelBound: boolean;
  constructor(readonly init: GssInit) {
    this.channelBound = init.channelBindings !== undefined && init.channelBindings.length > 0;
  }
  async step(): Promise<string> {
    this.contextComplete = true;
    return 'eA==';
  }
  async wrap(data: string): Promise<string> {
    return data;
  }
  async unwrap(data: string): Promise<string> {
    return data;
  }
}

function capturing(): { factory: (service: string, init: GssInit) => Promise<GssClient>; created: BindingGss[] } {
  const created: BindingGss[] = [];
  return {
    created,
    factory: async (_service, init) => {
      const gss = new BindingGss(init);
      created.push(gss);
      return gss;
    },
  };
}

describe('Kerberos channel binding through the GSS seam', () => {
  it('passes the target binding to the GSS layer at the first step, as a copy', async () => {
    const { factory, created } = capturing();
    const target: AuthTarget & ChannelBoundTarget = { host: 'server.example', service: 'HTTP', channelBindings: TLS_BINDING };
    const ctx = new KerberosAuthProvider({ gss: factory }).createContext(target, creds);
    assert.equal(bound(ctx), false, 'nothing is bound before the first step');
    await ctx.step();
    assert.equal(created.length, 1);
    const sent = created[0]?.init.channelBindings;
    assert.ok(sent);
    assert.ok(sent.equals(TLS_BINDING));
    assert.notEqual(sent, TLS_BINDING, 'the GSS layer gets its own copy');
    assert.equal(bound(ctx), true);
  });

  it('reads a binding set on the target after createContext, before the first step (the transport pattern)', async () => {
    const { factory, created } = capturing();
    const target: ChannelBoundTarget & AuthTarget = { host: 'server.example', service: 'HTTP' };
    const ctx = new KerberosAuthProvider({ gss: factory }).createContext(target, creds);
    (target as { channelBindings?: Buffer }).channelBindings = TLS_BINDING;
    await ctx.step();
    assert.ok(created[0]?.init.channelBindings?.equals(TLS_BINDING));
    assert.equal(bound(ctx), true);
  });

  it('passes no binding for a target without one (plain HTTP, SMB) or with an empty one', async () => {
    for (const target of [
      { host: 'server.example', service: 'cifs' },
      { host: 'server.example', service: 'HTTP', channelBindings: Buffer.alloc(0) },
    ] as Array<AuthTarget & ChannelBoundTarget>) {
      const { factory, created } = capturing();
      const ctx = new KerberosAuthProvider({ gss: factory }).createContext(target, creds);
      await ctx.step();
      assert.equal(created[0]?.init.channelBindings, undefined);
      assert.equal(bound(ctx), false);
    }
  });

  it('Negotiate forwards the same target binding to its Kerberos leg and reports channelBound', async () => {
    const { factory, created } = capturing();
    const target: AuthTarget & ChannelBoundTarget = { host: 'server.example', service: 'HTTP', channelBindings: TLS_BINDING };
    const ctx = new NegotiateAuthProvider({ gss: factory }).createContext(target, creds);
    assert.equal(bound(ctx), false);
    await ctx.step();
    assert.equal(ctx.negotiatedMechanism, 'kerberos');
    assert.ok(created[0]?.init.channelBindings?.equals(TLS_BINDING));
    assert.equal(bound(ctx), true);
  });

  it('the kerberos package path takes the binding but cannot send it: channelBound stays false', async () => {
    const calls: Array<{ service: string; options: unknown }> = [];
    const fakePackage: KerberosPackage = {
      GSS_C_MUTUAL_FLAG: 2,
      GSS_C_REPLAY_FLAG: 4,
      GSS_C_SEQUENCE_FLAG: 8,
      GSS_C_CONF_FLAG: 16,
      GSS_C_INTEG_FLAG: 32,
      GSS_MECH_OID_KRB5: 9,
      initializeClient: async (service, options) => {
        calls.push({ service, options });
        return { contextComplete: true, step: async () => 'eA==', wrap: async (d: string) => d, unwrap: async (d: string) => d };
      },
    };
    const factory = createKerberosPackageGssFactory(async () => fakePackage);
    const target: AuthTarget & ChannelBoundTarget = { host: 'server.example', service: 'HTTP', channelBindings: TLS_BINDING };
    const ctx = new KerberosAuthProvider({ gss: factory }).createContext(target, creds);
    await ctx.step();
    assert.equal(calls.length, 1);
    assert.equal(calls[0]?.service, 'HTTP@server.example');
    assert.equal(ctx.complete, true);
    assert.equal(bound(ctx), false, 'the kerberos package has no channel binding parameter');
  });
});
