// Runs in a child process in which the `kerberos` package and the addon do
// not resolve (no-kerberos-register.ts): what an NTLM-only consumer of
// @winlinux/auth sees after `npm install --omit=optional`. Prints one JSON
// object; the parent test asserts on it. No network, no kinit: the ticket
// cache is requested, so the Kerberos leg goes straight to the GSS layer.
import { createAuthProvider } from '../../src/auth/index.js';
import { unframeSpnego, OID_NTLMSSP } from '../../src/auth/spnego.js';
import type { AuthTarget } from '../../src/auth/types.js';

const target: AuthTarget = { host: 'server.domain', service: 'HTTP' };
const password = { username: 'alice', password: 'pw', domain: 'CORP', useTicketCache: true };
const ticketCacheOnly = { username: 'alice', useTicketCache: true };

const failure = async (run: () => Promise<unknown>): Promise<string> => {
  try {
    await run();
    return 'no error';
  } catch (err) {
    return (err as Error).message;
  }
};

const mechTypes = (token: Buffer | null | undefined): string[] => {
  const framed = unframeSpnego(token as Buffer);
  return framed.kind === 'init' ? framed.mechTypes : [];
};

const basic = await createAuthProvider('basic').createContext(target, password).step();
const ntlm = await createAuthProvider('ntlm').createContext(target, password).step();
const negotiate = createAuthProvider('negotiate').createContext(target, password);
const negotiateFirst = await negotiate.step();

const result = {
  basicComplete: basic.complete,
  ntlmOffers: mechTypes(ntlm.output),
  ntlmOffersNtlm: mechTypes(ntlm.output).includes(OID_NTLMSSP),
  kerberos: await failure(() => createAuthProvider('kerberos').createContext(target, ticketCacheOnly).step()),
  negotiateWon: negotiate.negotiatedMechanism,
  negotiateOffersNtlm: mechTypes(negotiateFirst.output).includes(OID_NTLMSSP),
  negotiateTicketCacheOnly: await failure(() => createAuthProvider('negotiate').createContext(target, ticketCacheOnly).step()),
};
process.stdout.write(`${JSON.stringify(result)}\n`);
