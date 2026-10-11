import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { planAuth, winrmEncrypted } from '../../dist/plan-auth.js';

const PW = { password: 'pw' };
const CACHE = { useTicketCache: true };
const HTTP = true; // E on: message encryption over plain HTTP
const HTTPS = false; // E off
const ADDON = true; // @winlinux/krb-session-key loads
const NO_ADDON = false;

describe('planAuth', () => {
  it('negotiate with password uses ntlm for winrm over http, negotiate over https, and ntlm for smb', () => {
    assert.deepEqual(planAuth('negotiate', PW, HTTP), {
      winrm: { refused: false, mechanism: 'ntlm' },
      smb: { refused: false, mechanism: 'ntlm' },
    });
    assert.deepEqual(planAuth('negotiate', PW, HTTPS), {
      winrm: { refused: false, mechanism: 'negotiate' },
      smb: { refused: false, mechanism: 'ntlm' },
    });
  });

  it('negotiate with password and ticket cache still uses ntlm for smb', () => {
    const both = { password: 'pw', useTicketCache: true };
    assert.deepEqual(planAuth('negotiate', both, HTTP).smb, { refused: false, mechanism: 'ntlm' });
    assert.deepEqual(planAuth('negotiate', both, HTTPS).smb, { refused: false, mechanism: 'ntlm' });
    assert.deepEqual(planAuth('negotiate', both, HTTP).winrm, { refused: false, mechanism: 'ntlm' });
  });

  it('negotiate with password and realm uses negotiate for smb only when Kerberos has a session key', () => {
    const withRealm = { password: 'pw', realm: 'EXAMPLE.COM' };
    for (const e of [HTTP, HTTPS]) {
      const keyed = planAuth('negotiate', withRealm, e, ADDON);
      assert.deepEqual(keyed.smb, { refused: false, mechanism: 'negotiate' });
      assert.deepEqual(keyed.winrm, { refused: false, mechanism: 'negotiate' }, 'winrm: negotiate with the addon');
      assert.deepEqual(planAuth('negotiate', withRealm, e, NO_ADDON).smb, { refused: false, mechanism: 'ntlm' }, 'no addon: ntlm');
      assert.deepEqual(planAuth('negotiate', withRealm, e).smb, { refused: false, mechanism: 'ntlm' }, 'default: no addon');
      assert.deepEqual(planAuth('negotiate', PW, e, ADDON).smb, { refused: false, mechanism: 'ntlm' }, 'no realm: ntlm');
      assert.deepEqual(
        planAuth('negotiate', { password: 'pw', realm: '' }, e, ADDON).smb,
        { refused: false, mechanism: 'ntlm' },
        'empty realm: ntlm',
      );
    }
  });

  it('kerberos and ticket-cache plans for smb do not depend on the addon', () => {
    for (const keyed of [NO_ADDON, ADDON]) {
      assert.deepEqual(planAuth('kerberos', PW, HTTPS, keyed).smb, { refused: false, mechanism: 'kerberos' });
      assert.deepEqual(planAuth('negotiate', CACHE, HTTPS, keyed).smb, { refused: false, mechanism: 'kerberos' });
      assert.deepEqual(planAuth('ntlm', PW, HTTPS, keyed).smb, { refused: false, mechanism: 'ntlm' });
    }
  });

  it('ticket cache only refuses winrm over http without the addon and uses kerberos over https and for smb', () => {
    const http = planAuth('negotiate', CACHE, HTTP);
    assert.equal(http.winrm.refused, true);
    assert.equal(http.winrm.refused && http.winrm.reason, 'Kerberos over plain HTTP is not supported; use --tls');
    assert.deepEqual(http.smb, { refused: false, mechanism: 'kerberos' });
    assert.deepEqual(planAuth('negotiate', CACHE, HTTP, NO_ADDON).winrm, http.winrm, 'default is no addon');
    assert.deepEqual(planAuth('negotiate', CACHE, HTTPS), {
      winrm: { refused: false, mechanism: 'kerberos' },
      smb: { refused: false, mechanism: 'kerberos' },
    });
  });

  it('kerberos refuses winrm over http without the addon and uses kerberos over https and for smb', () => {
    for (const creds of [PW, CACHE]) {
      const http = planAuth('kerberos', creds, HTTP);
      assert.equal(http.winrm.refused, true);
      assert.deepEqual(planAuth('kerberos', creds, HTTP, NO_ADDON).winrm, http.winrm, 'default is no addon');
      assert.deepEqual(http.smb, { refused: false, mechanism: 'kerberos' });
      assert.deepEqual(planAuth('kerberos', creds, HTTPS), {
        winrm: { refused: false, mechanism: 'kerberos' },
        smb: { refused: false, mechanism: 'kerberos' },
      });
    }
  });

  it('with the addon, winrm over http allows kerberos and negotiate', () => {
    // The addon supplies the gss_wrap_iov split winrm needs to seal bodies.
    for (const creds of [PW, CACHE]) {
      assert.deepEqual(planAuth('kerberos', creds, HTTP, ADDON), {
        winrm: { refused: false, mechanism: 'kerberos' },
        smb: { refused: false, mechanism: 'kerberos' },
      });
    }
    assert.deepEqual(planAuth('negotiate', CACHE, HTTP, ADDON), {
      winrm: { refused: false, mechanism: 'kerberos' },
      smb: { refused: false, mechanism: 'kerberos' },
    });
    // negotiate + password: Negotiate for winrm (Kerberos first, NTLM
    // fallback); smb still needs a realm for Negotiate.
    assert.deepEqual(planAuth('negotiate', PW, HTTP, ADDON), {
      winrm: { refused: false, mechanism: 'negotiate' },
      smb: { refused: false, mechanism: 'ntlm' },
    });
    // https plans are the same with or without the addon.
    for (const auth of ['kerberos', 'negotiate'] as const) {
      for (const creds of [PW, CACHE]) {
        assert.deepEqual(planAuth(auth, creds, HTTPS, ADDON).winrm, planAuth(auth, creds, HTTPS, NO_ADDON).winrm);
      }
    }
    // ntlm and basic never change.
    assert.deepEqual(planAuth('ntlm', PW, HTTP, ADDON), planAuth('ntlm', PW, HTTP, NO_ADDON));
    assert.deepEqual(planAuth('basic', PW, HTTP, ADDON), planAuth('basic', PW, HTTP, NO_ADDON));
  });

  it('encryption always over https counts as http', () => {
    assert.equal(winrmEncrypted({ tls: true, encryption: 'always' }), true);
    assert.equal(winrmEncrypted({ tls: true }), false);
    assert.equal(winrmEncrypted({ tls: true, encryption: 'auto' }), false);
    assert.equal(winrmEncrypted({}), true);
    assert.equal(winrmEncrypted(undefined), true);
    assert.equal(winrmEncrypted({ tls: false, encryption: 'never' }), false);
    const plan = planAuth('kerberos', PW, winrmEncrypted({ tls: true, encryption: 'always' }));
    assert.equal(plan.winrm.refused, true);
    const keyed = planAuth('kerberos', PW, winrmEncrypted({ tls: true, encryption: 'always' }), ADDON);
    assert.equal(keyed.winrm.refused, false);
  });

  it('ntlm uses ntlm for both', () => {
    for (const e of [HTTP, HTTPS]) {
      assert.deepEqual(planAuth('ntlm', PW, e), {
        winrm: { refused: false, mechanism: 'ntlm' },
        smb: { refused: false, mechanism: 'ntlm' },
      });
    }
  });

  it('basic refuses smb with a usage error', () => {
    const plan = planAuth('basic', PW, HTTPS);
    assert.deepEqual(plan.winrm, { refused: false, mechanism: 'basic' });
    assert.equal(plan.smb.refused, true);
    assert.equal(plan.smb.refused && plan.smb.reason, 'Basic authentication is HTTP-only; use ntlm or negotiate for files');
    assert.deepEqual(planAuth('basic', PW, HTTP).winrm, { refused: false, mechanism: 'basic' });
  });
});
