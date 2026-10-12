// Recorded PSRP fixtures must be redacted: no IP address, SID, user
// profile path, or the recorder's own names (from the env of this run).
// Also the redaction itself, on a sample.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { denyList, redactText, SENTINELS } from '../live/redact.js';

const FIXTURES = new URL('../fixtures/psrp/', import.meta.url);

function walk(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    const file = join(dir, name);
    if (statSync(file).isDirectory()) out.push(...walk(file));
    else if (!name.endsWith('.md')) out.push(file);
  }
  return out;
}

describe('recorded PSRP fixtures', () => {
  it('match no deny-list entry', () => {
    const deny = denyList(process.env);
    for (const file of walk(FIXTURES.pathname)) {
      const text = readFileSync(file, 'utf8');
      for (const entry of deny) assert.ok(!entry.test(text), `${file} contains ${entry.name}`);
    }
  });

  it('the deny list catches a raw sample and passes its redaction', () => {
    const raw = [
      '<S N="PSComputerName">winsrv-lab.corp.internal.test</S>',
      '<S N="User">CORP\\jdoe</S>',
      '<S N="Sid">S-1-5-21-123456789-234567890-345678901-1001</S>',
      '<S N="Path">C:\\Users\\jdoe\\Documents</S>',
      '<S N="Addr">10.1.2.3 and fe80::1ff:fe23:4567:890a and 127.0.0.1</S>',
    ].join('\n');
    const env = { WINRM_HOST: 'winsrv-lab.corp.internal.test', WINRM_DOMAIN: 'CORP', WINRM_USER: 'jdoe' };
    const deny = denyList(env);
    assert.ok(deny.some((d) => d.test(raw)), 'the raw sample is caught');
    const redacted = redactText(raw, { host: env.WINRM_HOST, domain: env.WINRM_DOMAIN, user: env.WINRM_USER });
    for (const entry of deny) assert.ok(!entry.test(redacted), `redacted text still contains ${entry.name}`);
    assert.ok(redacted.includes(`<S N="PSComputerName">${SENTINELS.host}</S>`));
    assert.ok(redacted.includes(`${SENTINELS.domain}\\${SENTINELS.user}`));
    assert.ok(redacted.includes(SENTINELS.sid));
    assert.ok(redacted.includes(`C:\\Users\\${SENTINELS.user}\\Documents`));
    assert.ok(redacted.includes(`${SENTINELS.ipv4} and ${SENTINELS.ipv6} and 127.0.0.1`), redacted);
    assert.equal(denyList({}).length, 4, 'no env names, only the patterns');
  });
});
