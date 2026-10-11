import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { redact } from '../../dist/redact.js';

describe('redact', () => {
  it('redacts the password, its base64 and the Basic token', () => {
    const password = 'S3cret-Pa55';
    const b64 = Buffer.from(password).toString('base64');
    const basic = Buffer.from(`alice:${password}`).toString('base64');
    const text = `pw=${password} b64=${b64} header=Basic ${basic}`;
    const out = redact(text, { username: 'alice', password });
    assert.equal(out, 'pw=*** b64=*** header=Basic ***');
  });

  it('leaves text alone for an empty password', () => {
    assert.equal(redact('nothing to hide', { username: 'alice', password: '' }), 'nothing to hide');
    assert.equal(redact('nothing to hide', { username: 'alice' }), 'nothing to hide');
  });
});
