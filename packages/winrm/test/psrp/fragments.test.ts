// PSRP fragments (MS-PSRP 2.2.4): the 21-byte header in network byte
// order, the 32768-byte blob cap, start and end flags, and the
// defragmenter's order and memory rules.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { Destination, EMPTY_GUID, MessageType, encodeMessage } from '../../src/winrm/psrp/messages.js';
import { Defragmenter, FRAGMENT_HEADER_BYTES, MAX_FRAGMENT_BLOB_BYTES, decodeFragments, encodeFragment, encodeFragments } from '../../src/winrm/psrp/fragments.js';
import { PSRemotingError } from '../../src/winrm/errors.js';

const RPID = '00112233-4455-6677-8899-aabbccddeeff';
const message = (data: string, type: number = MessageType.PIPELINE_OUTPUT) =>
  encodeMessage({ destination: Destination.client, messageType: type, rpid: RPID, pid: EMPTY_GUID, data });

describe('fragment encoding', () => {
  it('a one-fragment SESSION_CAPABILITY: ObjectId 1, FragmentId 0, S and E set, the message as the blob (reference vector)', () => {
    const body = message('<Obj/>', MessageType.SESSION_CAPABILITY);
    const [fragment, ...rest] = encodeFragments(1, body);
    assert.equal(rest.length, 0);
    assert.equal(
      fragment!.toString('hex'),
      '0000000000000001' + // ObjectId 1, big-endian
        '0000000000000000' + // FragmentId 0
        '03' + // flags: start | end
        '0000002e' + // BlobLength 46 (40-byte header + 6 bytes of data)
        body.toString('hex'),
    );
    assert.equal(fragment!.length, FRAGMENT_HEADER_BYTES + 46);
  });

  it('the specification example: a message in three fragments has S on the first and E on the last only', () => {
    // MS-PSRP 4.2 shows ObjectId 5 split into fragments 0, 1, 2.
    const body = Buffer.alloc(2 * MAX_FRAGMENT_BLOB_BYTES + 1, 0xab);
    const fragments = encodeFragments(5n, body);
    assert.equal(fragments.length, 3);
    const decoded = decodeFragments(Buffer.concat(fragments));
    assert.deepEqual(
      decoded.map((f) => [f.objectId, f.fragmentId, f.start, f.end, f.blob.length]),
      [
        [5n, 0n, true, false, MAX_FRAGMENT_BLOB_BYTES],
        [5n, 1n, false, false, MAX_FRAGMENT_BLOB_BYTES],
        [5n, 2n, false, true, 1],
      ],
    );
    assert.ok(Buffer.concat(decoded.map((f) => f.blob)).equals(body));
  });

  it('a message of exactly the cap is one fragment; one byte more is two; an empty message is one empty fragment', () => {
    assert.equal(encodeFragments(1, Buffer.alloc(MAX_FRAGMENT_BLOB_BYTES)).length, 1);
    assert.equal(encodeFragments(1, Buffer.alloc(MAX_FRAGMENT_BLOB_BYTES + 1)).length, 2);
    const [empty] = encodeFragments(7, Buffer.alloc(0));
    assert.deepEqual(decodeFragments(empty!)[0], { objectId: 7n, fragmentId: 0n, start: true, end: true, blob: Buffer.alloc(0) });
  });

  it('refuses ObjectId 0, a bad maxBlob, and ids out of the u64 range', () => {
    assert.throws(() => encodeFragments(0, Buffer.alloc(1)), PSRemotingError);
    assert.throws(() => encodeFragments(1, Buffer.alloc(1), 0), RangeError);
    assert.throws(() => encodeFragment({ objectId: 1n << 64n, fragmentId: 0n, start: true, end: true, blob: Buffer.alloc(0) }), PSRemotingError);
  });

  it('decodeFragments refuses a truncated header and a blob shorter than its BlobLength', () => {
    const [fragment] = encodeFragments(1, Buffer.alloc(10));
    assert.throws(() => decodeFragments(fragment!.subarray(0, 20)), /shorter than a fragment header/);
    assert.throws(() => decodeFragments(fragment!.subarray(0, fragment!.length - 1)), /announces 10 bytes, 9 follow/);
  });
});

describe('Defragmenter', () => {
  it('reassembles a message across three fragments pushed one at a time', () => {
    const body = message('x'.repeat(2 * MAX_FRAGMENT_BLOB_BYTES + 5));
    const fragments = encodeFragments(9, body);
    const d = new Defragmenter();
    assert.deepEqual(d.push(fragments[0]!), []);
    assert.equal(d.partialCount, 1);
    assert.deepEqual(d.push(fragments[1]!), []);
    const [done] = d.push(fragments[2]!);
    assert.equal(done?.data.length, 2 * MAX_FRAGMENT_BLOB_BYTES + 5);
    assert.equal(done?.messageType, MessageType.PIPELINE_OUTPUT);
    assert.equal(d.partialCount, 0);
  });

  it('decodes two interleaved messages in one stream, in completion order', () => {
    const a = encodeFragments(1, message('aaaa'), 2); // several fragments
    const b = encodeFragments(2, message('bb'), 2);
    const stream = Buffer.concat([a[0]!, b[0]!, a[1]!, ...b.slice(1), ...a.slice(2)]);
    const done = new Defragmenter().push(stream);
    assert.deepEqual(
      done.map((m) => m.data),
      ['bb', 'aaaa'],
    );
  });

  it('refuses an out-of-order FragmentId, a restart, and a fragment before its start (3.1.5.1.2 rule 4)', () => {
    const fragments = encodeFragments(3, message('x'.repeat(100)), 40);
    assert.equal(fragments.length, 4);
    const d = new Defragmenter();
    d.push(fragments[0]!);
    assert.throws(() => d.push(fragments[2]!), /fragment 2 of object 3 out of order; expected 1/);
    assert.equal(d.partialCount, 0, 'the broken object is dropped');
    assert.throws(() => new Defragmenter().push(fragments[1]!), /arrived before its start/);
    const again = new Defragmenter();
    again.push(fragments[0]!);
    assert.throws(() => again.push(fragments[0]!), /started again/);
    const first = Buffer.from(fragments[0]!);
    first.writeBigUInt64BE(4n, 8); // a start with FragmentId 4
    assert.throws(() => new Defragmenter().push(first), /starts at fragment 4, not 0/);
  });

  it('caps the messages in progress at 16: the 17th start throws before it is stored', () => {
    const d = new Defragmenter();
    for (let id = 1; id <= 16; id++) d.push(encodeFragments(id, message('x'.repeat(50)), 40)[0]!);
    assert.equal(d.partialCount, 16);
    assert.throws(() => d.push(encodeFragments(17, message('x'.repeat(50)), 40)[0]!), /more than 16 messages in progress/);
    assert.equal(d.partialCount, 16);
  });

  it('caps a message at the byte limit before its buffer grows', () => {
    const d = new Defragmenter(16, 100);
    const fragments = encodeFragments(1, Buffer.alloc(150), 60);
    d.push(fragments[0]!);
    assert.throws(() => d.push(fragments[1]!), /exceeds 100 bytes/);
    assert.equal(d.partialCount, 0);
    // The default limit is 64 MiB.
    const big = new Defragmenter();
    const header = encodeFragments(1, Buffer.alloc(0))[0]!.subarray(0, FRAGMENT_HEADER_BYTES);
    const fake = Buffer.from(header);
    fake[16] = 0x01; // start only
    fake.writeUInt32BE(0x7fffffff, 17); // a blob the stream does not carry
    assert.throws(() => big.push(fake), PSRemotingError, 'a blob length past the buffer is refused by decodeFragments');
  });

  it('a decoded message that is shorter than a header is refused', () => {
    const [fragment] = encodeFragments(1, Buffer.alloc(10));
    assert.throws(() => new Defragmenter().push(fragment!), /shorter than its 40-byte header/);
  });
});
