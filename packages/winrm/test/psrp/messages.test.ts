// PSRP message header (MS-PSRP 2.2.1): 40 bytes little-endian, GUIDs
// in .NET byte order, UTF-8 data; a server BOM is skipped.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { Destination, EMPTY_GUID, MessageType, decodeMessage, encodeMessage, guidFromBytes, guidToBytes, messageTypeName } from '../../src/winrm/psrp/messages.js';
import { PSRemotingError } from '../../src/winrm/errors.js';

const RPID = '00112233-4455-6677-8899-aabbccddeeff';

describe('GUID byte order (.NET, uuid.bytes_le)', () => {
  it('swaps the first three fields and keeps the rest', () => {
    assert.equal(guidToBytes(RPID).toString('hex'), '33221100554477668899aabbccddeeff');
    assert.equal(guidFromBytes(Buffer.from('33221100554477668899aabbccddeeff', 'hex')), RPID);
    assert.equal(guidFromBytes(guidToBytes('AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE')), 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee', 'lower-case canonical text');
    assert.ok(guidToBytes(EMPTY_GUID).equals(Buffer.alloc(16)));
  });

  it('refuses text that is not a GUID and byte strings of the wrong length', () => {
    assert.throws(() => guidToBytes('not-a-guid'), PSRemotingError);
    assert.throws(() => guidToBytes(''), PSRemotingError);
    assert.throws(() => guidFromBytes(Buffer.alloc(15)), PSRemotingError);
  });
});

describe('message header', () => {
  it('encodes SESSION_CAPABILITY to the server as the fixed byte vector', () => {
    const bytes = encodeMessage({ destination: Destination.server, messageType: MessageType.SESSION_CAPABILITY, rpid: RPID, pid: EMPTY_GUID, data: '<Obj/>' });
    assert.equal(
      bytes.toString('hex'),
      '02000000' + // Destination 2 (server), little-endian
        '02000100' + // MessageType 0x00010002, little-endian
        '33221100554477668899aabbccddeeff' + // RPID in .NET byte order
        '00000000000000000000000000000000' + // PID: the empty GUID for a pool message
        Buffer.from('<Obj/>').toString('hex'),
    );
    assert.equal(bytes.length, 40 + 6);
  });

  it('round-trips every message type of MS-PSRP 2.2.1', () => {
    for (const [name, type] of Object.entries(MessageType)) {
      const message = { destination: Destination.client, messageType: type, rpid: RPID, pid: 'ffffffff-0000-4000-8000-000000000001', data: `<S>${name}</S>` };
      assert.deepEqual(decodeMessage(encodeMessage(message)), message, name);
      assert.equal(messageTypeName(type), name);
    }
    assert.equal(messageTypeName(0x12345678), '0x12345678');
  });

  it('matches the wire values the specification assigns', () => {
    assert.equal(MessageType.SESSION_CAPABILITY, 0x00010002);
    assert.equal(MessageType.INIT_RUNSPACEPOOL, 0x00010004);
    assert.equal(MessageType.PUBLIC_KEY, 0x00010005);
    assert.equal(MessageType.ENCRYPTED_SESSION_KEY, 0x00010006);
    assert.equal(MessageType.PUBLIC_KEY_REQUEST, 0x00010007);
    assert.equal(MessageType.CONNECT_RUNSPACEPOOL, 0x00010008);
    assert.equal(MessageType.RUNSPACEPOOL_INIT_DATA, 0x0002100b);
    assert.equal(MessageType.RUNSPACEPOOL_STATE, 0x00021005);
    assert.equal(MessageType.CREATE_PIPELINE, 0x00021006);
    assert.equal(MessageType.APPLICATION_PRIVATE_DATA, 0x00021009);
    assert.equal(MessageType.RUNSPACEPOOL_HOST_CALL, 0x00021100);
    assert.equal(MessageType.RUNSPACEPOOL_HOST_RESPONSE, 0x00021101);
    assert.equal(MessageType.PIPELINE_INPUT, 0x00041002);
    assert.equal(MessageType.END_OF_PIPELINE_INPUT, 0x00041003);
    assert.equal(MessageType.PIPELINE_OUTPUT, 0x00041004);
    assert.equal(MessageType.ERROR_RECORD, 0x00041005);
    assert.equal(MessageType.PIPELINE_STATE, 0x00041006);
    assert.equal(MessageType.DEBUG_RECORD, 0x00041007);
    assert.equal(MessageType.VERBOSE_RECORD, 0x00041008);
    assert.equal(MessageType.WARNING_RECORD, 0x00041009);
    assert.equal(MessageType.PROGRESS_RECORD, 0x00041010);
    assert.equal(MessageType.INFORMATION_RECORD, 0x00041011);
    assert.equal(MessageType.PIPELINE_HOST_CALL, 0x00041100);
    assert.equal(MessageType.PIPELINE_HOST_RESPONSE, 0x00041101);
    assert.equal(Object.keys(MessageType).length, 31);
  });

  it('skips a UTF-8 byte order mark at the start of server data, and keeps one inside', () => {
    const header = encodeMessage({ destination: Destination.client, messageType: MessageType.PIPELINE_OUTPUT, rpid: RPID, pid: EMPTY_GUID, data: '' });
    const withBom = Buffer.concat([header, Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from('<S>x</S>')]);
    assert.equal(decodeMessage(withBom).data, '<S>x</S>');
    const inside = Buffer.concat([header, Buffer.from('<S>'), Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from('</S>')]);
    assert.equal(decodeMessage(inside).data, '<S>﻿</S>');
    assert.equal(decodeMessage(header).data, '', 'an empty message has no data');
  });

  it('refuses a short header and an unknown destination', () => {
    assert.throws(() => decodeMessage(Buffer.alloc(39)), PSRemotingError);
    const bad = encodeMessage({ destination: Destination.client, messageType: MessageType.PIPELINE_OUTPUT, rpid: RPID, pid: EMPTY_GUID, data: 'x' });
    bad.writeUInt32LE(3, 0);
    assert.throws(() => decodeMessage(bad), /destination 3/);
  });
});
