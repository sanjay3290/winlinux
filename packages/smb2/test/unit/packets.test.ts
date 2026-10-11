// Golden packet tests: every phase-1 request type serializes to the exact
// checked-in bytes, and the critical MS-SMB2 fields sit at the right offsets.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import Packet from "../../src/protocol/smb2/Packet.js";
import * as goldens from "../fixtures/golden-packets.js";

const base = {
  messageId: 7n,
  clientId: "a1b2c3d4",
  sessionId: "0102030405060708",
  treeId: 9,
  credit: 126,
};
const fileId = "1112131415161718191a1b1c1d1e1f20";

const headerCases: Array<[string, number, number, number]> = [
  // [golden, command, creditCharge, total length]
  ["negotiate", 0x0000, 0, 104],
  ["sessionSetup", 0x0001, 0, 97],
  ["treeConnect", 0x0003, 0, 106],
  ["create", 0x0005, 0, 146],
  ["read", 0x0008, 1, 113],
  ["readMultiCredit", 0x0008, 4, 113],
  ["write", 0x0009, 1, 115],
  ["close", 0x0006, 0, 88],
  ["queryInfo", 0x0010, 0, 104],
];

describe("golden packet headers", () => {
  for (const [name, command, creditCharge, length] of headerCases) {
    it(`${name}: header fields at the right offsets`, () => {
      const packet = Buffer.from(goldens[name as keyof typeof goldens], "hex");
      assert.equal(packet.length, length);
      assert.equal(packet.subarray(0, 4).toString("hex"), "fe534d42"); // SMB2
      assert.equal(packet.readUInt16LE(4), 64);
      assert.equal(packet.readUInt16LE(6), creditCharge);
      assert.equal(packet.readUInt16LE(12), command);
      assert.equal(packet.readBigUInt64LE(24), 7n);
      assert.equal(packet.readUInt32LE(36), 9); // treeId
      assert.equal(packet.subarray(48, 64).toString("hex"), "0".repeat(32)); // unsigned
    });
  }
});

describe("packet builders match goldens", () => {
  it("NEGOTIATE", () => {
    const packet = Packet.serializeMessage({ ...base, type: 0x0000 }, {
      dialects: [0x0202, 0x0210],
      clientGuid: Buffer.from("202122232425262728292a2b2c2d2e2f", "hex"),
    });
    assert.equal(packet.readUInt16LE(64), 36); // structure size
    assert.equal(packet.readUInt16LE(66), 2); // dialect count
    assert.equal(packet.readUInt16LE(100), 0x0202);
    assert.equal(packet.readUInt16LE(102), 0x0210);
    assert.equal(packet.toString("hex"), goldens.negotiate);
  });

  it("SESSION_SETUP", () => {
    const packet = Packet.serializeMessage({ ...base, type: 0x0001 }, {
      buffer: Buffer.from("46414b45544f4b454e", "hex"),
    });
    assert.equal(packet.readUInt16LE(64), 25);
    assert.equal(packet.readUInt16LE(76), 88); // security buffer offset
    assert.equal(packet.readUInt16LE(78), 9); // security buffer length
    assert.equal(packet.subarray(88).toString("ascii"), "FAKETOKEN");
    assert.equal(packet.toString("hex"), goldens.sessionSetup);
  });

  it("TREE_CONNECT", () => {
    const packet = Packet.serializeMessage({ ...base, type: 0x0003 }, {
      buffer: Buffer.from("\\\\127.0.0.1\\share", "ucs2"),
    });
    assert.equal(packet.readUInt16LE(64), 9);
    assert.equal(packet.readUInt16LE(68), 72); // path offset
    assert.equal(packet.readUInt16LE(70), 34); // path length
    assert.equal(packet.subarray(72).toString("ucs2"), "\\\\127.0.0.1\\share");
    assert.equal(packet.toString("hex"), goldens.treeConnect);
  });

  it("CREATE", () => {
    const name = Buffer.from("dir\\file.txt", "ucs2");
    const packet = Packet.serializeMessage({ ...base, type: 0x0005 }, {
      buffer: name,
      desiredAccess: 0x00000001,
      fileAttributes: 0x80,
      shareAccess: 0x7,
      createDisposition: 1,
      createOptions: 0,
      nameOffset: 0x0078,
      createContextsOffset: 0x007a + name.length,
    });
    assert.equal(packet.readUInt16LE(64), 57);
    assert.equal(packet.readUInt16LE(108), 0x78); // name offset
    assert.equal(packet.readUInt16LE(110), name.length);
    assert.equal(packet.subarray(120, 120 + name.length).toString("ucs2"), "dir\\file.txt");
    assert.equal(packet.toString("hex"), goldens.create);
  });

  it("READ", () => {
    const packet = Packet.serializeMessage({ ...base, type: 0x0008, creditCharge: 1 }, {
      fileId,
      length: 65536,
      offset: 0,
    });
    assert.equal(packet.readUInt16LE(64), 49);
    assert.equal(packet.readUInt32LE(68), 65536);
    assert.equal(packet.toString("hex"), goldens.read);
  });

  it("READ multi-credit", () => {
    const packet = Packet.serializeMessage({ ...base, type: 0x0008, creditCharge: 4 }, {
      fileId,
      length: 200000,
      offset: 65536,
    });
    assert.equal(packet.readUInt32LE(68), 200000);
    assert.equal(packet.readBigUInt64LE(72), 65536n);
    assert.equal(packet.toString("hex"), goldens.readMultiCredit);
  });

  it("WRITE", () => {
    const packet = Packet.serializeMessage({ ...base, type: 0x0009, creditCharge: 1 }, {
      fileId,
      buffer: Buffer.from("abc"),
      offset: 0,
    });
    assert.equal(packet.readUInt16LE(64), 49);
    assert.equal(packet.readUInt16LE(66), 112); // data offset
    assert.equal(packet.readUInt32LE(68), 3); // length from the buffer
    assert.equal(packet.subarray(112).toString("ascii"), "abc");
    assert.equal(packet.toString("hex"), goldens.write);
  });

  it("CLOSE", () => {
    const packet = Packet.serializeMessage({ ...base, type: 0x0006 }, { fileId });
    assert.equal(packet.readUInt16LE(64), 24);
    assert.equal(packet.subarray(72, 88).toString("hex"), fileId);
    assert.equal(packet.toString("hex"), goldens.close);
  });

  it("QUERY_INFO", () => {
    const packet = Packet.serializeMessage({ ...base, type: 0x0010 }, {
      infoType: 1,
      fileInfoClass: 4,
      fileId,
      buffer: Buffer.alloc(0),
    });
    assert.equal(packet.readUInt16LE(64), 41); // MS-SMB2 2.2.37
    assert.equal(packet[66], 1); // infoType File
    assert.equal(packet[67], 4); // FileBasicInformation
    assert.equal(packet.toString("hex"), goldens.queryInfo);
  });

  it("NetBIOS framing wraps the bare message", () => {
    const framed = Packet.serialize({ ...base, type: 0x0006 }, { fileId });
    assert.equal(framed[0], 0x00);
    assert.equal(framed.readUInt32BE(0) & 0xffffff, 88);
    assert.equal(framed.subarray(4).toString("hex"), goldens.close);
  });
});
