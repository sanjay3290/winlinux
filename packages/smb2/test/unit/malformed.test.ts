// Malformed server data: the list and entry parsers check every
// server-supplied offset and length and throw SmbError, never a RangeError
// from a Buffer read, and never loop or allocate past the buffer.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import QueryDirectory from "../../src/protocol/smb2/packets/QueryDirectory.js";
import ChangeNotify from "../../src/protocol/smb2/packets/ChangeNotify.js";
import * as structureUtil from "../../src/protocol/structureUtil.js";
import type Structure from "../../src/protocol/Structure.js";
import { SmbError } from "../../src/errors.js";

const malformed = (error: unknown) => {
  assert.ok(error instanceof SmbError, `expected SmbError, got ${String(error)}`);
  assert.match(error.message, /malformed/);
  return true;
};

// FileIdBothDirectoryInformation entries, NextEntryOffset-chained (raw
// writes, no SUT code). The fixed part is 104 bytes; the name follows.
function dirEntry(name: string, next: number): Buffer {
  const nameBytes = Buffer.from(name, "ucs2");
  const out = Buffer.alloc(Math.max(next, 104 + nameBytes.length));
  out.writeUInt32LE(next, 0);
  out.writeUInt32LE(0x80, 56); // FILE_ATTRIBUTE_NORMAL
  out.writeUInt32LE(nameBytes.length, 60);
  nameBytes.copy(out, 104);
  return out;
}

// FILE_NOTIFY_INFORMATION entries: NextEntryOffset, Action, FileNameLength, name.
function changeEntry(name: string, next: number, action = 1): Buffer {
  const nameBytes = Buffer.from(name, "ucs2");
  const out = Buffer.alloc(Math.max(next, 12 + nameBytes.length));
  out.writeUInt32LE(next, 0);
  out.writeUInt32LE(action, 4);
  out.writeUInt32LE(nameBytes.length, 8);
  nameBytes.copy(out, 12);
  return out;
}

describe("malformed list buffers", () => {
  it("still parses well-formed directory and change lists", () => {
    const first = dirEntry("a.txt", 120);
    const dir = QueryDirectory.parseResponseBuffer(Buffer.concat([first, dirEntry("b", 0)]));
    assert.deepEqual(dir.map((entry) => entry.filename), ["./a.txt", "./b"]);
    const changes = ChangeNotify.parseResponseBuffer(Buffer.concat([changeEntry("x", 16), changeEntry("yz", 0, 3)]));
    assert.deepEqual(changes.map((entry) => [entry.filename, entry.action]), [["./x", 1], ["./yz", 3]]);
  });

  it("refuses a buffer too short for NextEntryOffset", () => {
    assert.throws(() => structureUtil.parseList(Buffer.from([1, 0]), (entry) => entry), malformed);
  });

  it("refuses a NextEntryOffset past the end of the buffer", () => {
    const buffer = dirEntry("a", 0);
    buffer.writeUInt32LE(0x00100000, 0);
    assert.throws(() => QueryDirectory.parseResponseBuffer(buffer), malformed);
  });

  it("refuses a NextEntryOffset that leaves no room for the next entry's header", () => {
    const buffer = Buffer.concat([dirEntry("a", 120), Buffer.alloc(2)]);
    buffer.writeUInt32LE(120, 0);
    assert.throws(() => QueryDirectory.parseResponseBuffer(buffer), malformed);
  });

  for (const next of [1, 2, 3]) {
    it(`refuses a NextEntryOffset of ${next}, inside the entry's own header`, () => {
      const buffer = Buffer.concat([changeEntry("x", 16), changeEntry("y", 0)]);
      buffer.writeUInt32LE(next, 0);
      assert.throws(() => ChangeNotify.parseResponseBuffer(buffer), malformed);
    });
  }

  it("refuses more than 65536 entries in one list", () => {
    const count = 65537;
    const buffer = Buffer.alloc(count * 12);
    for (let index = 0; index < count; index++) buffer.writeUInt32LE(index === count - 1 ? 0 : 12, index * 12);
    assert.throws(() => ChangeNotify.parseResponseBuffer(buffer), malformed);
  });
});

describe("malformed directory entries", () => {
  it("refuses an entry shorter than the fixed FileIdBothDirectoryInformation part", () => {
    const buffer = Buffer.alloc(40); // NextEntryOffset 0, 36 bytes of entry
    assert.throws(() => QueryDirectory.parseResponseBuffer(buffer), malformed);
  });

  it("refuses a FileNameLength that runs past the entry", () => {
    const buffer = dirEntry("a.txt", 0);
    buffer.writeUInt32LE(0x10000, 60);
    assert.throws(() => QueryDirectory.parseResponseBuffer(buffer), malformed);
  });

  it("refuses a FileNameLength that runs into the next entry", () => {
    const buffer = Buffer.concat([dirEntry("a.txt", 120), dirEntry("b", 0)]);
    buffer.writeUInt32LE(40, 60); // 104 + 40 > 120
    assert.throws(() => QueryDirectory.parseResponseBuffer(buffer), malformed);
  });

  it("refuses a ShortNameLength larger than the 24-byte ShortName field", () => {
    const buffer = dirEntry("a.txt", 0);
    buffer[68] = 25;
    assert.throws(() => QueryDirectory.parseResponseBuffer(buffer), malformed);
  });
});

describe("malformed change entries", () => {
  it("refuses an entry shorter than Action and FileNameLength", () => {
    const buffer = Buffer.alloc(8); // NextEntryOffset 0, 4 bytes of entry
    assert.throws(() => ChangeNotify.parseResponseBuffer(buffer), malformed);
  });

  it("refuses a FileNameLength that runs past the entry", () => {
    const buffer = changeEntry("x", 0);
    buffer.writeUInt32LE(0xffffffff, 8);
    assert.throws(() => ChangeNotify.parseResponseBuffer(buffer), malformed);
  });
});

describe("parseStructure bounds", () => {
  it("reads no more array elements than the buffer holds", () => {
    const structure: Structure = {
      count: { type: Number, size: 4 },
      items: { type: Number, size: 2, countFieldName: "count" },
    };
    const buffer = Buffer.alloc(8);
    buffer.writeUInt32LE(100_000, 0);
    buffer.writeUInt16LE(7, 4);
    buffer.writeUInt16LE(9, 6);
    const data = structureUtil.parseStructure(buffer, structure);
    assert.equal((data.items as number[]).length, 2);
    assert.deepEqual(data.items, [7, 9]);
  });

  it("refuses a size or count field that is not a non-negative integer", () => {
    const structure: Structure = {
      length: { type: Number, size: 8 },
      data: { type: Buffer, sizeFieldName: "length" },
    };
    const buffer = Buffer.alloc(16);
    buffer.writeBigUInt64LE(1n << 40n, 0);
    assert.throws(() => structureUtil.parseStructure(buffer, structure), malformed);
  });

  it("keeps clamping a variable-length field to the bytes present (SMB2 ERROR bodies)", () => {
    // An error response carries a 9-byte ERROR body, parsed with the
    // command's own structure; the parser must not refuse it.
    const structure: Structure = {
      structureSize: { type: Number, size: 2 },
      length: { type: Number, size: 4 },
      buffer: { type: Buffer, sizeFieldName: "length" },
    };
    const buffer = Buffer.alloc(9);
    buffer.writeUInt16LE(9, 0);
    buffer.writeUInt32LE(100, 2);
    const data = structureUtil.parseStructure(buffer, structure);
    assert.equal((data.buffer as Buffer).length, 3);
  });
});
