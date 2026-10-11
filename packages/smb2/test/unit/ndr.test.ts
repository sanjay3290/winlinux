// DCE/RPC + NDR tests: UUID encoding, bind/request PDU layout, bind_ack
// parsing, and SRVSVC NetShareEnum marshalling round trips.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { NdrReader, NdrWriter, trimTrailingNuls } from "../../src/rpc/ndr.js";
import {
  MAX_RESPONSE_STUB,
  PduType,
  ResponseReader,
  SRVSVC_UUID,
  buildBind,
  buildRequest,
  parseBindAck,
  parseHeader,
  parseResponsePdu,
  uuidToBytes,
} from "../../src/rpc/dcerpc.js";
import {
  SHI1005_FLAGS_ENCRYPT_DATA,
  buildEnumRequest,
  buildGetInfoRequest,
  parseEnumResponse,
  parseGetInfoResponse,
} from "../../src/rpc/srvsvc.js";

describe("uuidToBytes", () => {
  it("encodes the SRVSVC UUID in mixed-endian wire form", () => {
    assert.equal(uuidToBytes(SRVSVC_UUID).toString("hex"), "c84f324b7016d30112785a47bf6ee188");
  });
});

describe("bind PDU", () => {
  it("lays out a 72-byte single-context bind", () => {
    const bind = buildBind(7);
    assert.equal(bind.length, 72);
    assert.deepEqual([...bind.subarray(0, 4)], [5, 0, PduType.Bind, 0x03]);
    assert.equal(bind.readUInt16LE(8), 72); // frag length
    assert.equal(bind.readUInt32LE(12), 7); // call id
    assert.equal(bind.readUInt16LE(16), 4280); // max xmit frag
    assert.equal(bind.readUInt16LE(18), 4280); // max recv frag
    assert.equal(bind[24], 1); // one context item
    assert.equal(
      bind.subarray(32, 48).toString("hex"),
      uuidToBytes(SRVSVC_UUID).toString("hex"),
    );
    assert.equal(bind.readUInt16LE(48), 3); // SRVSVC version 3.0
    assert.equal(bind.readUInt16LE(50), 0);
  });

  it("parses a bind_ack and rejects failures", () => {
    const ack = Buffer.concat([
      Buffer.from([5, 0, PduType.BindAck, 0x03, 0x10, 0, 0, 0, 0x44, 0, 0, 0, 7, 0, 0, 0]),
      Buffer.from([0xb8, 0x10, 0xb8, 0x10, 0, 0, 0, 0]), // max frags, assoc
      Buffer.from([0, 0]), // empty secondary address
      Buffer.from([0, 0]), // pad to 4
      Buffer.from([1, 0, 0, 0]), // one result
      Buffer.from([0, 0, 0, 0]), // accept
      uuidToBytes("8a885d04-1ceb-11c9-9fe8-08002b104860"),
      Buffer.from([2, 0, 0, 0]),
    ]);
    parseBindAck(ack); // throws nothing
    const header = parseHeader(ack);
    assert.equal(header.callId, 7);
    ack.writeUInt16LE(2, ack.length - 24); // reject the context
    assert.throws(() => parseBindAck(ack), /rejected/);
  });
});

describe("request/response PDUs", () => {
  it("round-trips a request stub and parses a response fragment", () => {
    const stub = Buffer.from("0123456789abcdef", "hex");
    const request = buildRequest(9, 15, stub);
    assert.equal(request[2], PduType.Request);
    assert.equal(request.readUInt16LE(22), 15); // opnum
    assert.deepEqual(request.subarray(24), stub);

    const response = Buffer.concat([
      Buffer.from([5, 0, PduType.Response, 0x03, 0x10, 0, 0, 0, 32, 0, 0, 0, 9, 0, 0, 0]),
      Buffer.from([8, 0, 0, 0, 0, 0, 0, 0]), // alloc hint, context, cancel, reserved
      stub,
    ]);
    const parsed = parseResponsePdu(response);
    assert.deepEqual(parsed.stub, stub);
    assert.equal(parsed.lastFrag, true);
  });

  it("throws the fault status on a fault PDU", () => {
    const fault = Buffer.alloc(32);
    fault[0] = 5;
    fault[2] = PduType.Fault;
    fault[3] = 0x03;
    fault.writeUInt16LE(32, 8);
    fault.writeUInt32LE(0x1c000006, 24);
    assert.throws(() => parseResponsePdu(fault), /1c000006/);
  });
});

describe("NetShareEnum NDR", () => {
  it("marshals the level-1 request exactly", () => {
    const request = buildEnumRequest(0);
    assert.equal(request.length, 36);
    const reader = new NdrReader(request);
    assert.deepEqual(
      Array.from({ length: 9 }, () => reader.uint32()),
      [0, 1, 1, 1, 0, 0, 0xffffffff, 0x20000, 0],
    );
  });

  it("round-trips a two-share response", () => {
    const writer = new NdrWriter();
    writer.uint32(1); // InfoStruct.Level
    writer.uint32(1); // union switch
    writer.uint32(0x100); // Level1 container
    writer.uint32(2); // EntriesRead
    writer.uint32(0x104); // Buffer array
    writer.uint32(2); // conformant max_count
    writer.uint32(0x108); writer.uint32(0); writer.uint32(0x10c); // share 1
    writer.uint32(0x110); writer.uint32(3); writer.uint32(0); // share 2, NULL remark
    const cvString = (text: string) => {
      const chars = Buffer.from(text + "\0", "utf16le");
      writer.uint32(text.length + 1);
      writer.uint32(0);
      writer.uint32(text.length + 1);
      writer.bytes(chars);
      if (chars.length % 4 !== 0) writer.bytes(Buffer.alloc(4 - (chars.length % 4)));
    };
    cvString("Shared");
    cvString("disk comment");
    cvString("IPC$");
    writer.uint32(2); // TotalEntries
    writer.uint32(0x200); // ResumeHandle pointer
    writer.uint32(0); // resume value
    writer.uint32(0); // status

    const { shares, resume, status } = parseEnumResponse(writer.buffer());
    assert.equal(status, 0);
    assert.equal(resume, 0);
    assert.deepEqual(shares, [
      { name: "Shared", type: "disk", comment: "disk comment" },
      { name: "IPC$", type: "ipc", comment: "" },
    ]);
  });

  it("parses an empty enumeration", () => {
    const writer = new NdrWriter();
    // Level, tag, NULL Level1, TotalEntries, NULL ResumeHandle, status.
    for (const value of [1, 1, 0, 0, 0, 0]) writer.uint32(value);
    const { shares, status } = parseEnumResponse(writer.buffer());
    assert.equal(status, 0);
    assert.deepEqual(shares, []);
  });

  it("rejects a non-level-1 union tag", () => {
    const writer = new NdrWriter();
    for (const value of [1, 2, 0, 0, 0, 0]) writer.uint32(value);
    assert.throws(() => parseEnumResponse(writer.buffer()), /info level 2/);
  });
});

describe("NetShareGetInfo NDR", () => {
  it("marshals the level-1005 request: NULL server, inline NetName string, level", () => {
    const request = buildGetInfoRequest("abc");
    const reader = new NdrReader(request);
    assert.equal(reader.uint32(), 0); // ServerName NULL
    assert.equal(reader.uint32(), 4); // max_count (with NUL)
    assert.equal(reader.uint32(), 0); // offset
    assert.equal(reader.uint32(), 4); // actual_count
    assert.equal(reader.bytes(8).toString("utf16le"), "abc\0");
    assert.equal(reader.uint32(), 1005); // Level, 4-aligned (8 bytes of chars need no pad)
    assert.equal(request.length, 28);

    // An even-length name gets a NUL and a 2-byte pad.
    const padded = buildGetInfoRequest("wl-enc");
    assert.equal(padded.length, 4 + 12 + 14 + 2 + 4);
    assert.equal(padded.readUInt32LE(padded.length - 4), 1005);
  });

  it("parses the flags and the status", () => {
    const writer = new NdrWriter();
    writer.uint32(1005);
    writer.uint32(0x20000);
    writer.uint32(SHI1005_FLAGS_ENCRYPT_DATA | 0x30);
    writer.uint32(0);
    assert.deepEqual(parseGetInfoResponse(writer.buffer()), { flags: 0x8030, status: 0 });
    assert.equal(SHI1005_FLAGS_ENCRYPT_DATA, 0x8000);

    const failed = new NdrWriter();
    failed.uint32(1005);
    failed.uint32(0); // NULL arm
    failed.uint32(2310); // NERR_NetNameNotFound
    assert.deepEqual(parseGetInfoResponse(failed.buffer()), { flags: undefined, status: 2310 });

    const wrong = new NdrWriter();
    wrong.uint32(1);
    assert.throws(() => parseGetInfoResponse(wrong.buffer()), /info level 1/);
  });
});

// Server-supplied string lengths are capped and trailing NULs are
// stripped in linear time.
describe("NDR string bounds", () => {
  const cv = (units: Buffer, actual = units.length / 2) => {
    const head = Buffer.alloc(12);
    head.writeUInt32LE(actual, 0);
    head.writeUInt32LE(0, 4);
    head.writeUInt32LE(actual, 8);
    return Buffer.concat([head, units, Buffer.alloc((4 - (units.length % 4)) % 4)]);
  };

  it("a 64 Ki-character run of NULs that is not trailing parses in well under 100 ms", () => {
    const units = Buffer.concat([Buffer.alloc(65535 * 2), Buffer.from("x", "utf16le")]);
    const started = performance.now();
    const text = new NdrReader(cv(units)).cvString();
    const elapsed = performance.now() - started;
    assert.equal(text.length, 65536);
    assert.ok(elapsed < 100, `${elapsed.toFixed(1)} ms`);
  });

  it("drops a long trailing NUL run and keeps the text", () => {
    const units = Buffer.concat([Buffer.from("share", "utf16le"), Buffer.alloc(65000 * 2)]);
    assert.equal(new NdrReader(cv(units)).cvString(), "share");
  });

  it("refuses an actual_count over 64 Ki characters, even with the bytes present", () => {
    const units = Buffer.alloc(65537 * 2, 0x41);
    assert.throws(() => new NdrReader(cv(units)).cvString(), /SRVSVC string of 65537 characters is over the 65536 limit/);
  });

  it("refuses a 1 M-character string at once", () => {
    const units = Buffer.alloc(1024 * 1024 * 2);
    const started = performance.now();
    assert.throws(() => new NdrReader(cv(units)).cvString(), /over the 65536 limit/);
    assert.ok(performance.now() - started < 100);
  });
});

describe("ResponseReader", () => {
  const pdu = (stub: Buffer, flags = 0x03, fragLength = 24 + stub.length, authLength = 0, ptype = PduType.Response) => {
    const out = Buffer.alloc(24 + stub.length);
    out[0] = 5;
    out[2] = ptype;
    out[3] = flags;
    out.writeUInt16LE(fragLength, 8);
    out.writeUInt16LE(authLength, 10);
    stub.copy(out, 24);
    return out;
  };

  it("joins fragments that arrive split across reads", () => {
    const reader = new ResponseReader();
    const wire = Buffer.concat([pdu(Buffer.from("ab"), 0x01), pdu(Buffer.from("cd"), 0x02)]);
    assert.equal(reader.push(wire.subarray(0, 10)), undefined);
    assert.equal(reader.push(wire.subarray(10, 40)), undefined);
    assert.equal(reader.push(wire.subarray(40))?.toString(), "abcd");
  });

  it("reports a fault", () => {
    const fault = pdu(Buffer.from([6, 0, 0, 0x1c, 0, 0, 0, 0]), 0x03, 32, 0, PduType.Fault);
    assert.throws(() => new ResponseReader().push(fault), /DCE\/RPC fault 0x1c000006/);
  });

  for (const fragLength of [0, 10, 20]) {
    it(`refuses a fragment length of ${fragLength}`, () => {
      assert.throws(() => new ResponseReader().push(pdu(Buffer.alloc(8), 0x01, fragLength)), /DCE\/RPC fragment length/);
    });
  }

  it("refuses an auth trailer longer than the fragment", () => {
    assert.throws(() => new ResponseReader().push(pdu(Buffer.alloc(8), 0x03, 32, 9)), /auth trailer/);
  });

  it("refuses a stub over the 16 MiB cap", () => {
    const reader = new ResponseReader();
    const chunk = pdu(Buffer.alloc(65535 - 24), 0x00);
    assert.throws(() => {
      for (let i = 0; i * (65535 - 24) <= MAX_RESPONSE_STUB; i++) reader.push(chunk);
    }, /over the 16777216-byte limit/);
  });

  it("trimTrailingNuls takes linear time on a 1 M-character string", () => {
    const started = performance.now();
    assert.equal(trimTrailingNuls("\0".repeat(1024 * 1024)), "");
    assert.equal(trimTrailingNuls("x" + "\0".repeat(1024 * 1024)), "x");
    assert.equal(trimTrailingNuls("\0".repeat(1024 * 1024) + "x"), "\0".repeat(1024 * 1024) + "x");
    assert.ok(performance.now() - started < 100);
  });
});
