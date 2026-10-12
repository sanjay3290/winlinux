// Status-code mapping tests.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  SmbAbortError,
  SmbAccessDeniedError,
  SmbAlreadyExistsError,
  SmbAuthError,
  SmbDirectoryNotEmptyError,
  SmbError,
  SmbIsADirectoryError,
  SmbNotADirectoryError,
  SmbNotFoundError,
  SmbSharingViolationError,
  SmbTimeoutError,
  throwForStatus,
  throwIfAborted,
  toSmbError,
} from "../../src/errors.js";

describe("throwForStatus", () => {
  const cases: Array<[number, typeof SmbError, RegExp]> = [
    [0xc0000022, SmbAccessDeniedError, /access denied/],
    [0xc0000034, SmbNotFoundError, /no such file/],
    [0xc000003a, SmbNotFoundError, /no such file/],
    [0xc0000225, SmbNotFoundError, /no such file/],
    [0xc00000cc, SmbNotFoundError, /^share not found: op/],
    [0xc0000103, SmbNotADirectoryError, /^not a directory: op/],
    [0xc00000ba, SmbIsADirectoryError, /^is a directory: op/],
    [0xc0000101, SmbDirectoryNotEmptyError, /^directory not empty: op/],
    [0xc0000035, SmbAlreadyExistsError, /already exists/],
    [0xc0000043, SmbSharingViolationError, /sharing violation/],
    [0xc000006d, SmbAuthError, /authentication failed/],
    [0xc0000072, SmbAuthError, /authentication failed/],
    [0xc0000001, SmbError, /0xc0000001/],
  ];
  for (const [status, cls, pattern] of cases) {
    it(`0x${status.toString(16)} -> ${cls.name}`, () => {
      assert.throws(() => throwForStatus(status, "op"), (error: unknown) => {
        assert.ok(error instanceof cls);
        assert.match((error as Error).message, pattern);
        assert.equal((error as SmbError).status, status);
        return true;
      });
    });
  }
});

describe("toSmbError", () => {
  it("translates response rejections and passes the rest through", () => {
    const translated = toSmbError({ header: { status: 0xc0000022 }, body: {} }, "op");
    assert.ok(translated instanceof SmbAccessDeniedError);

    const typed = new SmbError("x");
    assert.equal(toSmbError(typed, "op"), typed);

    const timeout = toSmbError(new Error("request_timeout: Read(3)"), "op");
    assert.ok(timeout instanceof SmbTimeoutError);

    const other = new Error("ECONNREFUSED");
    assert.equal(toSmbError(other, "op"), other);
  });
});

describe("SmbAbortError", () => {
  it("is an SmbError named AbortError, with the signal's reason as cause", () => {
    const reason = new Error("deadline");
    const error = new SmbAbortError("list share/dir was aborted", reason);
    assert.ok(error instanceof SmbError);
    assert.equal(error.name, "AbortError");
    assert.equal(error.message, "list share/dir was aborted");
    assert.equal((error as { cause?: unknown }).cause, reason);
    assert.equal(error.status, undefined);
    assert.equal("cause" in new SmbAbortError("x"), false);
  });

  it("throwIfAborted throws only for an aborted signal", () => {
    throwIfAborted(undefined, "op");
    throwIfAborted(new AbortController().signal, "op");
    const controller = new AbortController();
    controller.abort("stop");
    assert.throws(() => throwIfAborted(controller.signal, "op"), (error: unknown) => {
      assert.ok(error instanceof SmbAbortError);
      assert.equal((error as Error).message, "op was aborted");
      assert.equal((error as { cause?: unknown }).cause, "stop");
      return true;
    });
  });

  it("toSmbError names the aborted call and keeps the cause", () => {
    const inner = new SmbAbortError("Read(7) was aborted", "stop");
    const outer = toSmbError(inner, "read share/f");
    assert.ok(outer instanceof SmbAbortError);
    assert.equal((outer as Error).message, "read share/f was aborted");
    assert.equal((outer as { cause?: unknown }).cause, "stop");
  });
});
