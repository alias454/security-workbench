import { describe, expect, it } from "vitest";
import {
  getJsonType,
  isJsonArray,
  isJsonObject,
  safeJsonObjectParse,
  safeJsonParse,
} from "../src/index.js";

function expectError(result: ReturnType<typeof safeJsonParse>) {
  expect(result.ok).toBe(false);
  if (!result.ok) {
    return result.error;
  }
  throw new Error("expected parse error");
}

describe("safe JSON helpers", () => {
  it("describes JSON-compatible value types", () => {
    expect(getJsonType(null)).toBe("null");
    expect(getJsonType([])).toBe("array");
    expect(getJsonType({})).toBe("object");
    expect(getJsonType("x")).toBe("string");
    expect(getJsonType(1)).toBe("number");
    expect(getJsonType(true)).toBe("boolean");
    expect(getJsonType(undefined)).toBe("undefined");
  });

  it("provides object and array runtime guards", () => {
    expect(isJsonObject({ a: 1 })).toBe(true);
    expect(isJsonObject(null)).toBe(false);
    expect(isJsonObject([])).toBe(false);
    expect(isJsonArray([1, 2])).toBe(true);
    expect(isJsonArray({ 0: "x" })).toBe(false);
  });

  it("safeJsonParse parses valid JSON values", () => {
    expect(safeJsonParse('{"name":"example","enabled":true}')).toEqual({
      ok: true,
      value: { name: "example", enabled: true },
    });
    expect(safeJsonParse("[1,2,3]")).toEqual({ ok: true, value: [1, 2, 3] });
    expect(safeJsonParse("null")).toEqual({ ok: true, value: null });
  });

  it("safeJsonParse rejects malformed JSON with a stable structured error", () => {
    const error = expectError(safeJsonParse("{bad json}"));
    expect(error).toMatchObject({
      code: "INVALID_JSON",
      message: "Input must be valid JSON.",
      recoverable: false,
    });
  });

  it("safeJsonParse rejects non-string input with a stable structured error", () => {
    const error = expectError(safeJsonParse({ not: "a string" }));
    expect(error).toMatchObject({
      code: "INVALID_TYPE",
      message: "JSON input must be a string.",
      recoverable: false,
      details: {
        expected: "string",
        received: "object",
      },
    });
  });

  it("safeJsonObjectParse accepts JSON objects", () => {
    expect(safeJsonObjectParse('{"name":"example"}')).toEqual({
      ok: true,
      value: { name: "example" },
    });
  });

  it("safeJsonObjectParse rejects arrays", () => {
    const result = safeJsonObjectParse("[]");
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toMatchObject({
        code: "INVALID_TYPE",
        message: "Expected a JSON object.",
        recoverable: false,
        details: {
          expected: "object",
          received: "array",
        },
      });
    }
  });

  it("safeJsonObjectParse rejects null", () => {
    const result = safeJsonObjectParse("null");
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.details).toEqual({ expected: "object", received: "null" });
    }
  });

  it("safeJsonObjectParse rejects primitive JSON values", () => {
    for (const [input, received] of [
      ['"hello"', "string"],
      ["123", "number"],
      ["false", "boolean"],
    ] as const) {
      const result = safeJsonObjectParse(input);
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.error.details).toEqual({ expected: "object", received });
      }
    }
  });
});
