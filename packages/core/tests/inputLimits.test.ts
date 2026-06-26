import { describe, expect, it } from "vitest";
import { enforceInputSize, estimateInputBytes, megabytesToBytes } from "../src/inputLimits.js";

describe("input limits", () => {
  it("converts megabytes to bytes", () => {
    expect(megabytesToBytes(1)).toBe(1024 * 1024);
  });

  it("estimates string input size", () => {
    expect(estimateInputBytes("hello")).toBe(5);
  });

  it("refuses oversized input", () => {
    expect(() => enforceInputSize("hello", 0.000001)).toThrow(
      /Input refused:/
    );
  });

  it("accepts input under the limit", () => {
    expect(() => enforceInputSize("hello", 1)).not.toThrow();
  });
});
