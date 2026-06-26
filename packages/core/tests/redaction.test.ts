import { describe, expect, it } from "vitest";
import { redactString, redactValue } from "../src/redaction.js";

describe("redaction", () => {
  it("redacts URL credentials", () => {
    expect(redactString("https://user:pass@example.com/path")).toBe(
      "https://[REDACTED]@example.com/path"
    );
  });

  it("redacts bearer tokens", () => {
    expect(redactString("Authorization: Bearer abcdefghijklmnop")).toBe(
      "Authorization: Bearer [REDACTED]"
    );
  });

  it("redacts JWT-looking values", () => {
    const jwt =
      "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signaturehere";

    expect(redactString(jwt)).toBe("[REDACTED]");
  });

  it("redacts nested values", () => {
    expect(
      redactValue({
        url: "https://user:pass@example.com/path",
        nested: ["Bearer abcdefghijklmnop"],
      })
    ).toEqual({
      url: "https://[REDACTED]@example.com/path",
      nested: ["Bearer [REDACTED]"],
    });
  });

  it("handles circular references without throwing", () => {
    const value: Record<string, unknown> = { name: "example" };
    value.self = value;

    expect(redactValue(value)).toEqual({
      name: "example",
      self: "[CIRCULAR]",
    });
  });

  it("caps redaction recursion depth", () => {
    let value: Record<string, unknown> = { leaf: "done" };

    for (let index = 0; index < 40; index += 1) {
      value = { nested: value };
    }

    expect(JSON.stringify(redactValue(value))).toContain("[REDACTION_DEPTH_LIMIT]");
  });
});
