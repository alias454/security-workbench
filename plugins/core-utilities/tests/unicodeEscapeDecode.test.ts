import { describe, expect, it } from "vitest";
import { unicodeEscapeDecodeSkill } from "../src/unicodeEscapeDecode.js";

describe("unicode_escape_decode", () => {
  it("decodes Unicode, code point, hex, and common character escapes", async () => {
    const result = await unicodeEscapeDecodeSkill.run(String.raw`hello\n\u0041\u{1F600}\x21`);

    expect(result).toEqual({
      decoded: "hello\nA😀!",
    });
  });

  it("preserves unknown backslash escapes", async () => {
    const result = await unicodeEscapeDecodeSkill.run(String.raw`path\qname`);

    expect(result).toEqual({
      decoded: String.raw`path\qname`,
    });
  });

  it("rejects malformed Unicode escapes", async () => {
    await expect(
      async () => await unicodeEscapeDecodeSkill.run(String.raw`bad\u12zz`)
    ).rejects.toThrow("unicode_escape_decode invalid Unicode escape");
  });

  it("rejects malformed hex escapes", async () => {
    await expect(
      async () => await unicodeEscapeDecodeSkill.run(String.raw`bad\xzz`)
    ).rejects.toThrow("unicode_escape_decode invalid hex escape");
  });

  it("rejects non-string input", async () => {
    await expect(
      async () => await unicodeEscapeDecodeSkill.run(123 as unknown as string)
    ).rejects.toThrow("unicode_escape_decode input must be a string");
  });
});
