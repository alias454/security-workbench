import { describe, expect, it } from "vitest";
import { quotedPrintableDecodeSkill } from "../src/quotedPrintableDecode.js";

describe("quoted_printable_decode", () => {
  it("decodes ASCII quoted-printable escapes", async () => {
    const result = await quotedPrintableDecodeSkill.run("Hello=20World=21");

    expect(result).toEqual({
      decoded: "Hello World!",
    });
  });

  it("decodes UTF-8 quoted-printable byte sequences", async () => {
    const result = await quotedPrintableDecodeSkill.run("caf=C3=A9");

    expect(result).toEqual({
      decoded: "café",
    });
  });

  it("removes soft line breaks", async () => {
    const result = await quotedPrintableDecodeSkill.run("hello=\r\nworld=\nagain");

    expect(result).toEqual({
      decoded: "helloworldagain",
    });
  });

  it("rejects malformed quoted-printable escapes", async () => {
    await expect(
      async () => await quotedPrintableDecodeSkill.run("bad=ZZ")
    ).rejects.toThrow("quoted_printable_decode invalid escape");
  });

  it("rejects invalid UTF-8 byte sequences", async () => {
    await expect(
      async () => await quotedPrintableDecodeSkill.run("bad=FF")
    ).rejects.toThrow("quoted_printable_decode invalid UTF-8 byte sequence");
  });

  it("rejects non-string input", async () => {
    await expect(
      async () => await quotedPrintableDecodeSkill.run(123 as unknown as string)
    ).rejects.toThrow("quoted_printable_decode input must be a string");
  });
});
