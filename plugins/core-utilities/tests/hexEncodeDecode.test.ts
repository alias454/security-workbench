import { describe, expect, it } from "vitest";
import { hexDecodeSkill } from "../src/hexDecode.js";
import { hexEncodeSkill } from "../src/hexEncode.js";

describe("hex_encode", () => {
  it("encodes UTF-8 text as lowercase hexadecimal", async () => {
    const result = await hexEncodeSkill.run("Hello");

    expect(result).toEqual({
      encoded: "48656c6c6f",
    });
  });

  it("rejects non-string input", async () => {
    await expect(
      async () => await hexEncodeSkill.run(123 as unknown as string)
    ).rejects.toThrow("hex_encode input must be a string");
  });
});

describe("hex_decode", () => {
  it("decodes strict hexadecimal into UTF-8 text", async () => {
    const result = await hexDecodeSkill.run("48656c6c6f");

    expect(result).toEqual({
      decoded: "Hello",
    });
  });

  it("rejects non-string input", async () => {
    await expect(
      async () => await hexDecodeSkill.run(123 as unknown as string)
    ).rejects.toThrow("hex_decode input must be a string");
  });

  it("rejects odd-length hexadecimal", async () => {
    await expect(async () => await hexDecodeSkill.run("abc")).rejects.toThrow(
      "hex_decode input must be strict even-length hexadecimal"
    );
  });

  it("rejects non-hex characters", async () => {
    await expect(async () => await hexDecodeSkill.run("zz")).rejects.toThrow(
      "hex_decode input must be strict even-length hexadecimal"
    );
  });
});
