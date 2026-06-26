import { describe, expect, it } from "vitest";
import { urlDecodeSkill } from "../src/urlDecode.js";
import { urlEncodeSkill } from "../src/urlEncode.js";

describe("url_encode", () => {
  it("percent-encodes a string", async () => {
    const result = await urlEncodeSkill.run("hello world?x=1&y=2");

    expect(result).toEqual({
      encoded: "hello%20world%3Fx%3D1%26y%3D2",
    });
  });

  it("rejects non-string input", async () => {
    await expect(
      async () => await urlEncodeSkill.run(123 as unknown as string)
    ).rejects.toThrow("url_encode input must be a string");
  });
});

describe("url_decode", () => {
  it("decodes percent-encoded text", async () => {
    const result = await urlDecodeSkill.run("hello%20world%3Fx%3D1%26y%3D2");

    expect(result).toEqual({
      decoded: "hello world?x=1&y=2",
    });
  });

  it("rejects non-string input", async () => {
    await expect(
      async () => await urlDecodeSkill.run(123 as unknown as string)
    ).rejects.toThrow("url_decode input must be a string");
  });

  it("rejects malformed percent-encoded text", async () => {
    await expect(async () => await urlDecodeSkill.run("%ZZ")).rejects.toThrow(
      "url_decode input must be valid percent-encoded text"
    );
  });
});
