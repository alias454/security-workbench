import { describe, expect, it } from "vitest";
import { base32DecodeSkill, base32EncodeSkill } from "../src/base32.js";

describe("base32_encode", () => {
  it("encodes UTF-8 text using RFC4648 Base32", async () => {
    const result = await base32EncodeSkill.run("hello");

    expect(result).toEqual({
      encoded: "NBSWY3DP",
      alphabet: "RFC4648",
      padded: true,
    });
  });

  it("adds RFC4648 padding when required", async () => {
    const result = await base32EncodeSkill.run("f");

    expect(result).toEqual({
      encoded: "MY======",
      alphabet: "RFC4648",
      padded: true,
    });
  });
});

describe("base32_decode", () => {
  it("decodes strict RFC4648 padded Base32", async () => {
    const result = await base32DecodeSkill.run("MZXW6===");

    expect(result).toEqual({
      decoded: "foo",
      alphabet: "RFC4648",
    });
  });

  it("accepts lowercase input by normalizing to uppercase", async () => {
    const result = await base32DecodeSkill.run("nbswy3dp");

    expect(result).toEqual({
      decoded: "hello",
      alphabet: "RFC4648",
    });
  });

  it("rejects padding that appears before the end", async () => {
    await expect(
      async () => await base32DecodeSkill.run("NBS=Y3DP")
    ).rejects.toThrow("base32_decode padding must appear only at the end");
  });

  it("rejects unpadded input whose length is not a multiple of 8", async () => {
    await expect(
      async () => await base32DecodeSkill.run("NBSWY3D")
    ).rejects.toThrow("base32_decode input length must be a multiple of 8");
  });

  it("rejects non-string input", async () => {
    await expect(
      async () => await base32DecodeSkill.run(123 as unknown as string)
    ).rejects.toThrow("base32_decode input must be a string");
  });
});
