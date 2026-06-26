import { describe, expect, it } from "vitest";
import { base64DecodeSkill } from "../src/base64Decode.js";

describe("base64_decode", () => {
  it("decodes a base64 string", async () => {
    const result = await base64DecodeSkill.run("SGVsbG8=");

    expect(result).toEqual({
      decoded: "Hello",
    });
  });

  it("rejects non-string input", async () => {
    await expect(
      async () => await base64DecodeSkill.run(123 as unknown as string)
    ).rejects.toThrow("base64_decode input must be a string");
  });

  it("rejects malformed base64 input", async () => {
    await expect(
      async () => await base64DecodeSkill.run("not base64")
    ).rejects.toThrow("base64_decode input must be strict padded base64");
  });

  it("rejects unpadded base64 input", async () => {
    await expect(
      async () => await base64DecodeSkill.run("SGVsbG8")
    ).rejects.toThrow("base64_decode input must be strict padded base64");
  });
});
