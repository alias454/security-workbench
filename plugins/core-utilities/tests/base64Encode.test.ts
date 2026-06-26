import { describe, expect, it } from "vitest";
import { base64EncodeSkill } from "../src/base64Encode.js";

describe("base64_encode", () => {
  it("encodes a UTF-8 string", async () => {
    const result = await base64EncodeSkill.run("Hello");

    expect(result).toEqual({
      encoded: "SGVsbG8=",
    });
  });

  it("rejects non-string input", async () => {
    await expect(
      async () => await base64EncodeSkill.run(123 as unknown as string)
    ).rejects.toThrow("base64_encode input must be a string");
  });
});
