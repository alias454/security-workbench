import { describe, expect, it } from "vitest";
import { stringNormalizeSkill } from "../src/stringNormalize.js";

describe("string_normalize", () => {
  it("normalizes Unicode text to NFC", async () => {
    const result = await stringNormalizeSkill.run("e\u0301");

    expect(result).toEqual({
      normalized: "é",
      form: "NFC",
      changed: true,
    });
  });

  it("does not trim or case fold", async () => {
    const result = await stringNormalizeSkill.run("  Test  ");

    expect(result).toEqual({
      normalized: "  Test  ",
      form: "NFC",
      changed: false,
    });
  });

  it("rejects non-string input", async () => {
    await expect(
      async () => await stringNormalizeSkill.run(123 as unknown as string)
    ).rejects.toThrow("string_normalize input must be a string");
  });
});
