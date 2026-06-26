import { describe, expect, it } from "vitest";
import { calculateEntropySkill } from "../src/calculateEntropy.js";

describe("calculate_entropy", () => {
  it("returns zero entropy for an empty string", async () => {
    const result = await calculateEntropySkill.run("");

    expect(result).toEqual({
      entropy: 0,
      length: 0,
      unique_symbols: 0,
    });
  });

  it("returns zero entropy for repeated symbols", async () => {
    const result = await calculateEntropySkill.run("aaaa");

    expect(result).toEqual({
      entropy: 0,
      length: 4,
      unique_symbols: 1,
    });
  });

  it("calculates entropy for equally likely symbols", async () => {
    const result = await calculateEntropySkill.run("abcd");

    expect(result).toEqual({
      entropy: 2,
      length: 4,
      unique_symbols: 4,
    });
  });

  it("rejects non-string input", async () => {
    await expect(
      async () => await calculateEntropySkill.run(123 as unknown as string)
    ).rejects.toThrow("calculate_entropy input must be a string");
  });
});
