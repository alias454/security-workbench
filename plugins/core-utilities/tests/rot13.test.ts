import { describe, expect, it } from "vitest";
import { rot13Skill } from "../src/rot13.js";

describe("rot13", () => {
  it("rotates ASCII letters and preserves other characters", async () => {
    const result = await rot13Skill.run("Hello, World! Zebra-123");

    expect(result).toEqual({
      transformed: "Uryyb, Jbeyq! Mroen-123",
    });
  });

  it("is reversible when run twice", async () => {
    const first = await rot13Skill.run("Security Workbench");
    const second = await rot13Skill.run(first.transformed);

    expect(second).toEqual({ transformed: "Security Workbench" });
  });

  it("rejects non-string input", async () => {
    await expect(async () => await rot13Skill.run(123 as unknown as string)).rejects.toThrow(
      "rot13 input must be a string"
    );
  });
});
