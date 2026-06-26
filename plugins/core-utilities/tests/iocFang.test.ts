import { describe, expect, it } from "vitest";
import { defangIocsSkill } from "../src/defangIocs.js";
import { refangIocsSkill } from "../src/refangIocs.js";

describe("defang_iocs", () => {
  it("defangs URL, domain, and email text", async () => {
    const result = await defangIocsSkill.run(
      "https://evil.example.com/path contact admin@example.com"
    );

    expect(result).toEqual({
      defanged:
        "hxxps://evil[.]example[.]com/path contact admin[@]example[.]com",
    });
  });

  it("rejects non-string input", async () => {
    await expect(
      async () => await defangIocsSkill.run(123 as unknown as string)
    ).rejects.toThrow("defang_iocs input must be a string");
  });
});

describe("refang_iocs", () => {
  it("refangs common defanged IOC text", async () => {
    const result = await refangIocsSkill.run(
      "hxxps://evil[.]example[.]com/path contact admin[@]example[.]com"
    );

    expect(result).toEqual({
      refanged: "https://evil.example.com/path contact admin@example.com",
    });
  });

  it("supports common alternate dot and at forms", async () => {
    const result = await refangIocsSkill.run(
      "evil(dot)example[dot]com admin(at)example(.)com"
    );

    expect(result).toEqual({
      refanged: "evil.example.com admin@example.com",
    });
  });

  it("rejects non-string input", async () => {
    await expect(
      async () => await refangIocsSkill.run(123 as unknown as string)
    ).rejects.toThrow("refang_iocs input must be a string");
  });
});
