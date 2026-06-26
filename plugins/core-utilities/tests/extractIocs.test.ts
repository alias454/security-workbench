import { describe, expect, it } from "vitest";
import { extractIocsSkill } from "../src/extractIocs.js";

describe("extract_iocs", () => {
  it("is categorized as a parser", () => {
    expect(extractIocsSkill.metadata.category).toBe("parser");
  });

  it("extracts common indicators from normal text", async () => {
    const result = await extractIocsSkill.run(
      "Visit https://evil.example.com/path, email Admin@Example.com, ip 192.168.1.10, hash 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824, and domain sub.example.org."
    );

    expect(result).toEqual({
      urls: ["https://evil.example.com/path"],
      domains: ["evil.example.com", "example.com", "sub.example.org"],
      ipv4_addresses: ["192.168.1.10"],
      email_addresses: ["admin@example.com"],
      sha256_hashes: [
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
      ],
    });
  });

  it("extracts from common defanged text by normalizing first", async () => {
    const result = await extractIocsSkill.run(
      "hxxps://evil[.]example[.]com/path admin[@]example[.]com"
    );

    expect(result).toEqual({
      urls: ["https://evil.example.com/path"],
      domains: ["evil.example.com", "example.com"],
      ipv4_addresses: [],
      email_addresses: ["admin@example.com"],
      sha256_hashes: [],
    });
  });

  it("deduplicates indicators", async () => {
    const result = await extractIocsSkill.run(
      "example.com example.com https://example.com https://example.com"
    );

    expect(result).toEqual({
      urls: ["https://example.com"],
      domains: ["example.com"],
      ipv4_addresses: [],
      email_addresses: [],
      sha256_hashes: [],
    });
  });

  it("rejects non-string input", async () => {
    await expect(
      async () => await extractIocsSkill.run(123 as unknown as string)
    ).rejects.toThrow("extract_iocs input must be a string");
  });
});
