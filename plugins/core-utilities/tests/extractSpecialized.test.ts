import { describe, expect, it } from "vitest";
import {
  extractDomainsSkill,
  extractEmailsSkill,
  extractHashesSkill,
  extractIpv4Skill,
  extractUrlsSkill,
} from "../src/extractSpecialized.js";

const SHA256 = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
const SHA1 = "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d";
const MD5 = "5d41402abc4b2a76b9719d911017c592";

describe("specialized IOC extractors", () => {
  const input = `Visit hxxps://evil[.]example[.]com/path, contact admin[@]example[.]com, IP 192.168.1.10, hashes ${SHA256} ${SHA1} ${MD5}.`;

  it("are categorized as parsers", () => {
    for (const skill of [extractUrlsSkill, extractDomainsSkill, extractEmailsSkill, extractIpv4Skill, extractHashesSkill]) {
      expect(skill.metadata.category).toBe("parser");
    }
  });

  it("extracts URLs", async () => {
    const result = await extractUrlsSkill.run(input);

    expect(result).toEqual({
      urls: ["https://evil.example.com/path"],
      count: 1,
    });
  });

  it("extracts domains from URLs, email addresses, and bare domains", async () => {
    const result = await extractDomainsSkill.run(input);

    expect(result).toEqual({
      domains: ["evil.example.com", "example.com"],
      count: 2,
    });
  });

  it("extracts email addresses", async () => {
    const result = await extractEmailsSkill.run(input);

    expect(result).toEqual({
      email_addresses: ["admin@example.com"],
      count: 1,
    });
  });

  it("extracts IPv4 addresses and rejects invalid octets", async () => {
    const result = await extractIpv4Skill.run(`${input} 999.1.1.1`);

    expect(result).toEqual({
      ipv4_addresses: ["192.168.1.10"],
      count: 1,
    });
  });

  it("extracts common hex hash lengths", async () => {
    const result = await extractHashesSkill.run(input);

    expect(result).toEqual({
      md5_hashes: [MD5],
      sha1_hashes: [SHA1],
      sha256_hashes: [SHA256],
      sha512_hashes: [],
      total_count: 3,
    });
  });

  it("rejects non-string input", async () => {
    await expect(
      async () => await extractUrlsSkill.run(123 as unknown as string)
    ).rejects.toThrow("extract_urls input must be a string");
  });
});
