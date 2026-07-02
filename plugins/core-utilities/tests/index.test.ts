import { describe, expect, it } from "vitest";
import { skills } from "../src/index.js";

describe("core-utilities skill registry", () => {
  it("does not register duplicate skill names", () => {
    const names = skills.map((skill) => skill.metadata.name);
    expect(new Set(names).size).toBe(names.length);
  });

  it("registers explicit hash skills and removes hash_value", () => {
    const names = skills.map((skill) => skill.metadata.name);

    expect(names).toContain("identify_hash");
    expect(names).toContain("md5_hash");
    expect(names).toContain("sha1_hash");
    expect(names).toContain("sha256_hash");
    expect(names).toContain("sha512_hash");
    expect(names).not.toContain("hash_value");
  });

  it("categorizes observation extractors as parsers", () => {
    const categories = new Map(skills.map((skill) => [skill.metadata.name, skill.metadata.category]));

    for (const parserName of [
      "identify_hash",
      "json_parse",
      "extract_iocs",
      "extract_urls",
      "extract_defanged_urls",
      "extract_domains",
      "extract_emails",
      "extract_ipv4",
      "extract_hashes",
      "extract_cves",
      "extract_uuids",
    ]) {
      expect(categories.get(parserName)).toBe("parser");
    }

    for (const transformName of ["md5_hash", "sha1_hash", "sha256_hash", "sha512_hash", "json_format", "count_lines", "normalize_indicators"]) {
      expect(categories.get(transformName)).toBe("transform");
    }
  });
});
