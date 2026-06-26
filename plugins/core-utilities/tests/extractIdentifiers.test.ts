import { describe, expect, it } from "vitest";

import { extractCvesSkill, extractUuidsSkill } from "../src/extractIdentifiers.js";

describe("extract_cves", () => {
  it("is categorized as a parser", () => {
    expect(extractCvesSkill.metadata.category).toBe("parser");
  });

  it("extracts CVE identifiers, normalizes case, dedupes, and preserves first-seen order", () => {
    expect(
      extractCvesSkill.run(
        "Find cve-2024-1234, CVE-2025-99999, cve-2024-1234, and CVE-1999-0001.",
      ),
    ).toEqual({
      cves: ["CVE-2024-1234", "CVE-2025-99999", "CVE-1999-0001"],
      count: 3,
    });
  });

  it("does not match short CVE sequence numbers", () => {
    expect(extractCvesSkill.run("CVE-2024-123 is too short.")).toEqual({
      cves: [],
      count: 0,
    });
  });

  it("returns an empty list when no CVEs are present", () => {
    expect(extractCvesSkill.run("nothing here")).toEqual({
      cves: [],
      count: 0,
    });
  });
});

describe("extract_uuids", () => {
  it("is categorized as a parser", () => {
    expect(extractUuidsSkill.metadata.category).toBe("parser");
  });

  it("extracts canonical UUIDs, normalizes case, dedupes, and preserves first-seen order", () => {
    expect(
      extractUuidsSkill.run(
        "IDs: 550E8400-E29B-41D4-A716-446655440000, " +
          "6ba7b810-9dad-11d1-80b4-00c04fd430c8, " +
          "550e8400-e29b-41d4-a716-446655440000.",
      ),
    ).toEqual({
      uuids: [
        "550e8400-e29b-41d4-a716-446655440000",
        "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
      ],
      count: 2,
    });
  });

  it("does not match compact UUID values without hyphens", () => {
    expect(extractUuidsSkill.run("550e8400e29b41d4a716446655440000")).toEqual({
      uuids: [],
      count: 0,
    });
  });

  it("returns an empty list when no UUIDs are present", () => {
    expect(extractUuidsSkill.run("nothing here")).toEqual({
      uuids: [],
      count: 0,
    });
  });
});
