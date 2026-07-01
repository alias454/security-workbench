import { describe, expect, it } from "vitest";
import { parseBgpPrefixTable, parseBgpPrefixTableSkill } from "../src/parseBgpPrefixTable.js";
import { skills } from "../src/index.js";

async function runBgpPrefixTable(input: string) {
  return await parseBgpPrefixTableSkill.run(input);
}

describe("parse_bgp_prefix_table", () => {
  it("exports the parser skill with local-only permissions", () => {
    expect(skills.map((skill) => skill.metadata.name)).toContain("parse_bgp_prefix_table");
    expect(parseBgpPrefixTableSkill.metadata).toMatchObject({
      name: "parse_bgp_prefix_table",
      category: "parser",
      execution: {
        mode: "local_only",
        network_access: "none",
        deterministic: true,
      },
      permissions: {
        network: "none",
        filesystem: "none",
        sends: [],
        persists: false,
        runs_external_binaries: false,
      },
      exposure: {
        hosted_default: "allowlist_only",
        requires_authentication: true,
        rate_limit_recommended: true,
        audit_required: true,
      },
    });
  });

  it("parses prefix-first and ASN-first rows with IPv4, IPv6, notes, duplicates, and conflicting origins", async () => {
    const output = await runBgpPrefixTable([
      "# prefix origin table",
      "104.16.0.0/12 AS13335 Cloudflare example",
      "AS15169 2001:4860::/32 Google example",
      "203.0.113.0/24 AS64512 lab prefix",
      "104.16.0.0/12 AS13335 duplicate",
      "104.16.0.0/12 AS15169 conflicting-origin",
    ].join("\n"));

    expect(output.artifact).toEqual({ id: "artifact_bgp_prefix_table", type: "bgp_prefix_table" });
    expect(output.observed.valid_entry_count).toBe(5);
    expect(output.observed.ipv4_prefix_count).toBe(4);
    expect(output.observed.ipv6_prefix_count).toBe(1);
    expect(output.observed.unique_prefix_count).toBe(3);
    expect(output.observed.unique_origin_asn_count).toBe(3);
    expect(output.observed.prefix_lengths).toEqual({ "12": 3, "24": 1, "32": 1 });
    expect(output.observed.origin_asn_counts).toEqual({ AS13335: 2, AS15169: 2, AS64512: 1 });
    expect(output.observed.entries[1]).toMatchObject({
      line: 3,
      prefix: "2001:4860::/32",
      normalized_prefix: "2001:4860::/32",
      ip_version: "ipv6",
      prefix_length: 32,
      origin_asn: "AS15169",
      origin_asn_number: 15169,
      note: "Google example",
    });
    expect(output.observed.duplicate_entries).toEqual([
      {
        normalized_prefix: "104.16.0.0/12",
        origin_asn: "AS13335",
        first_line: 2,
        duplicate_line: 5,
        occurrences: 2,
      },
    ]);
    expect(output.observed.conflicting_prefixes).toEqual([
      {
        normalized_prefix: "104.16.0.0/12",
        origin_asns: ["AS13335", "AS15169"],
        lines: [2, 5, 6],
      },
    ]);
    expect(output.warnings).toEqual([]);
  });

  it("preserves valid rows and reports malformed rows", async () => {
    const output = await runBgpPrefixTable([
      "104.16.0.0/12 AS13335",
      "198.51.100.10 AS64512",
      "AS15169 2001:4860::/129",
      "203.0.113.0/24 AS64512 AS13335",
      "2001:db8::/32 AS64512",
    ].join("\n"));

    expect(output.observed.valid_entry_count).toBe(2);
    expect(output.observed.malformed_line_count).toBe(3);
    expect(output.observed.entries.map((entry) => entry.normalized_prefix)).toEqual([
      "104.16.0.0/12",
      "2001:db8::/32",
    ]);
    expect(output.observed.invalid_lines).toEqual([
      { line: 2, value: "198.51.100.10 AS64512", reason: "missing valid CIDR prefix token" },
      { line: 3, value: "AS15169 2001:4860::/129", reason: "missing valid CIDR prefix token" },
      { line: 4, value: "203.0.113.0/24 AS64512 AS13335", reason: "line must contain exactly one origin ASN token" },
    ]);
    expect(output.warnings).toHaveLength(3);
  });

  it("warns about mixed line endings", async () => {
    const output = await runBgpPrefixTable("104.16.0.0/12 AS13335\r\n2001:db8::/32 AS64512\n");

    expect(output.observed.line_ending).toBe("mixed");
    expect(output.warnings).toContain("BGP prefix table input contains mixed line endings.");
  });

  it("rejects empty input, inputs with no valid entries, and non-string input", () => {
    expect(() => parseBgpPrefixTableSkill.run("\n\t\n")).toThrow(
      "parse_bgp_prefix_table input must not be empty"
    );
    expect(() => parseBgpPrefixTable("# only comments\n198.51.100.10 AS64512")).toThrow(
      "parse_bgp_prefix_table input did not contain any valid prefix/origin ASN rows"
    );
    expect(() => parseBgpPrefixTableSkill.run(123 as unknown as string)).toThrow(
      "parse_bgp_prefix_table input must be a string"
    );
  });
});
