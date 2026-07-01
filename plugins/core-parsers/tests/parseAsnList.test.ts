import { describe, expect, it } from "vitest";
import { parseAsnList, parseAsnListSkill } from "../src/parseAsnList.js";
import { skills } from "../src/index.js";

async function runAsnList(input: string) {
  return await parseAsnListSkill.run(input);
}

describe("parse_asn_list", () => {
  it("exports the parser skill with local-only permissions", () => {
    expect(skills.map((skill) => skill.metadata.name)).toContain("parse_asn_list");
    expect(parseAsnListSkill.metadata).toMatchObject({
      name: "parse_asn_list",
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

  it("parses AS-prefixed and bare ASN rows with notes, comments, and duplicates", async () => {
    const output = await runAsnList([
      "# ASN watchlist",
      "AS13335 # Cloudflare example",
      "15169, Google example",
      "AS64512 lab network",
      "AS13335 # duplicate",
    ].join("\n"));

    expect(output.artifact).toEqual({ id: "artifact_asn_list", type: "asn_list" });
    expect(output.observed.line_ending).toBe("lf");
    expect(output.observed.physical_line_count).toBe(5);
    expect(output.observed.comment_line_count).toBe(1);
    expect(output.observed.inline_comment_count).toBe(2);
    expect(output.observed.valid_entry_count).toBe(4);
    expect(output.observed.unique_asn_count).toBe(3);
    expect(output.observed.normalized_asns).toEqual(["AS13335", "AS15169", "AS64512", "AS13335"]);
    expect(output.observed.asn_counts).toEqual({ AS13335: 2, AS15169: 1, AS64512: 1 });
    expect(output.observed.entries[1]).toMatchObject({
      line: 3,
      value: "15169, Google example",
      normalized_asn: "AS15169",
      asn_number: 15169,
      note: "Google example",
      comment: null,
    });
    expect(output.observed.duplicate_entry_count).toBe(1);
    expect(output.observed.duplicate_entries).toEqual([
      {
        normalized_asn: "AS13335",
        first_line: 2,
        duplicate_line: 5,
        occurrences: 2,
      },
    ]);
    expect(output.warnings).toEqual([]);
  });

  it("preserves valid entries and reports malformed lines", async () => {
    const output = await runAsnList([
      "AS13335",
      "AS4294967296",
      "ASnotvalid",
      "AS15169 AS13335",
      "64512",
    ].join("\n"));

    expect(output.observed.valid_entry_count).toBe(2);
    expect(output.observed.malformed_line_count).toBe(3);
    expect(output.observed.normalized_asns).toEqual(["AS13335", "AS64512"]);
    expect(output.observed.invalid_lines).toEqual([
      { line: 2, value: "AS4294967296", reason: "missing valid ASN token" },
      { line: 3, value: "ASnotvalid", reason: "missing valid ASN token" },
      { line: 4, value: "AS15169 AS13335", reason: "line must contain exactly one ASN token" },
    ]);
    expect(output.warnings).toHaveLength(3);
  });

  it("warns about mixed line endings", async () => {
    const output = await runAsnList("AS13335\r\nAS15169\n");

    expect(output.observed.line_ending).toBe("mixed");
    expect(output.warnings).toContain("ASN list input contains mixed line endings.");
  });

  it("rejects empty input, inputs with no valid entries, and non-string input", () => {
    expect(() => parseAsnListSkill.run("\n\t\n")).toThrow("parse_asn_list input must not be empty");
    expect(() => parseAsnList("# only comments\nASnotvalid")).toThrow(
      "parse_asn_list input did not contain any valid ASN entries"
    );
    expect(() => parseAsnListSkill.run(123 as unknown as string)).toThrow("parse_asn_list input must be a string");
  });
});
