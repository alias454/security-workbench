import { describe, expect, it } from "vitest";
import { parseAsnAllowDenyList, parseAsnAllowDenyListSkill } from "../src/parseAsnAllowDenyList.js";
import { skills } from "../src/index.js";

async function runAsnAllowDenyList(input: string) {
  return await parseAsnAllowDenyListSkill.run(input);
}

describe("parse_asn_allow_deny_list", () => {
  it("exports the parser skill with local-only permissions", () => {
    expect(skills.map((skill) => skill.metadata.name)).toContain("parse_asn_allow_deny_list");
    expect(parseAsnAllowDenyListSkill.metadata).toMatchObject({
      name: "parse_asn_allow_deny_list",
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

  it("parses action-first and ASN-first policy rows with aliases, comments, duplicates, and conflicts", async () => {
    const output = await runAsnAllowDenyList([
      "# ASN policy list",
      "allow AS13335 # vendor allow",
      "AS15169 deny suspicious concentration",
      "permit, 64512, lab allow",
      "block AS15169 # duplicate deny alias",
      "allow AS15169 # conflict with deny",
    ].join("\n"));

    expect(output.artifact).toEqual({ id: "artifact_asn_allow_deny_list", type: "asn_allow_deny_list" });
    expect(output.observed.valid_entry_count).toBe(5);
    expect(output.observed.allow_entry_count).toBe(3);
    expect(output.observed.deny_entry_count).toBe(2);
    expect(output.observed.unique_asn_count).toBe(3);
    expect(output.observed.action_counts).toEqual({ allow: 3, deny: 2 });
    expect(output.observed.entries[2]).toMatchObject({
      line: 4,
      action: "allow",
      action_token: "permit",
      normalized_asn: "AS64512",
      asn_number: 64512,
      reason: "lab allow",
      comment: null,
    });
    expect(output.observed.duplicate_entries).toEqual([
      {
        action: "deny",
        normalized_asn: "AS15169",
        first_line: 3,
        duplicate_line: 5,
        occurrences: 2,
      },
    ]);
    expect(output.observed.conflicting_entries).toEqual([
      {
        normalized_asn: "AS15169",
        allow_lines: [6],
        deny_lines: [3, 5],
      },
    ]);
    expect(output.warnings).toEqual([]);
  });

  it("preserves valid entries and reports malformed rows", async () => {
    const output = await runAsnAllowDenyList([
      "allow AS13335",
      "AS15169",
      "allow AS15169 deny",
      "allow ASnotvalid",
      "allow AS64512",
    ].join("\n"));

    expect(output.observed.valid_entry_count).toBe(2);
    expect(output.observed.malformed_line_count).toBe(3);
    expect(output.observed.entries.map((entry) => entry.normalized_asn)).toEqual(["AS13335", "AS64512"]);
    expect(output.observed.invalid_lines).toEqual([
      { line: 2, value: "AS15169", reason: "missing allow or deny action" },
      { line: 3, value: "allow AS15169 deny", reason: "line must contain exactly one allow or deny action" },
      { line: 4, value: "allow ASnotvalid", reason: "missing valid ASN token" },
    ]);
    expect(output.warnings).toHaveLength(3);
  });

  it("warns about mixed line endings", async () => {
    const output = await runAsnAllowDenyList("allow AS13335\r\ndeny AS15169\n");

    expect(output.observed.line_ending).toBe("mixed");
    expect(output.warnings).toContain("ASN allow/deny list input contains mixed line endings.");
  });

  it("rejects empty input, inputs with no valid entries, and non-string input", () => {
    expect(() => parseAsnAllowDenyListSkill.run("\n\t\n")).toThrow(
      "parse_asn_allow_deny_list input must not be empty"
    );
    expect(() => parseAsnAllowDenyList("# only comments\nallow ASnotvalid")).toThrow(
      "parse_asn_allow_deny_list input did not contain any valid ASN policy entries"
    );
    expect(() => parseAsnAllowDenyListSkill.run(123 as unknown as string)).toThrow(
      "parse_asn_allow_deny_list input must be a string"
    );
  });
});
