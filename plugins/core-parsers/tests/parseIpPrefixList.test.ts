import { describe, expect, it } from "vitest";
import { parseIpPrefixList, parseIpPrefixListSkill } from "../src/parseIpPrefixList.js";
import { skills } from "../src/index.js";

async function runIpPrefixList(input: string) {
  return await parseIpPrefixListSkill.run(input);
}

describe("parse_ip_prefix_list", () => {
  it("exports the parser skill with local-only permissions", () => {
    expect(skills.map((skill) => skill.metadata.name)).toContain("parse_ip_prefix_list");
    expect(parseIpPrefixListSkill.metadata).toMatchObject({
      name: "parse_ip_prefix_list",
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

  it("parses IPv4, IPv6, host addresses, CIDR prefixes, comments, and duplicates", async () => {
    const output = await runIpPrefixList([
      "# vendor allowlist",
      "203.0.113.0/24",
      "198.51.100.10",
      "2001:db8::/32",
      "2001:DB8::1 # inline host comment",
      "203.0.113.0/24 # duplicate",
    ].join("\n"));

    expect(output.artifact).toEqual({ id: "artifact_ip_prefix_list", type: "ip_prefix_list" });
    expect(output.observed.line_ending).toBe("lf");
    expect(output.observed.physical_line_count).toBe(6);
    expect(output.observed.comment_line_count).toBe(1);
    expect(output.observed.inline_comment_count).toBe(2);
    expect(output.observed.valid_entry_count).toBe(5);
    expect(output.observed.host_address_count).toBe(2);
    expect(output.observed.cidr_prefix_count).toBe(3);
    expect(output.observed.ipv4_entry_count).toBe(3);
    expect(output.observed.ipv6_entry_count).toBe(2);
    expect(output.observed.malformed_line_count).toBe(0);
    expect(output.observed.prefix_lengths).toEqual({ "24": 2, "32": 1 });
    expect(output.observed.entries.map((entry) => entry.normalized_value)).toEqual([
      "203.0.113.0/24",
      "198.51.100.10",
      "2001:db8::/32",
      "2001:db8::1",
      "203.0.113.0/24",
    ]);
    expect(output.observed.entries[3]).toMatchObject({
      line: 5,
      kind: "host",
      ip_version: "ipv6",
      normalized_address: "2001:db8::1",
      comment: "inline host comment",
    });
    expect(output.observed.duplicate_entry_count).toBe(1);
    expect(output.observed.duplicate_entries).toEqual([
      {
        normalized_value: "203.0.113.0/24",
        first_line: 2,
        duplicate_line: 6,
        occurrences: 2,
      },
    ]);
    expect(output.warnings).toEqual([]);
  });

  it("preserves valid entries and reports malformed lines", async () => {
    const output = await runIpPrefixList([
      "203.0.113.0/33",
      "999.1.1.1",
      "2001:db8::/129",
      "not-an-ip",
      "198.51.100.1/32",
    ].join("\n"));

    expect(output.observed.valid_entry_count).toBe(1);
    expect(output.observed.malformed_line_count).toBe(4);
    expect(output.observed.entries).toEqual([
      {
        line: 5,
        kind: "cidr",
        ip_version: "ipv4",
        value: "198.51.100.1/32",
        normalized_value: "198.51.100.1/32",
        address: "198.51.100.1",
        normalized_address: "198.51.100.1",
        prefix_length: 32,
        comment: null,
      },
    ]);
    expect(output.observed.invalid_lines).toEqual([
      { line: 1, value: "203.0.113.0/33", reason: "IPv4 CIDR prefix length must be between 0 and 32" },
      { line: 2, value: "999.1.1.1", reason: "invalid IP address" },
      { line: 3, value: "2001:db8::/129", reason: "IPv6 CIDR prefix length must be between 0 and 128" },
      { line: 4, value: "not-an-ip", reason: "invalid IP address" },
    ]);
    expect(output.warnings).toHaveLength(4);
  });

  it("supports compressed, full, and IPv4-embedded IPv6 forms", async () => {
    const output = await runIpPrefixList([
      "::1",
      "2001:0db8:0000:0000:0000:ff00:0042:8329/128",
      "::ffff:192.0.2.128/128",
      "2001:db8::192.0.2.1/128",
    ].join("\n"));

    expect(output.observed.valid_entry_count).toBe(4);
    expect(output.observed.ipv6_entry_count).toBe(4);
    expect(output.observed.entries.map((entry) => entry.normalized_value)).toEqual([
      "::1",
      "2001:0db8:0000:0000:0000:ff00:0042:8329/128",
      "::ffff:192.0.2.128/128",
      "2001:db8::192.0.2.1/128",
    ]);
  });

  it("rejects extra unmodeled tokens instead of silently parsing partial rows", async () => {
    const output = await runIpPrefixList("203.0.113.10 allow\n198.51.100.10");

    expect(output.observed.valid_entry_count).toBe(1);
    expect(output.observed.malformed_line_count).toBe(1);
    expect(output.observed.invalid_lines).toEqual([
      {
        line: 1,
        value: "203.0.113.10 allow",
        reason: "line must contain exactly one IP address or CIDR prefix token",
      },
    ]);
  });

  it("warns about mixed line endings", async () => {
    const output = await runIpPrefixList("203.0.113.10\r\n198.51.100.0/24\n");

    expect(output.observed.line_ending).toBe("mixed");
    expect(output.warnings).toContain("IP prefix list input contains mixed line endings.");
  });

  it("rejects empty input, inputs with no valid entries, and non-string input", () => {
    expect(() => parseIpPrefixListSkill.run("\n\t\n")).toThrow(
      "parse_ip_prefix_list input must not be empty"
    );
    expect(() => parseIpPrefixList("# only comments\n999.999.999.999")).toThrow(
      "parse_ip_prefix_list input did not contain any valid IP addresses or CIDR prefixes"
    );
    expect(() => parseIpPrefixListSkill.run(123 as unknown as string)).toThrow(
      "parse_ip_prefix_list input must be a string"
    );
  });
});
