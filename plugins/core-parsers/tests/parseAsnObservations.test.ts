import { describe, expect, it } from "vitest";
import { parseAsnObservations, parseAsnObservationsSkill } from "../src/parseAsnObservations.js";
import { skills } from "../src/index.js";

async function runAsnObservations(input: string) {
  return await parseAsnObservationsSkill.run(input);
}

describe("parse_asn_observations", () => {
  it("exports the parser skill with local-only permissions", () => {
    expect(skills.map((skill) => skill.metadata.name)).toContain("parse_asn_observations");
    expect(parseAsnObservationsSkill.metadata).toMatchObject({
      name: "parse_asn_observations",
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

  it("parses ASN observations with timestamp, indicator, source, attributes, comments, and repeated ASNs", async () => {
    const output = await runAsnObservations([
      "# ASN observations",
      "2026-06-30T12:00:00Z AS13335 evil.example source=feed-a",
      "asn=AS15169 198.51.100.10 source=proxy",
      "AS13335 suspicious.example source=feed-b confidence=medium # repeated",
      "AS64512 lab-observation",
    ].join("\n"));

    expect(output.artifact).toEqual({ id: "artifact_asn_observations", type: "asn_observations" });
    expect(output.observed.valid_observation_count).toBe(4);
    expect(output.observed.unique_asn_count).toBe(3);
    expect(output.observed.observations_with_indicator_count).toBe(4);
    expect(output.observed.observations_with_source_count).toBe(3);
    expect(output.observed.observations_with_timestamp_count).toBe(1);
    expect(output.observed.asn_counts).toEqual({ AS13335: 2, AS15169: 1, AS64512: 1 });
    expect(output.observed.entries[0]).toMatchObject({
      line: 2,
      normalized_asn: "AS13335",
      asn_number: 13335,
      indicator: "evil.example",
      source: "feed-a",
      timestamp: "2026-06-30T12:00:00Z",
      attributes: { source: "feed-a" },
      context: ["2026-06-30T12:00:00Z", "evil.example", "source=feed-a"],
    });
    expect(output.observed.entries[2]).toMatchObject({
      line: 4,
      normalized_asn: "AS13335",
      indicator: "suspicious.example",
      source: "feed-b",
      attributes: { source: "feed-b", confidence: "medium" },
      comment: "repeated",
    });
    expect(output.observed.repeated_asns).toEqual([
      { normalized_asn: "AS13335", count: 2, first_line: 2, lines: [2, 4] },
    ]);
    expect(output.warnings).toEqual([]);
  });

  it("preserves valid observations and reports malformed rows", async () => {
    const output = await runAsnObservations([
      "AS13335 evil.example",
      "ASnotvalid source=feed",
      "AS15169 AS13335 duplicate-asn-row",
      "asn=AS64512 source=proxy",
    ].join("\n"));

    expect(output.observed.valid_observation_count).toBe(2);
    expect(output.observed.malformed_line_count).toBe(2);
    expect(output.observed.entries.map((entry) => entry.normalized_asn)).toEqual(["AS13335", "AS64512"]);
    expect(output.observed.invalid_lines).toEqual([
      { line: 2, value: "ASnotvalid source=feed", reason: "missing valid ASN token" },
      { line: 3, value: "AS15169 AS13335 duplicate-asn-row", reason: "line must contain exactly one ASN observation" },
    ]);
    expect(output.warnings).toHaveLength(2);
  });

  it("warns about mixed line endings", async () => {
    const output = await runAsnObservations("AS13335 evil.example\r\nAS15169 example.net\n");

    expect(output.observed.line_ending).toBe("mixed");
    expect(output.warnings).toContain("ASN observations input contains mixed line endings.");
  });

  it("rejects empty input, inputs with no valid entries, and non-string input", () => {
    expect(() => parseAsnObservationsSkill.run("\n\t\n")).toThrow(
      "parse_asn_observations input must not be empty"
    );
    expect(() => parseAsnObservations("# only comments\nASnotvalid source=feed")).toThrow(
      "parse_asn_observations input did not contain any valid ASN observations"
    );
    expect(() => parseAsnObservationsSkill.run(123 as unknown as string)).toThrow(
      "parse_asn_observations input must be a string"
    );
  });
});
