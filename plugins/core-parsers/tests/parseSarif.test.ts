import { describe, expect, it } from "vitest";
import { parseSarif, parseSarifSkill } from "../src/parseSarif.js";
import { skills } from "../src/index.js";

async function runSarif(input: string) {
  return await parseSarifSkill.run(input);
}

function sampleSarif() {
  return {
    version: "2.1.0",
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    runs: [
      {
        tool: {
          driver: {
            name: "ExampleScanner",
            version: "1.2.3",
            informationUri: "https://scanner.example.com/docs",
            rules: [
              {
                id: "SEC001",
                name: "Example SQL Injection",
                shortDescription: { text: "SQL injection pattern" },
                fullDescription: { text: "Detects string-built SQL queries." },
                helpUri: "https://scanner.example.com/rules/SEC001",
                defaultConfiguration: { level: "error" },
                properties: {
                  tags: ["security", "injection"],
                  precision: "high",
                },
              },
              {
                id: "SEC002",
                name: "Example Token Disclosure",
                defaultConfiguration: { level: "warning" },
                properties: { tags: ["secrets"] },
              },
            ],
          },
          extensions: [{ name: "example-extension" }],
        },
        automationDetails: { id: "ci-main" },
        invocations: [{ commandLine: "scanner --sarif" }],
        originalUriBaseIds: {
          SRCROOT: { uri: "file:///repo/" },
        },
        artifacts: [
          { location: { uri: "src/app.ts" } },
          { location: { uri: "src/config.ts" } },
        ],
        taxonomies: [
          {
            name: "CWE",
            taxa: [{ id: "CWE-89" }, { id: "CWE-798" }],
          },
        ],
        results: [
          {
            ruleId: "SEC001",
            ruleIndex: 0,
            kind: "fail",
            level: "error",
            baselineState: "new",
            message: { text: "User input reaches SQL query." },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: "src/app.ts", uriBaseId: "SRCROOT" },
                  region: { startLine: 42, startColumn: 7, endLine: 42, endColumn: 24 },
                },
                logicalLocations: [{ fullyQualifiedName: "handler.login" }],
              },
            ],
            relatedLocations: [{ id: 1, message: { text: "request parameter" } }],
            fingerprints: { primaryLocationLineHash: "abc123" },
            partialFingerprints: { primaryLocationStartColumnFingerprint: "def456" },
            suppressions: [{ kind: "external" }],
            fixes: [{ description: { text: "Use parameterized queries." } }],
            taxa: [{ id: "CWE-89" }],
            properties: { precision: "high" },
          },
          {
            ruleId: "SEC002",
            ruleIndex: 1,
            level: "warning",
            message: { markdown: "Token-like value observed." },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: "src/config.ts" },
                  region: { startLine: 8 },
                },
              },
            ],
            baselineState: "unchanged",
          },
        ],
        properties: { category: "sast" },
      },
    ],
  };
}

describe("parse_sarif", () => {
  it("exports the parser skill with local-only permissions", () => {
    expect(skills.map((skill) => skill.metadata.name)).toContain("parse_sarif");
    expect(parseSarifSkill.metadata).toMatchObject({
      name: "parse_sarif",
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

  it("parses SARIF runs, rules, results, locations, fingerprints, suppressions, fixes, and taxa", async () => {
    const output = await runSarif(JSON.stringify(sampleSarif(), null, 2));

    expect(output.artifact).toEqual({ id: "artifact_sarif", type: "sarif", version: "2.1.0" });
    expect(output.observed.schema_present).toBe(true);
    expect(output.observed.run_count).toBe(1);
    expect(output.observed.tool_driver_names).toEqual(["ExampleScanner"]);
    expect(output.observed.tool_driver_versions).toEqual(["1.2.3"]);
    expect(output.observed.tool_extension_names).toEqual(["example-extension"]);
    expect(output.observed.automation_ids).toEqual(["ci-main"]);
    expect(output.observed.invocation_count).toBe(1);
    expect(output.observed.artifact_count).toBe(2);
    expect(output.observed.rule_count).toBe(2);
    expect(output.observed.result_count).toBe(2);
    expect(output.observed.taxon_count).toBe(2);
    expect(output.observed.artifact_uris).toEqual(["src/app.ts", "src/config.ts"]);
    expect(output.observed.result_location_uris).toEqual(["src/app.ts", "src/config.ts"]);
    expect(output.observed.result_location_refs).toEqual(["src/app.ts:42", "src/config.ts:8"]);
    expect(output.observed.rule_ids).toEqual(["SEC001", "SEC002"]);
    expect(output.observed.result_rule_ids).toEqual(["SEC001", "SEC002"]);
    expect(output.observed.result_levels).toEqual({ error: 1, warning: 1 });
    expect(output.observed.result_kinds).toEqual(["fail"]);
    expect(output.observed.baseline_states).toEqual(["new", "unchanged"]);
    expect(output.observed.suppression_count).toBe(1);
    expect(output.observed.suppression_kinds).toEqual(["external"]);
    expect(output.observed.fixes_present_count).toBe(1);
    expect(output.observed.fingerprint_keys).toEqual(["primaryLocationLineHash"]);
    expect(output.observed.partial_fingerprint_keys).toEqual(["primaryLocationStartColumnFingerprint"]);
    expect(output.observed.taxa_ids).toEqual(["CWE-798", "CWE-89"]);
    expect(output.observed.tags).toEqual(["injection", "secrets", "security"]);
    expect(output.observed.property_keys).toEqual(["result.precision", "rule.precision", "rule.tags", "run.category"]);
    expect(output.warnings).toEqual([]);
  });

  it("preserves useful normalized run, rule, and result records", async () => {
    const output = await runSarif(JSON.stringify(sampleSarif()));

    expect(output.observed.runs[0]).toMatchObject({
      run_index: 0,
      tool_driver_name: "ExampleScanner",
      tool_driver_version: "1.2.3",
      automation_id: "ci-main",
      original_uri_base_ids: ["SRCROOT"],
      artifact_count: 2,
      rule_count: 2,
      result_count: 2,
    });
    expect(output.observed.rules[0]).toMatchObject({
      id: "SEC001",
      name: "Example SQL Injection",
      short_description_text: "SQL injection pattern",
      default_level: "error",
      tags: ["injection", "security"],
    });
    expect(output.observed.results[0]).toMatchObject({
      rule_id: "SEC001",
      rule_index: 0,
      level: "error",
      baseline_state: "new",
      message_text: "User input reaches SQL query.",
      location_count: 1,
      related_location_count: 1,
      suppression_count: 1,
      fix_count: 1,
      fixes_present: true,
      taxa_ids: ["CWE-89"],
    });
    expect(output.observed.results[0]?.locations[0]).toMatchObject({
      uri: "src/app.ts",
      uri_base_id: "SRCROOT",
      region_start_line: 42,
      region_start_column: 7,
      region_end_line: 42,
      region_end_column: 24,
      logical_location_names: ["handler.login"],
    });
    expect(output.observed.results[1]?.message_markdown_present).toBe(true);
  });

  it("supports multiple runs and missing optional arrays", async () => {
    const input = {
      version: "2.1.0",
      runs: [
        {
          tool: { driver: { name: "CodeQL", semanticVersion: "2.17.0" } },
          results: [{ ruleId: "js/example", level: "note", message: { text: "note" } }],
        },
        {
          tool: { driver: { name: "Semgrep" } },
          results: [{ ruleId: "ts/example", message: { text: "missing level" } }],
        },
      ],
    };

    const output = await runSarif(JSON.stringify(input));

    expect(output.observed.run_count).toBe(2);
    expect(output.observed.tool_driver_names).toEqual(["CodeQL", "Semgrep"]);
    expect(output.observed.tool_driver_versions).toEqual(["2.17.0"]);
    expect(output.observed.result_count).toBe(2);
    expect(output.observed.result_levels).toEqual({ note: 1, unknown: 1 });
  });

  it("emits warnings for malformed shapes while preserving valid runs and results", async () => {
    const input = {
      version: "2.1.0",
      vendorRoot: true,
      runs: [
        {
          vendorRun: "kept as unknown",
          tool: { driver: { name: "ShapeScanner", rules: [{ id: "OK" }, "bad-rule"] } },
          results: [
            {
              ruleId: "OK",
              level: "error",
              locations: "not-array",
              suppressions: ["bad-suppression"],
              fixes: "not-array",
              vendorResult: 7,
            },
            "bad-result",
          ],
        },
      ],
    };

    const output = await runSarif(JSON.stringify(input));

    expect(output.observed.run_count).toBe(1);
    expect(output.observed.result_count).toBe(1);
    expect(output.observed.rule_count).toBe(1);
    expect(output.observed.unknown_top_level_keys).toEqual(["vendorRoot"]);
    expect(output.observed.unknown_run_keys).toEqual(["vendorRun"]);
    expect(output.observed.unknown_result_keys).toEqual(["vendorResult"]);
    expect(output.warnings).toContain("runs[0].tool.driver.rules[1] is string, not an object.");
    expect(output.warnings).toContain("runs[0].results[0].locations is string, not an array.");
    expect(output.warnings).toContain("runs[0].results[0].suppressions[0] is string, not an object.");
    expect(output.warnings).toContain("runs[0].results[0].fixes is string, not an array.");
    expect(output.warnings).toContain("runs[0].results[1] is string, not an object.");
  });

  it("detects mixed line endings", async () => {
    const input = '{"version":"2.1.0",\r\n"runs":[{"tool":{"driver":{"name":"Mixed"}},"results":[]}]}\n';
    const output = await runSarif(input);

    expect(output.observed.line_ending).toBe("mixed");
    expect(output.warnings).toContain("SARIF input contains mixed line endings.");
  });

  it("rejects non-string, empty, invalid JSON, non-object, missing runs, and empty runs", () => {
    expect(() => parseSarif(7 as unknown as string)).toThrow("parse_sarif input must be a string");
    expect(() => parseSarif("   ")).toThrow("parse_sarif input must not be empty");
    expect(() => parseSarif("{bad json}")).toThrow("parse_sarif input must be valid JSON");
    expect(() => parseSarif("[]")).toThrow("parse_sarif input must be a JSON object; received array");
    expect(() => parseSarif(JSON.stringify({ version: "2.1.0" }))).toThrow(
      "parse_sarif input must contain a non-empty runs array"
    );
    expect(() => parseSarif(JSON.stringify({ version: "2.1.0", runs: [] }))).toThrow(
      "parse_sarif input must contain a non-empty runs array"
    );
  });
});
