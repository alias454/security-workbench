import { describe, expect, it } from "vitest";
import {
  reviewStaticAnalysisResults,
  reviewStaticAnalysisResultsSkill,
} from "../src/reviewStaticAnalysisResults.js";

const parsedSarifOutput = {
  artifact: {
    id: "artifact_sarif",
    type: "sarif",
    version: "2.1.0",
  },
  observed: {
    run_count: 1,
    tool_driver_names: ["CodeQL"],
    rule_count: 2,
    result_count: 2,
    result_levels: { error: 1, warning: 1 },
    results: [
      {
        run_index: 0,
        result_index: 0,
        rule_id: "js/sql-injection",
        level: "error",
        kind: "fail",
        baseline_state: "new",
        message_text: "Query depends on request input.",
        location_count: 1,
        locations: [
          {
            uri: "src/app.ts",
            region_start_line: 42,
            logical_location_names: ["handler.login"],
          },
        ],
        suppression_count: 0,
        fix_count: 1,
        fixes_present: true,
        taxa_ids: ["CWE-89"],
        fingerprint_keys: ["primaryLocationLineHash"],
        partial_fingerprint_keys: [],
      },
      {
        run_index: 0,
        result_index: 1,
        rule_id: "js/hardcoded-credential",
        level: "warning",
        kind: "fail",
        baseline_state: "unchanged",
        message_text: "Hard-coded credential-like value.",
        location_count: 1,
        locations: [
          {
            uri: "src/config.ts",
            region_start_line: 7,
            logical_location_names: [],
          },
        ],
        suppression_count: 1,
        fix_count: 0,
        fixes_present: false,
        taxa_ids: ["CWE-798"],
        fingerprint_keys: [],
        partial_fingerprint_keys: ["primaryLocationStartColumnFingerprint"],
      },
    ],
  },
  warnings: [],
} as const;

describe("review_static_analysis_results", () => {
  it("exports the reviewer skill with local-only permissions", () => {
    expect(reviewStaticAnalysisResultsSkill.metadata.name).toBe("review_static_analysis_results");
    expect(reviewStaticAnalysisResultsSkill.metadata.category).toBe("reviewer");
    expect(reviewStaticAnalysisResultsSkill.metadata.execution).toEqual({
      mode: "local_only",
      network_access: "none",
      deterministic: true,
    });
    expect(reviewStaticAnalysisResultsSkill.metadata.permissions).toEqual({
      network: "none",
      filesystem: "none",
      sends: [],
      persists: false,
      runs_external_binaries: false,
    });
  });

  it("emits evidence-backed signals for parsed SARIF results", () => {
    const output = reviewStaticAnalysisResults(parsedSarifOutput);

    expect(output.artifact).toMatchObject({
      type: "static_analysis_review",
      source_artifact_id: "artifact_sarif",
      source_artifact_type: "sarif",
      source_format: "sarif",
      source_version: "2.1.0",
    });
    expect(output.observed.reviewed_result_count).toBe(2);
    expect(output.observed.high_attention_result_count).toBe(1);
    expect(output.observed.informational_result_count).toBe(1);
    expect(output.observed.fix_available_count).toBe(1);
    expect(output.observed.new_result_count).toBe(1);
    expect(output.observed.affected_artifact_uris).toEqual(["src/app.ts", "src/config.ts"]);
    expect(output.observed.affected_rule_ids).toEqual(["js/hardcoded-credential", "js/sql-injection"]);
    expect(output.evidence.length).toBe(2);
    expect(output.signals.length).toBe(2);
    expect(output.signals.map((signal) => signal.type)).toEqual([
      "static_analysis.high_attention_result_present",
      "static_analysis.suppressed_result_present",
    ]);
    expect(output.signals.every((signal) => signal.evidence_refs.length > 0)).toBe(true);
  });

  it("accepts a JSON run result from parse_sarif", () => {
    const runResult = {
      run_id: "run_parser",
      status: "completed",
      skill: { name: "parse_sarif", version: "0.1.0" },
      output: parsedSarifOutput,
      errors: [],
      warnings: [],
    };

    const output = reviewStaticAnalysisResults(JSON.stringify(runResult));

    expect(output.observed.source_parser).toBe("parse_sarif");
    expect(output.observed.tool_driver_names).toEqual(["CodeQL"]);
  });

  it("returns no signals for parsed SARIF with no results", () => {
    const output = reviewStaticAnalysisResults({
      artifact: { id: "artifact_sarif", type: "sarif", version: "2.1.0" },
      observed: {
        run_count: 1,
        tool_driver_names: ["MinimalScanner"],
        rule_count: 0,
        result_count: 0,
        result_levels: {},
        results: [],
      },
      warnings: [],
    });

    expect(output.signals).toEqual([]);
    expect(output.evidence).toEqual([]);
    expect(output.observed.signal_count).toBe(0);
  });

  it("rejects non-SARIF parser output", () => {
    expect(() =>
      reviewStaticAnalysisResults({
        artifact: { id: "artifact_package_json", type: "package_json" },
        observed: {},
        warnings: [],
      }),
    ).toThrow("review_static_analysis_results input artifact.type must be sarif");
  });
});
