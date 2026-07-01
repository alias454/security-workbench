import { describe, expect, it } from "vitest";
import { dedupeScannerResults } from "../src/dedupeScannerResults.js";
import { normalizeScannerResults } from "../src/normalizeScannerResults.js";
import { parseSemgrepJson } from "../src/parseSemgrepJson.js";
import { scannerSummary, scannerSummarySkill } from "../src/scannerSummary.js";
import { skills } from "../src/index.js";

function duplicatedSemgrepJson(): string {
  return JSON.stringify({
    version: "1.75.0",
    results: [
      {
        check_id: "typescript.express.security.audit.express-sqli.express-sqli",
        path: "src/app.ts",
        start: { line: 42, col: 7 },
        end: { line: 42, col: 28 },
        extra: {
          message: "Detected string-built SQL query.",
          severity: "ERROR",
          metadata: { cwe: ["CWE-89"] },
        },
      },
      {
        check_id: "typescript.express.security.audit.express-sqli.express-sqli",
        path: "src/app.ts",
        start: { line: 42, col: 7 },
        end: { line: 42, col: 28 },
        extra: {
          message: "Detected string-built SQL query.",
          severity: "ERROR",
          metadata: { cwe: ["CWE-89"] },
        },
      },
      {
        check_id: "javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp",
        path: "src/config.ts",
        start: { line: 8, col: 12 },
        extra: {
          message: "RegExp constructed from non-literal input.",
          severity: "WARNING",
          is_ignored: true,
        },
      },
    ],
  });
}

describe("scanner_summary", () => {
  it("exports the summary skill with local-only permissions", () => {
    expect(skills.map((skill) => skill.metadata.name)).toContain("scanner_summary");
    expect(scannerSummarySkill.metadata).toMatchObject({
      name: "scanner_summary",
      category: "transform",
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
    });
  });

  it("summarizes deduped scanner observations without scoring them", () => {
    const normalized = normalizeScannerResults(parseSemgrepJson(duplicatedSemgrepJson()));
    const deduped = dedupeScannerResults(normalized);
    const output = scannerSummary(deduped);

    expect(output.artifact).toEqual({
      id: "artifact_scanner_summary",
      type: "scanner_summary",
      source_artifact_id: "artifact_deduped_scanner_results",
      source_artifact_type: "deduped_scanner_results",
    });
    expect(output.observed.summary_template).toBe("scanner_summary_v1");
    expect(output.observed.source_result_count).toBe(3);
    expect(output.observed.summarized_result_count).toBe(2);
    expect(output.observed.duplicate_result_count).toBe(1);
    expect(output.observed.scanners).toEqual(["semgrep"]);
    expect(output.observed.normalized_severities).toEqual({ high: 1, medium: 1 });
    expect(output.observed.normalized_statuses).toEqual({ ignored: 1, observed: 1 });
    expect(output.observed.ignored_count).toBe(1);
    expect(output.observed.rule_count).toBe(2);
    expect(output.observed.file_path_count).toBe(2);
    expect(output.observed.limitations.join(" ")).toContain("not risk scoring");
    expect(output.observed.summary_records[0]).toMatchObject({
      scanner: "semgrep",
      duplicate_count: 1,
    });
  });

  it("accepts JSON run results from dedupe_scanner_results", () => {
    const normalized = normalizeScannerResults(parseSemgrepJson(duplicatedSemgrepJson()));
    const deduped = dedupeScannerResults(normalized);
    const output = scannerSummary(JSON.stringify({ output: deduped }));

    expect(output.observed.summarized_result_count).toBe(2);
  });

  it("rejects unsupported input shapes", () => {
    expect(() => scannerSummary("not json")).toThrow("scanner_summary input must be normalized");
    expect(() => scannerSummary({ artifact: { type: "semgrep_json" }, observed: {} })).toThrow(
      "scanner_summary input artifact.type must be normalized_scanner_results, deduped_scanner_results, or merged_scanner_results",
    );
    expect(() => scannerSummary({ artifact: { type: "deduped_scanner_results" } })).toThrow(
      "scanner_summary input must contain artifact and observed objects",
    );
  });
});
