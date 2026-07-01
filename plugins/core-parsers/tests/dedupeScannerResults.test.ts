import { describe, expect, it } from "vitest";
import { dedupeScannerResults, dedupeScannerResultsSkill } from "../src/dedupeScannerResults.js";
import { normalizeScannerResults } from "../src/normalizeScannerResults.js";
import { parseSemgrepJson } from "../src/parseSemgrepJson.js";
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
        },
      },
    ],
  });
}

describe("dedupe_scanner_results", () => {
  it("exports the dedupe skill with local-only permissions", () => {
    expect(skills.map((skill) => skill.metadata.name)).toContain("dedupe_scanner_results");
    expect(dedupeScannerResultsSkill.metadata).toMatchObject({
      name: "dedupe_scanner_results",
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

  it("deduplicates normalized scanner observations while preserving source refs", () => {
    const normalized = normalizeScannerResults(parseSemgrepJson(duplicatedSemgrepJson()));
    const output = dedupeScannerResults(normalized);

    expect(output.artifact).toEqual({
      id: "artifact_deduped_scanner_results",
      type: "deduped_scanner_results",
      source_artifact_id: "artifact_normalized_scanner_results",
      source_artifact_type: "normalized_scanner_results",
    });
    expect(output.observed.source_normalizer).toBe("normalize_scanner_results");
    expect(output.observed.source_result_count).toBe(3);
    expect(output.observed.unique_result_count).toBe(2);
    expect(output.observed.duplicate_result_count).toBe(1);
    expect(output.observed.duplicate_group_count).toBe(1);
    expect(output.observed.normalized_severities).toEqual({ high: 1, medium: 1 });
    expect(output.observed.duplicate_groups[0]).toMatchObject({
      duplicate_count: 2,
      source_result_refs: ["semgrep.results[0]", "semgrep.results[1]"],
    });
    expect(output.observed.deduped_results[0]?.representative_result).toMatchObject({
      scanner: "semgrep",
      rule_id: "javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp",
    });
  });

  it("accepts JSON run results from normalize_scanner_results", () => {
    const normalized = normalizeScannerResults(parseSemgrepJson(duplicatedSemgrepJson()));
    const output = dedupeScannerResults(JSON.stringify({ output: normalized }));

    expect(output.observed.source_result_count).toBe(3);
    expect(output.observed.unique_result_count).toBe(2);
  });

  it("rejects unsupported input shapes", () => {
    expect(() => dedupeScannerResults("not json")).toThrow("dedupe_scanner_results input must be normalize_scanner_results output");
    expect(() => dedupeScannerResults({ artifact: { type: "semgrep_json" }, observed: {} })).toThrow(
      "dedupe_scanner_results input artifact.type must be normalized_scanner_results",
    );
    expect(() => dedupeScannerResults({ artifact: { type: "normalized_scanner_results" } })).toThrow(
      "dedupe_scanner_results input must contain artifact and observed objects",
    );
  });
});
