import { describe, expect, it } from "vitest";
import { normalizeScannerResults } from "../src/normalizeScannerResults.js";
import { parseGrypeJson } from "../src/parseGrypeJson.js";
import { parseSemgrepJson } from "../src/parseSemgrepJson.js";
import { mergeScannerResults, mergeScannerResultsSkill } from "../src/mergeScannerResults.js";
import { skills } from "../src/index.js";

function semgrepJson(): string {
  return JSON.stringify({
    version: "1.75.0",
    results: [
      {
        check_id: "typescript.express.security.audit.express-sqli.express-sqli",
        path: "src/app.ts",
        start: { line: 42, col: 7 },
        extra: {
          message: "Detected string-built SQL query.",
          severity: "ERROR",
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

function grypeJson(): string {
  return JSON.stringify({
    matches: [
      {
        vulnerability: {
          id: "CVE-2024-0001",
          namespace: "nvd:cpe",
          severity: "Critical",
          fix: { state: "fixed", versions: ["1.2.3"] },
          urls: ["https://nvd.example/CVE-2024-0001"],
        },
        artifact: {
          name: "openssl",
          version: "1.2.2",
          type: "deb",
          purl: "pkg:deb/debian/openssl@1.2.2",
          locations: [{ path: "/var/lib/dpkg/status" }],
        },
        matchDetails: [{ matcher: "dpkg-matcher", type: "exact-direct-match" }],
      },
    ],
  });
}

describe("merge_scanner_results", () => {
  it("exports the merge skill with local-only permissions", () => {
    expect(skills.map((skill) => skill.metadata.name)).toContain("merge_scanner_results");
    expect(mergeScannerResultsSkill.metadata).toMatchObject({
      name: "merge_scanner_results",
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

  it("merges scanner observations across normalized scanner outputs", () => {
    const semgrep = normalizeScannerResults(parseSemgrepJson(semgrepJson()));
    const grype = normalizeScannerResults(parseGrypeJson(grypeJson()));
    const output = mergeScannerResults([semgrep, semgrep, grype]);

    expect(output.artifact).toEqual({
      id: "artifact_merged_scanner_results",
      type: "merged_scanner_results",
      source_artifact_type: "scanner_result_collection",
    });
    expect(output.observed.source_input_count).toBe(3);
    expect(output.observed.source_record_count).toBe(5);
    expect(output.observed.source_observation_count).toBe(5);
    expect(output.observed.merged_result_count).toBe(3);
    expect(output.observed.duplicate_result_count).toBe(2);
    expect(output.observed.duplicate_group_count).toBe(2);
    expect(output.observed.scanners).toEqual(["grype", "semgrep"]);
    expect(output.observed.normalized_severities).toEqual({ critical: 1, high: 1, medium: 1 });
    expect(output.observed.vulnerability_ids).toEqual(["CVE-2024-0001"]);
    expect(output.observed.merged_results.find((result) => result.scanners.includes("grype"))).toMatchObject({
      duplicate_count: 1,
      vulnerability_ids: ["CVE-2024-0001"],
    });
  });

  it("accepts JSON with an inputs array", () => {
    const semgrep = normalizeScannerResults(parseSemgrepJson(semgrepJson()));
    const grype = normalizeScannerResults(parseGrypeJson(grypeJson()));
    const output = mergeScannerResults(JSON.stringify({ inputs: [{ output: semgrep }, { output: grype }] }));

    expect(output.observed.source_input_count).toBe(2);
    expect(output.observed.merged_result_count).toBe(3);
  });

  it("rejects unsupported input shapes", () => {
    expect(() => mergeScannerResults("not json")).toThrow("merge_scanner_results input must be scanner result output");
    expect(() => mergeScannerResults({ artifact: { type: "semgrep_json" }, observed: {} })).toThrow(
      "merge_scanner_results input 0 artifact.type must be normalized_scanner_results or deduped_scanner_results",
    );
    expect(() => mergeScannerResults({ artifact: { type: "normalized_scanner_results" } })).toThrow(
      "merge_scanner_results input 0 must contain artifact and observed objects",
    );
  });
});
