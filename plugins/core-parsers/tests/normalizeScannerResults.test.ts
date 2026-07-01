import { describe, expect, it } from "vitest";
import { normalizeScannerResults, normalizeScannerResultsSkill } from "../src/normalizeScannerResults.js";
import { parseCheckovJson } from "../src/parseCheckovJson.js";
import { parseGrypeJson } from "../src/parseGrypeJson.js";
import { parseSemgrepJson } from "../src/parseSemgrepJson.js";
import { skills } from "../src/index.js";

function semgrepJson(): string {
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
          metadata: {
            category: "security",
            confidence: "HIGH",
            cwe: ["CWE-89"],
            owasp: ["A03:2021"],
            references: ["https://semgrep.example/rules/express-sqli"],
          },
          fix: "db.query(sql, [userId])",
        },
      },
      {
        check_id: "javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp",
        path: "src/config.ts",
        start: { line: 8, col: 12 },
        extra: {
          message: "RegExp constructed from non-literal input.",
          severity: "WARNING",
          metadata: { category: "security" },
          is_ignored: true,
        },
      },
    ],
  });
}

function checkovJson(): string {
  return JSON.stringify({
    check_type: "terraform",
    results: {
      failed_checks: [
        {
          check_id: "CKV_AWS_20",
          check_name: "S3 Bucket has an ACL defined which allows public READ access.",
          check_class: "checkov.terraform.checks.resource.aws.S3PublicACLRead",
          file_path: "/main.tf",
          file_line_range: [12, 24],
          resource: "aws_s3_bucket.public",
          resource_address: "aws_s3_bucket.public",
          guideline: "https://docs.prismacloud.example/CKV_AWS_20",
          severity: "HIGH",
        },
      ],
      passed_checks: [
        {
          check_id: "CKV_AWS_21",
          check_name: "S3 Bucket has versioning enabled.",
          file_path: "/main.tf",
          file_line_range: [30, 40],
          resource: "aws_s3_bucket.logs",
          severity: "LOW",
        },
      ],
      skipped_checks: [
        {
          check_id: "CKV_AWS_999",
          check_name: "Skipped check",
          file_path: "/skip.tf",
          suppress_comment: "accepted test fixture skip",
        },
      ],
    },
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
          relatedVulnerabilities: [{ id: "GHSA-xxxx-yyyy" }],
          urls: ["https://nvd.example/CVE-2024-0001"],
        },
        artifact: {
          name: "openssl",
          version: "1.2.2",
          type: "deb",
          language: "c",
          purl: "pkg:deb/debian/openssl@1.2.2",
          locations: [{ path: "/var/lib/dpkg/status" }],
        },
        matchDetails: [{ matcher: "dpkg-matcher", type: "exact-direct-match" }],
      },
    ],
  });
}

describe("normalize_scanner_results", () => {
  it("exports the normalizer skill with local-only permissions", () => {
    expect(skills.map((skill) => skill.metadata.name)).toContain("normalize_scanner_results");
    expect(normalizeScannerResultsSkill.metadata).toMatchObject({
      name: "normalize_scanner_results",
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

  it("normalizes parsed Semgrep observations without scoring them", () => {
    const output = normalizeScannerResults(parseSemgrepJson(semgrepJson()));

    expect(output.artifact).toEqual({
      id: "artifact_normalized_scanner_results",
      type: "normalized_scanner_results",
      source_artifact_id: "artifact_semgrep_json",
      source_artifact_type: "semgrep_json",
      scanner: "semgrep",
    });
    expect(output.observed.source_parser).toBe("parse_semgrep_json");
    expect(output.observed.scanner_family).toBe("sast");
    expect(output.observed.normalized_result_count).toBe(2);
    expect(output.observed.normalized_severities).toEqual({ high: 1, medium: 1 });
    expect(output.observed.normalized_statuses).toEqual({ ignored: 1, observed: 1 });
    expect(output.observed.fix_available_count).toBe(1);
    expect(output.observed.cwe_ids).toEqual(["CWE-89"]);
    expect(output.observed.results[0]).toMatchObject({
      scanner: "semgrep",
      result_kind: "code_scan_result",
      rule_id: "typescript.express.security.audit.express-sqli.express-sqli",
      file_path: "src/app.ts",
      start_line: 42,
      normalized_severity: "high",
      normalized_status: "observed",
      fix_available: true,
    });
  });

  it("normalizes parsed Checkov observations", () => {
    const output = normalizeScannerResults(parseCheckovJson(checkovJson()));

    expect(output.observed.source_parser).toBe("parse_checkov_json");
    expect(output.observed.scanner_family).toBe("iac");
    expect(output.observed.normalized_result_count).toBe(3);
    expect(output.observed.failed_count).toBe(1);
    expect(output.observed.passed_count).toBe(1);
    expect(output.observed.skipped_count).toBe(1);
    expect(output.observed.suppressed_count).toBe(1);
    expect(output.observed.results[0]).toMatchObject({
      scanner: "checkov",
      result_kind: "iac_check_result",
      rule_id: "CKV_AWS_20",
      resource: "aws_s3_bucket.public",
      normalized_severity: "high",
      normalized_status: "failed",
    });
  });

  it("normalizes parsed Grype observations", () => {
    const output = normalizeScannerResults(parseGrypeJson(grypeJson()));

    expect(output.observed.source_parser).toBe("parse_grype_json");
    expect(output.observed.scanner_family).toBe("sca");
    expect(output.observed.normalized_result_count).toBe(1);
    expect(output.observed.vulnerability_ids).toEqual(["CVE-2024-0001"]);
    expect(output.observed.package_names).toEqual(["openssl"]);
    expect(output.observed.fix_available_count).toBe(1);
    expect(output.observed.results[0]).toMatchObject({
      scanner: "grype",
      result_kind: "vulnerability_match",
      package_name: "openssl",
      package_version: "1.2.2",
      vulnerability_id: "CVE-2024-0001",
      normalized_severity: "critical",
      normalized_status: "observed",
    });
  });

  it("accepts JSON run results from parser skills", () => {
    const parsed = parseSemgrepJson(semgrepJson());
    const output = normalizeScannerResults(JSON.stringify({ output: parsed }));

    expect(output.observed.source_parser).toBe("parse_semgrep_json");
    expect(output.observed.normalized_result_count).toBe(2);
  });

  it("rejects unsupported input shapes", () => {
    expect(() => normalizeScannerResults("not json")).toThrow("normalize_scanner_results input must be parsed scanner output");
    expect(() => normalizeScannerResults({ artifact: { type: "sarif" }, observed: {} })).toThrow(
      "normalize_scanner_results input artifact.type must be semgrep_json, checkov_json, or grype_json",
    );
    expect(() => normalizeScannerResults({ artifact: { type: "semgrep_json" } })).toThrow(
      "normalize_scanner_results input must contain artifact and observed objects",
    );
  });
});
