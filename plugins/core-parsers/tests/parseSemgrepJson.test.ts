import { describe, expect, it } from "vitest";
import { parseSemgrepJson, parseSemgrepJsonSkill } from "../src/parseSemgrepJson.js";
import { skills } from "../src/index.js";

function sampleSemgrepJson(): string {
  return JSON.stringify({
    version: "1.75.0",
    paths: {
      scanned: ["src/app.ts", "src/config.ts"],
      skipped: [{ path: "dist/bundle.js", reason: "ignored", details: "matched .semgrepignore" }],
    },
    results: [
      {
        check_id: "typescript.express.security.audit.express-sqli.express-sqli",
        path: "src/app.ts",
        start: { line: 42, col: 7, offset: 1200 },
        end: { line: 42, col: 28, offset: 1221 },
        fingerprint: "abc123",
        extra: {
          message: "Detected string-built SQL query.",
          severity: "ERROR",
          metadata: {
            category: "security",
            confidence: "HIGH",
            impact: "HIGH",
            likelihood: "MEDIUM",
            technology: ["express", "typescript"],
            cwe: ["CWE-89"],
            owasp: ["A03:2021"],
            references: ["https://semgrep.example/rules/express-sqli"],
          },
          fix: "db.query(sql, [userId])",
          validation_state: "NO_VALIDATOR",
        },
      },
      {
        check_id: "javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp",
        path: "src/config.ts",
        start: { line: 8, col: 12 },
        end: { line: 8, col: 31 },
        extra: {
          message: "RegExp constructed from non-literal input.",
          severity: "WARNING",
          metadata: {
            category: "security",
            confidence: "MEDIUM",
            technology: ["javascript"],
          },
          is_ignored: true,
        },
      },
    ],
    errors: [{ code: 2, level: "warn", type: "Syntax error", message: "Could not parse file", path: "src/bad.ts" }],
  });
}

describe("parse_semgrep_json", () => {
  it("exports the parser skill with local-only permissions", () => {
    expect(skills.map((skill) => skill.metadata.name)).toContain("parse_semgrep_json");
    expect(parseSemgrepJsonSkill.metadata).toMatchObject({
      name: "parse_semgrep_json",
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
    });
  });

  it("parses Semgrep results, metadata, paths, skipped paths, and errors", async () => {
    const output = parseSemgrepJson(sampleSemgrepJson());

    expect(output.artifact).toEqual({ id: "artifact_semgrep_json", type: "semgrep_json", version: "1.75.0" });
    expect(output.observed.result_count).toBe(2);
    expect(output.observed.error_count).toBe(1);
    expect(output.observed.scanned_path_count).toBe(2);
    expect(output.observed.skipped_path_count).toBe(1);
    expect(output.observed.rule_ids).toEqual([
      "javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp",
      "typescript.express.security.audit.express-sqli.express-sqli",
    ]);
    expect(output.observed.paths).toEqual(["src/app.ts", "src/config.ts"]);
    expect(output.observed.severities).toEqual({ ERROR: 1, WARNING: 1 });
    expect(output.observed.confidences).toEqual(["HIGH", "MEDIUM"]);
    expect(output.observed.categories).toEqual(["security"]);
    expect(output.observed.technologies).toEqual(["express", "javascript", "typescript"]);
    expect(output.observed.cwe_ids).toEqual(["CWE-89"]);
    expect(output.observed.owasp_ids).toEqual(["A03:2021"]);
    expect(output.observed.ignored_count).toBe(1);
    expect(output.observed.fix_present_count).toBe(1);
    expect(output.observed.fingerprint_present_count).toBe(1);
    expect(output.observed.results[0]).toMatchObject({
      check_id: "typescript.express.security.audit.express-sqli.express-sqli",
      path: "src/app.ts",
      message: "Detected string-built SQL query.",
      severity: "ERROR",
      confidence: "HIGH",
      category: "security",
      fix_present: true,
      fingerprint_present: true,
    });
    expect(output.observed.results[0]?.start).toEqual({ line: 42, column: 7, offset: 1200 });
    expect(output.observed.errors[0]).toMatchObject({ code: "2", level: "warn", path: "src/bad.ts" });
    expect(output.warnings).toEqual([]);
  });

  it("rejects malformed and unsupported input", () => {
    expect(() => parseSemgrepJson("not json")).toThrow("parse_semgrep_json input must be valid JSON");
    expect(() => parseSemgrepJson("[]")).toThrow("parse_semgrep_json input must be a JSON object");
    expect(() => parseSemgrepJson('{"version":"1.0.0"}')).toThrow('parse_semgrep_json input must contain a "results" array');
  });

  it("warns on malformed optional result and error shapes while preserving object entries", () => {
    const output = parseSemgrepJson(JSON.stringify({
      results: [
        { check_id: "rule.one", path: "a.ts", extra: { severity: "INFO", custom: true } },
        "bad",
      ],
      errors: [{ message: "warning", extra: true }, null],
      paths: { skipped: ["generated.js"] },
    }));

    expect(output.observed.result_count).toBe(1);
    expect(output.observed.error_count).toBe(1);
    expect(output.observed.skipped_paths).toEqual([{ path: "generated.js", reason: null, details: null }]);
    expect(output.observed.unknown_error_keys).toEqual(["extra"]);
    expect(output.warnings).toContain('Semgrep field "results" contains non-object entries that were ignored.');
    expect(output.warnings).toContain('Semgrep field "errors" should be an array of objects when present.');
    expect(output.warnings).toContain("Semgrep result extra contains unrecognized keys: custom.");
  });
});
