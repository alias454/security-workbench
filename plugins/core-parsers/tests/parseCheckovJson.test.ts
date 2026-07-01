import { describe, expect, it } from "vitest";
import { parseCheckovJson, parseCheckovJsonSkill } from "../src/parseCheckovJson.js";
import { skills } from "../src/index.js";

function sampleCheckovJson(): string {
  return JSON.stringify({
    check_type: "terraform",
    results: {
      failed_checks: [
        {
          check_id: "CKV_AWS_20",
          bc_check_id: "BC_AWS_NETWORKING_4",
          check_name: "S3 Bucket has an ACL defined which allows public READ access.",
          check_class: "checkov.terraform.checks.resource.aws.S3PublicACLRead",
          file_path: "/main.tf",
          repo_file_path: "/main.tf",
          file_line_range: [12, 22],
          resource: "aws_s3_bucket.public",
          resource_address: "aws_s3_bucket.public",
          guideline: "https://docs.bridgecrew.io/docs/s3_1-acl-read-permissions-everyone",
          severity: "HIGH",
          evaluations: { acl: "public-read" },
          code_block: [[12, "resource \"aws_s3_bucket\" \"public\" {"]],
        },
      ],
      passed_checks: [
        {
          check_id: "CKV_AWS_21",
          check_name: "S3 bucket has versioning enabled",
          file_path: "/main.tf",
          file_line_range: [24, 30],
          resource: "aws_s3_bucket.versioned",
          severity: "LOW",
        },
      ],
      skipped_checks: [
        {
          check_id: "CKV_AWS_18",
          check_name: "S3 bucket access logging is enabled",
          file_path: "/main.tf",
          file_line_range: [32, 40],
          resource: "aws_s3_bucket.logs",
          suppress_comment: "accepted for test fixture",
        },
      ],
      parsing_errors: ["bad.tf"],
    },
    summary: { passed: 1, failed: 1, skipped: 1, parsing_errors: 1 },
  });
}

describe("parse_checkov_json", () => {
  it("exports the parser skill with local-only permissions", () => {
    expect(skills.map((skill) => skill.metadata.name)).toContain("parse_checkov_json");
    expect(parseCheckovJsonSkill.metadata).toMatchObject({
      name: "parse_checkov_json",
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

  it("parses Checkov checks, statuses, paths, resources, and parsing errors", async () => {
    const output = parseCheckovJson(sampleCheckovJson());

    expect(output.artifact).toEqual({ id: "artifact_checkov_json", type: "checkov_json", check_type: "terraform" });
    expect(output.observed.check_type).toBe("terraform");
    expect(output.observed.result_count).toBe(3);
    expect(output.observed.failed_count).toBe(1);
    expect(output.observed.passed_count).toBe(1);
    expect(output.observed.skipped_count).toBe(1);
    expect(output.observed.parsing_error_count).toBe(1);
    expect(output.observed.statuses).toEqual({ failed: 1, passed: 1, skipped: 1 });
    expect(output.observed.severities).toEqual({ HIGH: 1, LOW: 1, unknown: 1 });
    expect(output.observed.check_ids).toEqual(["CKV_AWS_18", "CKV_AWS_20", "CKV_AWS_21"]);
    expect(output.observed.file_paths).toEqual(["/main.tf"]);
    expect(output.observed.resources).toEqual([
      "aws_s3_bucket.logs",
      "aws_s3_bucket.public",
      "aws_s3_bucket.versioned",
    ]);
    expect(output.observed.results[0]).toMatchObject({
      status: "failed",
      check_id: "CKV_AWS_20",
      resource: "aws_s3_bucket.public",
      severity: "HIGH",
      evaluations_present: true,
      code_block_present: true,
      file_line_range: { start: 12, end: 22 },
    });
    expect(output.observed.parsing_errors).toEqual([{ error_index: 0, value: "bad.tf" }]);
    expect(output.warnings).toEqual([]);
  });

  it("rejects malformed and unsupported input", () => {
    expect(() => parseCheckovJson("not json")).toThrow("parse_checkov_json input must be valid JSON");
    expect(() => parseCheckovJson("[]")).toThrow("parse_checkov_json input must be a JSON object");
    expect(() => parseCheckovJson('{"check_type":"terraform"}')).toThrow('parse_checkov_json input must contain a "results" object');
  });

  it("warns on malformed optional result shapes", () => {
    const output = parseCheckovJson(JSON.stringify({
      check_type: "terraform",
      results: {
        failed_checks: [{ check_id: "CKV_TEST", extra: true }, "bad"],
        passed_checks: {},
        custom: [],
      },
    }));

    expect(output.observed.result_count).toBe(1);
    expect(output.observed.unknown_result_keys).toEqual(["extra"]);
    expect(output.warnings).toContain('Checkov results field "failed_checks" contains 1 non-object entries that were ignored.');
    expect(output.warnings).toContain('Checkov results field "passed_checks" should be an array when present.');
    expect(output.warnings).toContain('Checkov results object contains unrecognized key "custom".');
  });
});
