import { describe, expect, it } from "vitest";
import { formatSkillRunResult, type FormattableSkillRunResult } from "../src/runFormat.js";

function result(overrides: Partial<FormattableSkillRunResult> = {}): FormattableSkillRunResult {
  return {
    run_id: "run_test",
    status: "completed",
    skill: {
      name: "base64_encode",
      version: "0.1.0",
    },
    policy: {
      allow_network: false,
      network_used: false,
      external_sinks: [],
    },
    output: {
      encoded: "SGVsbG8=",
    },
    errors: [],
    warnings: [],
    ...overrides,
  };
}

describe("formatSkillRunResult", () => {
  it("formats JSON output as the complete structured run result", () => {
    const output = formatSkillRunResult(result(), { format: "json" });
    const parsed = JSON.parse(output) as Record<string, unknown>;

    expect(parsed).toMatchObject({
      run_id: "run_test",
      status: "completed",
      skill: { name: "base64_encode", version: "0.1.0" },
      output: { encoded: "SGVsbG8=" },
    });
  });

  it("formats pretty output with run metadata and rendered output", () => {
    const output = formatSkillRunResult(result(), { format: "pretty" });

    expect(output).toContain("Run");
    expect(output).toContain("Status: completed");
    expect(output).toContain("Skill: base64_encode@0.1.0");
    expect(output).toContain("Output");
    expect(output).toContain('"encoded": "SGVsbG8="');
  });

  it("includes warnings and errors in pretty output", () => {
    const output = formatSkillRunResult(
      result({ status: "failed", warnings: ["careful"], errors: ["boom"] }),
      { format: "pretty" }
    );

    expect(output).toContain("Warnings");
    expect(output).toContain("- careful");
    expect(output).toContain("Errors");
    expect(output).toContain("- boom");
  });


  it("defangs IOC-like values in pretty output by default", () => {
    const output = formatSkillRunResult(
      result({
        skill: { name: "extract_iocs", version: "0.1.0" },
        output: {
          urls: ["https://evil.example.com/path"],
          domains: ["evil.example.com"],
          ipv4_addresses: ["192.0.2.10"],
          email_addresses: ["admin@example.com"],
          sha256_hashes: ["2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"],
        },
      }),
      { format: "pretty" }
    );

    expect(output).toContain("Display safety: safe");
    expect(output).toContain("hxxps://evil[.]example[.]com/path");
    expect(output).toContain("evil[.]example[.]com");
    expect(output).toContain("192[.]0[.]2[.]10");
    expect(output).toContain("admin[@]example[.]com");
    expect(output).not.toContain("https://evil.example.com/path");
  });

  it("allows IOC-like values in unsafe pretty output", () => {
    const output = formatSkillRunResult(
      result({
        skill: { name: "extract_iocs", version: "0.1.0" },
        output: {
          urls: ["https://evil.example.com/path"],
          domains: ["evil.example.com"],
          ipv4_addresses: ["192.0.2.10"],
          email_addresses: ["admin@example.com"],
          sha256_hashes: [],
        },
      }),
      { format: "pretty", unsafe: true }
    );

    expect(output).toContain("Display safety: unsafe");
    expect(output).toContain("https://evil.example.com/path");
    expect(output).toContain("admin@example.com");
  });

  it("keeps JSON output canonical and unmodified", () => {
    const output = formatSkillRunResult(
      result({
        skill: { name: "extract_iocs", version: "0.1.0" },
        output: { urls: ["https://evil.example.com/path"] },
      }),
      { format: "json" }
    );
    const parsed = JSON.parse(output) as { output: { urls: string[] } };

    expect(parsed.output.urls).toEqual(["https://evil.example.com/path"]);
  });

  it("renders missing output explicitly in pretty output", () => {
    const output = formatSkillRunResult(result({ output: undefined }), {
      format: "pretty",
    });

    expect(output).toContain("(none)");
  });


  it("renders GitHub Actions workflow observations in pretty output", () => {
    const output = formatSkillRunResult(
      result({
        skill: { name: "parse_github_actions_workflow", version: "0.1.0" },
        output: {
          artifact: { id: "artifact_github_actions_workflow", type: "github_actions_workflow", name: "CI" },
          observed: {
            name: "CI",
            line_ending: "lf",
            physical_line_count: 12,
            run_name_present: false,
            job_count: 1,
            total_step_count: 2,
            uses_step_count: 1,
            run_step_count: 1,
            job_level_uses_count: 0,
            checkout_step_count: 1,
            triggers: { configured: true, value_kind: "object", event_names: ["push"], schedule_cron_count: 0 },
            top_level_keys: ["jobs", "name", "on"],
            unknown_top_level_keys: [],
            top_level_env_keys: [],
            top_level_permissions: { entries: [{ scope: "contents", value: "read" }] },
            jobs: [{ id: "build", step_count: 2, runs_on: ["ubuntu-latest"] }],
            unique_action_uses: ["actions/checkout@v4"],
            checkout_steps: [{ path: "jobs.build.steps[0]", uses: "actions/checkout@v4", persist_credentials: "false", fetch_depth: "1" }],
            referenced_contexts: ["github"],
            referenced_secret_names: [],
          },
          warnings: [],
        },
      }),
      { format: "pretty" }
    );

    expect(output).toContain("GitHub Actions Workflow");
    expect(output).toContain("Name: CI");
    expect(output).toContain("Trigger events (1)");
    expect(output).toContain("actions/checkout@v4");
  });


  it("renders TruffleHog NDJSON observations in pretty output without raw secret values", () => {
    const output = formatSkillRunResult(
      result({
        skill: { name: "parse_trufflehog_ndjson", version: "0.1.0" },
        output: {
          artifact: { id: "artifact_trufflehog_ndjson", type: "trufflehog_ndjson" },
          observed: {
            line_ending: "lf",
            physical_line_count: 2,
            ndjson_line_count: 2,
            blank_line_count: 0,
            valid_record_count: 2,
            malformed_line_count: 0,
            non_object_line_count: 0,
            verified_count: 1,
            unverified_count: 1,
            unknown_verification_count: 0,
            raw_secret_present_count: 2,
            raw_v2_secret_present_count: 0,
            redacted_secret_present_count: 1,
            detector_names: ["AWS", "GitHub"],
            decoder_names: ["PLAIN"],
            source_names: ["git"],
            repositories: ["https://github.com/example-org/example-repo.git"],
            files: ["src/config.ts"],
            file_line_refs: ["src/config.ts:42"],
            extra_data_keys: ["account"],
            structured_data_keys: [],
            unknown_top_level_keys: [],
            result_records: [
              {
                line_number: 1,
                detector_name: "AWS",
                verification_status: "verified",
                source: { file: "src/config.ts", line: 42 },
              },
            ],
          },
          warnings: [],
        },
      }),
      { format: "pretty" }
    );

    expect(output).toContain("TruffleHog NDJSON");
    expect(output).toContain("Valid records: 2");
    expect(output).toContain("Detector names (2)");
    expect(output).toContain("AWS");
    expect(output).toContain("src/config[.]ts:42");
    expect(output).not.toContain("fixture-aws-secret-value");
  });


  it("renders SARIF observations in pretty output", () => {
    const output = formatSkillRunResult(
      result({
        skill: { name: "parse_sarif", version: "0.1.0" },
        output: {
          artifact: { id: "artifact_sarif", type: "sarif", version: "2.1.0" },
          observed: {
            version: "2.1.0",
            schema_present: true,
            line_ending: "lf",
            physical_line_count: 20,
            run_count: 1,
            rule_count: 2,
            result_count: 2,
            artifact_count: 1,
            invocation_count: 1,
            taxon_count: 1,
            suppression_count: 1,
            fixes_present_count: 1,
            fingerprint_key_count: 1,
            partial_fingerprint_key_count: 1,
            tool_driver_names: ["ExampleScanner"],
            tool_extension_names: ["example-extension"],
            result_levels: { error: 1, warning: 1 },
            rule_ids: ["SEC001", "SEC002"],
            result_rule_ids: ["SEC001", "SEC002"],
            result_location_refs: ["src/app.ts:42"],
            tags: ["security"],
            taxa_ids: ["CWE-89"],
            fingerprint_keys: ["primaryLocationLineHash"],
            partial_fingerprint_keys: ["primaryLocationStartColumnFingerprint"],
            unknown_top_level_keys: [],
            runs: [{ run_index: 0, tool_driver_name: "ExampleScanner", tool_driver_version: "1.2.3", rule_count: 2, result_count: 2 }],
            results: [
              {
                run_index: 0,
                result_index: 0,
                rule_id: "SEC001",
                level: "error",
                locations: [{ uri: "src/app.ts", region_start_line: 42 }],
              },
            ],
          },
          warnings: [],
        },
      }),
      { format: "pretty" }
    );

    expect(output).toContain("SARIF");
    expect(output).toContain("Version: 2.1.0");
    expect(output).toContain("Tool drivers (1)");
    expect(output).toContain("ExampleScanner");
    expect(output).toContain("Result location refs (1)");
    expect(output).toContain("src/app[.]ts:42");
  });


  it("renders browser extension permission review signals in pretty output", () => {
    const output = formatSkillRunResult(
      result({
        skill: { name: "review_browser_extension_permissions", version: "0.1.0" },
        output: {
          artifact: {
            id: "artifact_browser_extension_permission_review",
            type: "browser_extension_permission_review",
            source_artifact_id: "artifact_browser_extension_manifest",
            source_artifact_type: "browser_extension_manifest",
            name: "Fixture Extension",
            version: "1.0.0",
            manifest_version: 3,
          },
          observed: {
            source_parser: "parse_browser_extension_manifest",
            source_warning_count: 0,
            manifest_generation: "mv3",
            evidence_count: 2,
            signal_count: 2,
            broad_host_permissions: ["<all_urls>"],
            broad_optional_host_permissions: [],
            wildcard_host_permissions: ["<all_urls>"],
            notable_api_permissions: ["tabs"],
            notable_optional_api_permissions: [],
            broad_content_script_matches: ["<all_urls>"],
            background_present: true,
            background_type: "service_worker",
            externally_connectable_present: false,
            externally_connectable_matches: [],
            web_accessible_resources_present: false,
            web_accessible_resource_count: 0,
            web_accessible_resource_matches: [],
            update_url_present: false,
            oauth2_present: false,
            content_security_policy_present: true,
          },
          evidence: [
            { id: "evidence_browser_extension_001", type: "browser_extension_broad_host_permissions" },
            { id: "evidence_browser_extension_002", type: "browser_extension_notable_api_permissions" },
          ],
          signals: [
            {
              id: "signal_browser_extension_001",
              type: "browser_extension.broad_host_permissions_present",
              summary: "Browser extension manifest declares broad required host permissions.",
              confidence: "confirmed",
              evidence_refs: ["evidence_browser_extension_001"],
            },
          ],
          warnings: [],
        },
      }),
      { format: "pretty" }
    );

    expect(output).toContain("Browser Extension Permission Review");
    expect(output).toContain("Signals: 2");
    expect(output).toContain("Broad host permissions (1)");
    expect(output).toContain("<all_urls>");
    expect(output).toContain("Notable API permissions (1)");
    expect(output).toContain("browser_extension.broad_host_permissions_present");
  });

});
