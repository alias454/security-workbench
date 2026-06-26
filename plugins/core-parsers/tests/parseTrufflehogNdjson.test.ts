import { describe, expect, it } from "vitest";
import { parseTrufflehogNdjson, parseTrufflehogNdjsonSkill } from "../src/parseTrufflehogNdjson.js";
import { skills } from "../src/index.js";

async function runTrufflehog(input: string) {
  return await parseTrufflehogNdjsonSkill.run(input);
}

describe("parse_trufflehog_ndjson", () => {
  it("exports the parser skill with local-only permissions", () => {
    expect(skills.map((skill) => skill.metadata.name)).toContain("parse_trufflehog_ndjson");
    expect(parseTrufflehogNdjsonSkill.metadata).toMatchObject({
      name: "parse_trufflehog_ndjson",
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

  it("parses common TruffleHog result records", async () => {
    const firstRaw = "fixture-aws-secret-value";
    const input = [
      JSON.stringify({
        SourceMetadata: {
          Data: {
            Git: {
              repository: "https://github.com/example-org/example-repo.git",
              file: "src/config.ts",
              line: 42,
              commit: "abc123",
            },
          },
        },
        SourceID: 7,
        SourceType: 16,
        SourceName: "git",
        DetectorType: 2,
        DetectorName: "AWS",
        DecoderName: "PLAIN",
        Verified: true,
        Raw: firstRaw,
        Redacted: "AKIA****************",
        ExtraData: {
          account: "123456789012",
          region: "us-east-1",
        },
      }),
      JSON.stringify({
        SourceMetadata: {
          Data: {
            Git: {
              repository: "https://github.com/example-org/example-repo.git",
              file: "scripts/deploy.sh",
              line: "8",
            },
          },
        },
        SourceType: "git",
        SourceName: "git",
        DetectorName: "GitHub",
        DecoderName: "BASE64",
        Verified: false,
        RawV2: "fixture-github-token-value",
      }),
    ].join("\n");

    const output = await runTrufflehog(input);

    expect(output.artifact).toEqual({ id: "artifact_trufflehog_ndjson", type: "trufflehog_ndjson" });
    expect(output.observed.valid_record_count).toBe(2);
    expect(output.observed.detector_names).toEqual(["AWS", "GitHub"]);
    expect(output.observed.decoder_names).toEqual(["BASE64", "PLAIN"]);
    expect(output.observed.source_names).toEqual(["git"]);
    expect(output.observed.repositories).toEqual(["https://github.com/example-org/example-repo.git"]);
    expect(output.observed.files).toEqual(["scripts/deploy.sh", "src/config.ts"]);
    expect(output.observed.file_line_refs).toEqual(["scripts/deploy.sh:8", "src/config.ts:42"]);
    expect(output.observed.verified_count).toBe(1);
    expect(output.observed.unverified_count).toBe(1);
    expect(output.observed.unknown_verification_count).toBe(0);
    expect(output.observed.raw_secret_present_count).toBe(1);
    expect(output.observed.raw_v2_secret_present_count).toBe(1);
    expect(output.observed.redacted_secret_present_count).toBe(1);
    expect(output.observed.extra_data_keys).toEqual(["account", "region"]);
    expect(output.observed.source_metadata_keys).toContain("Data.Git.repository");
    expect(output.warnings).toEqual([]);
  });

  it("does not emit raw secret values", async () => {
    const rawSecret = "fixture-very-sensitive-token-value";
    const output = await runTrufflehog(JSON.stringify({
      DetectorName: "Generic",
      Verified: true,
      Raw: rawSecret,
    }));

    const record = output.observed.result_records[0];
    expect(record?.secret.raw_present).toBe(true);
    expect(record?.secret.raw_length).toBe(rawSecret.length);
    expect(record?.secret.raw_sha256).toMatch(/^[a-f0-9]{64}$/);
    expect(record?.secret.redacted_value).toBe(`[REDACTED:${rawSecret.length}]`);
    expect(record?.secret.redacted_generated).toBe(true);
    expect(JSON.stringify(output)).not.toContain(rawSecret);
  });

  it("observes source metadata variants and structured-data keys", async () => {
    const output = await runTrufflehog(JSON.stringify({
      SourceMetadata: {
        Data: {
          S3: {
            bucket: "example-fixtures",
            key: "configs/app.env",
            link: "https://s3.example.com/example-fixtures/configs/app.env",
          },
        },
      },
      SourceID: "s3-source",
      SourceType: "s3",
      SourceName: "s3 bucket",
      DetectorName: "PrivateKey",
      Verified: null,
      Redacted: "-----BEGIN ******** KEY-----",
      StructuredData: {
        algorithm: "rsa",
        block_type: "private key",
      },
    }));

    expect(output.observed.source_types).toEqual(["s3"]);
    expect(output.observed.unknown_verification_count).toBe(1);
    expect(output.observed.structured_data_keys).toEqual(["algorithm", "block_type"]);
    expect(output.observed.result_records[0]?.source).toMatchObject({
      bucket: "example-fixtures",
      key: "configs/app.env",
      link: "https://s3.example.com/example-fixtures/configs/app.env",
    });
  });

  it("preserves malformed lines and non-object lines as warnings", async () => {
    const output = await runTrufflehog([
      JSON.stringify({ DetectorName: "AWS", Verified: true, Raw: "fixture-one" }),
      "{bad json}",
      JSON.stringify(["array"]),
      "   ",
      JSON.stringify({ DetectorName: "Slack", Verified: false, Raw: "fixture-two" }),
    ].join("\n"));

    expect(output.observed.valid_record_count).toBe(2);
    expect(output.observed.malformed_line_count).toBe(1);
    expect(output.observed.non_object_line_count).toBe(1);
    expect(output.observed.blank_line_count).toBe(1);
    expect(output.warnings).toContain("TruffleHog NDJSON line 2 is not valid JSON.");
    expect(output.warnings).toContain("TruffleHog NDJSON line 3 is array, not an object.");
  });

  it("detects mixed line endings", async () => {
    const output = await runTrufflehog(`${JSON.stringify({ DetectorName: "AWS" })}\r\n${JSON.stringify({ DetectorName: "Slack" })}\n`);

    expect(output.observed.line_ending).toBe("mixed");
    expect(output.warnings).toContain("TruffleHog NDJSON input contains mixed line endings.");
  });

  it("preserves unknown top-level keys", async () => {
    const output = await runTrufflehog(JSON.stringify({
      DetectorName: "CustomDetector",
      Verified: "true",
      Raw: "fixture-custom-secret",
      CustomField: "custom value",
      AnotherVendorField: 123,
    }));

    expect(output.observed.verified_count).toBe(1);
    expect(output.observed.unknown_top_level_keys).toEqual(["AnotherVendorField", "CustomField"]);
    expect(output.observed.result_records[0]?.unknown_top_level_keys).toEqual(["AnotherVendorField", "CustomField"]);
  });

  it("handles case-insensitive common field names", async () => {
    const output = await runTrufflehog(JSON.stringify({
      detectorname: "LowercaseDetector",
      sourcename: "filesystem",
      verified: false,
      raw: "fixture-lowercase-secret",
    }));

    expect(output.observed.detector_names).toEqual(["LowercaseDetector"]);
    expect(output.observed.source_names).toEqual(["filesystem"]);
    expect(output.observed.unverified_count).toBe(1);
    expect(output.observed.raw_secret_present_count).toBe(1);
  });

  it("rejects non-string, empty, and inputs with no valid records", () => {
    expect(() => parseTrufflehogNdjson(7 as unknown as string)).toThrow("parse_trufflehog_ndjson input must be a string");
    expect(() => parseTrufflehogNdjson("   ")).toThrow("parse_trufflehog_ndjson input must not be empty");
    expect(() => parseTrufflehogNdjson("{bad json}\n[]")).toThrow(
      "parse_trufflehog_ndjson input did not contain any valid result records"
    );
  });
});
