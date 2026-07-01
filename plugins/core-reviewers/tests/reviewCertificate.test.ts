import { describe, expect, it } from "vitest";
import { reviewCertificate, reviewCertificateSkill } from "../src/reviewCertificate.js";

const parsedPemCertificateOutput = {
  artifact: {
    id: "artifact_pem_certificate",
    type: "pem_certificate",
  },
  observed: {
    valid_certificate_count: 2,
    invalid_certificate_block_count: 0,
    certificates: [
      {
        certificate_index: 0,
        subject: "CN=example.com\nO=Security Workbench Test\nC=US",
        issuer: "CN=example.com\nO=Security Workbench Test\nC=US",
        serial_number: "01",
        valid_from_iso: "2026-01-01T00:00:00.000Z",
        valid_to_iso: "2027-01-01T00:00:00.000Z",
        subject_alt_names: [
          { type: "DNS", value: "example.com" },
          { type: "DNS", value: "www.example.com" },
        ],
        subject_alt_name_present: true,
        ca: true,
        public_key_type: "rsa",
        public_key_size_bits: 2048,
      },
      {
        certificate_index: 1,
        subject: "CN=legacy.example",
        issuer: "CN=Test Issuer",
        serial_number: "02",
        valid_from_iso: "2020-01-01T00:00:00.000Z",
        valid_to_iso: "2023-01-01T00:00:00.000Z",
        subject_alt_names: [],
        subject_alt_name_present: false,
        ca: false,
        public_key_type: "rsa",
        public_key_size_bits: 1024,
      },
    ],
  },
  warnings: [],
} as const;

describe("review_certificate", () => {
  it("exports the reviewer skill with local-only permissions", () => {
    expect(reviewCertificateSkill.metadata.name).toBe("review_certificate");
    expect(reviewCertificateSkill.metadata.category).toBe("reviewer");
    expect(reviewCertificateSkill.metadata.execution).toEqual({
      mode: "local_only",
      network_access: "none",
      deterministic: true,
    });
    expect(reviewCertificateSkill.metadata.permissions).toEqual({
      network: "none",
      filesystem: "none",
      sends: [],
      persists: false,
      runs_external_binaries: false,
    });
  });

  it("emits evidence-backed signals for parsed certificate observations", () => {
    const output = reviewCertificate(parsedPemCertificateOutput);

    expect(output.artifact).toMatchObject({
      type: "certificate_review",
      source_artifact_id: "artifact_pem_certificate",
      source_artifact_type: "pem_certificate",
    });
    expect(output.observed.source_parser).toBe("parse_pem_certificate");
    expect(output.observed.reviewed_certificate_count).toBe(2);
    expect(output.observed.ca_certificate_count).toBe(1);
    expect(output.observed.self_issued_certificate_count).toBe(1);
    expect(output.observed.missing_subject_alt_name_count).toBe(1);
    expect(output.observed.weak_public_key_count).toBe(1);
    expect(output.observed.long_validity_window_count).toBe(1);
    expect(output.observed.subjects).toEqual([
      "CN=example.com\nO=Security Workbench Test\nC=US",
      "CN=legacy.example",
    ]);
    expect(output.evidence.length).toBe(output.observed.evidence_count);
    expect(output.signals.length).toBe(output.observed.signal_count);
    expect(output.signals.map((signal) => signal.type)).toEqual([
      "certificate.ca_certificate_present",
      "certificate.self_issued_certificate_observed",
      "certificate.subject_alt_name_not_observed",
      "certificate.weak_public_key_observed",
      "certificate.long_validity_window_observed",
    ]);
    expect(output.signals.every((signal) => signal.evidence_refs.length > 0)).toBe(true);
  });

  it("accepts a JSON run result from parse_pem_certificate", () => {
    const runResult = {
      run_id: "run_parser",
      status: "completed",
      skill: { name: "parse_pem_certificate", version: "0.1.0" },
      output: parsedPemCertificateOutput,
      errors: [],
      warnings: [],
    };

    const output = reviewCertificate(JSON.stringify(runResult));

    expect(output.observed.source_parser).toBe("parse_pem_certificate");
    expect(output.observed.public_key_types).toEqual(["rsa"]);
  });

  it("preserves source parser warning count without copying all source warnings", () => {
    const output = reviewCertificate({
      ...parsedPemCertificateOutput,
      warnings: ["source parser warning"],
    });

    expect(output.observed.source_warning_count).toBe(1);
    expect(output.warnings).toEqual([
      "Source parser emitted 1 warning(s); review output preserves source_warning_count only.",
    ]);
  });

  it("returns no signals for a non-CA certificate with SANs and an acceptable observed key size", () => {
    const output = reviewCertificate({
      artifact: { id: "artifact_pem_certificate", type: "pem_certificate" },
      observed: {
        valid_certificate_count: 1,
        invalid_certificate_block_count: 0,
        certificates: [
          {
            certificate_index: 0,
            subject: "CN=app.example",
            issuer: "CN=Test Issuer",
            serial_number: "03",
            valid_from_iso: "2026-01-01T00:00:00.000Z",
            valid_to_iso: "2027-01-01T00:00:00.000Z",
            subject_alt_names: [{ type: "DNS", value: "app.example" }],
            subject_alt_name_present: true,
            ca: false,
            public_key_type: "rsa",
            public_key_size_bits: 2048,
          },
        ],
      },
      warnings: [],
    });

    expect(output.signals).toEqual([]);
    expect(output.evidence).toEqual([]);
    expect(output.observed.signal_count).toBe(0);
  });

  it("emits a signal when parser output contains invalid PEM certificate blocks", () => {
    const output = reviewCertificate({
      artifact: { id: "artifact_pem_certificate", type: "pem_certificate" },
      observed: {
        valid_certificate_count: 1,
        invalid_certificate_block_count: 1,
        certificates: [
          {
            certificate_index: 0,
            subject: "CN=app.example",
            issuer: "CN=Test Issuer",
            serial_number: "03",
            valid_from_iso: "2026-01-01T00:00:00.000Z",
            valid_to_iso: "2027-01-01T00:00:00.000Z",
            subject_alt_names: [{ type: "DNS", value: "app.example" }],
            subject_alt_name_present: true,
            ca: false,
            public_key_type: "rsa",
            public_key_size_bits: 2048,
          },
        ],
        invalid_blocks: [{ block_index: 1, reason: "bad certificate" }],
      },
      warnings: ["1 PEM CERTIFICATE block(s) could not be parsed."],
    });

    expect(output.signals.map((signal) => signal.type)).toEqual(["certificate.invalid_pem_block_observed"]);
    expect(output.observed.invalid_certificate_block_count).toBe(1);
  });

  it("rejects invalid JSON strings", () => {
    expect(() => reviewCertificate("{bad json}")).toThrow(
      "review_certificate input must be parsed PEM certificate JSON or a JSON run result from parse_pem_certificate",
    );
  });

  it("rejects non-PEM-certificate parser output", () => {
    expect(() =>
      reviewCertificate({
        artifact: { id: "artifact_package_json", type: "package_json" },
        observed: {},
        warnings: [],
      }),
    ).toThrow("review_certificate input artifact.type must be pem_certificate");
  });
});
