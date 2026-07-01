import { describe, expect, it } from "vitest";
import { reviewJwt, reviewJwtSkill } from "../src/reviewJwt.js";

const parsedUnsignedJwtOutput = {
  header: {
    alg: "none",
    typ: "JWT",
    jku: "https://keys.example.invalid/jwks.json",
    crit: ["example"],
  },
  payload: {
    sub: "user-123",
    iss: "https://issuer.example.invalid",
    iat: 1_700_000_000,
    nbf: 1_700_000_000,
    access_token: "should-not-be-copied-to-evidence",
  },
  algorithm: "none",
  type: "JWT",
  signature_present: false,
  signature_length: 0,
  signature_verified: false,
  warnings: ["JWT signature is not verified by parse_jwt."],
} as const;

describe("review_jwt", () => {
  it("exports the reviewer skill with local-only permissions", () => {
    expect(reviewJwtSkill.metadata.name).toBe("review_jwt");
    expect(reviewJwtSkill.metadata.category).toBe("reviewer");
    expect(reviewJwtSkill.metadata.execution).toEqual({
      mode: "local_only",
      network_access: "none",
      deterministic: true,
    });
    expect(reviewJwtSkill.metadata.permissions).toEqual({
      network: "none",
      filesystem: "none",
      sends: [],
      persists: false,
      runs_external_binaries: false,
    });
  });

  it("emits evidence-backed JWT review signals without copying sensitive claim values", () => {
    const output = reviewJwt(parsedUnsignedJwtOutput);

    expect(output.artifact).toMatchObject({
      type: "jwt_review",
      source_artifact_id: null,
      source_artifact_type: null,
    });
    expect(output.observed.source_parser).toBe("parse_jwt");
    expect(output.observed.algorithm).toBe("none");
    expect(output.observed.signature_present).toBe(false);
    expect(output.observed.claim_names).toEqual(["access_token", "iat", "iss", "nbf", "sub"]);
    expect(output.observed.registered_claims_missing).toContain("exp");
    expect(output.observed.sensitive_claim_name_count).toBe(1);
    expect(output.observed.remote_key_reference_header_count).toBe(1);
    expect(output.signals.map((signal) => signal.type)).toEqual([
      "jwt.signature_not_verified_by_parser",
      "jwt.unsecured_algorithm_observed",
      "jwt.signature_not_present",
      "jwt.expiration_claim_not_observed",
      "jwt.remote_key_reference_header_observed",
      "jwt.critical_header_observed",
      "jwt.sensitive_claim_name_observed",
    ]);
    expect(output.signals.every((signal) => signal.evidence_refs.length > 0)).toBe(true);
    expect(JSON.stringify(output)).not.toContain("should-not-be-copied-to-evidence");
  });

  it("accepts a JSON run result from parse_jwt", () => {
    const runResult = {
      run_id: "run_parser",
      status: "completed",
      skill: { name: "parse_jwt", version: "0.1.0" },
      output: parsedUnsignedJwtOutput,
      errors: [],
      warnings: [],
    };

    const output = reviewJwt(JSON.stringify(runResult));

    expect(output.observed.source_parser).toBe("parse_jwt");
    expect(output.observed.source_warning_count).toBe(1);
    expect(output.warnings).toEqual(["Source parser emitted 1 warning(s); review output preserves source_warning_count only."]);
  });

  it("emits a long validity-window signal from exp and iat without current-time classification", () => {
    const output = reviewJwt({
      header: { alg: "RS256", typ: "JWT" },
      payload: {
        iss: "https://issuer.example.invalid",
        aud: "api://example",
        sub: "user-123",
        iat: 1_700_000_000,
        exp: 1_700_000_000 + 120 * 24 * 60 * 60,
      },
      algorithm: "RS256",
      type: "JWT",
      signature_present: true,
      signature_length: 48,
      signature_verified: false,
      warnings: [],
    });

    expect(output.observed.validity_window_seconds).toBe(10_368_000);
    expect(output.signals.map((signal) => signal.type)).toContain("jwt.long_validity_window_observed");
    expect(output.observed.limitations).toContain(
      "Does not use current time to classify exp, nbf, or iat claims as currently valid, expired, or not-yet-valid.",
    );
  });

  it("rejects objects that are not parse_jwt output", () => {
    expect(() =>
      reviewJwt({
        artifact: { id: "artifact_package_json", type: "package_json" },
        observed: {},
        warnings: [],
      }),
    ).toThrow("review_jwt input must be parse_jwt output with header and payload objects");
  });
});
