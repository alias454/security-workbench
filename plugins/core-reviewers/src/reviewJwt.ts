import type { EvidenceRecord, JsonObject, JsonValue, SignalRecord, Skill } from "@security-workbench/schemas";
import { localOnlyPermissions } from "./localOnlyPermissions.js";

type ReviewRecord = Record<string, unknown>;
type Confidence = "confirmed" | "high" | "medium" | "low" | "unknown";
type Severity = "informational" | "low" | "medium" | "high" | "critical";

export interface JwtReviewOutput {
  readonly artifact: {
    readonly id: "artifact_jwt_review";
    readonly type: "jwt_review";
    readonly source_artifact_id: string | null;
    readonly source_artifact_type: string | null;
  };
  readonly observed: {
    readonly source_parser: "parse_jwt";
    readonly source_warning_count: number;
    readonly algorithm: string | null;
    readonly type: string | null;
    readonly signature_present: boolean;
    readonly signature_verified: false;
    readonly header_parameter_names: readonly string[];
    readonly claim_names: readonly string[];
    readonly claim_count: number;
    readonly registered_claims_present: readonly string[];
    readonly registered_claims_missing: readonly string[];
    readonly temporal_claims_present: readonly string[];
    readonly validity_window_seconds: number | null;
    readonly sensitive_claim_name_count: number;
    readonly remote_key_reference_header_count: number;
    readonly evidence_count: number;
    readonly signal_count: number;
    readonly limitations: readonly string[];
  };
  readonly evidence: readonly EvidenceRecord[];
  readonly signals: readonly SignalRecord[];
  readonly warnings: readonly string[];
}

interface ParsedJwtForReview {
  readonly artifact: {
    readonly id?: string;
    readonly type?: string;
  };
  readonly header: ReviewRecord;
  readonly payload: ReviewRecord;
  readonly algorithm: string | null;
  readonly type: string | null;
  readonly signature_present: boolean;
  readonly signature_verified: false;
  readonly warnings?: readonly string[];
}

const REGISTERED_CLAIMS = ["iss", "sub", "aud", "exp", "nbf", "iat", "jti"] as const;
const TEMPORAL_CLAIMS = ["exp", "nbf", "iat"] as const;
const REMOTE_KEY_REFERENCE_HEADERS = ["jku", "x5u"] as const;
const LONG_VALIDITY_WINDOW_SECONDS = 90 * 24 * 60 * 60;
const SENSITIVE_CLAIM_NAME_PATTERN = /(^|[_-])(password|passwd|pwd|secret|api[_-]?key|private[_-]?key|client[_-]?secret|access[_-]?token|refresh[_-]?token|id[_-]?token|token)([_-]|$)/i;

function isRecord(value: unknown): value is ReviewRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function parseJsonString(input: string): unknown {
  try {
    return JSON.parse(input) as unknown;
  } catch {
    throw new Error("review_jwt input must be parse_jwt output JSON or a JSON run result from parse_jwt");
  }
}

function childRecord(record: ReviewRecord, key: string): ReviewRecord | undefined {
  const value = record[key];
  return isRecord(value) ? value : undefined;
}

function stringOrNull(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}

function booleanOrFalse(value: unknown): boolean {
  return value === true;
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((entry): entry is string => typeof entry === "string") : [];
}

function uniqueSorted(values: readonly string[]): string[] {
  return [...new Set(values.filter((value) => value.length > 0))].sort((left, right) => left.localeCompare(right));
}

function evidenceValue(value: unknown): JsonValue {
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "number" ||
    typeof value === "boolean" ||
    Array.isArray(value) ||
    isRecord(value)
  ) {
    return value as JsonValue;
  }

  return String(value);
}

function jsonType(value: unknown): string {
  if (value === null) {
    return "null";
  }
  if (Array.isArray(value)) {
    return "array";
  }
  return typeof value;
}

function unwrapInput(input: unknown): ParsedJwtForReview {
  const parsed = typeof input === "string" ? parseJsonString(input) : input;
  const candidate = isRecord(parsed) && isRecord(parsed.output) ? parsed.output : parsed;

  if (!isRecord(candidate)) {
    throw new Error("review_jwt input must be an object");
  }

  const header = childRecord(candidate, "header");
  const payload = childRecord(candidate, "payload");

  if (!header || !payload) {
    throw new Error("review_jwt input must be parse_jwt output with header and payload objects");
  }

  const artifact = childRecord(candidate, "artifact");
  if (artifact && artifact.type !== "jwt") {
    throw new Error("review_jwt input artifact.type must be jwt when artifact metadata is present");
  }

  const signatureVerified = candidate.signature_verified;
  if (signatureVerified !== false) {
    throw new Error("review_jwt input must come from parse_jwt output with signature_verified false");
  }

  return {
    artifact: {
      id: artifact ? stringOrNull(artifact.id) ?? undefined : undefined,
      type: artifact ? stringOrNull(artifact.type) ?? undefined : undefined,
    },
    header,
    payload,
    algorithm: stringOrNull(candidate.algorithm),
    type: stringOrNull(candidate.type),
    signature_present: booleanOrFalse(candidate.signature_present),
    signature_verified: false,
    warnings: stringArray(candidate.warnings),
  };
}

function unixSeconds(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function validityWindowSeconds(payload: ReviewRecord): number | null {
  const issuedAt = unixSeconds(payload.iat);
  const expiresAt = unixSeconds(payload.exp);

  if (issuedAt === null || expiresAt === null || expiresAt < issuedAt) {
    return null;
  }

  return expiresAt - issuedAt;
}

function claimNames(payload: ReviewRecord): string[] {
  return uniqueSorted(Object.keys(payload));
}

function headerParameterNames(header: ReviewRecord): string[] {
  return uniqueSorted(Object.keys(header));
}

function registeredClaimsPresent(payload: ReviewRecord): string[] {
  return REGISTERED_CLAIMS.filter((claimName) => Object.prototype.hasOwnProperty.call(payload, claimName));
}

function registeredClaimsMissing(payload: ReviewRecord): string[] {
  return REGISTERED_CLAIMS.filter((claimName) => !Object.prototype.hasOwnProperty.call(payload, claimName));
}

function temporalClaimsPresent(payload: ReviewRecord): string[] {
  return TEMPORAL_CLAIMS.filter((claimName) => Object.prototype.hasOwnProperty.call(payload, claimName));
}

function collectSensitiveClaimPaths(value: unknown, prefix = "payload"): string[] {
  if (!isRecord(value)) {
    return [];
  }

  const paths: string[] = [];
  for (const [key, child] of Object.entries(value)) {
    const path = `${prefix}.${key}`;
    if (SENSITIVE_CLAIM_NAME_PATTERN.test(key)) {
      paths.push(path);
    }
    if (isRecord(child)) {
      paths.push(...collectSensitiveClaimPaths(child, path));
    }
    if (Array.isArray(child)) {
      child.forEach((entry, index) => {
        if (isRecord(entry)) {
          paths.push(...collectSensitiveClaimPaths(entry, `${path}[${String(index)}]`));
        }
      });
    }
  }

  return uniqueSorted(paths);
}

function remoteKeyReferenceHeaders(header: ReviewRecord): string[] {
  return REMOTE_KEY_REFERENCE_HEADERS.filter((headerName) => Object.prototype.hasOwnProperty.call(header, headerName));
}

function createEvidenceBuilder(sourceArtifactId: string | null) {
  const evidence: EvidenceRecord[] = [];

  function addEvidence(
    type: string,
    path: string,
    value: unknown,
    description: string,
    valueKind: EvidenceRecord["value_kind"] = "metadata",
  ): string {
    const id = `evidence_jwt_${String(evidence.length + 1).padStart(3, "0")}`;
    evidence.push({
      id,
      type,
      artifact_ref: sourceArtifactId ?? undefined,
      path,
      value: evidenceValue(value),
      value_kind: valueKind,
      value_redacted: valueKind === "presence",
      sensitivity: "medium",
      description,
    });
    return id;
  }

  return { evidence, addEvidence };
}

function addSignal(
  signals: SignalRecord[],
  input: {
    type: string;
    summary: string;
    evidenceRefs: readonly string[];
    severity: Severity;
    confidence: Confidence;
    observed: JsonObject;
    tags?: readonly string[];
  },
): void {
  signals.push({
    id: `signal_jwt_${String(signals.length + 1).padStart(3, "0")}`,
    type: input.type,
    summary: input.summary,
    severity: input.severity,
    confidence: input.confidence,
    evidence_refs: input.evidenceRefs,
    observed: input.observed,
    tags: input.tags ?? ["jwt"],
  });
}

function addJwtSignals(parsed: ParsedJwtForReview, addEvidence: ReturnType<typeof createEvidenceBuilder>["addEvidence"], signals: SignalRecord[]): void {
  const algorithm = parsed.algorithm?.toLowerCase() ?? null;
  const remoteHeaders = remoteKeyReferenceHeaders(parsed.header);
  const sensitiveClaimPaths = collectSensitiveClaimPaths(parsed.payload);
  const windowSeconds = validityWindowSeconds(parsed.payload);
  const expiresAt = unixSeconds(parsed.payload.exp);
  const notBefore = unixSeconds(parsed.payload.nbf);

  if (parsed.signature_verified === false) {
    const evidenceRef = addEvidence(
      "jwt_signature_not_verified_by_parser",
      "signature_verified",
      false,
      "parse_jwt decoded the token without verifying the JWT signature.",
    );

    addSignal(signals, {
      type: "jwt.signature_not_verified_by_parser",
      summary: "JWT signature was not verified by the parser.",
      evidenceRefs: [evidenceRef],
      severity: "informational",
      confidence: "confirmed",
      observed: {
        signature_verified: false,
      },
      tags: ["jwt", "parser-limitation"],
    });
  }

  if (algorithm === "none") {
    const evidenceRef = addEvidence(
      "jwt_unsecured_algorithm",
      "header.alg",
      parsed.algorithm,
      "JWT header declares the unsecured none algorithm.",
    );

    addSignal(signals, {
      type: "jwt.unsecured_algorithm_observed",
      summary: "JWT header declares alg=none.",
      evidenceRefs: [evidenceRef],
      severity: "high",
      confidence: "confirmed",
      observed: {
        algorithm: parsed.algorithm ?? "unknown",
      },
      tags: ["jwt", "algorithm"],
    });
  }

  if (!parsed.signature_present) {
    const evidenceRef = addEvidence(
      "jwt_signature_absent",
      "signature_present",
      false,
      "JWT parser observed an empty signature segment.",
    );

    addSignal(signals, {
      type: "jwt.signature_not_present",
      summary: "JWT signature segment is empty.",
      evidenceRefs: [evidenceRef],
      severity: "high",
      confidence: "confirmed",
      observed: {
        signature_present: false,
        algorithm: parsed.algorithm ?? "unknown",
      },
      tags: ["jwt", "signature"],
    });
  }

  if (!Object.prototype.hasOwnProperty.call(parsed.payload, "exp")) {
    const evidenceRef = addEvidence(
      "jwt_expiration_claim_absent",
      "payload.exp",
      false,
      "JWT payload does not contain an exp claim.",
      "presence",
    );

    addSignal(signals, {
      type: "jwt.expiration_claim_not_observed",
      summary: "JWT payload does not include an exp claim.",
      evidenceRefs: [evidenceRef],
      severity: "medium",
      confidence: "confirmed",
      observed: {
        exp_present: false,
      },
      tags: ["jwt", "claims", "expiration"],
    });
  }

  if (windowSeconds !== null && windowSeconds > LONG_VALIDITY_WINDOW_SECONDS) {
    const evidenceRef = addEvidence(
      "jwt_long_validity_window",
      "payload.exp",
      {
        iat_present: true,
        exp_present: true,
        validity_window_seconds: windowSeconds,
        threshold_seconds: LONG_VALIDITY_WINDOW_SECONDS,
      },
      "JWT exp and iat claims encode a long validity window. This does not classify the token as currently valid or expired.",
    );

    addSignal(signals, {
      type: "jwt.long_validity_window_observed",
      summary: "JWT exp and iat claims encode a long validity window.",
      evidenceRefs: [evidenceRef],
      severity: "medium",
      confidence: "confirmed",
      observed: {
        validity_window_seconds: windowSeconds,
        threshold_seconds: LONG_VALIDITY_WINDOW_SECONDS,
      },
      tags: ["jwt", "claims", "expiration"],
    });
  }

  if (expiresAt !== null && notBefore !== null && expiresAt < notBefore) {
    const evidenceRef = addEvidence(
      "jwt_inconsistent_temporal_claims",
      "payload.exp",
      {
        exp: expiresAt,
        nbf: notBefore,
      },
      "JWT exp claim is numerically earlier than the nbf claim.",
    );

    addSignal(signals, {
      type: "jwt.inconsistent_temporal_claims_observed",
      summary: "JWT temporal claims are internally inconsistent: exp is before nbf.",
      evidenceRefs: [evidenceRef],
      severity: "medium",
      confidence: "confirmed",
      observed: {
        exp: expiresAt,
        nbf: notBefore,
      },
      tags: ["jwt", "claims", "temporal"],
    });
  }

  if (remoteHeaders.length > 0) {
    const evidenceRef = addEvidence(
      "jwt_remote_key_reference_headers",
      "header",
      {
        header_names: remoteHeaders,
      },
      "JWT header includes parameter names that can reference remote key material. Values are not fetched by this reviewer.",
    );

    addSignal(signals, {
      type: "jwt.remote_key_reference_header_observed",
      summary: "JWT header includes remote key reference parameter(s).",
      evidenceRefs: [evidenceRef],
      severity: "medium",
      confidence: "confirmed",
      observed: {
        header_names: remoteHeaders,
      },
      tags: ["jwt", "header", "key-reference"],
    });
  }

  if (Object.prototype.hasOwnProperty.call(parsed.header, "jwk")) {
    const evidenceRef = addEvidence(
      "jwt_embedded_jwk_header",
      "header.jwk",
      {
        present: true,
        value_type: jsonType(parsed.header.jwk),
      },
      "JWT header contains an embedded jwk parameter. The reviewer records presence only and does not validate key material.",
      "presence",
    );

    addSignal(signals, {
      type: "jwt.embedded_jwk_header_observed",
      summary: "JWT header contains an embedded jwk parameter.",
      evidenceRefs: [evidenceRef],
      severity: "low",
      confidence: "confirmed",
      observed: {
        jwk_present: true,
        jwk_value_type: jsonType(parsed.header.jwk),
      },
      tags: ["jwt", "header", "key-reference"],
    });
  }

  if (Array.isArray(parsed.header.crit) && parsed.header.crit.length > 0) {
    const critValues = parsed.header.crit.filter((entry): entry is string => typeof entry === "string");
    const evidenceRef = addEvidence(
      "jwt_critical_header_parameters",
      "header.crit",
      {
        crit: critValues,
        crit_count: parsed.header.crit.length,
      },
      "JWT header includes crit entries. This reviewer records them but does not validate JOSE processing behavior.",
    );

    addSignal(signals, {
      type: "jwt.critical_header_observed",
      summary: "JWT header includes crit parameter entries.",
      evidenceRefs: [evidenceRef],
      severity: "low",
      confidence: "confirmed",
      observed: {
        crit: critValues,
        crit_count: parsed.header.crit.length,
      },
      tags: ["jwt", "header", "crit"],
    });
  }

  if (sensitiveClaimPaths.length > 0) {
    const evidenceRef = addEvidence(
      "jwt_sensitive_claim_names",
      "payload",
      {
        claim_paths: sensitiveClaimPaths,
        claim_path_count: sensitiveClaimPaths.length,
      },
      "JWT payload includes claim names commonly associated with secrets or tokens. Values are not copied into evidence.",
      "presence",
    );

    addSignal(signals, {
      type: "jwt.sensitive_claim_name_observed",
      summary: "JWT payload includes sensitive-looking claim name(s).",
      evidenceRefs: [evidenceRef],
      severity: "medium",
      confidence: "medium",
      observed: {
        claim_paths: sensitiveClaimPaths,
        claim_path_count: sensitiveClaimPaths.length,
      },
      tags: ["jwt", "claims", "sensitive-name"],
    });
  }
}

export function reviewJwt(input: unknown): JwtReviewOutput {
  const parsed = unwrapInput(input);
  const sourceArtifactId = stringOrNull(parsed.artifact.id);
  const { evidence, addEvidence } = createEvidenceBuilder(sourceArtifactId);
  const signals: SignalRecord[] = [];
  const warnings: string[] = [];
  const sensitiveClaimPaths = collectSensitiveClaimPaths(parsed.payload);

  addJwtSignals(parsed, addEvidence, signals);

  if ((parsed.warnings?.length ?? 0) > 0) {
    warnings.push(`Source parser emitted ${parsed.warnings?.length ?? 0} warning(s); review output preserves source_warning_count only.`);
  }

  return {
    artifact: {
      id: "artifact_jwt_review",
      type: "jwt_review",
      source_artifact_id: parsed.artifact.id ?? null,
      source_artifact_type: parsed.artifact.type ?? null,
    },
    observed: {
      source_parser: "parse_jwt",
      source_warning_count: parsed.warnings?.length ?? 0,
      algorithm: parsed.algorithm,
      type: parsed.type,
      signature_present: parsed.signature_present,
      signature_verified: false,
      header_parameter_names: headerParameterNames(parsed.header),
      claim_names: claimNames(parsed.payload),
      claim_count: claimNames(parsed.payload).length,
      registered_claims_present: registeredClaimsPresent(parsed.payload),
      registered_claims_missing: registeredClaimsMissing(parsed.payload),
      temporal_claims_present: temporalClaimsPresent(parsed.payload),
      validity_window_seconds: validityWindowSeconds(parsed.payload),
      sensitive_claim_name_count: sensitiveClaimPaths.length,
      remote_key_reference_header_count: remoteKeyReferenceHeaders(parsed.header).length,
      evidence_count: evidence.length,
      signal_count: signals.length,
      limitations: [
        "Consumes parse_jwt output and does not verify JWT signatures.",
        "Does not validate issuer, audience, key material, JWKS, JKU, X5U, or embedded JWK trust.",
        "Does not use current time to classify exp, nbf, or iat claims as currently valid, expired, or not-yet-valid.",
        "Does not perform network lookups, revocation checks, or token introspection.",
        "Does not determine whether the token was accepted by any service.",
      ],
    },
    evidence,
    signals,
    warnings,
  };
}

export const reviewJwtSkill: Skill<unknown, JwtReviewOutput> = {
  metadata: {
    name: "review_jwt",
    version: "0.1.0",
    category: "reviewer",
    description: "Review parsed JWT header and claim observations without verifying signatures or performing network lookups.",
    execution: {
      mode: "local_only",
      network_access: "none",
      deterministic: true,
    },
    permissions: localOnlyPermissions,
    exposure: {
      surfaces: ["cli", "api", "web", "mcp"],
      default_exposure: "enabled",
      hosted_default: "allowlist_only",
      requires_authentication: true,
      rate_limit_recommended: true,
      audit_required: true,
      max_input_mb: 1,
      risk: "medium",
      rationale: [
        "Reviews already parsed JWT metadata and claim names from parse_jwt output.",
        "Does not verify signatures, validate trust, introspect tokens, perform network lookups, score risk, or generate findings.",
        "Output may include JWT header names, claim names, and selected non-secret metadata from attacker-controlled artifacts.",
      ],
    },
  },
  run: reviewJwt,
};
