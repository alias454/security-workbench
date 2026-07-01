import type { EvidenceRecord, JsonObject, JsonValue, SignalRecord, Skill } from "@security-workbench/schemas";
import { localOnlyPermissions } from "./localOnlyPermissions.js";

type ReviewRecord = Record<string, unknown>;
type Confidence = "confirmed" | "high" | "medium" | "low" | "unknown";
type Severity = "informational" | "low" | "medium" | "high" | "critical";

export interface CertificateReviewCertificateObservation {
  readonly certificate_index: number;
  readonly subject: string | null;
  readonly issuer: string | null;
  readonly serial_number: string | null;
  readonly subject_alt_name_present: boolean;
  readonly subject_alt_name_count: number;
  readonly ca: boolean;
  readonly self_issued: boolean;
  readonly public_key_type: string | null;
  readonly public_key_size_bits: number | null;
  readonly validity_window_days: number | null;
}

export interface CertificateReviewOutput {
  readonly artifact: {
    readonly id: "artifact_certificate_review";
    readonly type: "certificate_review";
    readonly source_artifact_id: string | null;
    readonly source_artifact_type: string | null;
  };
  readonly observed: {
    readonly source_parser: "parse_pem_certificate";
    readonly source_warning_count: number;
    readonly reviewed_certificate_count: number;
    readonly valid_certificate_count: number;
    readonly invalid_certificate_block_count: number;
    readonly ca_certificate_count: number;
    readonly self_issued_certificate_count: number;
    readonly missing_subject_alt_name_count: number;
    readonly weak_public_key_count: number;
    readonly long_validity_window_count: number;
    readonly evidence_count: number;
    readonly signal_count: number;
    readonly subjects: readonly string[];
    readonly issuers: readonly string[];
    readonly public_key_types: readonly string[];
    readonly limitations: readonly string[];
    readonly certificates: readonly CertificateReviewCertificateObservation[];
  };
  readonly evidence: readonly EvidenceRecord[];
  readonly signals: readonly SignalRecord[];
  readonly warnings: readonly string[];
}

interface ParsedPemCertificateForReview {
  readonly artifact: {
    readonly id?: string;
    readonly type?: string;
  };
  readonly observed: ReviewRecord;
  readonly warnings?: readonly string[];
}

const DAY_MS = 24 * 60 * 60 * 1000;
const LONG_VALIDITY_WINDOW_DAYS = 825;

function isRecord(value: unknown): value is ReviewRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function parseJsonString(input: string): unknown {
  try {
    return JSON.parse(input) as unknown;
  } catch {
    throw new Error("review_certificate input must be parsed PEM certificate JSON or a JSON run result from parse_pem_certificate");
  }
}

function childRecord(record: ReviewRecord, key: string): ReviewRecord | undefined {
  const value = record[key];
  return isRecord(value) ? value : undefined;
}

function stringOrNull(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}

function numberOrNull(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function numberOrZero(value: unknown): number {
  return typeof value === "number" && Number.isFinite(value) ? value : 0;
}

function booleanOrFalse(value: unknown): boolean {
  return value === true;
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((entry): entry is string => typeof entry === "string") : [];
}

function recordArray(value: unknown): ReviewRecord[] {
  return Array.isArray(value) ? value.filter(isRecord) : [];
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

function unwrapInput(input: unknown): ParsedPemCertificateForReview {
  const parsed = typeof input === "string" ? parseJsonString(input) : input;
  const candidate = isRecord(parsed) && isRecord(parsed.output) ? parsed.output : parsed;

  if (!isRecord(candidate)) {
    throw new Error("review_certificate input must be an object");
  }

  const artifact = childRecord(candidate, "artifact");
  const observed = childRecord(candidate, "observed");

  if (!artifact || !observed) {
    throw new Error("review_certificate input must be parse_pem_certificate output with artifact and observed fields");
  }

  if (artifact.type !== "pem_certificate") {
    throw new Error("review_certificate input artifact.type must be pem_certificate");
  }

  return {
    artifact: {
      id: stringOrNull(artifact.id) ?? undefined,
      type: stringOrNull(artifact.type) ?? undefined,
    },
    observed,
    warnings: stringArray(candidate.warnings),
  };
}

function validityWindowDays(certificate: ReviewRecord): number | null {
  const validFromIso = stringOrNull(certificate.valid_from_iso);
  const validToIso = stringOrNull(certificate.valid_to_iso);

  if (!validFromIso || !validToIso) {
    return null;
  }

  const validFrom = new Date(validFromIso).getTime();
  const validTo = new Date(validToIso).getTime();

  if (!Number.isFinite(validFrom) || !Number.isFinite(validTo) || validTo < validFrom) {
    return null;
  }

  return Math.round((validTo - validFrom) / DAY_MS);
}

function certificateObservations(observed: ReviewRecord): CertificateReviewCertificateObservation[] {
  return recordArray(observed.certificates).map((certificate) => {
    const subject = stringOrNull(certificate.subject);
    const issuer = stringOrNull(certificate.issuer);
    const subjectAltNames = recordArray(certificate.subject_alt_names);

    return {
      certificate_index: numberOrZero(certificate.certificate_index),
      subject,
      issuer,
      serial_number: stringOrNull(certificate.serial_number),
      subject_alt_name_present: booleanOrFalse(certificate.subject_alt_name_present),
      subject_alt_name_count: subjectAltNames.length,
      ca: booleanOrFalse(certificate.ca),
      self_issued: subject !== null && issuer !== null && subject === issuer,
      public_key_type: stringOrNull(certificate.public_key_type),
      public_key_size_bits: numberOrNull(certificate.public_key_size_bits),
      validity_window_days: validityWindowDays(certificate),
    };
  });
}

function isWeakPublicKey(certificate: CertificateReviewCertificateObservation): boolean {
  const type = certificate.public_key_type?.toLowerCase() ?? "";
  const size = certificate.public_key_size_bits;

  if (size === null) {
    return false;
  }

  if (type === "rsa" || type === "dsa") {
    return size < 2048;
  }

  if (type === "ec" || type === "ecdh" || type === "ecdsa") {
    return size < 224;
  }

  return false;
}

function hasLongValidityWindow(certificate: CertificateReviewCertificateObservation): boolean {
  return certificate.validity_window_days !== null && certificate.validity_window_days > LONG_VALIDITY_WINDOW_DAYS;
}

function createEvidenceBuilder(sourceArtifactId: string | null) {
  const evidence: EvidenceRecord[] = [];

  function addEvidence(type: string, path: string, value: unknown, description: string): string {
    const id = `evidence_certificate_${String(evidence.length + 1).padStart(3, "0")}`;
    evidence.push({
      id,
      type,
      artifact_ref: sourceArtifactId ?? undefined,
      path,
      value: evidenceValue(value),
      value_kind: "metadata",
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
    id: `signal_certificate_${String(signals.length + 1).padStart(3, "0")}`,
    type: input.type,
    summary: input.summary,
    severity: input.severity,
    confidence: input.confidence,
    evidence_refs: input.evidenceRefs,
    observed: input.observed,
    tags: input.tags ?? ["certificate"],
  });
}

function certificateLabel(certificate: CertificateReviewCertificateObservation): string {
  if (certificate.subject) {
    return certificate.subject.replace(/\n/g, ", ");
  }

  if (certificate.serial_number) {
    return `serial ${certificate.serial_number}`;
  }

  return `certificate ${String(certificate.certificate_index)}`;
}

function addCertificateSignals(
  certificates: readonly CertificateReviewCertificateObservation[],
  addEvidence: (type: string, path: string, value: unknown, description: string) => string,
  signals: SignalRecord[],
): void {
  for (const certificate of certificates) {
    const path = `observed.certificates[${String(certificate.certificate_index)}]`;
    const label = certificateLabel(certificate);

    if (!certificate.ca && !certificate.subject_alt_name_present) {
      const evidenceRef = addEvidence(
        "certificate_subject_alt_name_absent",
        `${path}.subject_alt_name_present`,
        {
          certificate_index: certificate.certificate_index,
          subject: certificate.subject,
          issuer: certificate.issuer,
          subject_alt_name_present: certificate.subject_alt_name_present,
        },
        "Parsed certificate metadata did not include subjectAltName entries for a non-CA certificate.",
      );

      addSignal(signals, {
        type: "certificate.subject_alt_name_not_observed",
        summary: `Subject alternative names were not observed for ${label}.`,
        evidenceRefs: [evidenceRef],
        severity: "low",
        confidence: "medium",
        observed: {
          certificate_index: certificate.certificate_index,
          subject: certificate.subject ?? "unknown",
          issuer: certificate.issuer ?? "unknown",
          ca: certificate.ca,
        },
        tags: ["certificate", "subject-alt-name"],
      });
    }

    if (certificate.ca) {
      const evidenceRef = addEvidence(
        "certificate_ca_flag_present",
        `${path}.ca`,
        {
          certificate_index: certificate.certificate_index,
          subject: certificate.subject,
          issuer: certificate.issuer,
          ca: certificate.ca,
        },
        "Parsed X.509 metadata marked this certificate as a CA certificate.",
      );

      addSignal(signals, {
        type: "certificate.ca_certificate_present",
        summary: `CA certificate observed for ${label}.`,
        evidenceRefs: [evidenceRef],
        severity: "informational",
        confidence: "confirmed",
        observed: {
          certificate_index: certificate.certificate_index,
          subject: certificate.subject ?? "unknown",
          issuer: certificate.issuer ?? "unknown",
        },
        tags: ["certificate", "ca"],
      });
    }

    if (certificate.self_issued) {
      const evidenceRef = addEvidence(
        "certificate_self_issued_names",
        `${path}.subject`,
        {
          certificate_index: certificate.certificate_index,
          subject: certificate.subject,
          issuer: certificate.issuer,
        },
        "Parsed certificate subject and issuer strings are identical. This is a self-issued observation, not certificate-chain validation.",
      );

      addSignal(signals, {
        type: "certificate.self_issued_certificate_observed",
        summary: `Self-issued certificate metadata observed for ${label}.`,
        evidenceRefs: [evidenceRef],
        severity: "informational",
        confidence: "confirmed",
        observed: {
          certificate_index: certificate.certificate_index,
          subject: certificate.subject ?? "unknown",
          issuer: certificate.issuer ?? "unknown",
        },
        tags: ["certificate", "self-issued"],
      });
    }

    if (isWeakPublicKey(certificate)) {
      const evidenceRef = addEvidence(
        "certificate_weak_public_key_size",
        `${path}.public_key_size_bits`,
        {
          certificate_index: certificate.certificate_index,
          public_key_type: certificate.public_key_type,
          public_key_size_bits: certificate.public_key_size_bits,
        },
        "Parsed public key metadata indicates a small key size for the observed key family.",
      );

      addSignal(signals, {
        type: "certificate.weak_public_key_observed",
        summary: `Small ${certificate.public_key_type ?? "unknown"} public key observed for ${label}.`,
        evidenceRefs: [evidenceRef],
        severity: "medium",
        confidence: "high",
        observed: {
          certificate_index: certificate.certificate_index,
          public_key_type: certificate.public_key_type ?? "unknown",
          public_key_size_bits: certificate.public_key_size_bits ?? 0,
        },
        tags: ["certificate", "public-key"],
      });
    }

    if (hasLongValidityWindow(certificate)) {
      const evidenceRef = addEvidence(
        "certificate_long_validity_window",
        `${path}.validity_window_days`,
        {
          certificate_index: certificate.certificate_index,
          validity_window_days: certificate.validity_window_days,
        },
        "Parsed certificate dates encode a long validity window. This is an observation only and does not validate trust or policy compliance.",
      );

      addSignal(signals, {
        type: "certificate.long_validity_window_observed",
        summary: `Long encoded validity window observed for ${label}.`,
        evidenceRefs: [evidenceRef],
        severity: "informational",
        confidence: "confirmed",
        observed: {
          certificate_index: certificate.certificate_index,
          validity_window_days: certificate.validity_window_days ?? 0,
          threshold_days: LONG_VALIDITY_WINDOW_DAYS,
        },
        tags: ["certificate", "validity-window"],
      });
    }
  }
}

export function reviewCertificate(input: unknown): CertificateReviewOutput {
  const parsed = unwrapInput(input);
  const observed = parsed.observed;
  const sourceArtifactId = stringOrNull(parsed.artifact.id);
  const { evidence, addEvidence } = createEvidenceBuilder(sourceArtifactId);
  const signals: SignalRecord[] = [];
  const warnings: string[] = [];
  const certificates = certificateObservations(observed);
  const invalidCertificateBlockCount = numberOrZero(observed.invalid_certificate_block_count);

  addCertificateSignals(certificates, addEvidence, signals);

  if (invalidCertificateBlockCount > 0) {
    const evidenceRef = addEvidence(
      "certificate_invalid_pem_blocks_present",
      "observed.invalid_blocks",
      {
        invalid_certificate_block_count: invalidCertificateBlockCount,
      },
      "The parser observed PEM CERTIFICATE blocks that could not be parsed as X.509 certificates.",
    );

    addSignal(signals, {
      type: "certificate.invalid_pem_block_observed",
      summary: `${String(invalidCertificateBlockCount)} invalid PEM certificate block(s) observed in parser output.`,
      evidenceRefs: [evidenceRef],
      severity: "low",
      confidence: "confirmed",
      observed: {
        invalid_certificate_block_count: invalidCertificateBlockCount,
      },
      tags: ["certificate", "parse-quality"],
    });
  }

  if ((parsed.warnings?.length ?? 0) > 0) {
    warnings.push(`Source parser emitted ${parsed.warnings?.length ?? 0} warning(s); review output preserves source_warning_count only.`);
  }

  const weakPublicKeyCount = certificates.filter(isWeakPublicKey).length;
  const longValidityWindowCount = certificates.filter(hasLongValidityWindow).length;

  return {
    artifact: {
      id: "artifact_certificate_review",
      type: "certificate_review",
      source_artifact_id: parsed.artifact.id ?? null,
      source_artifact_type: parsed.artifact.type ?? null,
    },
    observed: {
      source_parser: "parse_pem_certificate",
      source_warning_count: parsed.warnings?.length ?? 0,
      reviewed_certificate_count: certificates.length,
      valid_certificate_count: numberOrZero(observed.valid_certificate_count),
      invalid_certificate_block_count: invalidCertificateBlockCount,
      ca_certificate_count: certificates.filter((certificate) => certificate.ca).length,
      self_issued_certificate_count: certificates.filter((certificate) => certificate.self_issued).length,
      missing_subject_alt_name_count: certificates.filter((certificate) => !certificate.ca && !certificate.subject_alt_name_present).length,
      weak_public_key_count: weakPublicKeyCount,
      long_validity_window_count: longValidityWindowCount,
      evidence_count: evidence.length,
      signal_count: signals.length,
      subjects: uniqueSorted(certificates.map((certificate) => certificate.subject ?? "")),
      issuers: uniqueSorted(certificates.map((certificate) => certificate.issuer ?? "")),
      public_key_types: uniqueSorted(certificates.map((certificate) => certificate.public_key_type ?? "")),
      limitations: [
        "Does not validate certificate chains or trust anchors.",
        "Does not perform hostname matching.",
        "Does not check revocation status.",
        "Does not perform network lookups or certificate transparency enrichment.",
        "Does not use current time to classify certificates as expired or not-yet-valid.",
      ],
      certificates,
    },
    evidence,
    signals,
    warnings,
  };
}

export const reviewCertificateSkill: Skill<unknown, CertificateReviewOutput> = {
  metadata: {
    name: "review_certificate",
    version: "0.1.0",
    category: "reviewer",
    description: "Review parsed PEM certificate observations and emit evidence-backed local certificate signals without trust-chain validation.",
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
      max_input_mb: 2,
      risk: "medium",
      rationale: [
        "Reviews already parsed X.509 certificate metadata from PEM certificate parser output.",
        "Does not validate certificate chains, match hostnames, check revocation, perform network lookups, or score risk.",
        "Output may include certificate subjects, issuers, serial numbers, SAN values, and fingerprints from attacker-controlled artifacts.",
      ],
    },
  },
  run: reviewCertificate,
};
