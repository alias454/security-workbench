import type { EvidenceRecord, JsonObject, JsonValue, SignalRecord, Skill } from "@security-workbench/schemas";
import { localOnlyPermissions } from "./localOnlyPermissions.js";

type ReviewRecord = Record<string, unknown>;
type Confidence = "confirmed" | "high" | "medium" | "low" | "unknown";
type Severity = "informational" | "low" | "medium" | "high" | "critical";

export interface EmailHeaderReviewOutput {
  readonly artifact: {
    readonly id: "artifact_email_header_review";
    readonly type: "email_header_review";
    readonly source_artifact_id: null;
    readonly source_artifact_type: null;
  };
  readonly observed: {
    readonly source_parser: "parse_email_headers";
    readonly source_warning_count: number;
    readonly header_count: number;
    readonly duplicate_header_names: readonly string[];
    readonly received_count: number;
    readonly authentication_results_count: number;
    readonly from_present: boolean;
    readonly to_present: boolean;
    readonly subject_present: boolean;
    readonly date_present: boolean;
    readonly message_id_present: boolean;
    readonly reply_to_present: boolean;
    readonly return_path_present: boolean;
    readonly sender_present: boolean;
    readonly from_domain: string | null;
    readonly reply_to_domain: string | null;
    readonly return_path_domain: string | null;
    readonly sender_domain: string | null;
    readonly authentication_result_mechanisms: readonly string[];
    readonly authentication_result_failures: readonly EmailAuthenticationResultObservation[];
    readonly evidence_count: number;
    readonly signal_count: number;
    readonly limitations: readonly string[];
  };
  readonly evidence: readonly EvidenceRecord[];
  readonly signals: readonly SignalRecord[];
  readonly warnings: readonly string[];
}

export interface EmailAuthenticationResultObservation {
  readonly mechanism: string;
  readonly result: string;
}

interface ParsedEmailHeadersForReview {
  readonly headers: readonly ReviewRecord[];
  readonly header_count: number;
  readonly duplicate_header_names: readonly string[];
  readonly observed: ReviewRecord;
  readonly warnings?: readonly string[];
}

const AUTHENTICATION_MECHANISMS = ["spf", "dkim", "dmarc", "arc", "bimi"] as const;
const FAILURE_AUTH_RESULTS = ["fail", "softfail", "temperror", "permerror"] as const;
const LIMITATIONS = [
  "Does not perform DNS lookup, SPF validation, DKIM signature validation, DMARC policy validation, ARC validation, BIMI validation, or reputation checks.",
  "Does not inspect message body content, attachments, links, or landing pages.",
  "Does not classify a message as phishing, spam, malicious, benign, delivered, or blocked.",
  "Reviews normalized observations from parse_email_headers only.",
] as const;

function isRecord(value: unknown): value is ReviewRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function parseJsonString(input: string): unknown {
  try {
    return JSON.parse(input) as unknown;
  } catch {
    throw new Error("review_email_header input must be parse_email_headers output JSON or a JSON run result from parse_email_headers");
  }
}

function childRecord(record: ReviewRecord, key: string): ReviewRecord | undefined {
  const value = record[key];
  return isRecord(value) ? value : undefined;
}

function stringOrNull(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((entry): entry is string => typeof entry === "string") : [];
}

function recordArray(value: unknown): ReviewRecord[] {
  return Array.isArray(value) ? value.filter(isRecord) : [];
}

function numberOrZero(value: unknown): number {
  return typeof value === "number" && Number.isFinite(value) ? value : 0;
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

function unwrapInput(input: unknown): ParsedEmailHeadersForReview {
  const parsed = typeof input === "string" ? parseJsonString(input) : input;
  const candidate = isRecord(parsed) && isRecord(parsed.output) ? parsed.output : parsed;

  if (!isRecord(candidate)) {
    throw new Error("review_email_header input must be an object");
  }

  const headers = recordArray(candidate.headers);
  const observed = childRecord(candidate, "observed");

  if (!observed || !Array.isArray(candidate.headers)) {
    throw new Error("review_email_header input must be parse_email_headers output with headers and observed fields");
  }

  if (isRecord(parsed) && isRecord(parsed.skill) && parsed.skill.name !== "parse_email_headers") {
    throw new Error("review_email_header JSON run result skill.name must be parse_email_headers");
  }

  return {
    headers,
    header_count: numberOrZero(candidate.header_count),
    duplicate_header_names: stringArray(candidate.duplicate_header_names),
    observed,
    warnings: stringArray(candidate.warnings),
  };
}

function firstHeaderValue(headers: readonly ReviewRecord[], nameLower: string): string | null {
  for (const header of headers) {
    if (stringOrNull(header.name_lower) === nameLower) {
      return stringOrNull(header.value);
    }
  }

  return null;
}

function observedString(observed: ReviewRecord, key: string): string | null {
  return stringOrNull(observed[key]);
}

function firstEmailDomain(value: string | null): string | null {
  if (value === null) {
    return null;
  }

  const emailMatch = value.match(/[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})/);
  return emailMatch?.[1]?.toLowerCase() ?? null;
}

function authResultObservations(authenticationResults: readonly string[]): EmailAuthenticationResultObservation[] {
  const observations: EmailAuthenticationResultObservation[] = [];

  for (const value of authenticationResults) {
    for (const mechanism of AUTHENTICATION_MECHANISMS) {
      const pattern = new RegExp(`\\b${mechanism}=([A-Za-z0-9_-]+)`, "gi");
      for (const match of value.matchAll(pattern)) {
        const result = match[1]?.toLowerCase();
        if (result) {
          observations.push({ mechanism, result });
        }
      }
    }
  }

  return uniqueAuthResultObservations(observations);
}

function uniqueAuthResultObservations(observations: readonly EmailAuthenticationResultObservation[]): EmailAuthenticationResultObservation[] {
  const seen = new Set<string>();
  const unique: EmailAuthenticationResultObservation[] = [];

  for (const observation of observations) {
    const key = `${observation.mechanism}:${observation.result}`;
    if (!seen.has(key)) {
      seen.add(key);
      unique.push(observation);
    }
  }

  return unique.sort((left, right) => `${left.mechanism}:${left.result}`.localeCompare(`${right.mechanism}:${right.result}`));
}

function failureAuthResults(observations: readonly EmailAuthenticationResultObservation[]): EmailAuthenticationResultObservation[] {
  return observations.filter((observation) => FAILURE_AUTH_RESULTS.includes(observation.result as (typeof FAILURE_AUTH_RESULTS)[number]));
}

function createEvidenceBuilder() {
  const evidence: EvidenceRecord[] = [];

  function addEvidence(
    type: string,
    path: string,
    value: unknown,
    description: string,
    valueKind: EvidenceRecord["value_kind"] = "metadata",
  ): string {
    const id = `evidence_email_header_${String(evidence.length + 1).padStart(3, "0")}`;
    evidence.push({
      id,
      type,
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
    id: `signal_email_header_${String(signals.length + 1).padStart(3, "0")}`,
    type: input.type,
    summary: input.summary,
    severity: input.severity,
    confidence: input.confidence,
    evidence_refs: input.evidenceRefs,
    observed: input.observed,
    tags: input.tags ?? ["email", "headers"],
  });
}

function addEmailHeaderSignals(
  parsed: ParsedEmailHeadersForReview,
  addEvidence: ReturnType<typeof createEvidenceBuilder>["addEvidence"],
  signals: SignalRecord[],
): void {
  const observed = parsed.observed;
  const authenticationResults = stringArray(observed.authentication_results);
  const authObservations = authResultObservations(authenticationResults);
  const authFailures = failureAuthResults(authObservations);
  const receivedCount = numberOrZero(observed.received_count);
  const messageId = observedString(observed, "message_id");
  const date = observedString(observed, "date");
  const from = observedString(observed, "from");
  const fromDomain = firstEmailDomain(from);
  const replyToDomain = firstEmailDomain(firstHeaderValue(parsed.headers, "reply-to"));
  const returnPathDomain = firstEmailDomain(firstHeaderValue(parsed.headers, "return-path"));
  const senderDomain = firstEmailDomain(firstHeaderValue(parsed.headers, "sender"));

  if (parsed.duplicate_header_names.length > 0) {
    const evidenceRef = addEvidence(
      "email_header_duplicate_names",
      "duplicate_header_names",
      parsed.duplicate_header_names,
      "parse_email_headers observed repeated header field names.",
    );

    addSignal(signals, {
      type: "email_header.duplicate_header_name_observed",
      summary: "Duplicate email header field names were observed.",
      evidenceRefs: [evidenceRef],
      severity: "low",
      confidence: "confirmed",
      observed: { duplicate_header_names: parsed.duplicate_header_names },
      tags: ["email", "headers", "structure"],
    });
  }

  if (authenticationResults.length === 0) {
    const evidenceRef = addEvidence(
      "email_header_authentication_results_absent",
      "observed.authentication_results",
      false,
      "No Authentication-Results header value was observed by parse_email_headers.",
      "presence",
    );

    addSignal(signals, {
      type: "email_header.authentication_results_not_observed",
      summary: "Authentication-Results header was not observed.",
      evidenceRefs: [evidenceRef],
      severity: "informational",
      confidence: "confirmed",
      observed: { authentication_results_present: false },
      tags: ["email", "authentication", "parser-observation"],
    });
  }

  if (authFailures.length > 0) {
    const evidenceRef = addEvidence(
      "email_header_authentication_result_failure",
      "observed.authentication_results",
      authFailures,
      "Authentication-Results header text contains one or more failed or error authentication results. This is parsed header text, not independent validation.",
    );

    addSignal(signals, {
      type: "email_header.authentication_result_failure_observed",
      summary: "Authentication-Results text reports failed or error authentication outcomes.",
      evidenceRefs: [evidenceRef],
      severity: "medium",
      confidence: "confirmed",
      observed: { authentication_result_failures: authFailures as unknown as JsonValue },
      tags: ["email", "authentication", "parser-observation"],
    });
  }

  if (receivedCount === 0) {
    const evidenceRef = addEvidence(
      "email_header_received_chain_absent",
      "observed.received_count",
      0,
      "No Received header field was observed by parse_email_headers.",
    );

    addSignal(signals, {
      type: "email_header.received_chain_not_observed",
      summary: "Received header chain was not observed.",
      evidenceRefs: [evidenceRef],
      severity: "informational",
      confidence: "confirmed",
      observed: { received_count: 0 },
      tags: ["email", "routing", "parser-observation"],
    });
  }

  if (messageId === null) {
    const evidenceRef = addEvidence(
      "email_header_message_id_absent",
      "observed.message_id",
      false,
      "No Message-ID header value was observed by parse_email_headers.",
      "presence",
    );

    addSignal(signals, {
      type: "email_header.message_id_not_observed",
      summary: "Message-ID header was not observed.",
      evidenceRefs: [evidenceRef],
      severity: "low",
      confidence: "confirmed",
      observed: { message_id_present: false },
      tags: ["email", "identity", "parser-observation"],
    });
  }

  if (date === null) {
    const evidenceRef = addEvidence(
      "email_header_date_absent",
      "observed.date",
      false,
      "No Date header value was observed by parse_email_headers.",
      "presence",
    );

    addSignal(signals, {
      type: "email_header.date_not_observed",
      summary: "Date header was not observed.",
      evidenceRefs: [evidenceRef],
      severity: "low",
      confidence: "confirmed",
      observed: { date_present: false },
      tags: ["email", "identity", "parser-observation"],
    });
  }

  if (fromDomain !== null && replyToDomain !== null && fromDomain !== replyToDomain) {
    const evidenceRef = addEvidence(
      "email_header_reply_to_from_domain_mismatch",
      "headers.reply-to",
      { from_domain: fromDomain, reply_to_domain: replyToDomain },
      "Reply-To domain differs from the From domain. This is a structural observation, not a phishing verdict.",
    );

    addSignal(signals, {
      type: "email_header.reply_to_from_domain_mismatch_observed",
      summary: "Reply-To domain differs from From domain.",
      evidenceRefs: [evidenceRef],
      severity: "medium",
      confidence: "confirmed",
      observed: { from_domain: fromDomain, reply_to_domain: replyToDomain },
      tags: ["email", "identity", "domain-mismatch"],
    });
  }

  if (fromDomain !== null && returnPathDomain !== null && fromDomain !== returnPathDomain) {
    const evidenceRef = addEvidence(
      "email_header_return_path_from_domain_mismatch",
      "headers.return-path",
      { from_domain: fromDomain, return_path_domain: returnPathDomain },
      "Return-Path domain differs from the From domain. This is a structural observation, not a delivery or authentication verdict.",
    );

    addSignal(signals, {
      type: "email_header.return_path_from_domain_mismatch_observed",
      summary: "Return-Path domain differs from From domain.",
      evidenceRefs: [evidenceRef],
      severity: "low",
      confidence: "confirmed",
      observed: { from_domain: fromDomain, return_path_domain: returnPathDomain },
      tags: ["email", "identity", "domain-mismatch"],
    });
  }

  if (fromDomain !== null && senderDomain !== null && fromDomain !== senderDomain) {
    const evidenceRef = addEvidence(
      "email_header_sender_from_domain_mismatch",
      "headers.sender",
      { from_domain: fromDomain, sender_domain: senderDomain },
      "Sender domain differs from the From domain. This is a structural observation, not a phishing verdict.",
    );

    addSignal(signals, {
      type: "email_header.sender_from_domain_mismatch_observed",
      summary: "Sender domain differs from From domain.",
      evidenceRefs: [evidenceRef],
      severity: "low",
      confidence: "confirmed",
      observed: { from_domain: fromDomain, sender_domain: senderDomain },
      tags: ["email", "identity", "domain-mismatch"],
    });
  }
}

export function reviewEmailHeader(input: unknown): EmailHeaderReviewOutput {
  const parsed = unwrapInput(input);
  const { evidence, addEvidence } = createEvidenceBuilder();
  const signals: SignalRecord[] = [];
  addEmailHeaderSignals(parsed, addEvidence, signals);

  const observed = parsed.observed;
  const from = observedString(observed, "from");
  const replyTo = firstHeaderValue(parsed.headers, "reply-to");
  const returnPath = firstHeaderValue(parsed.headers, "return-path");
  const sender = firstHeaderValue(parsed.headers, "sender");
  const authenticationResults = stringArray(observed.authentication_results);
  const authObservations = authResultObservations(authenticationResults);
  const authFailures = failureAuthResults(authObservations);
  const sourceWarningCount = parsed.warnings?.length ?? 0;
  const warnings = sourceWarningCount > 0
    ? [`Source parser emitted ${sourceWarningCount} warning(s); review output preserves source_warning_count only.`]
    : [];

  return {
    artifact: {
      id: "artifact_email_header_review",
      type: "email_header_review",
      source_artifact_id: null,
      source_artifact_type: null,
    },
    observed: {
      source_parser: "parse_email_headers",
      source_warning_count: sourceWarningCount,
      header_count: parsed.header_count,
      duplicate_header_names: parsed.duplicate_header_names,
      received_count: numberOrZero(observed.received_count),
      authentication_results_count: authenticationResults.length,
      from_present: from !== null,
      to_present: observedString(observed, "to") !== null,
      subject_present: observedString(observed, "subject") !== null,
      date_present: observedString(observed, "date") !== null,
      message_id_present: observedString(observed, "message_id") !== null,
      reply_to_present: replyTo !== null,
      return_path_present: returnPath !== null,
      sender_present: sender !== null,
      from_domain: firstEmailDomain(from),
      reply_to_domain: firstEmailDomain(replyTo),
      return_path_domain: firstEmailDomain(returnPath),
      sender_domain: firstEmailDomain(sender),
      authentication_result_mechanisms: uniqueSorted(authObservations.map((observation) => observation.mechanism)),
      authentication_result_failures: authFailures,
      evidence_count: evidence.length,
      signal_count: signals.length,
      limitations: LIMITATIONS,
    },
    evidence,
    signals,
    warnings,
  };
}

export const reviewEmailHeaderSkill: Skill<unknown, EmailHeaderReviewOutput> = {
  metadata: {
    name: "review_email_header",
    version: "0.1.0",
    category: "reviewer",
    description:
      "Review parsed email header observations and emit evidence-backed routing, authentication-result, and identity-mismatch signals without DNS validation or phishing verdicts.",
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
        "Reviews already parsed email header metadata that may contain sender, recipient, routing, subject, and authentication-result metadata.",
        "Does not perform DNS, SPF, DKIM, DMARC, ARC, BIMI, reputation, URL, body, or attachment analysis.",
        "Output preserves evidence-backed header observations with explicit limitations and does not classify phishing, spam, maliciousness, delivery, or authenticity.",
      ],
    },
  },
  run: reviewEmailHeader,
};
