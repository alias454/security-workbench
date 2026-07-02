import type { EvidenceRecord, JsonObject, JsonValue, SignalRecord, Skill } from "@security-workbench/schemas";
import { localOnlyPermissions } from "./localOnlyPermissions.js";

type ReviewRecord = Record<string, unknown>;
type Confidence = "confirmed" | "high" | "medium" | "low" | "unknown";
type Severity = "informational" | "low" | "medium" | "high" | "critical";

export interface SecurityHeaderCookieObservation {
  readonly cookie_index: number;
  readonly secure_present: boolean;
  readonly http_only_present: boolean;
  readonly same_site_present: boolean;
  readonly same_site_value: string | null;
}

export interface SecurityHeadersReviewOutput {
  readonly artifact: {
    readonly id: "artifact_security_headers_review";
    readonly type: "security_headers_review";
    readonly source_artifact_id: string | null;
    readonly source_artifact_type: string | null;
  };
  readonly observed: {
    readonly source_parser: "parse_http_headers";
    readonly source_warning_count: number;
    readonly status_line_present: boolean;
    readonly status_code: number | null;
    readonly header_count: number;
    readonly duplicate_header_names: readonly string[];
    readonly content_security_policy_present: boolean;
    readonly content_security_policy_count: number;
    readonly content_security_policy_has_unsafe_inline: boolean;
    readonly content_security_policy_has_wildcard_source: boolean;
    readonly content_security_policy_has_frame_ancestors: boolean;
    readonly strict_transport_security_present: boolean;
    readonly strict_transport_security_max_age: number | null;
    readonly strict_transport_security_include_subdomains_present: boolean;
    readonly x_frame_options_present: boolean;
    readonly frame_protection_observed: boolean;
    readonly x_content_type_options_present: boolean;
    readonly referrer_policy_present: boolean;
    readonly permissions_policy_present: boolean;
    readonly set_cookie_count: number;
    readonly set_cookie_without_secure_count: number;
    readonly set_cookie_without_http_only_count: number;
    readonly set_cookie_without_same_site_count: number;
    readonly location_present: boolean;
    readonly evidence_count: number;
    readonly signal_count: number;
    readonly cookie_observations: readonly SecurityHeaderCookieObservation[];
    readonly limitations: readonly string[];
  };
  readonly evidence: readonly EvidenceRecord[];
  readonly signals: readonly SignalRecord[];
  readonly warnings: readonly string[];
}

interface ParsedSecurityHeadersForReview {
  readonly artifact: {
    readonly id?: string;
    readonly type?: string;
  };
  readonly observed: ReviewRecord;
  readonly headers: readonly ReviewRecord[];
  readonly warnings?: readonly string[];
}

const MIN_HSTS_MAX_AGE_SECONDS = 15_552_000;
const LIMITATIONS = [
  "Does not perform HTTP requests, browser policy validation, TLS validation, DNS lookup, redirect following, or live endpoint checks.",
  "Does not determine whether headers are sufficient for a specific application, deployment, browser, or threat model.",
  "Does not classify an endpoint as secure, insecure, exploitable, malicious, benign, compliant, or non-compliant.",
  "Reviews normalized observations from parse_http_headers only.",
] as const;

function isRecord(value: unknown): value is ReviewRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function parseJsonString(input: string): unknown {
  try {
    return JSON.parse(input) as unknown;
  } catch {
    throw new Error("review_security_headers input must be parse_http_headers output JSON or a JSON run result from parse_http_headers");
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

function numberOrNull(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function numberOrZero(value: unknown): number {
  return typeof value === "number" && Number.isFinite(value) ? value : 0;
}

function booleanValue(value: unknown): boolean {
  return value === true;
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

function unwrapInput(input: unknown): ParsedSecurityHeadersForReview {
  const parsed = typeof input === "string" ? parseJsonString(input) : input;
  const candidate = isRecord(parsed) && isRecord(parsed.output) ? parsed.output : parsed;

  if (!isRecord(candidate)) {
    throw new Error("review_security_headers input must be an object");
  }

  const artifact = childRecord(candidate, "artifact");
  const observed = childRecord(candidate, "observed");

  if (!artifact || artifact.type !== "http_headers" || !observed) {
    throw new Error("review_security_headers input must be parse_http_headers output with artifact.type http_headers and observed fields");
  }

  if (isRecord(parsed) && isRecord(parsed.skill) && parsed.skill.name !== "parse_http_headers") {
    throw new Error("review_security_headers JSON run result skill.name must be parse_http_headers");
  }

  return {
    artifact: {
      id: stringOrNull(artifact.id) ?? undefined,
      type: "http_headers",
    },
    observed,
    headers: recordArray(observed.headers),
    warnings: stringArray(candidate.warnings),
  };
}

function headerValues(headers: readonly ReviewRecord[], nameLower: string): string[] {
  const values: string[] = [];

  for (const header of headers) {
    if (stringOrNull(header.lower_name) === nameLower) {
      const value = stringOrNull(header.value);
      if (value !== null) {
        values.push(value);
      }
    }
  }

  return values;
}

function firstHeaderValue(headers: readonly ReviewRecord[], nameLower: string): string | null {
  return headerValues(headers, nameLower)[0] ?? null;
}

function normalizedTokenSet(value: string): Set<string> {
  return new Set(
    value
      .split(";")
      .map((entry) => entry.trim().toLowerCase())
      .filter((entry) => entry.length > 0),
  );
}

function parseHstsMaxAge(value: string | null): number | null {
  if (value === null) {
    return null;
  }

  for (const directive of value.split(";")) {
    const trimmed = directive.trim();
    const separatorIndex = trimmed.indexOf("=");
    if (separatorIndex <= 0) {
      continue;
    }

    const name = trimmed.slice(0, separatorIndex).trim().toLowerCase();
    const rawValue = trimmed.slice(separatorIndex + 1).trim();
    if (name !== "max-age") {
      continue;
    }

    const parsed = Number(rawValue);
    return Number.isFinite(parsed) && parsed >= 0 ? parsed : null;
  }

  return null;
}

function cspHasWildcardSource(values: readonly string[]): boolean {
  return values.some((value) =>
    value
      .split(/[\s;]/)
      .map((entry) => entry.trim())
      .some((entry) => entry === "*" || entry.startsWith("*.")),
  );
}

function cspHasUnsafeInline(values: readonly string[]): boolean {
  return values.some((value) => value.toLowerCase().includes("'unsafe-inline'"));
}

function cspHasFrameAncestors(values: readonly string[]): boolean {
  return values.some((value) => value.toLowerCase().includes("frame-ancestors"));
}

function cookieObservations(cookieValues: readonly string[]): SecurityHeaderCookieObservation[] {
  return cookieValues.map((value, index) => {
    const attributes = normalizedTokenSet(value);
    const sameSiteDirective = [...attributes].find((attribute) => attribute.startsWith("samesite="));
    const sameSiteValue = sameSiteDirective?.slice("samesite=".length) ?? null;

    return {
      cookie_index: index,
      secure_present: attributes.has("secure"),
      http_only_present: attributes.has("httponly"),
      same_site_present: sameSiteValue !== null,
      same_site_value: sameSiteValue,
    };
  });
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
    const id = `evidence_security_headers_${String(evidence.length + 1).padStart(3, "0")}`;
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
    id: `signal_security_headers_${String(signals.length + 1).padStart(3, "0")}`,
    type: input.type,
    summary: input.summary,
    severity: input.severity,
    confidence: input.confidence,
    evidence_refs: input.evidenceRefs,
    observed: input.observed,
    tags: input.tags ?? ["http-headers", "security-headers"],
  });
}

function addPresenceSignal(
  signals: SignalRecord[],
  addEvidence: ReturnType<typeof createEvidenceBuilder>["addEvidence"],
  input: {
    headerName: string;
    signalType: string;
    summary: string;
    severity: Severity;
    observed: JsonObject;
    tags?: readonly string[];
  },
): void {
  const evidenceRef = addEvidence(
    "security_header_not_observed",
    `observed.${input.headerName}`,
    false,
    `${input.headerName} was not observed by parse_http_headers.`,
    "presence",
  );

  addSignal(signals, {
    type: input.signalType,
    summary: input.summary,
    evidenceRefs: [evidenceRef],
    severity: input.severity,
    confidence: "confirmed",
    observed: input.observed,
    tags: input.tags,
  });
}

function addSecurityHeaderSignals(
  facts: ReturnType<typeof buildObservedFacts>,
  addEvidence: ReturnType<typeof createEvidenceBuilder>["addEvidence"],
  signals: SignalRecord[],
): void {
  if (facts.duplicateHeaderNames.length > 0) {
    const evidenceRef = addEvidence(
      "security_header_duplicate_names",
      "observed.duplicate_header_names",
      facts.duplicateHeaderNames,
      "parse_http_headers observed repeated header field names.",
    );

    addSignal(signals, {
      type: "security_headers.duplicate_header_name_observed",
      summary: "Duplicate HTTP header field names were observed.",
      evidenceRefs: [evidenceRef],
      severity: "low",
      confidence: "confirmed",
      observed: { duplicate_header_names: facts.duplicateHeaderNames },
      tags: ["http-headers", "structure"],
    });
  }

  if (!facts.contentSecurityPolicyPresent) {
    addPresenceSignal(signals, addEvidence, {
      headerName: "content_security_policy_present",
      signalType: "security_headers.content_security_policy_not_observed",
      summary: "Content-Security-Policy header was not observed.",
      severity: "medium",
      observed: { content_security_policy_present: false },
      tags: ["http-headers", "content-security-policy"],
    });
  }

  if (facts.contentSecurityPolicyHasUnsafeInline) {
    const evidenceRef = addEvidence(
      "security_header_csp_unsafe_inline",
      "headers.content-security-policy",
      { unsafe_inline_present: true },
      "Content-Security-Policy contains an unsafe-inline source token. This is a header-text observation only.",
    );

    addSignal(signals, {
      type: "security_headers.csp_unsafe_inline_observed",
      summary: "Content-Security-Policy contains unsafe-inline.",
      evidenceRefs: [evidenceRef],
      severity: "medium",
      confidence: "confirmed",
      observed: { content_security_policy_has_unsafe_inline: true },
      tags: ["http-headers", "content-security-policy"],
    });
  }

  if (facts.contentSecurityPolicyHasWildcardSource) {
    const evidenceRef = addEvidence(
      "security_header_csp_wildcard_source",
      "headers.content-security-policy",
      { wildcard_source_present: true },
      "Content-Security-Policy contains a wildcard source token. This is a header-text observation only.",
    );

    addSignal(signals, {
      type: "security_headers.csp_wildcard_source_observed",
      summary: "Content-Security-Policy contains a wildcard source token.",
      evidenceRefs: [evidenceRef],
      severity: "medium",
      confidence: "confirmed",
      observed: { content_security_policy_has_wildcard_source: true },
      tags: ["http-headers", "content-security-policy"],
    });
  }

  if (!facts.strictTransportSecurityPresent) {
    addPresenceSignal(signals, addEvidence, {
      headerName: "strict_transport_security_present",
      signalType: "security_headers.strict_transport_security_not_observed",
      summary: "Strict-Transport-Security header was not observed.",
      severity: "medium",
      observed: { strict_transport_security_present: false },
      tags: ["http-headers", "hsts"],
    });
  } else {
    if (facts.strictTransportSecurityMaxAge === null) {
      const evidenceRef = addEvidence(
        "security_header_hsts_max_age_absent",
        "headers.strict-transport-security",
        { max_age_present: false },
        "Strict-Transport-Security was observed without a parseable max-age directive.",
      );

      addSignal(signals, {
        type: "security_headers.hsts_max_age_not_observed",
        summary: "Strict-Transport-Security max-age directive was not observed.",
        evidenceRefs: [evidenceRef],
        severity: "medium",
        confidence: "confirmed",
        observed: { strict_transport_security_max_age: null },
        tags: ["http-headers", "hsts"],
      });
    } else if (facts.strictTransportSecurityMaxAge < MIN_HSTS_MAX_AGE_SECONDS) {
      const evidenceRef = addEvidence(
        "security_header_hsts_short_max_age",
        "headers.strict-transport-security.max-age",
        facts.strictTransportSecurityMaxAge,
        "Strict-Transport-Security max-age is below the local review threshold used by this reviewer.",
      );

      addSignal(signals, {
        type: "security_headers.hsts_short_max_age_observed",
        summary: "Strict-Transport-Security max-age is below the local review threshold.",
        evidenceRefs: [evidenceRef],
        severity: "low",
        confidence: "confirmed",
        observed: {
          strict_transport_security_max_age: facts.strictTransportSecurityMaxAge,
          threshold_seconds: MIN_HSTS_MAX_AGE_SECONDS,
        },
        tags: ["http-headers", "hsts"],
      });
    }

    if (!facts.strictTransportSecurityIncludeSubdomainsPresent) {
      const evidenceRef = addEvidence(
        "security_header_hsts_include_subdomains_absent",
        "headers.strict-transport-security",
        { include_subdomains_present: false },
        "Strict-Transport-Security was observed without includeSubDomains.",
      );

      addSignal(signals, {
        type: "security_headers.hsts_include_subdomains_not_observed",
        summary: "Strict-Transport-Security includeSubDomains directive was not observed.",
        evidenceRefs: [evidenceRef],
        severity: "informational",
        confidence: "confirmed",
        observed: { strict_transport_security_include_subdomains_present: false },
        tags: ["http-headers", "hsts"],
      });
    }
  }

  if (!facts.frameProtectionObserved) {
    addPresenceSignal(signals, addEvidence, {
      headerName: "frame_protection_observed",
      signalType: "security_headers.frame_protection_not_observed",
      summary: "No X-Frame-Options header or CSP frame-ancestors directive was observed.",
      severity: "medium",
      observed: { x_frame_options_present: false, content_security_policy_has_frame_ancestors: false },
      tags: ["http-headers", "clickjacking"],
    });
  }

  if (!facts.xContentTypeOptionsPresent) {
    addPresenceSignal(signals, addEvidence, {
      headerName: "x_content_type_options_present",
      signalType: "security_headers.x_content_type_options_not_observed",
      summary: "X-Content-Type-Options header was not observed.",
      severity: "low",
      observed: { x_content_type_options_present: false },
      tags: ["http-headers", "mime-sniffing"],
    });
  }

  if (!facts.referrerPolicyPresent) {
    addPresenceSignal(signals, addEvidence, {
      headerName: "referrer_policy_present",
      signalType: "security_headers.referrer_policy_not_observed",
      summary: "Referrer-Policy header was not observed.",
      severity: "low",
      observed: { referrer_policy_present: false },
      tags: ["http-headers", "privacy"],
    });
  }

  if (!facts.permissionsPolicyPresent) {
    addPresenceSignal(signals, addEvidence, {
      headerName: "permissions_policy_present",
      signalType: "security_headers.permissions_policy_not_observed",
      summary: "Permissions-Policy header was not observed.",
      severity: "informational",
      observed: { permissions_policy_present: false },
      tags: ["http-headers", "browser-policy"],
    });
  }

  if (facts.setCookieWithoutSecureCount > 0) {
    const evidenceRef = addEvidence(
      "security_header_cookie_secure_absent",
      "headers.set-cookie",
      { cookie_count_without_secure: facts.setCookieWithoutSecureCount },
      "One or more Set-Cookie headers were observed without a Secure attribute. Cookie values are not copied into evidence.",
    );

    addSignal(signals, {
      type: "security_headers.cookie_secure_attribute_not_observed",
      summary: "One or more Set-Cookie headers lacked an observed Secure attribute.",
      evidenceRefs: [evidenceRef],
      severity: "medium",
      confidence: "confirmed",
      observed: { set_cookie_without_secure_count: facts.setCookieWithoutSecureCount },
      tags: ["http-headers", "cookies"],
    });
  }

  if (facts.setCookieWithoutHttpOnlyCount > 0) {
    const evidenceRef = addEvidence(
      "security_header_cookie_http_only_absent",
      "headers.set-cookie",
      { cookie_count_without_http_only: facts.setCookieWithoutHttpOnlyCount },
      "One or more Set-Cookie headers were observed without an HttpOnly attribute. Cookie values are not copied into evidence.",
    );

    addSignal(signals, {
      type: "security_headers.cookie_http_only_attribute_not_observed",
      summary: "One or more Set-Cookie headers lacked an observed HttpOnly attribute.",
      evidenceRefs: [evidenceRef],
      severity: "low",
      confidence: "confirmed",
      observed: { set_cookie_without_http_only_count: facts.setCookieWithoutHttpOnlyCount },
      tags: ["http-headers", "cookies"],
    });
  }

  if (facts.setCookieWithoutSameSiteCount > 0) {
    const evidenceRef = addEvidence(
      "security_header_cookie_same_site_absent",
      "headers.set-cookie",
      { cookie_count_without_same_site: facts.setCookieWithoutSameSiteCount },
      "One or more Set-Cookie headers were observed without a SameSite attribute. Cookie values are not copied into evidence.",
    );

    addSignal(signals, {
      type: "security_headers.cookie_same_site_attribute_not_observed",
      summary: "One or more Set-Cookie headers lacked an observed SameSite attribute.",
      evidenceRefs: [evidenceRef],
      severity: "low",
      confidence: "confirmed",
      observed: { set_cookie_without_same_site_count: facts.setCookieWithoutSameSiteCount },
      tags: ["http-headers", "cookies"],
    });
  }
}

function buildObservedFacts(parsed: ParsedSecurityHeadersForReview) {
  const observed = parsed.observed;
  const headers = parsed.headers;
  const cspValues = headerValues(headers, "content-security-policy");
  const hstsValue = firstHeaderValue(headers, "strict-transport-security");
  const hstsLower = hstsValue?.toLowerCase() ?? "";
  const cookies = cookieObservations(headerValues(headers, "set-cookie"));
  const cspFrameAncestors = cspHasFrameAncestors(cspValues);
  const xFrameOptionsPresent = booleanValue(observed.x_frame_options_present);

  return {
    statusLinePresent: booleanValue(observed.status_line_present),
    statusCode: numberOrNull(observed.status_code),
    headerCount: numberOrZero(observed.header_count),
    duplicateHeaderNames: stringArray(observed.duplicate_header_names),
    contentSecurityPolicyPresent: booleanValue(observed.content_security_policy_present),
    contentSecurityPolicyCount: cspValues.length,
    contentSecurityPolicyHasUnsafeInline: cspHasUnsafeInline(cspValues),
    contentSecurityPolicyHasWildcardSource: cspHasWildcardSource(cspValues),
    contentSecurityPolicyHasFrameAncestors: cspFrameAncestors,
    strictTransportSecurityPresent: booleanValue(observed.strict_transport_security_present),
    strictTransportSecurityMaxAge: parseHstsMaxAge(hstsValue),
    strictTransportSecurityIncludeSubdomainsPresent: hstsLower.includes("includesubdomains"),
    xFrameOptionsPresent,
    frameProtectionObserved: xFrameOptionsPresent || cspFrameAncestors,
    xContentTypeOptionsPresent: booleanValue(observed.x_content_type_options_present),
    referrerPolicyPresent: booleanValue(observed.referrer_policy_present),
    permissionsPolicyPresent: booleanValue(observed.permissions_policy_present),
    setCookieCount: numberOrZero(observed.set_cookie_count),
    setCookieWithoutSecureCount: cookies.filter((cookie) => !cookie.secure_present).length,
    setCookieWithoutHttpOnlyCount: cookies.filter((cookie) => !cookie.http_only_present).length,
    setCookieWithoutSameSiteCount: cookies.filter((cookie) => !cookie.same_site_present).length,
    locationPresent: booleanValue(observed.location_present),
    cookieObservations: cookies,
  };
}

export function reviewSecurityHeaders(input: unknown): SecurityHeadersReviewOutput {
  const parsed = unwrapInput(input);
  const facts = buildObservedFacts(parsed);
  const sourceArtifactId = parsed.artifact.id ?? null;
  const { evidence, addEvidence } = createEvidenceBuilder(sourceArtifactId);
  const signals: SignalRecord[] = [];
  addSecurityHeaderSignals(facts, addEvidence, signals);

  const sourceWarningCount = parsed.warnings?.length ?? 0;
  const warnings = sourceWarningCount > 0
    ? [`Source parser emitted ${sourceWarningCount} warning(s); review output preserves source_warning_count only.`]
    : [];

  return {
    artifact: {
      id: "artifact_security_headers_review",
      type: "security_headers_review",
      source_artifact_id: sourceArtifactId,
      source_artifact_type: parsed.artifact.type ?? null,
    },
    observed: {
      source_parser: "parse_http_headers",
      source_warning_count: sourceWarningCount,
      status_line_present: facts.statusLinePresent,
      status_code: facts.statusCode,
      header_count: facts.headerCount,
      duplicate_header_names: facts.duplicateHeaderNames,
      content_security_policy_present: facts.contentSecurityPolicyPresent,
      content_security_policy_count: facts.contentSecurityPolicyCount,
      content_security_policy_has_unsafe_inline: facts.contentSecurityPolicyHasUnsafeInline,
      content_security_policy_has_wildcard_source: facts.contentSecurityPolicyHasWildcardSource,
      content_security_policy_has_frame_ancestors: facts.contentSecurityPolicyHasFrameAncestors,
      strict_transport_security_present: facts.strictTransportSecurityPresent,
      strict_transport_security_max_age: facts.strictTransportSecurityMaxAge,
      strict_transport_security_include_subdomains_present: facts.strictTransportSecurityIncludeSubdomainsPresent,
      x_frame_options_present: facts.xFrameOptionsPresent,
      frame_protection_observed: facts.frameProtectionObserved,
      x_content_type_options_present: facts.xContentTypeOptionsPresent,
      referrer_policy_present: facts.referrerPolicyPresent,
      permissions_policy_present: facts.permissionsPolicyPresent,
      set_cookie_count: facts.setCookieCount,
      set_cookie_without_secure_count: facts.setCookieWithoutSecureCount,
      set_cookie_without_http_only_count: facts.setCookieWithoutHttpOnlyCount,
      set_cookie_without_same_site_count: facts.setCookieWithoutSameSiteCount,
      location_present: facts.locationPresent,
      evidence_count: evidence.length,
      signal_count: signals.length,
      cookie_observations: facts.cookieObservations,
      limitations: LIMITATIONS,
    },
    evidence,
    signals,
    warnings,
  };
}

export const reviewSecurityHeadersSkill: Skill<unknown, SecurityHeadersReviewOutput> = {
  metadata: {
    name: "review_security_headers",
    version: "0.1.0",
    category: "reviewer",
    description:
      "Review parsed HTTP security header observations and emit evidence-backed browser policy and cookie attribute signals without live endpoint checks or scoring.",
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
        "Reviews already parsed HTTP response header metadata that may include cookie names, redirect targets, and application policy details.",
        "Does not perform HTTP requests, browser policy validation, TLS validation, DNS lookup, redirects, reputation checks, scoring, or finding generation.",
        "Output preserves evidence-backed header observations with explicit limitations and does not classify security, exploitability, compliance, maliciousness, or benignness.",
      ],
    },
  },
  run: reviewSecurityHeaders,
};
