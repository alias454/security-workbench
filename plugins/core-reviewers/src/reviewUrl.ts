import type { EvidenceRecord, JsonObject, JsonValue, SignalRecord, Skill } from "@security-workbench/schemas";
import { localOnlyPermissions } from "./localOnlyPermissions.js";

type ReviewRecord = Record<string, unknown>;
type Severity = "informational" | "low" | "medium" | "high" | "critical";
type Confidence = "confirmed" | "high" | "medium" | "low" | "unknown";

export interface UrlReviewUrlObservation {
  readonly url_index: number;
  readonly normalized_url: string;
  readonly scheme: string;
  readonly hostname: string;
  readonly port: string | null;
  readonly path_present: boolean;
  readonly query_present: boolean;
  readonly fragment_present: boolean;
  readonly userinfo_present: boolean;
  readonly url_length: number;
  readonly hostname_length: number;
  readonly hostname_label_count: number;
  readonly query_parameter_count: number;
  readonly redirect_parameter_names: readonly string[];
  readonly file_extension: string | null;
  readonly source: string | null;
  readonly first_seen_line: number | null;
  readonly occurrence_count: number;
}

export interface UrlReviewOutput {
  readonly artifact: {
    readonly id: "artifact_url_review";
    readonly type: "url_review";
    readonly source_artifact_id: string | null;
    readonly source_artifact_type: string | null;
  };
  readonly observed: {
    readonly source_parser: "extract_defanged_urls";
    readonly source_warning_count: number;
    readonly reviewed_url_count: number;
    readonly plain_http_count: number;
    readonly userinfo_url_count: number;
    readonly ip_literal_host_count: number;
    readonly non_default_port_count: number;
    readonly punycode_host_count: number;
    readonly long_hostname_count: number;
    readonly long_url_count: number;
    readonly many_subdomains_count: number;
    readonly query_parameter_url_count: number;
    readonly fragment_url_count: number;
    readonly redirect_parameter_url_count: number;
    readonly suspicious_file_extension_count: number;
    readonly evidence_count: number;
    readonly signal_count: number;
    readonly urls: readonly UrlReviewUrlObservation[];
    readonly limitations: readonly string[];
  };
  readonly evidence: readonly EvidenceRecord[];
  readonly signals: readonly SignalRecord[];
  readonly warnings: readonly string[];
}

interface ExtractedUrlForReview {
  readonly original_value?: unknown;
  readonly normalized_url?: unknown;
  readonly scheme?: unknown;
  readonly hostname?: unknown;
  readonly port?: unknown;
  readonly path_present?: unknown;
  readonly query_present?: unknown;
  readonly fragment_present?: unknown;
  readonly username_present?: unknown;
  readonly password_present?: unknown;
  readonly source?: unknown;
  readonly first_seen_line?: unknown;
  readonly occurrence_count?: unknown;
}

interface ExtractDefangedUrlsForReview {
  readonly artifact: {
    readonly id?: string;
    readonly type?: string;
  };
  readonly urls: readonly ExtractedUrlForReview[];
  readonly warnings?: readonly string[];
}

const LONG_URL_THRESHOLD = 2_048;
const LONG_HOSTNAME_THRESHOLD = 120;
const MANY_SUBDOMAINS_THRESHOLD = 4;

const REDIRECT_PARAMETER_NAMES = new Set([
  "continue",
  "dest",
  "destination",
  "next",
  "redir",
  "redirect",
  "redirect_uri",
  "redirect_url",
  "return",
  "return_to",
  "return_url",
  "target",
  "u",
  "uri",
  "url",
]);

const SUSPICIOUS_FILE_EXTENSIONS = new Set([
  "apk",
  "bat",
  "cmd",
  "com",
  "dll",
  "dmg",
  "exe",
  "hta",
  "iso",
  "jar",
  "js",
  "jse",
  "lnk",
  "msi",
  "ps1",
  "scr",
  "vbe",
  "vbs",
  "wsf",
]);

const LIMITATIONS = [
  "Reviews URL structure observed by extract_defanged_urls only.",
  "Does not perform DNS lookup, URL fetching, redirect following, reputation checks, browser rendering, or content inspection.",
  "Does not classify a URL as phishing, spam, malicious, benign, exploitable, safe, or unsafe.",
  "Does not perform typosquat, brand impersonation, or domain registration analysis.",
] as const;

function isRecord(value: unknown): value is ReviewRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function parseJsonString(input: string): unknown {
  try {
    return JSON.parse(input) as unknown;
  } catch {
    throw new Error("review_url input must be extract_defanged_urls output JSON or a JSON run result from extract_defanged_urls");
  }
}

function stringOrNull(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}

function booleanValue(value: unknown): boolean {
  return value === true;
}

function numberOrNull(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function numberOrDefault(value: unknown, fallback: number): number {
  const parsed = numberOrNull(value);
  return parsed === null ? fallback : parsed;
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((entry): entry is string => typeof entry === "string") : [];
}

function childRecord(record: ReviewRecord, key: string): ReviewRecord | undefined {
  const value = record[key];
  return isRecord(value) ? value : undefined;
}

function recordArray(value: unknown): ReviewRecord[] {
  return Array.isArray(value) ? value.filter(isRecord) : [];
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

function unwrapInput(input: unknown): ExtractDefangedUrlsForReview {
  const parsed = typeof input === "string" ? parseJsonString(input) : input;
  const candidate = isRecord(parsed) && isRecord(parsed.output) ? parsed.output : parsed;

  if (!isRecord(candidate)) {
    throw new Error("review_url input must be an object");
  }

  const artifact = childRecord(candidate, "artifact");
  if (!artifact || artifact.type !== "defanged_url_extraction") {
    throw new Error("review_url input must be extract_defanged_urls output with artifact.type defanged_url_extraction");
  }

  if (isRecord(parsed) && isRecord(parsed.skill) && parsed.skill.name !== "extract_defanged_urls") {
    throw new Error("review_url JSON run result skill.name must be extract_defanged_urls");
  }

  return {
    artifact: {
      id: stringOrNull(artifact.id) ?? undefined,
      type: "defanged_url_extraction",
    },
    urls: recordArray(candidate.urls),
    warnings: stringArray(candidate.warnings),
  };
}

function uniqueSorted(values: readonly string[]): string[] {
  return [...new Set(values)].sort((left, right) => left.localeCompare(right));
}

function hostnameLabelCount(hostname: string): number {
  const normalized = hostname.replace(/^\[/, "").replace(/\]$/, "");
  if (normalized.includes(":")) {
    return 1;
  }

  return normalized.split(".").filter((label) => label.length > 0).length;
}

function isIpv4Literal(hostname: string): boolean {
  const parts = hostname.split(".");
  return parts.length === 4 && parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) >= 0 && Number(part) <= 255);
}

function isIpLiteralHost(hostname: string): boolean {
  const normalized = hostname.replace(/^\[/, "").replace(/\]$/, "");
  return isIpv4Literal(normalized) || normalized.includes(":");
}

function isDefaultPort(scheme: string, port: string | null): boolean {
  return port === null || (scheme === "http" && port === "80") || (scheme === "https" && port === "443");
}

function parseUrlOrNull(value: string): URL | null {
  try {
    return new URL(value);
  } catch {
    return null;
  }
}

function queryParameterNames(parsed: URL | null): string[] {
  if (parsed === null) {
    return [];
  }

  return uniqueSorted([...parsed.searchParams.keys()].map((name) => name.toLowerCase()));
}

function redirectParameterNames(parsed: URL | null): string[] {
  return queryParameterNames(parsed).filter((name) => REDIRECT_PARAMETER_NAMES.has(name));
}

function fileExtension(parsed: URL | null): string | null {
  if (parsed === null) {
    return null;
  }

  const lastSegment = parsed.pathname.split("/").filter((segment) => segment.length > 0).at(-1) ?? "";
  const dotIndex = lastSegment.lastIndexOf(".");
  if (dotIndex <= 0 || dotIndex === lastSegment.length - 1) {
    return null;
  }

  const extension = lastSegment.slice(dotIndex + 1).toLowerCase();
  return /^[a-z0-9]{1,12}$/.test(extension) ? extension : null;
}

function toUrlObservation(input: ExtractedUrlForReview, index: number): UrlReviewUrlObservation | null {
  const normalizedUrl = stringOrNull(input.normalized_url);
  const hostname = stringOrNull(input.hostname);
  const scheme = stringOrNull(input.scheme);
  if (normalizedUrl === null || hostname === null || scheme === null) {
    return null;
  }

  const parsed = parseUrlOrNull(normalizedUrl);
  const redirectNames = redirectParameterNames(parsed);
  const parameterNames = queryParameterNames(parsed);

  return {
    url_index: index,
    normalized_url: normalizedUrl,
    scheme,
    hostname,
    port: stringOrNull(input.port),
    path_present: booleanValue(input.path_present),
    query_present: booleanValue(input.query_present),
    fragment_present: booleanValue(input.fragment_present),
    userinfo_present: booleanValue(input.username_present) || booleanValue(input.password_present),
    url_length: normalizedUrl.length,
    hostname_length: hostname.length,
    hostname_label_count: hostnameLabelCount(hostname),
    query_parameter_count: parameterNames.length,
    redirect_parameter_names: redirectNames,
    file_extension: fileExtension(parsed),
    source: stringOrNull(input.source),
    first_seen_line: numberOrNull(input.first_seen_line),
    occurrence_count: numberOrDefault(input.occurrence_count, 1),
  };
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
    const id = `evidence_url_review_${String(evidence.length + 1).padStart(3, "0")}`;
    evidence.push({
      id,
      type,
      artifact_ref: sourceArtifactId ?? undefined,
      path,
      value: evidenceValue(value),
      value_kind: valueKind,
      description,
    });
    return id;
  }

  return { evidence, addEvidence };
}

function createSignalBuilder(sourceArtifactId: string | null) {
  const signals: SignalRecord[] = [];

  function addSignal(
    type: string,
    summary: string,
    evidenceRefs: readonly string[],
    observed: JsonObject,
    severity: Severity = "informational",
    confidence: Confidence = "confirmed",
  ): void {
    signals.push({
      id: `signal_url_review_${String(signals.length + 1).padStart(3, "0")}`,
      type,
      summary,
      severity,
      confidence,
      artifact_refs: sourceArtifactId === null ? [] : [sourceArtifactId],
      evidence_refs: evidenceRefs,
      observed,
      tags: ["url", "structure", "local-only"],
    });
  }

  return { signals, addSignal };
}

function buildReview(input: ExtractDefangedUrlsForReview): UrlReviewOutput {
  const sourceArtifactId = input.artifact.id ?? null;
  const { evidence, addEvidence } = createEvidenceBuilder(sourceArtifactId);
  const { signals, addSignal } = createSignalBuilder(sourceArtifactId);
  const urls = input.urls
    .map((url, index) => toUrlObservation(url, index))
    .filter((url): url is UrlReviewUrlObservation => url !== null);

  const countEvidenceRefs = [
    addEvidence("url.count", "$.urls", urls.length, "Count of URL observations reviewed from extract_defanged_urls output."),
  ];

  if (urls.length === 0) {
    addSignal(
      "url.no_urls_observed",
      "No URL observations were available for URL review.",
      countEvidenceRefs,
      { reviewed_url_count: 0 },
      "informational",
    );
  }

  for (const url of urls) {
    const basePath = `$.urls[${url.url_index}]`;
    const baseObserved: JsonObject = {
      url_index: url.url_index,
      hostname: url.hostname,
      scheme: url.scheme,
    };

    if (url.scheme === "http") {
      const evidenceRef = addEvidence("url.scheme", `${basePath}.scheme`, url.scheme, "URL uses plain HTTP scheme.");
      addSignal("url.plain_http_observed", "URL uses the plain HTTP scheme.", [evidenceRef], baseObserved, "low");
    }

    if (url.userinfo_present) {
      const evidenceRef = addEvidence("url.userinfo", `${basePath}.userinfo_present`, true, "URL includes a username or password component; credential values are expected to be redacted upstream.", "presence");
      addSignal("url.userinfo_observed", "URL includes a userinfo component.", [evidenceRef], baseObserved, "medium");
    }

    if (isIpLiteralHost(url.hostname)) {
      const evidenceRef = addEvidence("url.hostname", `${basePath}.hostname`, url.hostname, "URL hostname is an IP literal rather than a domain name.");
      addSignal("url.ip_literal_host_observed", "URL hostname is an IP literal.", [evidenceRef], baseObserved, "low");
    }

    if (!isDefaultPort(url.scheme, url.port)) {
      const evidenceRef = addEvidence("url.port", `${basePath}.port`, url.port, "URL includes a non-default port for the observed scheme.");
      addSignal("url.non_default_port_observed", "URL includes a non-default port.", [evidenceRef], { ...baseObserved, port: url.port }, "informational");
    }

    if (url.hostname.includes("xn--")) {
      const evidenceRef = addEvidence("url.hostname", `${basePath}.hostname`, url.hostname, "URL hostname includes punycode label text.");
      addSignal("url.punycode_host_observed", "URL hostname includes punycode label text.", [evidenceRef], baseObserved, "low");
    }

    if (url.hostname_length >= LONG_HOSTNAME_THRESHOLD) {
      const evidenceRef = addEvidence("url.hostname_length", `${basePath}.hostname_length`, url.hostname_length, "URL hostname length meets or exceeds the long-hostname threshold.");
      addSignal("url.long_hostname_observed", "URL hostname length meets or exceeds the configured threshold.", [evidenceRef], { ...baseObserved, hostname_length: url.hostname_length, threshold: LONG_HOSTNAME_THRESHOLD });
    }

    if (url.url_length >= LONG_URL_THRESHOLD) {
      const evidenceRef = addEvidence("url.length", `${basePath}.url_length`, url.url_length, "URL length meets or exceeds the long-URL threshold.");
      addSignal("url.long_url_observed", "URL length meets or exceeds the configured threshold.", [evidenceRef], { ...baseObserved, url_length: url.url_length, threshold: LONG_URL_THRESHOLD });
    }

    if (url.hostname_label_count > MANY_SUBDOMAINS_THRESHOLD) {
      const evidenceRef = addEvidence("url.hostname_label_count", `${basePath}.hostname_label_count`, url.hostname_label_count, "URL hostname contains more labels than the configured many-subdomains threshold.");
      addSignal("url.many_subdomains_observed", "URL hostname contains many labels.", [evidenceRef], { ...baseObserved, hostname_label_count: url.hostname_label_count, threshold: MANY_SUBDOMAINS_THRESHOLD }, "informational");
    }

    if (url.query_parameter_count > 0) {
      const evidenceRef = addEvidence("url.query_parameter_count", `${basePath}.query_parameter_count`, url.query_parameter_count, "URL includes query parameters.");
      addSignal("url.query_parameters_observed", "URL includes query parameters.", [evidenceRef], { ...baseObserved, query_parameter_count: url.query_parameter_count }, "informational");
    }

    if (url.fragment_present) {
      const evidenceRef = addEvidence("url.fragment", `${basePath}.fragment_present`, true, "URL includes a fragment component.", "presence");
      addSignal("url.fragment_observed", "URL includes a fragment component.", [evidenceRef], baseObserved, "informational");
    }

    if (url.redirect_parameter_names.length > 0) {
      const evidenceRef = addEvidence("url.redirect_parameter_names", `${basePath}.redirect_parameter_names`, url.redirect_parameter_names, "URL includes query parameter names commonly used for redirect targets.");
      addSignal("url.redirect_parameter_name_observed", "URL includes redirect-like query parameter names.", [evidenceRef], { ...baseObserved, redirect_parameter_names: url.redirect_parameter_names }, "low");
    }

    if (url.file_extension !== null && SUSPICIOUS_FILE_EXTENSIONS.has(url.file_extension)) {
      const evidenceRef = addEvidence("url.file_extension", `${basePath}.file_extension`, url.file_extension, "URL path ends with a file extension commonly associated with executable or script content.");
      addSignal("url.suspicious_file_extension_observed", "URL path ends with an executable or script-like file extension.", [evidenceRef], { ...baseObserved, file_extension: url.file_extension }, "low");
    }
  }

  const sourceWarnings = input.warnings ?? [];
  const warnings = sourceWarnings.length > 0
    ? [`Source parser emitted ${sourceWarnings.length} warning(s); review output preserves source_warning_count only.`]
    : [];

  const plainHttpCount = urls.filter((url) => url.scheme === "http").length;
  const userinfoUrlCount = urls.filter((url) => url.userinfo_present).length;
  const ipLiteralHostCount = urls.filter((url) => isIpLiteralHost(url.hostname)).length;
  const nonDefaultPortCount = urls.filter((url) => !isDefaultPort(url.scheme, url.port)).length;
  const punycodeHostCount = urls.filter((url) => url.hostname.includes("xn--")).length;
  const longHostnameCount = urls.filter((url) => url.hostname_length >= LONG_HOSTNAME_THRESHOLD).length;
  const longUrlCount = urls.filter((url) => url.url_length >= LONG_URL_THRESHOLD).length;
  const manySubdomainsCount = urls.filter((url) => url.hostname_label_count > MANY_SUBDOMAINS_THRESHOLD).length;
  const queryParameterUrlCount = urls.filter((url) => url.query_parameter_count > 0).length;
  const fragmentUrlCount = urls.filter((url) => url.fragment_present).length;
  const redirectParameterUrlCount = urls.filter((url) => url.redirect_parameter_names.length > 0).length;
  const suspiciousFileExtensionCount = urls.filter((url) => url.file_extension !== null && SUSPICIOUS_FILE_EXTENSIONS.has(url.file_extension)).length;

  return {
    artifact: {
      id: "artifact_url_review",
      type: "url_review",
      source_artifact_id: sourceArtifactId,
      source_artifact_type: input.artifact.type ?? null,
    },
    observed: {
      source_parser: "extract_defanged_urls",
      source_warning_count: sourceWarnings.length,
      reviewed_url_count: urls.length,
      plain_http_count: plainHttpCount,
      userinfo_url_count: userinfoUrlCount,
      ip_literal_host_count: ipLiteralHostCount,
      non_default_port_count: nonDefaultPortCount,
      punycode_host_count: punycodeHostCount,
      long_hostname_count: longHostnameCount,
      long_url_count: longUrlCount,
      many_subdomains_count: manySubdomainsCount,
      query_parameter_url_count: queryParameterUrlCount,
      fragment_url_count: fragmentUrlCount,
      redirect_parameter_url_count: redirectParameterUrlCount,
      suspicious_file_extension_count: suspiciousFileExtensionCount,
      evidence_count: evidence.length,
      signal_count: signals.length,
      urls,
      limitations: LIMITATIONS,
    },
    evidence,
    signals,
    warnings,
  };
}

export function reviewUrl(input: unknown): UrlReviewOutput {
  return buildReview(unwrapInput(input));
}

export const reviewUrlSkill: Skill<unknown, UrlReviewOutput> = {
  metadata: {
    name: "review_url",
    version: "0.1.0",
    category: "reviewer",
    description: "Review extracted URL structure from extract_defanged_urls output without fetching, enrichment, scoring, or verdicts.",
    execution: {
      mode: "local_only",
      network_access: "none",
      deterministic: true,
    },
    permissions: localOnlyPermissions,
  },

  run(input: unknown) {
    return reviewUrl(input);
  },
};
