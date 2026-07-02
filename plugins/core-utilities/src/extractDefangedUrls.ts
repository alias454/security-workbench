import type { Skill } from "@security-workbench/schemas";
import { localOnlyPermissions } from "./localOnlyPermissions.js";

export interface ExtractedDefangedUrlObservation {
  original_value: string;
  normalized_url: string;
  scheme: "http" | "https";
  hostname: string;
  port: string | null;
  path_present: boolean;
  query_present: boolean;
  fragment_present: boolean;
  username_present: boolean;
  password_present: boolean;
  transformations: string[];
  source: "raw_text" | "indicator_normalization";
  first_seen_line: number;
  occurrence_count: number;
}

export interface ExtractDefangedUrlsOutput {
  artifact: {
    id: "artifact_defanged_url_extraction";
    type: "defanged_url_extraction";
  };
  observed: {
    input_source_type: "raw_text" | "indicator_normalization";
    candidate_count: number;
    url_count: number;
    duplicate_count: number;
    credentialed_url_count: number;
    transformation_counts: Record<string, number>;
  };
  urls: ExtractedDefangedUrlObservation[];
  limitations: string[];
  warnings: string[];
}

interface NormalizedIndicatorObservationInput {
  readonly original_value?: unknown;
  readonly normalized_value?: unknown;
  readonly indicator_type?: unknown;
  readonly transformations?: unknown;
  readonly first_seen_line?: unknown;
  readonly occurrence_count?: unknown;
}

interface IndicatorNormalizationInput {
  readonly artifact?: {
    readonly type?: unknown;
  };
  readonly indicators?: unknown;
}

interface UrlCandidate {
  readonly originalValue: string;
  readonly normalizedValue: string;
  readonly transformations: readonly string[];
  readonly source: "raw_text" | "indicator_normalization";
  readonly firstSeenLine: number;
  readonly occurrenceCount: number;
}

const URL_TOKEN_PATTERN = /\b(?:hxxps?|https?):\/\/[^\s"'`]+/gi;

function assertString(input: string): void {
  if (typeof input !== "string") {
    throw new Error("extract_defanged_urls input must be a string");
  }
}

function stringValue(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}

function numberOrDefault(value: unknown, fallback: number): number {
  return typeof value === "number" && Number.isFinite(value) ? value : fallback;
}

function stringArray(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return [];
  }

  return value.filter((entry): entry is string => typeof entry === "string");
}

function uniqueSorted(values: readonly string[]): string[] {
  return [...new Set(values)].sort((a, b) => a.localeCompare(b));
}

function trimCandidate(value: string): string {
  return value
    .trim()
    .replace(/^["'`]+/g, "")
    .replace(/["'`),.;!?]+$/g, "");
}

function replaceWithTracking(
  input: string,
  pattern: RegExp,
  replacement: string,
  transformation: string,
  transformations: Set<string>
): string {
  const output = input.replace(pattern, replacement);
  if (output !== input) {
    transformations.add(transformation);
  }
  return output;
}

function normalizeUrlCandidate(value: string): { normalizedValue: string; transformations: string[] } {
  const transformations = new Set<string>();
  let normalized = trimCandidate(value);

  normalized = replaceWithTracking(normalized, /hxxps:\/\//gi, "https://", "hxxps_to_https", transformations);
  normalized = replaceWithTracking(normalized, /hxxp:\/\//gi, "http://", "hxxp_to_http", transformations);
  normalized = replaceWithTracking(
    normalized,
    /\s*(?:\[\.\]|\(\.\)|\{\.\}|<\.>|\[dot\]|\(dot\)|\{dot\}|<dot>)\s*/gi,
    ".",
    "defanged_dot",
    transformations
  );
  normalized = replaceWithTracking(normalized, /\s+dot\s+/gi, ".", "word_dot", transformations);

  return {
    normalizedValue: trimCandidate(normalized),
    transformations: uniqueSorted([...transformations]),
  };
}

function safeUrlString(url: URL): string {
  const clone = new URL(url.href);

  if (clone.username.length > 0) {
    clone.username = "[REDACTED]";
  }

  if (clone.password.length > 0) {
    clone.password = "[REDACTED]";
  }

  return clone.href;
}

function lineNumberForIndex(input: string, index: number): number {
  return input.slice(0, index).split(/\n/).length;
}

function candidateFromRawText(input: string): UrlCandidate[] {
  const candidates: UrlCandidate[] = [];

  for (const match of input.matchAll(URL_TOKEN_PATTERN)) {
    const rawValue = trimCandidate(match[0]);
    const matchIndex = match.index ?? 0;
    const { normalizedValue, transformations } = normalizeUrlCandidate(rawValue);

    candidates.push({
      originalValue: rawValue,
      normalizedValue,
      transformations,
      source: "raw_text",
      firstSeenLine: lineNumberForIndex(input, matchIndex),
      occurrenceCount: 1,
    });
  }

  return candidates;
}

function unwrapRunResult(value: unknown): unknown {
  if (typeof value !== "object" || value === null || !("output" in value)) {
    return value;
  }

  return (value as { readonly output?: unknown }).output;
}

function parseIndicatorNormalizationInput(input: string): IndicatorNormalizationInput | null {
  const trimmed = input.trim();
  if (!trimmed.startsWith("{")) {
    return null;
  }

  try {
    const parsed = unwrapRunResult(JSON.parse(trimmed));
    if (typeof parsed !== "object" || parsed === null) {
      return null;
    }

    const candidate = parsed as IndicatorNormalizationInput;
    return candidate.artifact?.type === "indicator_normalization" ? candidate : null;
  } catch {
    return null;
  }
}

function candidatesFromIndicatorNormalization(input: IndicatorNormalizationInput): UrlCandidate[] {
  if (!Array.isArray(input.indicators)) {
    return [];
  }

  const candidates: UrlCandidate[] = [];

  for (const indicator of input.indicators as NormalizedIndicatorObservationInput[]) {
    if (indicator.indicator_type !== "url") {
      continue;
    }

    const normalizedValue = stringValue(indicator.normalized_value);
    const originalValue = stringValue(indicator.original_value) ?? normalizedValue;
    if (normalizedValue === null || originalValue === null) {
      continue;
    }

    candidates.push({
      originalValue,
      normalizedValue,
      transformations: stringArray(indicator.transformations),
      source: "indicator_normalization",
      firstSeenLine: numberOrDefault(indicator.first_seen_line, 1),
      occurrenceCount: numberOrDefault(indicator.occurrence_count, 1),
    });
  }

  return candidates;
}

function toUrlObservation(candidate: UrlCandidate): ExtractedDefangedUrlObservation | null {
  try {
    const parsed = new URL(candidate.normalizedValue);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return null;
    }

    return {
      original_value: candidate.originalValue,
      normalized_url: safeUrlString(parsed),
      scheme: parsed.protocol === "https:" ? "https" : "http",
      hostname: parsed.hostname.toLowerCase(),
      port: parsed.port.length > 0 ? parsed.port : null,
      path_present: parsed.pathname !== "/",
      query_present: parsed.search.length > 0,
      fragment_present: parsed.hash.length > 0,
      username_present: parsed.username.length > 0,
      password_present: parsed.password.length > 0,
      transformations: uniqueSorted(candidate.transformations),
      source: candidate.source,
      first_seen_line: candidate.firstSeenLine,
      occurrence_count: candidate.occurrenceCount,
    };
  } catch {
    return null;
  }
}

function incrementCount(counts: Record<string, number>, key: string, amount = 1): void {
  counts[key] = (counts[key] ?? 0) + amount;
}

function mergeUrlObservations(candidates: readonly UrlCandidate[]): ExtractedDefangedUrlObservation[] {
  const observations = new Map<string, ExtractedDefangedUrlObservation>();

  for (const candidate of candidates) {
    const observation = toUrlObservation(candidate);
    if (observation === null) {
      continue;
    }

    const existing = observations.get(observation.normalized_url);
    if (existing !== undefined) {
      existing.occurrence_count += observation.occurrence_count;
      existing.transformations = uniqueSorted([...existing.transformations, ...observation.transformations]);
      existing.first_seen_line = Math.min(existing.first_seen_line, observation.first_seen_line);
      continue;
    }

    observations.set(observation.normalized_url, observation);
  }

  return [...observations.values()].sort((a, b) => a.normalized_url.localeCompare(b.normalized_url));
}

export const extractDefangedUrlsSkill: Skill<string, ExtractDefangedUrlsOutput> = {
  metadata: {
    name: "extract_defanged_urls",
    version: "0.1.0",
    category: "parser",
    description:
      "Extract and normalize defanged HTTP/HTTPS URL candidates while preserving source and transformation metadata.",
    execution: {
      mode: "local_only",
      network_access: "none",
      deterministic: true,
    },
    permissions: localOnlyPermissions,
  },

  run(input: string) {
    assertString(input);

    const indicatorInput = parseIndicatorNormalizationInput(input);
    const inputSourceType = indicatorInput === null ? "raw_text" : "indicator_normalization";
    const candidates = indicatorInput === null
      ? candidateFromRawText(input)
      : candidatesFromIndicatorNormalization(indicatorInput);
    const urls = mergeUrlObservations(candidates);
    const transformationCounts: Record<string, number> = {};

    for (const url of urls) {
      for (const transformation of url.transformations) {
        incrementCount(transformationCounts, transformation, url.occurrence_count);
      }
    }

    const totalOccurrences = urls.reduce((sum, url) => sum + url.occurrence_count, 0);
    const warnings = urls.length === 0 ? ["No defanged or HTTP/HTTPS URL candidates observed."] : [];

    return {
      artifact: {
        id: "artifact_defanged_url_extraction",
        type: "defanged_url_extraction",
      },
      observed: {
        input_source_type: inputSourceType,
        candidate_count: candidates.length,
        url_count: urls.length,
        duplicate_count: totalOccurrences > urls.length ? totalOccurrences - urls.length : 0,
        credentialed_url_count: urls.filter((url) => url.username_present || url.password_present).length,
        transformation_counts: transformationCounts,
      },
      urls,
      limitations: [
        "extract_defanged_urls extracts URL candidates only; it does not review URL risk.",
        "extract_defanged_urls performs no DNS, reputation, web content, or network enrichment.",
        "Presence in output does not imply maliciousness, phishing, spam, or policy violation.",
      ],
      warnings,
    };
  },
};
