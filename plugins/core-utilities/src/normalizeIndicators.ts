import type { Skill } from "@security-workbench/schemas";
import { localOnlyPermissions } from "./localOnlyPermissions.js";

export type NormalizedIndicatorType =
  | "url"
  | "domain"
  | "host_port"
  | "ipv4"
  | "ipv4_port"
  | "ipv6"
  | "email_address"
  | "md5"
  | "sha1"
  | "sha256"
  | "sha512"
  | "unknown";

export interface NormalizedIndicatorObservation {
  original_value: string;
  normalized_value: string;
  indicator_type: NormalizedIndicatorType;
  transformations: string[];
  first_seen_line: number;
  occurrence_count: number;
}

export interface UnrecognizedIndicatorCandidate {
  original_value: string;
  normalized_value: string;
  transformations: string[];
  first_seen_line: number;
}

export interface NormalizeIndicatorsOutput {
  artifact: {
    id: "artifact_indicator_normalization";
    type: "indicator_normalization";
  };
  normalized_text: string;
  observed: {
    input_line_count: number;
    candidate_count: number;
    normalized_indicator_count: number;
    duplicate_count: number;
    unrecognized_candidate_count: number;
    indicator_type_counts: Record<string, number>;
    transformation_counts: Record<string, number>;
  };
  indicators: NormalizedIndicatorObservation[];
  unrecognized_candidates: UnrecognizedIndicatorCandidate[];
  limitations: string[];
  warnings: string[];
}

interface CandidateObservation {
  originalValue: string;
  normalizedValue: string;
  transformations: string[];
  firstSeenLine: number;
}

const URL_TOKEN_PATTERN = /\b(?:hxxps?|https?):\/\/[^\s"'`]+/gi;
const EMAIL_TOKEN_PATTERN = /\b[A-Z0-9._%+-]+\s*(?:@|\[@\]|\(@\)|\{@\}|<@>|\[at\]|\(at\)|\{at\}|<at>|\s+at\s+)\s*[A-Z0-9-]+(?:\s*(?:\.|\[\.\]|\(\.\)|\{\.\}|<\.>|\[dot\]|\(dot\)|\{dot\}|<dot>|\s+dot\s+)\s*[A-Z0-9-]+)+\b/gi;
const HOST_TOKEN_PATTERN = /\b[A-Z0-9-]+(?:\s*(?:\.|\[\.\]|\(\.\)|\{\.\}|<\.>|\[dot\]|\(dot\)|\{dot\}|<dot>|\s+dot\s+)\s*[A-Z0-9-]+)+(?::\d{1,5})?\b/gi;
const HASH_TOKEN_PATTERN = /\b[A-F0-9]{32}\b|\b[A-F0-9]{40}\b|\b[A-F0-9]{64}\b|\b[A-F0-9]{128}\b/gi;
const IPV6_TOKEN_PATTERN = /\b(?:[A-F0-9]{1,4}:){2,7}[A-F0-9]{0,4}\b/gi;
const DOMAIN_PATTERN = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const EMAIL_PATTERN = /^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,63}$/;
const IPV4_PATTERN = /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;
const IPV6_PATTERN = /^(?:[a-f0-9]{1,4}:){2,7}[a-f0-9]{0,4}$/;
const HOST_PORT_PATTERN = /^(.+):(\d{1,5})$/;

function assertString(input: string): void {
  if (typeof input !== "string") {
    throw new Error("normalize_indicators input must be a string");
  }
}

function uniqueSorted(values: string[]): string[] {
  return [...new Set(values)].sort((a, b) => a.localeCompare(b));
}

function trimCandidate(value: string): string {
  return value
    .trim()
    .replace(/^["'`]+/g, "")
    .replace(/["'`),;!?]+$/g, "");
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

function normalizeCandidate(value: string): { normalizedValue: string; transformations: string[] } {
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
  normalized = replaceWithTracking(
    normalized,
    /\s+dot\s+/gi,
    ".",
    "word_dot",
    transformations
  );
  normalized = replaceWithTracking(
    normalized,
    /\s*(?:\[@\]|\(@\)|\{@\}|<@>|\[at\]|\(at\)|\{at\}|<at>)\s*/gi,
    "@",
    "defanged_at",
    transformations
  );
  normalized = replaceWithTracking(
    normalized,
    /\s+at\s+/gi,
    "@",
    "word_at",
    transformations
  );

  normalized = trimCandidate(normalized).toLowerCase();

  return {
    normalizedValue: normalized,
    transformations: uniqueSorted([...transformations]),
  };
}


function normalizeText(input: string): string {
  return input
    .replace(/hxxps:\/\//gi, "https://")
    .replace(/hxxp:\/\//gi, "http://")
    .replace(/\s*(?:\[\.\]|\(\.\)|\{\.\}|<\.>|\[dot\]|\(dot\)|\{dot\}|<dot>)\s*/gi, ".")
    .replace(/\s+dot\s+/gi, ".")
    .replace(/\s*(?:\[@\]|\(@\)|\{@\}|<@>|\[at\]|\(at\)|\{at\}|<at>)\s*/gi, "@")
    .replace(/\s+at\s+/gi, "@");
}

function lineNumberForIndex(input: string, index: number): number {
  return input.slice(0, index).split(/\n/).length;
}

function addPatternCandidates(input: string, pattern: RegExp, candidates: CandidateObservation[]): void {
  for (const match of input.matchAll(pattern)) {
    const rawValue = match[0];
    const matchIndex = match.index ?? 0;
    const { normalizedValue, transformations } = normalizeCandidate(rawValue);
    if (normalizedValue.length === 0) {
      continue;
    }

    candidates.push({
      originalValue: trimCandidate(rawValue),
      normalizedValue,
      transformations,
      firstSeenLine: lineNumberForIndex(input, matchIndex),
    });
  }
}

function isValidPort(port: string): boolean {
  const parsed = Number(port);
  return Number.isInteger(parsed) && parsed >= 1 && parsed <= 65535;
}

function isIpv4Like(value: string): boolean {
  return /^\d+(?:\.\d+){3}$/.test(value);
}

function isUrl(value: string): boolean {
  if (!/^https?:\/\//.test(value)) {
    return false;
  }

  try {
    const parsed = new URL(value);
    return parsed.protocol === "http:" || parsed.protocol === "https:";
  } catch {
    return false;
  }
}

function classifyIndicator(value: string): NormalizedIndicatorType {
  if (isUrl(value)) {
    return "url";
  }

  if (EMAIL_PATTERN.test(value)) {
    return "email_address";
  }

  const hostPortMatch = value.match(HOST_PORT_PATTERN);
  if (hostPortMatch !== null && isValidPort(hostPortMatch[2] ?? "")) {
    const host = hostPortMatch[1] ?? "";
    if (IPV4_PATTERN.test(host)) {
      return "ipv4_port";
    }

    if (DOMAIN_PATTERN.test(host)) {
      return "host_port";
    }
  }

  if (IPV4_PATTERN.test(value)) {
    return "ipv4";
  }

  if (IPV6_PATTERN.test(value)) {
    return "ipv6";
  }

  if (/^[a-f0-9]{32}$/.test(value)) {
    return "md5";
  }

  if (/^[a-f0-9]{40}$/.test(value)) {
    return "sha1";
  }

  if (/^[a-f0-9]{64}$/.test(value)) {
    return "sha256";
  }

  if (/^[a-f0-9]{128}$/.test(value)) {
    return "sha512";
  }

  if (DOMAIN_PATTERN.test(value) && !isIpv4Like(value)) {
    return "domain";
  }

  return "unknown";
}

function incrementCount(counts: Record<string, number>, key: string): void {
  counts[key] = (counts[key] ?? 0) + 1;
}

export const normalizeIndicatorsSkill: Skill<string, NormalizeIndicatorsOutput> = {
  metadata: {
    name: "normalize_indicators",
    version: "0.1.0",
    category: "transform",
    description:
      "Normalize defanged and delimiter-messy candidate indicators without enrichment or maliciousness claims.",
    execution: {
      mode: "local_only",
      network_access: "none",
      deterministic: true,
    },
    permissions: localOnlyPermissions,
  },

  run(input: string) {
    assertString(input);

    const candidates: CandidateObservation[] = [];
    addPatternCandidates(input, URL_TOKEN_PATTERN, candidates);
    addPatternCandidates(input, EMAIL_TOKEN_PATTERN, candidates);
    addPatternCandidates(input, HOST_TOKEN_PATTERN, candidates);
    addPatternCandidates(input, HASH_TOKEN_PATTERN, candidates);
    addPatternCandidates(input, IPV6_TOKEN_PATTERN, candidates);

    const indicatorMap = new Map<string, NormalizedIndicatorObservation>();
    const unrecognizedMap = new Map<string, UnrecognizedIndicatorCandidate>();

    for (const candidate of candidates) {
      const indicatorType = classifyIndicator(candidate.normalizedValue);
      const key = `${indicatorType}:${candidate.normalizedValue}`;

      if (indicatorType === "unknown") {
        if (!unrecognizedMap.has(key)) {
          unrecognizedMap.set(key, {
            original_value: candidate.originalValue,
            normalized_value: candidate.normalizedValue,
            transformations: candidate.transformations,
            first_seen_line: candidate.firstSeenLine,
          });
        }
        continue;
      }

      const existing = indicatorMap.get(key);
      if (existing !== undefined) {
        existing.occurrence_count += 1;
        existing.transformations = uniqueSorted([...existing.transformations, ...candidate.transformations]);
        continue;
      }

      indicatorMap.set(key, {
        original_value: candidate.originalValue,
        normalized_value: candidate.normalizedValue,
        indicator_type: indicatorType,
        transformations: candidate.transformations,
        first_seen_line: candidate.firstSeenLine,
        occurrence_count: 1,
      });
    }

    const indicators = [...indicatorMap.values()].sort((a, b) => {
      const typeOrder = a.indicator_type.localeCompare(b.indicator_type);
      if (typeOrder !== 0) {
        return typeOrder;
      }
      return a.normalized_value.localeCompare(b.normalized_value);
    });
    const unrecognizedCandidates = [...unrecognizedMap.values()].sort((a, b) =>
      a.normalized_value.localeCompare(b.normalized_value)
    );

    const indicatorTypeCounts: Record<string, number> = {};
    const transformationCounts: Record<string, number> = {};
    for (const indicator of indicators) {
      incrementCount(indicatorTypeCounts, indicator.indicator_type);
      for (const transformation of indicator.transformations) {
        incrementCount(transformationCounts, transformation);
      }
    }

    const duplicateCount = candidates.length - indicatorMap.size - unrecognizedMap.size;
    const warnings = candidates.length === 0 ? ["No candidate indicators observed."] : [];

    return {
      artifact: {
        id: "artifact_indicator_normalization",
        type: "indicator_normalization",
      },
      normalized_text: normalizeText(input),
      observed: {
        input_line_count: input.length === 0 ? 0 : input.split(/\r\n|\r|\n/).length,
        candidate_count: candidates.length,
        normalized_indicator_count: indicators.length,
        duplicate_count: duplicateCount < 0 ? 0 : duplicateCount,
        unrecognized_candidate_count: unrecognizedCandidates.length,
        indicator_type_counts: indicatorTypeCounts,
        transformation_counts: transformationCounts,
      },
      indicators,
      unrecognized_candidates: unrecognizedCandidates,
      limitations: [
        "normalize_indicators normalizes candidate indicators only; it does not confirm IOC status.",
        "normalize_indicators performs no DNS, reputation, vulnerability, or network enrichment.",
        "Presence in output does not imply maliciousness, compromise, phishing, spam, or policy violation.",
      ],
      warnings,
    };
  },
};
