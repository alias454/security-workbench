import type { Skill } from "@security-workbench/schemas";
import { localOnlyPermissions } from "./localOnlyPermissions.js";
import {
  countValues,
  detectLineEnding,
  normalizeListInput,
  parseAsnKeyValueToken,
  parseAsnToken,
  splitLines,
  splitRowTokens,
  stripInlineComment,
  type AsnListLineEnding,
  type ParsedAsnToken,
} from "./asnParsing.js";

export interface AsnObservationEntry {
  readonly line: number;
  readonly value: string;
  readonly normalized_asn: string;
  readonly asn_number: number;
  readonly indicator: string | null;
  readonly source: string | null;
  readonly timestamp: string | null;
  readonly attributes: Record<string, string>;
  readonly context: readonly string[];
  readonly comment: string | null;
}

export interface AsnRepeatedObservation {
  readonly normalized_asn: string;
  readonly count: number;
  readonly first_line: number;
  readonly lines: readonly number[];
}

export interface AsnObservationInvalidLine {
  readonly line: number;
  readonly value: string;
  readonly reason: string;
}

export interface ParseAsnObservationsOutput {
  readonly artifact: {
    readonly id: "artifact_asn_observations";
    readonly type: "asn_observations";
  };
  readonly observed: {
    readonly line_ending: AsnListLineEnding;
    readonly physical_line_count: number;
    readonly blank_line_count: number;
    readonly comment_line_count: number;
    readonly nonempty_line_count: number;
    readonly inline_comment_count: number;
    readonly valid_observation_count: number;
    readonly malformed_line_count: number;
    readonly unique_asn_count: number;
    readonly observations_with_indicator_count: number;
    readonly observations_with_source_count: number;
    readonly observations_with_timestamp_count: number;
    readonly repeated_asn_count: number;
    readonly asn_counts: Record<string, number>;
    readonly entries: readonly AsnObservationEntry[];
    readonly repeated_asns: readonly AsnRepeatedObservation[];
    readonly invalid_lines: readonly AsnObservationInvalidLine[];
  };
  readonly warnings: readonly string[];
}

const ISO_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/;
const KEY_VALUE = /^([A-Za-z][A-Za-z0-9_.-]*)=(.+)$/;

function parseKeyValue(value: string): { key: string; value: string } | null {
  const match = value.match(KEY_VALUE);
  if (!match) {
    return null;
  }

  return { key: (match[1] ?? "").toLowerCase(), value: match[2] ?? "" };
}

function parseObservationLine(value: string): { entry: Omit<AsnObservationEntry, "line" | "value" | "comment"> | null; reason: string | null } {
  const tokens = splitRowTokens(value);
  if (tokens.length === 0) {
    return { entry: null, reason: "missing ASN observation" };
  }

  const asnCandidates: Array<{ token: string; index: number; parsed: ParsedAsnToken }> = [];
  const attributes: Record<string, string> = {};
  let source: string | null = null;
  let timestamp: string | null = null;

  for (const [index, token] of tokens.entries()) {
    const directAsn = parseAsnToken(token);
    const keyValueAsn = parseAsnKeyValueToken(token);
    const parsedAsn = directAsn ?? keyValueAsn;
    if (parsedAsn !== null) {
      asnCandidates.push({ token, index, parsed: parsedAsn });
      continue;
    }

    const keyValue = parseKeyValue(token);
    if (keyValue !== null) {
      attributes[keyValue.key] = keyValue.value;
      if (keyValue.key === "source") {
        source = keyValue.value;
      }
      if (keyValue.key === "timestamp" || keyValue.key === "time") {
        timestamp = keyValue.value;
      }
      continue;
    }

    if (timestamp === null && ISO_TIMESTAMP.test(token)) {
      timestamp = token;
    }
  }

  if (asnCandidates.length === 0) {
    return { entry: null, reason: "missing valid ASN token" };
  }

  if (asnCandidates.length > 1) {
    return { entry: null, reason: "line must contain exactly one ASN observation" };
  }

  const asnCandidate = asnCandidates[0];
  const context = tokens.filter((_, index) => index !== asnCandidate.index);
  const indicatorTokens = context.filter((token) => {
    const keyValue = parseKeyValue(token);
    return keyValue === null && !ISO_TIMESTAMP.test(token);
  });

  return {
    entry: {
      normalized_asn: asnCandidate.parsed.normalized_asn,
      asn_number: asnCandidate.parsed.asn_number,
      indicator: indicatorTokens[0] ?? null,
      source,
      timestamp,
      attributes,
      context,
    },
    reason: null,
  };
}

function repeatedAsns(entries: readonly AsnObservationEntry[]): AsnRepeatedObservation[] {
  const byAsn = new Map<string, number[]>();
  for (const entry of entries) {
    const lines = byAsn.get(entry.normalized_asn) ?? [];
    lines.push(entry.line);
    byAsn.set(entry.normalized_asn, lines);
  }

  return Array.from(byAsn.entries())
    .filter(([, lines]) => lines.length > 1)
    .map(([normalizedAsn, lines]) => ({
      normalized_asn: normalizedAsn,
      count: lines.length,
      first_line: lines[0] ?? 0,
      lines,
    }));
}

export function parseAsnObservations(input: string): ParseAsnObservationsOutput {
  const text = normalizeListInput(input, "parse_asn_observations");
  const lineEnding = detectLineEnding(text);
  const lines = splitLines(text);
  const warnings: string[] = [];
  const entries: AsnObservationEntry[] = [];
  const invalidLines: AsnObservationInvalidLine[] = [];
  let blankLineCount = 0;
  let commentLineCount = 0;
  let inlineCommentCount = 0;
  let nonemptyLineCount = 0;

  for (const [index, line] of lines.entries()) {
    const lineNumber = index + 1;
    const trimmed = line.trim();

    if (trimmed.length === 0) {
      blankLineCount += 1;
      continue;
    }

    nonemptyLineCount += 1;

    if (trimmed.startsWith("#") || trimmed.startsWith("//")) {
      commentLineCount += 1;
      continue;
    }

    const { value, comment } = stripInlineComment(line);
    if (comment !== null) {
      inlineCommentCount += 1;
    }

    if (value.length === 0) {
      commentLineCount += 1;
      continue;
    }

    const { entry, reason } = parseObservationLine(value);
    if (entry === null) {
      const message = `ASN observations line ${lineNumber} is invalid: ${reason ?? "invalid ASN observation"}.`;
      warnings.push(message);
      invalidLines.push({ line: lineNumber, value, reason: reason ?? "invalid ASN observation" });
      continue;
    }

    entries.push({ line: lineNumber, value, comment, ...entry });
  }

  if (entries.length === 0) {
    throw new Error("parse_asn_observations input did not contain any valid ASN observations");
  }

  if (lineEnding === "mixed") {
    warnings.push("ASN observations input contains mixed line endings.");
  }

  const asns = entries.map((entry) => entry.normalized_asn);
  const repeated = repeatedAsns(entries);

  return {
    artifact: {
      id: "artifact_asn_observations",
      type: "asn_observations",
    },
    observed: {
      line_ending: lineEnding,
      physical_line_count: lines.length,
      blank_line_count: blankLineCount,
      comment_line_count: commentLineCount,
      nonempty_line_count: nonemptyLineCount,
      inline_comment_count: inlineCommentCount,
      valid_observation_count: entries.length,
      malformed_line_count: invalidLines.length,
      unique_asn_count: new Set(asns).size,
      observations_with_indicator_count: entries.filter((entry) => entry.indicator !== null).length,
      observations_with_source_count: entries.filter((entry) => entry.source !== null).length,
      observations_with_timestamp_count: entries.filter((entry) => entry.timestamp !== null).length,
      repeated_asn_count: repeated.length,
      asn_counts: countValues(asns),
      entries,
      repeated_asns: repeated,
      invalid_lines: invalidLines,
    },
    warnings,
  };
}

export const parseAsnObservationsSkill: Skill<string, ParseAsnObservationsOutput> = {
  metadata: {
    name: "parse_asn_observations",
    version: "0.1.0",
    category: "parser",
    description:
      "Parse newline-oriented ASN observation artifacts into structured observations without ASN lookup, reputation, clustering, or scoring.",
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
      risk: "low",
      rationale: [
        "Parses attacker-controlled ASN observation text into structured observations.",
        "Does not perform ASN lookup, ownership lookup, reputation lookup, clustering, network access, persistence, external binary execution, or scoring.",
        "Hosted exposure remains allowlist-only because ASN observations can disclose sensitive infrastructure or threat-intelligence context.",
      ],
    },
  },

  run(input: string) {
    return parseAsnObservations(input);
  },
};
