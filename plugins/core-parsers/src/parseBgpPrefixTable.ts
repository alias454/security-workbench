import type { Skill } from "@security-workbench/schemas";
import { localOnlyPermissions } from "./localOnlyPermissions.js";
import {
  countValues,
  detectLineEnding,
  normalizeListInput,
  parseAsnToken,
  splitLines,
  splitRowTokens,
  stripInlineComment,
  type AsnListLineEnding,
} from "./asnParsing.js";
import { parseIpPrefixList, type IpAddressVersion } from "./parseIpPrefixList.js";

export interface BgpPrefixTableEntry {
  readonly line: number;
  readonly value: string;
  readonly prefix: string;
  readonly normalized_prefix: string;
  readonly ip_version: IpAddressVersion;
  readonly prefix_length: number;
  readonly origin_asn: string;
  readonly origin_asn_number: number;
  readonly note: string | null;
  readonly comment: string | null;
}

export interface BgpPrefixDuplicateEntry {
  readonly normalized_prefix: string;
  readonly origin_asn: string;
  readonly first_line: number;
  readonly duplicate_line: number;
  readonly occurrences: number;
}

export interface BgpPrefixOriginConflict {
  readonly normalized_prefix: string;
  readonly origin_asns: readonly string[];
  readonly lines: readonly number[];
}

export interface BgpPrefixTableInvalidLine {
  readonly line: number;
  readonly value: string;
  readonly reason: string;
}

export interface ParseBgpPrefixTableOutput {
  readonly artifact: {
    readonly id: "artifact_bgp_prefix_table";
    readonly type: "bgp_prefix_table";
  };
  readonly observed: {
    readonly line_ending: AsnListLineEnding;
    readonly physical_line_count: number;
    readonly blank_line_count: number;
    readonly comment_line_count: number;
    readonly nonempty_line_count: number;
    readonly inline_comment_count: number;
    readonly valid_entry_count: number;
    readonly malformed_line_count: number;
    readonly ipv4_prefix_count: number;
    readonly ipv6_prefix_count: number;
    readonly unique_prefix_count: number;
    readonly unique_origin_asn_count: number;
    readonly duplicate_entry_count: number;
    readonly conflicting_prefix_count: number;
    readonly prefix_lengths: Record<string, number>;
    readonly origin_asn_counts: Record<string, number>;
    readonly prefix_counts: Record<string, number>;
    readonly entries: readonly BgpPrefixTableEntry[];
    readonly duplicate_entries: readonly BgpPrefixDuplicateEntry[];
    readonly conflicting_prefixes: readonly BgpPrefixOriginConflict[];
    readonly invalid_lines: readonly BgpPrefixTableInvalidLine[];
  };
  readonly warnings: readonly string[];
}

interface ParsedPrefixToken {
  readonly normalized_prefix: string;
  readonly ip_version: IpAddressVersion;
  readonly prefix_length: number;
}

function parsePrefixToken(token: string): ParsedPrefixToken | null {
  if (!token.includes("/")) {
    return null;
  }

  try {
    const output = parseIpPrefixList(token);
    const entry = output.observed.entries[0];
    if (!entry || entry.kind !== "cidr" || entry.prefix_length === null) {
      return null;
    }

    return {
      normalized_prefix: entry.normalized_value,
      ip_version: entry.ip_version,
      prefix_length: entry.prefix_length,
    };
  } catch {
    return null;
  }
}

function parseBgpRow(value: string): { entry: Omit<BgpPrefixTableEntry, "line" | "value" | "comment"> | null; reason: string | null } {
  const tokens = splitRowTokens(value);
  if (tokens.length === 0) {
    return { entry: null, reason: "missing prefix and origin ASN" };
  }

  const prefixCandidates = tokens
    .map((token, index) => ({ token, index, parsed: parsePrefixToken(token) }))
    .filter((candidate): candidate is { token: string; index: number; parsed: ParsedPrefixToken } => candidate.parsed !== null);
  const asnCandidates = tokens
    .map((token, index) => ({ token, index, parsed: parseAsnToken(token) }))
    .filter((candidate): candidate is { token: string; index: number; parsed: NonNullable<ReturnType<typeof parseAsnToken>> } => candidate.parsed !== null);

  if (prefixCandidates.length === 0) {
    return { entry: null, reason: "missing valid CIDR prefix token" };
  }

  if (prefixCandidates.length > 1) {
    return { entry: null, reason: "line must contain exactly one CIDR prefix token" };
  }

  if (asnCandidates.length === 0) {
    return { entry: null, reason: "missing valid origin ASN token" };
  }

  if (asnCandidates.length > 1) {
    return { entry: null, reason: "line must contain exactly one origin ASN token" };
  }

  const prefixCandidate = prefixCandidates[0];
  const asnCandidate = asnCandidates[0];
  const noteTokens = tokens.filter((_, index) => index !== prefixCandidate.index && index !== asnCandidate.index);

  return {
    entry: {
      prefix: prefixCandidate.token,
      normalized_prefix: prefixCandidate.parsed.normalized_prefix,
      ip_version: prefixCandidate.parsed.ip_version,
      prefix_length: prefixCandidate.parsed.prefix_length,
      origin_asn: asnCandidate.parsed.normalized_asn,
      origin_asn_number: asnCandidate.parsed.asn_number,
      note: noteTokens.length > 0 ? noteTokens.join(" ") : null,
    },
    reason: null,
  };
}

function duplicateEntries(entries: readonly BgpPrefixTableEntry[]): BgpPrefixDuplicateEntry[] {
  const seen = new Map<string, { firstLine: number; count: number }>();
  const duplicates: BgpPrefixDuplicateEntry[] = [];

  for (const entry of entries) {
    const key = `${entry.normalized_prefix}:${entry.origin_asn}`;
    const current = seen.get(key);
    if (current === undefined) {
      seen.set(key, { firstLine: entry.line, count: 1 });
      continue;
    }

    current.count += 1;
    duplicates.push({
      normalized_prefix: entry.normalized_prefix,
      origin_asn: entry.origin_asn,
      first_line: current.firstLine,
      duplicate_line: entry.line,
      occurrences: current.count,
    });
  }

  return duplicates;
}

function conflictingPrefixes(entries: readonly BgpPrefixTableEntry[]): BgpPrefixOriginConflict[] {
  const byPrefix = new Map<string, { asns: Set<string>; lines: number[] }>();

  for (const entry of entries) {
    const current = byPrefix.get(entry.normalized_prefix) ?? { asns: new Set<string>(), lines: [] };
    current.asns.add(entry.origin_asn);
    current.lines.push(entry.line);
    byPrefix.set(entry.normalized_prefix, current);
  }

  return Array.from(byPrefix.entries())
    .filter(([, value]) => value.asns.size > 1)
    .map(([normalizedPrefix, value]) => ({
      normalized_prefix: normalizedPrefix,
      origin_asns: Array.from(value.asns),
      lines: value.lines,
    }));
}

function increment(record: Record<string, number>, key: string): void {
  record[key] = (record[key] ?? 0) + 1;
}

export function parseBgpPrefixTable(input: string): ParseBgpPrefixTableOutput {
  const text = normalizeListInput(input, "parse_bgp_prefix_table");
  const lineEnding = detectLineEnding(text);
  const lines = splitLines(text);
  const warnings: string[] = [];
  const entries: BgpPrefixTableEntry[] = [];
  const invalidLines: BgpPrefixTableInvalidLine[] = [];
  const prefixLengths: Record<string, number> = {};
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

    const { entry, reason } = parseBgpRow(value);
    if (entry === null) {
      const message = `BGP prefix table line ${lineNumber} is invalid: ${reason ?? "invalid BGP prefix row"}.`;
      warnings.push(message);
      invalidLines.push({ line: lineNumber, value, reason: reason ?? "invalid BGP prefix row" });
      continue;
    }

    increment(prefixLengths, String(entry.prefix_length));
    entries.push({ line: lineNumber, value, comment, ...entry });
  }

  if (entries.length === 0) {
    throw new Error("parse_bgp_prefix_table input did not contain any valid prefix/origin ASN rows");
  }

  if (lineEnding === "mixed") {
    warnings.push("BGP prefix table input contains mixed line endings.");
  }

  const prefixes = entries.map((entry) => entry.normalized_prefix);
  const originAsns = entries.map((entry) => entry.origin_asn);
  const duplicates = duplicateEntries(entries);
  const conflicts = conflictingPrefixes(entries);

  return {
    artifact: {
      id: "artifact_bgp_prefix_table",
      type: "bgp_prefix_table",
    },
    observed: {
      line_ending: lineEnding,
      physical_line_count: lines.length,
      blank_line_count: blankLineCount,
      comment_line_count: commentLineCount,
      nonempty_line_count: nonemptyLineCount,
      inline_comment_count: inlineCommentCount,
      valid_entry_count: entries.length,
      malformed_line_count: invalidLines.length,
      ipv4_prefix_count: entries.filter((entry) => entry.ip_version === "ipv4").length,
      ipv6_prefix_count: entries.filter((entry) => entry.ip_version === "ipv6").length,
      unique_prefix_count: new Set(prefixes).size,
      unique_origin_asn_count: new Set(originAsns).size,
      duplicate_entry_count: duplicates.length,
      conflicting_prefix_count: conflicts.length,
      prefix_lengths: prefixLengths,
      origin_asn_counts: countValues(originAsns),
      prefix_counts: countValues(prefixes),
      entries,
      duplicate_entries: duplicates,
      conflicting_prefixes: conflicts,
      invalid_lines: invalidLines,
    },
    warnings,
  };
}

export const parseBgpPrefixTableSkill: Skill<string, ParseBgpPrefixTableOutput> = {
  metadata: {
    name: "parse_bgp_prefix_table",
    version: "0.1.0",
    category: "parser",
    description:
      "Parse simple BGP prefix-to-origin ASN table artifacts into structured observations without routing lookup, reputation, or scoring.",
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
        "Parses attacker-controlled prefix/origin ASN table text into structured observations.",
        "Does not perform routing lookup, RIR/RDAP lookup, ownership lookup, reputation lookup, network access, persistence, external binary execution, or scoring.",
        "Hosted exposure remains allowlist-only because prefix tables can disclose sensitive infrastructure or detection policy.",
      ],
    },
  },

  run(input: string) {
    return parseBgpPrefixTable(input);
  },
};
