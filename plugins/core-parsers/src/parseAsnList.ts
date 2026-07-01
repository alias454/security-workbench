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

export interface AsnListEntry {
  readonly line: number;
  readonly value: string;
  readonly normalized_asn: string;
  readonly asn_number: number;
  readonly note: string | null;
  readonly comment: string | null;
}

export interface AsnListDuplicateEntry {
  readonly normalized_asn: string;
  readonly first_line: number;
  readonly duplicate_line: number;
  readonly occurrences: number;
}

export interface AsnListInvalidLine {
  readonly line: number;
  readonly value: string;
  readonly reason: string;
}

export interface ParseAsnListOutput {
  readonly artifact: {
    readonly id: "artifact_asn_list";
    readonly type: "asn_list";
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
    readonly duplicate_entry_count: number;
    readonly unique_asn_count: number;
    readonly normalized_asns: readonly string[];
    readonly asn_numbers: readonly number[];
    readonly asn_counts: Record<string, number>;
    readonly duplicate_entries: readonly AsnListDuplicateEntry[];
    readonly entries: readonly AsnListEntry[];
    readonly invalid_lines: readonly AsnListInvalidLine[];
  };
  readonly warnings: readonly string[];
}

function duplicateEntries(entries: readonly AsnListEntry[]): AsnListDuplicateEntry[] {
  const seen = new Map<string, { firstLine: number; count: number }>();
  const duplicates: AsnListDuplicateEntry[] = [];

  for (const entry of entries) {
    const current = seen.get(entry.normalized_asn);
    if (current === undefined) {
      seen.set(entry.normalized_asn, { firstLine: entry.line, count: 1 });
      continue;
    }

    current.count += 1;
    duplicates.push({
      normalized_asn: entry.normalized_asn,
      first_line: current.firstLine,
      duplicate_line: entry.line,
      occurrences: current.count,
    });
  }

  return duplicates;
}

function parseAsnListLine(value: string): { entry: Omit<AsnListEntry, "line" | "value" | "comment"> | null; reason: string | null } {
  const tokens = splitRowTokens(value);
  if (tokens.length === 0) {
    return { entry: null, reason: "missing ASN" };
  }

  const parsedTokens = tokens
    .map((token, index) => ({ token, index, parsed: parseAsnToken(token) }))
    .filter((candidate): candidate is { token: string; index: number; parsed: NonNullable<ReturnType<typeof parseAsnToken>> } => candidate.parsed !== null);

  if (parsedTokens.length === 0) {
    return { entry: null, reason: "missing valid ASN token" };
  }

  if (parsedTokens.length > 1) {
    return { entry: null, reason: "line must contain exactly one ASN token" };
  }

  const parsed = parsedTokens[0].parsed;
  const noteTokens = tokens.filter((_, index) => index !== parsedTokens[0].index);

  return {
    entry: {
      normalized_asn: parsed.normalized_asn,
      asn_number: parsed.asn_number,
      note: noteTokens.length > 0 ? noteTokens.join(" ") : null,
    },
    reason: null,
  };
}

export function parseAsnList(input: string): ParseAsnListOutput {
  const text = normalizeListInput(input, "parse_asn_list");
  const lineEnding = detectLineEnding(text);
  const lines = splitLines(text);
  const warnings: string[] = [];
  const entries: AsnListEntry[] = [];
  const invalidLines: AsnListInvalidLine[] = [];
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

    const { entry, reason } = parseAsnListLine(value);
    if (entry === null) {
      const message = `ASN list line ${lineNumber} is invalid: ${reason ?? "invalid ASN row"}.`;
      warnings.push(message);
      invalidLines.push({ line: lineNumber, value, reason: reason ?? "invalid ASN row" });
      continue;
    }

    entries.push({ line: lineNumber, value, comment, ...entry });
  }

  if (entries.length === 0) {
    throw new Error("parse_asn_list input did not contain any valid ASN entries");
  }

  if (lineEnding === "mixed") {
    warnings.push("ASN list input contains mixed line endings.");
  }

  const normalizedAsns = entries.map((entry) => entry.normalized_asn);
  const duplicates = duplicateEntries(entries);
  const uniqueAsns = Array.from(new Set(normalizedAsns));

  return {
    artifact: {
      id: "artifact_asn_list",
      type: "asn_list",
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
      duplicate_entry_count: duplicates.length,
      unique_asn_count: uniqueAsns.length,
      normalized_asns: normalizedAsns,
      asn_numbers: entries.map((entry) => entry.asn_number),
      asn_counts: countValues(normalizedAsns),
      duplicate_entries: duplicates,
      entries,
      invalid_lines: invalidLines,
    },
    warnings,
  };
}

export const parseAsnListSkill: Skill<string, ParseAsnListOutput> = {
  metadata: {
    name: "parse_asn_list",
    version: "0.1.0",
    category: "parser",
    description:
      "Parse newline-oriented ASN list artifacts into structured observations without ASN lookup, ownership claims, reputation, or scoring.",
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
        "Parses attacker-controlled ASN list text into structured observations.",
        "Does not perform ASN lookup, ownership lookup, reputation lookup, network access, persistence, external binary execution, or scoring.",
        "Hosted exposure remains allowlist-only because ASN lists can disclose sensitive infrastructure or detection policy.",
      ],
    },
  },

  run(input: string) {
    return parseAsnList(input);
  },
};
