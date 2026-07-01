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

export type AsnPolicyAction = "allow" | "deny";

export interface AsnAllowDenyEntry {
  readonly line: number;
  readonly action: AsnPolicyAction;
  readonly action_token: string;
  readonly value: string;
  readonly normalized_asn: string;
  readonly asn_number: number;
  readonly reason: string | null;
  readonly comment: string | null;
}

export interface AsnPolicyDuplicateEntry {
  readonly action: AsnPolicyAction;
  readonly normalized_asn: string;
  readonly first_line: number;
  readonly duplicate_line: number;
  readonly occurrences: number;
}

export interface AsnPolicyConflictEntry {
  readonly normalized_asn: string;
  readonly allow_lines: readonly number[];
  readonly deny_lines: readonly number[];
}

export interface AsnAllowDenyInvalidLine {
  readonly line: number;
  readonly value: string;
  readonly reason: string;
}

export interface ParseAsnAllowDenyListOutput {
  readonly artifact: {
    readonly id: "artifact_asn_allow_deny_list";
    readonly type: "asn_allow_deny_list";
  };
  readonly observed: {
    readonly line_ending: AsnListLineEnding;
    readonly physical_line_count: number;
    readonly blank_line_count: number;
    readonly comment_line_count: number;
    readonly nonempty_line_count: number;
    readonly inline_comment_count: number;
    readonly valid_entry_count: number;
    readonly allow_entry_count: number;
    readonly deny_entry_count: number;
    readonly malformed_line_count: number;
    readonly duplicate_entry_count: number;
    readonly conflict_entry_count: number;
    readonly unique_asn_count: number;
    readonly action_counts: Record<string, number>;
    readonly asn_counts: Record<string, number>;
    readonly entries: readonly AsnAllowDenyEntry[];
    readonly duplicate_entries: readonly AsnPolicyDuplicateEntry[];
    readonly conflicting_entries: readonly AsnPolicyConflictEntry[];
    readonly invalid_lines: readonly AsnAllowDenyInvalidLine[];
  };
  readonly warnings: readonly string[];
}

const ACTION_ALIASES: Record<string, AsnPolicyAction> = {
  allow: "allow",
  permit: "allow",
  accept: "allow",
  deny: "deny",
  block: "deny",
  drop: "deny",
  reject: "deny",
};

function parseActionToken(value: string): AsnPolicyAction | null {
  return ACTION_ALIASES[value.toLowerCase()] ?? null;
}

function parsePolicyLine(value: string): { entry: Omit<AsnAllowDenyEntry, "line" | "value" | "comment"> | null; reason: string | null } {
  const tokens = splitRowTokens(value);
  if (tokens.length === 0) {
    return { entry: null, reason: "missing action and ASN" };
  }

  const firstTokenAction = parseActionToken(tokens[0] ?? "");
  const firstTokenAsn = parseAsnToken(tokens[0] ?? "");
  const secondTokenAction = parseActionToken(tokens[1] ?? "");
  const secondTokenAsn = parseAsnToken(tokens[1] ?? "");

  let actionToken: string | null = null;
  let action: AsnPolicyAction | null = null;
  let asnToken: ReturnType<typeof parseAsnToken> = null;
  let reasonTokens: string[] = [];

  if (firstTokenAction !== null && secondTokenAsn !== null) {
    actionToken = tokens[0] ?? null;
    action = firstTokenAction;
    asnToken = secondTokenAsn;
    reasonTokens = tokens.slice(2);
  } else if (firstTokenAsn !== null && secondTokenAction !== null) {
    actionToken = tokens[1] ?? null;
    action = secondTokenAction;
    asnToken = firstTokenAsn;
    reasonTokens = tokens.slice(2);
  } else {
    const asnCandidates = tokens
      .map((token, index) => ({ token, index, parsed: parseAsnToken(token) }))
      .filter((candidate): candidate is { token: string; index: number; parsed: NonNullable<ReturnType<typeof parseAsnToken>> } => candidate.parsed !== null);
    const actionCandidates = tokens
      .map((token, index) => ({ token, index, action: parseActionToken(token) }))
      .filter((candidate): candidate is { token: string; index: number; action: AsnPolicyAction } => candidate.action !== null);

    if (asnCandidates.length === 0) {
      return { entry: null, reason: "missing valid ASN token" };
    }

    if (asnCandidates.length > 1) {
      return { entry: null, reason: "line must contain exactly one ASN token" };
    }

    if (actionCandidates.length === 0) {
      return { entry: null, reason: "missing allow or deny action" };
    }

    return { entry: null, reason: "line must use action-first or ASN-first format" };
  }

  if (actionToken === null || action === null || asnToken === null) {
    return { entry: null, reason: "invalid ASN policy row" };
  }

  const reasonActionTokens = reasonTokens.filter((token) => parseActionToken(token) !== null);
  if (reasonActionTokens.length > 0 && reasonActionTokens.length === reasonTokens.length) {
    return { entry: null, reason: "line must contain exactly one allow or deny action" };
  }

  return {
    entry: {
      action,
      action_token: actionToken,
      normalized_asn: asnToken.normalized_asn,
      asn_number: asnToken.asn_number,
      reason: reasonTokens.length > 0 ? reasonTokens.join(" ") : null,
    },
    reason: null,
  };
}

function duplicateEntries(entries: readonly AsnAllowDenyEntry[]): AsnPolicyDuplicateEntry[] {
  const seen = new Map<string, { firstLine: number; count: number }>();
  const duplicates: AsnPolicyDuplicateEntry[] = [];

  for (const entry of entries) {
    const key = `${entry.action}:${entry.normalized_asn}`;
    const current = seen.get(key);
    if (current === undefined) {
      seen.set(key, { firstLine: entry.line, count: 1 });
      continue;
    }

    current.count += 1;
    duplicates.push({
      action: entry.action,
      normalized_asn: entry.normalized_asn,
      first_line: current.firstLine,
      duplicate_line: entry.line,
      occurrences: current.count,
    });
  }

  return duplicates;
}

function conflictingEntries(entries: readonly AsnAllowDenyEntry[]): AsnPolicyConflictEntry[] {
  const byAsn = new Map<string, { allow: number[]; deny: number[] }>();

  for (const entry of entries) {
    const current = byAsn.get(entry.normalized_asn) ?? { allow: [], deny: [] };
    current[entry.action].push(entry.line);
    byAsn.set(entry.normalized_asn, current);
  }

  return Array.from(byAsn.entries())
    .filter(([, value]) => value.allow.length > 0 && value.deny.length > 0)
    .map(([normalizedAsn, value]) => ({
      normalized_asn: normalizedAsn,
      allow_lines: value.allow,
      deny_lines: value.deny,
    }));
}

export function parseAsnAllowDenyList(input: string): ParseAsnAllowDenyListOutput {
  const text = normalizeListInput(input, "parse_asn_allow_deny_list");
  const lineEnding = detectLineEnding(text);
  const lines = splitLines(text);
  const warnings: string[] = [];
  const entries: AsnAllowDenyEntry[] = [];
  const invalidLines: AsnAllowDenyInvalidLine[] = [];
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

    const { entry, reason } = parsePolicyLine(value);
    if (entry === null) {
      const message = `ASN allow/deny list line ${lineNumber} is invalid: ${reason ?? "invalid ASN policy row"}.`;
      warnings.push(message);
      invalidLines.push({ line: lineNumber, value, reason: reason ?? "invalid ASN policy row" });
      continue;
    }

    entries.push({ line: lineNumber, value, comment, ...entry });
  }

  if (entries.length === 0) {
    throw new Error("parse_asn_allow_deny_list input did not contain any valid ASN policy entries");
  }

  if (lineEnding === "mixed") {
    warnings.push("ASN allow/deny list input contains mixed line endings.");
  }

  const duplicates = duplicateEntries(entries);
  const conflicts = conflictingEntries(entries);
  const actions = entries.map((entry) => entry.action);
  const asns = entries.map((entry) => entry.normalized_asn);

  return {
    artifact: {
      id: "artifact_asn_allow_deny_list",
      type: "asn_allow_deny_list",
    },
    observed: {
      line_ending: lineEnding,
      physical_line_count: lines.length,
      blank_line_count: blankLineCount,
      comment_line_count: commentLineCount,
      nonempty_line_count: nonemptyLineCount,
      inline_comment_count: inlineCommentCount,
      valid_entry_count: entries.length,
      allow_entry_count: actions.filter((action) => action === "allow").length,
      deny_entry_count: actions.filter((action) => action === "deny").length,
      malformed_line_count: invalidLines.length,
      duplicate_entry_count: duplicates.length,
      conflict_entry_count: conflicts.length,
      unique_asn_count: new Set(asns).size,
      action_counts: countValues(actions),
      asn_counts: countValues(asns),
      entries,
      duplicate_entries: duplicates,
      conflicting_entries: conflicts,
      invalid_lines: invalidLines,
    },
    warnings,
  };
}

export const parseAsnAllowDenyListSkill: Skill<string, ParseAsnAllowDenyListOutput> = {
  metadata: {
    name: "parse_asn_allow_deny_list",
    version: "0.1.0",
    category: "parser",
    description:
      "Parse newline-oriented ASN allow/deny policy artifacts into structured observations without enforcement, ASN lookup, reputation, or scoring.",
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
        "Parses attacker-controlled ASN policy list text into structured observations.",
        "Does not enforce policy, perform ASN lookup, ownership lookup, reputation lookup, network access, persistence, external binary execution, or scoring.",
        "Hosted exposure remains allowlist-only because ASN allow/deny lists can disclose sensitive detection policy.",
      ],
    },
  },

  run(input: string) {
    return parseAsnAllowDenyList(input);
  },
};
