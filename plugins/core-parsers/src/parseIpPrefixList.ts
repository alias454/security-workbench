import type { Skill } from "@security-workbench/schemas";
import { localOnlyPermissions } from "./localOnlyPermissions.js";

export type IpPrefixListLineEnding = "none" | "lf" | "crlf" | "mixed";
export type IpAddressVersion = "ipv4" | "ipv6";
export type IpPrefixEntryKind = "host" | "cidr";

export interface IpPrefixListEntry {
  readonly line: number;
  readonly kind: IpPrefixEntryKind;
  readonly ip_version: IpAddressVersion;
  readonly value: string;
  readonly normalized_value: string;
  readonly address: string;
  readonly normalized_address: string;
  readonly prefix_length: number | null;
  readonly comment: string | null;
}

export interface IpPrefixListDuplicateEntry {
  readonly normalized_value: string;
  readonly first_line: number;
  readonly duplicate_line: number;
  readonly occurrences: number;
}

export interface IpPrefixListInvalidLine {
  readonly line: number;
  readonly value: string;
  readonly reason: string;
}

export interface ParseIpPrefixListOutput {
  readonly artifact: {
    readonly id: "artifact_ip_prefix_list";
    readonly type: "ip_prefix_list";
  };
  readonly observed: {
    readonly line_ending: IpPrefixListLineEnding;
    readonly physical_line_count: number;
    readonly blank_line_count: number;
    readonly comment_line_count: number;
    readonly nonempty_line_count: number;
    readonly inline_comment_count: number;
    readonly valid_entry_count: number;
    readonly host_address_count: number;
    readonly cidr_prefix_count: number;
    readonly ipv4_entry_count: number;
    readonly ipv6_entry_count: number;
    readonly malformed_line_count: number;
    readonly duplicate_entry_count: number;
    readonly duplicate_entries: readonly IpPrefixListDuplicateEntry[];
    readonly prefix_lengths: Record<string, number>;
    readonly entries: readonly IpPrefixListEntry[];
    readonly invalid_lines: readonly IpPrefixListInvalidLine[];
  };
  readonly warnings: readonly string[];
}

interface ParsedAddress {
  readonly ip_version: IpAddressVersion;
  readonly normalized_address: string;
}

interface ParsedLineValue {
  readonly kind: IpPrefixEntryKind;
  readonly address: string;
  readonly normalized_address: string;
  readonly ip_version: IpAddressVersion;
  readonly prefix_length: number | null;
  readonly normalized_value: string;
}

const IPV4_OCTET = /^(?:0|[1-9]\d{0,2})$/;
const IPV6_HEXTET = /^[0-9A-Fa-f]{1,4}$/;

function normalizeInput(input: string): string {
  if (typeof input !== "string") {
    throw new Error("parse_ip_prefix_list input must be a string");
  }

  if (input.length === 0 || input.trim().length === 0) {
    throw new Error("parse_ip_prefix_list input must not be empty");
  }

  return input.charCodeAt(0) === 0xfeff ? input.slice(1) : input;
}

function detectLineEnding(text: string): IpPrefixListLineEnding {
  const crlfCount = (text.match(/\r\n/g) ?? []).length;
  const withoutCrLf = text.replace(/\r\n/g, "");
  const lfCount = (withoutCrLf.match(/\n/g) ?? []).length;
  const crCount = (withoutCrLf.match(/\r/g) ?? []).length;

  if (crlfCount === 0 && lfCount === 0 && crCount === 0) {
    return "none";
  }

  if (crlfCount > 0 && lfCount === 0 && crCount === 0) {
    return "crlf";
  }

  if (crlfCount === 0 && lfCount > 0 && crCount === 0) {
    return "lf";
  }

  return "mixed";
}

function splitLines(text: string): string[] {
  return text.replace(/\r\n/g, "\n").replace(/\r/g, "\n").split("\n");
}

function stripInlineComment(line: string): { value: string; comment: string | null } {
  const commentIndex = line.indexOf("#");
  if (commentIndex === -1) {
    return { value: line.trim(), comment: null };
  }

  return {
    value: line.slice(0, commentIndex).trim(),
    comment: line.slice(commentIndex + 1).trim(),
  };
}

function normalizeIpv4Address(value: string): string | null {
  const parts = value.split(".");
  if (parts.length !== 4) {
    return null;
  }

  const normalizedParts: string[] = [];
  for (const part of parts) {
    if (!IPV4_OCTET.test(part)) {
      return null;
    }

    const octet = Number(part);
    if (!Number.isInteger(octet) || octet < 0 || octet > 255) {
      return null;
    }

    normalizedParts.push(String(octet));
  }

  return normalizedParts.join(".");
}

function validHextets(parts: readonly string[]): boolean {
  return parts.every((part) => IPV6_HEXTET.test(part));
}

function splitIpv6Parts(value: string): string[] {
  if (value.length === 0) {
    return [];
  }

  return value.split(":");
}

function normalizeIpv6Address(value: string): string | null {
  if (value.length === 0 || /\s/.test(value) || value.includes("%") || value.includes("[")) {
    return null;
  }

  const doubleColonMatches = value.match(/::/g) ?? [];
  if (doubleColonMatches.length > 1) {
    return null;
  }

  let hextetText = value;
  let embeddedIpv4HextetCount = 0;

  if (value.includes(".")) {
    const lastColonIndex = value.lastIndexOf(":");
    if (lastColonIndex === -1) {
      return null;
    }

    const ipv4Part = value.slice(lastColonIndex + 1);
    if (normalizeIpv4Address(ipv4Part) === null) {
      return null;
    }

    hextetText = value[lastColonIndex - 1] === ":"
      ? value.slice(0, lastColonIndex + 1)
      : value.slice(0, lastColonIndex);
    embeddedIpv4HextetCount = 2;
  }

  if (hextetText.includes("::")) {
    const [leftText = "", rightText = ""] = hextetText.split("::");
    const leftParts = splitIpv6Parts(leftText);
    const rightParts = splitIpv6Parts(rightText);

    if (!validHextets(leftParts) || !validHextets(rightParts)) {
      return null;
    }

    const presentHextetCount = leftParts.length + rightParts.length + embeddedIpv4HextetCount;
    if (presentHextetCount >= 8) {
      return null;
    }

    return value.toLowerCase();
  }

  const parts = splitIpv6Parts(hextetText);
  if (!validHextets(parts)) {
    return null;
  }

  if (parts.length + embeddedIpv4HextetCount !== 8) {
    return null;
  }

  return value.toLowerCase();
}

function parseAddress(value: string): ParsedAddress | null {
  const normalizedIpv4 = normalizeIpv4Address(value);
  if (normalizedIpv4 !== null) {
    return { ip_version: "ipv4", normalized_address: normalizedIpv4 };
  }

  const normalizedIpv6 = normalizeIpv6Address(value);
  if (normalizedIpv6 !== null) {
    return { ip_version: "ipv6", normalized_address: normalizedIpv6 };
  }

  return null;
}

function parsePrefixLength(value: string): number | null {
  if (!/^\d+$/.test(value)) {
    return null;
  }

  const prefixLength = Number(value);
  return Number.isInteger(prefixLength) ? prefixLength : null;
}

function parseLineValue(value: string): { parsed: ParsedLineValue | null; reason: string | null } {
  if (/\s|,/.test(value)) {
    return { parsed: null, reason: "line must contain exactly one IP address or CIDR prefix token" };
  }

  const slashParts = value.split("/");
  if (slashParts.length > 2) {
    return { parsed: null, reason: "CIDR prefix contains more than one slash" };
  }

  const addressText = slashParts[0] ?? "";
  if (addressText.length === 0) {
    return { parsed: null, reason: "missing IP address" };
  }

  const parsedAddress = parseAddress(addressText);
  if (parsedAddress === null) {
    return { parsed: null, reason: "invalid IP address" };
  }

  if (slashParts.length === 1) {
    return {
      parsed: {
        kind: "host",
        address: addressText,
        normalized_address: parsedAddress.normalized_address,
        ip_version: parsedAddress.ip_version,
        prefix_length: null,
        normalized_value: parsedAddress.normalized_address,
      },
      reason: null,
    };
  }

  const prefixLengthText = slashParts[1] ?? "";
  const prefixLength = parsePrefixLength(prefixLengthText);
  if (prefixLength === null) {
    return { parsed: null, reason: "invalid CIDR prefix length" };
  }

  const maxPrefixLength = parsedAddress.ip_version === "ipv4" ? 32 : 128;
  if (prefixLength < 0 || prefixLength > maxPrefixLength) {
    return {
      parsed: null,
      reason: `${parsedAddress.ip_version === "ipv4" ? "IPv4" : "IPv6"} CIDR prefix length must be between 0 and ${maxPrefixLength}`,
    };
  }

  return {
    parsed: {
      kind: "cidr",
      address: addressText,
      normalized_address: parsedAddress.normalized_address,
      ip_version: parsedAddress.ip_version,
      prefix_length: prefixLength,
      normalized_value: `${parsedAddress.normalized_address}/${prefixLength}`,
    },
    reason: null,
  };
}

function increment(record: Record<string, number>, key: string): void {
  record[key] = (record[key] ?? 0) + 1;
}

function duplicateEntries(entries: readonly IpPrefixListEntry[]): IpPrefixListDuplicateEntry[] {
  const seen = new Map<string, { firstLine: number; count: number }>();
  const duplicates: IpPrefixListDuplicateEntry[] = [];

  for (const entry of entries) {
    const current = seen.get(entry.normalized_value);
    if (current === undefined) {
      seen.set(entry.normalized_value, { firstLine: entry.line, count: 1 });
      continue;
    }

    current.count += 1;
    duplicates.push({
      normalized_value: entry.normalized_value,
      first_line: current.firstLine,
      duplicate_line: entry.line,
      occurrences: current.count,
    });
  }

  return duplicates;
}

export function parseIpPrefixList(input: string): ParseIpPrefixListOutput {
  const text = normalizeInput(input);
  const lineEnding = detectLineEnding(text);
  const lines = splitLines(text);
  const warnings: string[] = [];
  const entries: IpPrefixListEntry[] = [];
  const invalidLines: IpPrefixListInvalidLine[] = [];
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

    const { parsed, reason } = parseLineValue(value);
    if (parsed === null) {
      const message = `IP prefix list line ${lineNumber} is invalid: ${reason ?? "invalid IP address or CIDR prefix"}.`;
      warnings.push(message);
      invalidLines.push({ line: lineNumber, value, reason: reason ?? "invalid IP address or CIDR prefix" });
      continue;
    }

    if (parsed.prefix_length !== null) {
      increment(prefixLengths, String(parsed.prefix_length));
    }

    entries.push({
      line: lineNumber,
      kind: parsed.kind,
      ip_version: parsed.ip_version,
      value,
      normalized_value: parsed.normalized_value,
      address: parsed.address,
      normalized_address: parsed.normalized_address,
      prefix_length: parsed.prefix_length,
      comment,
    });
  }

  if (entries.length === 0) {
    throw new Error("parse_ip_prefix_list input did not contain any valid IP addresses or CIDR prefixes");
  }

  if (lineEnding === "mixed") {
    warnings.push("IP prefix list input contains mixed line endings.");
  }

  const duplicates = duplicateEntries(entries);

  return {
    artifact: {
      id: "artifact_ip_prefix_list",
      type: "ip_prefix_list",
    },
    observed: {
      line_ending: lineEnding,
      physical_line_count: lines.length,
      blank_line_count: blankLineCount,
      comment_line_count: commentLineCount,
      nonempty_line_count: nonemptyLineCount,
      inline_comment_count: inlineCommentCount,
      valid_entry_count: entries.length,
      host_address_count: entries.filter((entry) => entry.kind === "host").length,
      cidr_prefix_count: entries.filter((entry) => entry.kind === "cidr").length,
      ipv4_entry_count: entries.filter((entry) => entry.ip_version === "ipv4").length,
      ipv6_entry_count: entries.filter((entry) => entry.ip_version === "ipv6").length,
      malformed_line_count: invalidLines.length,
      duplicate_entry_count: duplicates.length,
      duplicate_entries: duplicates,
      prefix_lengths: prefixLengths,
      entries,
      invalid_lines: invalidLines,
    },
    warnings,
  };
}

export const parseIpPrefixListSkill: Skill<string, ParseIpPrefixListOutput> = {
  metadata: {
    name: "parse_ip_prefix_list",
    version: "0.1.0",
    category: "parser",
    description:
      "Parse newline-oriented IP address and CIDR prefix lists into structured observations without ASN lookup, ownership claims, or scoring.",
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
        "Parses attacker-controlled IP and CIDR list text into structured observations.",
        "Does not perform ASN lookup, ownership lookup, reputation lookup, network access, persistence, external binary execution, or scoring.",
        "Hosted exposure remains allowlist-only because IP lists can disclose sensitive infrastructure or detection policy.",
      ],
    },
  },

  run(input: string) {
    return parseIpPrefixList(input);
  },
};
