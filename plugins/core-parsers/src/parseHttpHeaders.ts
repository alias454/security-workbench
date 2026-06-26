import type { Skill } from "@security-workbench/schemas";
import { localOnlyPermissions } from "./localOnlyPermissions.js";

export interface ParsedHttpHeaderField {
  readonly original_name: string;
  readonly lower_name: string;
  readonly value: string;
}

export type HttpHeaderLineEnding = "lf" | "crlf" | "mixed" | "none";

export interface ParseHttpHeadersOutput {
  readonly artifact: {
    readonly id: "artifact_http_headers";
    readonly type: "http_headers";
  };
  readonly observed: {
    readonly status_line_present: boolean;
    readonly http_version: string | null;
    readonly status_code: number | null;
    readonly reason_phrase: string | null;
    readonly line_ending: HttpHeaderLineEnding;
    readonly header_count: number;
    readonly unique_header_name_count: number;
    readonly duplicate_header_names: readonly string[];
    readonly malformed_line_count: number;
    readonly folded_line_count: number;
    readonly headers: readonly ParsedHttpHeaderField[];
    readonly header_names: readonly string[];
    readonly content_security_policy_present: boolean;
    readonly strict_transport_security_present: boolean;
    readonly x_frame_options_present: boolean;
    readonly x_content_type_options_present: boolean;
    readonly referrer_policy_present: boolean;
    readonly permissions_policy_present: boolean;
    readonly set_cookie_count: number;
    readonly location_present: boolean;
  };
  readonly warnings: readonly string[];
}

const STATUS_LINE_PATTERN = /^HTTP\/(\d+(?:\.\d+)?)\s+(\d{3})(?:\s+(.*))?$/i;
const HEADER_NAME_PATTERN = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;

function normalizeInput(input: string): string {
  if (typeof input !== "string") {
    throw new Error("parse_http_headers input must be a string");
  }

  if (input.length === 0 || input.trim().length === 0) {
    throw new Error("parse_http_headers input must not be empty");
  }

  return input.charCodeAt(0) === 0xfeff ? input.slice(1) : input;
}

function detectLineEnding(text: string): HttpHeaderLineEnding {
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

function headerPreambleLines(text: string): string[] {
  const lines = splitLines(text);
  const endIndex = lines.findIndex((line) => line.length === 0);
  return endIndex === -1 ? lines : lines.slice(0, endIndex);
}

function uniqueSorted(values: Iterable<string>): string[] {
  return [...new Set(values)].sort();
}

function duplicateHeaderNames(headers: readonly ParsedHttpHeaderField[]): string[] {
  const counts = new Map<string, number>();

  for (const header of headers) {
    counts.set(header.lower_name, (counts.get(header.lower_name) ?? 0) + 1);
  }

  return [...counts.entries()]
    .filter(([, count]) => count > 1)
    .map(([name]) => name)
    .sort();
}

export function parseHttpHeaders(input: string): ParseHttpHeadersOutput {
  const text = normalizeInput(input);
  const lineEnding = detectLineEnding(text);
  const lines = headerPreambleLines(text);
  const warnings: string[] = [];
  const headers: ParsedHttpHeaderField[] = [];
  let statusLinePresent = false;
  let httpVersion: string | null = null;
  let statusCode: number | null = null;
  let reasonPhrase: string | null = null;
  let malformedLineCount = 0;
  let foldedLineCount = 0;

  for (const [lineIndex, line] of lines.entries()) {
    if (lineIndex === 0) {
      const statusMatch = line.match(STATUS_LINE_PATTERN);
      if (statusMatch) {
        statusLinePresent = true;
        httpVersion = statusMatch[1] ?? null;
        statusCode = Number(statusMatch[2]);
        reasonPhrase = statusMatch[3]?.trim() ?? null;
        continue;
      }
    }

    if (/^[ \t]/.test(line)) {
      const previous = headers[headers.length - 1];
      if (previous === undefined) {
        malformedLineCount += 1;
        warnings.push(`HTTP header line ${lineIndex + 1} is a folded continuation without a preceding header.`);
        continue;
      }

      foldedLineCount += 1;
      const continuedValue = `${previous.value} ${line.trim()}`.trim();
      headers[headers.length - 1] = {
        original_name: previous.original_name,
        lower_name: previous.lower_name,
        value: continuedValue,
      };
      warnings.push(`HTTP header line ${lineIndex + 1} is a folded continuation line.`);
      continue;
    }

    const separatorIndex = line.indexOf(":");
    if (separatorIndex <= 0) {
      malformedLineCount += 1;
      warnings.push(`HTTP header line ${lineIndex + 1} is missing a valid name/value separator.`);
      continue;
    }

    const originalName = line.slice(0, separatorIndex).trim();
    const value = line.slice(separatorIndex + 1).trim();

    if (!HEADER_NAME_PATTERN.test(originalName)) {
      malformedLineCount += 1;
      warnings.push(`HTTP header line ${lineIndex + 1} has an invalid header name.`);
      continue;
    }

    headers.push({
      original_name: originalName,
      lower_name: originalName.toLowerCase(),
      value,
    });
  }

  if (headers.length === 0) {
    throw new Error("parse_http_headers input did not contain any valid header fields");
  }

  if (lineEnding === "mixed") {
    warnings.push("HTTP header input contains mixed line endings.");
  }

  const headerNames = uniqueSorted(headers.map((header) => header.lower_name));
  const duplicateNames = duplicateHeaderNames(headers);
  const headerNameSet = new Set(headerNames);

  return {
    artifact: {
      id: "artifact_http_headers",
      type: "http_headers",
    },
    observed: {
      status_line_present: statusLinePresent,
      http_version: httpVersion,
      status_code: statusCode,
      reason_phrase: reasonPhrase,
      line_ending: lineEnding,
      header_count: headers.length,
      unique_header_name_count: headerNames.length,
      duplicate_header_names: duplicateNames,
      malformed_line_count: malformedLineCount,
      folded_line_count: foldedLineCount,
      headers,
      header_names: headerNames,
      content_security_policy_present: headerNameSet.has("content-security-policy"),
      strict_transport_security_present: headerNameSet.has("strict-transport-security"),
      x_frame_options_present: headerNameSet.has("x-frame-options"),
      x_content_type_options_present: headerNameSet.has("x-content-type-options"),
      referrer_policy_present: headerNameSet.has("referrer-policy"),
      permissions_policy_present: headerNameSet.has("permissions-policy"),
      set_cookie_count: headers.filter((header) => header.lower_name === "set-cookie").length,
      location_present: headerNameSet.has("location"),
    },
    warnings,
  };
}

export const parseHttpHeadersSkill: Skill<string, ParseHttpHeadersOutput> = {
  metadata: {
    name: "parse_http_headers",
    version: "0.1.0",
    category: "parser",
    description:
      "Parse HTTP response/header blocks into normalized header observations without network access or risk scoring.",
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
        "Parses attacker-controlled HTTP header text into structured observations.",
        "Does not perform network access, persist input, call external services, or execute artifact content.",
        "Hosted exposure remains allowlist-only because header values may contain sensitive application or session metadata.",
      ],
    },
  },
  run(input: string): ParseHttpHeadersOutput {
    return parseHttpHeaders(input);
  },
};
