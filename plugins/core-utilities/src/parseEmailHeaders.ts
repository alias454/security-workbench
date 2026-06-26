import type { Skill } from "@security-workbench/schemas";
import { localOnlyPermissions } from "./localOnlyPermissions.js";

export interface ParsedEmailHeader {
  name: string;
  name_lower: string;
  value: string;
}

export interface ParseEmailHeadersOutput {
  headers: ParsedEmailHeader[];
  header_count: number;
  duplicate_header_names: string[];
  observed: {
    from: string | null;
    to: string | null;
    cc: string | null;
    subject: string | null;
    date: string | null;
    message_id: string | null;
    received_count: number;
    authentication_results: string[];
  };
  warnings: string[];
}

const HEADER_NAME_PATTERN = /^[A-Za-z0-9!#$%&'*+\-.^_`|~]+$/;

function assertString(input: string): void {
  if (typeof input !== "string") {
    throw new Error("parse_email_headers input must be a string");
  }
}

function normalizeLines(input: string): string[] {
  return input.replace(/\r\n/g, "\n").replace(/\r/g, "\n").split("\n");
}

function getFirst(headers: ParsedEmailHeader[], nameLower: string): string | null {
  return headers.find((header) => header.name_lower === nameLower)?.value ?? null;
}

function getAll(headers: ParsedEmailHeader[], nameLower: string): string[] {
  return headers
    .filter((header) => header.name_lower === nameLower)
    .map((header) => header.value);
}

export const parseEmailHeadersSkill: Skill<string, ParseEmailHeadersOutput> = {
  metadata: {
    name: "parse_email_headers",
    version: "0.1.0",
    category: "parser",
    description: "Parse an RFC822-style email header block into normalized header fields.",
    execution: {
      mode: "local_only",
      network_access: "none",
      deterministic: true,
    },
    permissions: localOnlyPermissions,
  },

  run(input: string) {
    assertString(input);

    const headers: ParsedEmailHeader[] = [];
    const warnings: string[] = [];
    let current: ParsedEmailHeader | null = null;

    for (const rawLine of normalizeLines(input)) {
      if (rawLine.length === 0) {
        break;
      }

      if (/^[ \t]/.test(rawLine)) {
        if (current === null) {
          throw new Error("parse_email_headers continuation line encountered before any header");
        }

        current.value = `${current.value} ${rawLine.trim()}`;
        continue;
      }

      const colonIndex = rawLine.indexOf(":");
      if (colonIndex <= 0) {
        throw new Error("parse_email_headers encountered malformed header line without field name and colon");
      }

      const name = rawLine.slice(0, colonIndex);
      if (!HEADER_NAME_PATTERN.test(name)) {
        throw new Error(`parse_email_headers invalid header name: ${name}`);
      }

      current = {
        name,
        name_lower: name.toLowerCase(),
        value: rawLine.slice(colonIndex + 1).trim(),
      };
      headers.push(current);
    }

    const counts = new Map<string, number>();
    for (const header of headers) {
      counts.set(header.name_lower, (counts.get(header.name_lower) ?? 0) + 1);
    }

    const duplicate_header_names = [...counts.entries()]
      .filter(([, count]) => count > 1)
      .map(([name]) => name)
      .sort((a, b) => a.localeCompare(b));

    if (headers.length === 0) {
      warnings.push("No headers parsed.");
    }

    const authentication_results = getAll(headers, "authentication-results");

    return {
      headers,
      header_count: headers.length,
      duplicate_header_names,
      observed: {
        from: getFirst(headers, "from"),
        to: getFirst(headers, "to"),
        cc: getFirst(headers, "cc"),
        subject: getFirst(headers, "subject"),
        date: getFirst(headers, "date"),
        message_id: getFirst(headers, "message-id"),
        received_count: getAll(headers, "received").length,
        authentication_results,
      },
      warnings,
    };
  },
};
