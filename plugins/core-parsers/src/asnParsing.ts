export type AsnListLineEnding = "none" | "lf" | "crlf" | "mixed";

export interface ParsedAsnToken {
  readonly value: string;
  readonly normalized_asn: string;
  readonly asn_number: number;
}

const ASN_TOKEN = /^(?:AS)?(\d{1,10})$/i;
const ASN_KEY_VALUE = /^asn=(?:AS)?(\d{1,10})$/i;
const MAX_ASN = 4294967295;

export function normalizeListInput(input: string, skillName: string): string {
  if (typeof input !== "string") {
    throw new Error(`${skillName} input must be a string`);
  }

  if (input.length === 0 || input.trim().length === 0) {
    throw new Error(`${skillName} input must not be empty`);
  }

  return input.charCodeAt(0) === 0xfeff ? input.slice(1) : input;
}

export function detectLineEnding(text: string): AsnListLineEnding {
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

export function splitLines(text: string): string[] {
  return text.replace(/\r\n/g, "\n").replace(/\r/g, "\n").split("\n");
}

export function stripInlineComment(line: string): { value: string; comment: string | null } {
  const commentIndex = line.indexOf("#");
  if (commentIndex === -1) {
    return { value: line.trim(), comment: null };
  }

  return {
    value: line.slice(0, commentIndex).trim(),
    comment: line.slice(commentIndex + 1).trim(),
  };
}

export function splitRowTokens(value: string): string[] {
  return value
    .split(/[\s,]+/)
    .map((token) => token.trim())
    .filter((token) => token.length > 0);
}

function normalizeAsnNumber(value: string): number | null {
  if (!/^\d+$/.test(value)) {
    return null;
  }

  const asnNumber = Number(value);
  if (!Number.isSafeInteger(asnNumber) || asnNumber < 0 || asnNumber > MAX_ASN) {
    return null;
  }

  return asnNumber;
}

export function parseAsnToken(value: string): ParsedAsnToken | null {
  const match = value.match(ASN_TOKEN);
  if (!match) {
    return null;
  }

  const asnNumber = normalizeAsnNumber(match[1] ?? "");
  if (asnNumber === null) {
    return null;
  }

  return {
    value,
    normalized_asn: `AS${asnNumber}`,
    asn_number: asnNumber,
  };
}

export function parseAsnKeyValueToken(value: string): ParsedAsnToken | null {
  const match = value.match(ASN_KEY_VALUE);
  if (!match) {
    return null;
  }

  const asnNumber = normalizeAsnNumber(match[1] ?? "");
  if (asnNumber === null) {
    return null;
  }

  return {
    value,
    normalized_asn: `AS${asnNumber}`,
    asn_number: asnNumber,
  };
}

export function countValues(values: readonly string[]): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const value of values) {
    counts[value] = (counts[value] ?? 0) + 1;
  }
  return counts;
}
