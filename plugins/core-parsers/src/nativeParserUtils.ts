export type NativeJsonLineEnding = "lf" | "crlf" | "mixed" | "none";
export type NativeJsonValueKind = "string" | "array" | "object" | "boolean" | "number" | "null" | "unknown";

export type JsonRecord = Record<string, unknown>;

export function normalizeTextInput(input: string, parserName: string): string {
  if (typeof input !== "string") {
    throw new Error(`${parserName} input must be a string`);
  }

  if (input.length === 0 || input.trim().length === 0) {
    throw new Error(`${parserName} input must not be empty`);
  }

  return input.charCodeAt(0) === 0xfeff ? input.slice(1) : input;
}

export function detectLineEnding(text: string): NativeJsonLineEnding {
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

export function physicalLineCount(text: string): number {
  return text.replace(/\r\n/g, "\n").replace(/\r/g, "\n").split("\n").length;
}

export function isRecord(value: unknown): value is JsonRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function valueKind(value: unknown): NativeJsonValueKind {
  if (value === null) {
    return "null";
  }

  if (Array.isArray(value)) {
    return "array";
  }

  const type = typeof value;
  if (type === "string" || type === "boolean" || type === "number") {
    return type;
  }

  if (isRecord(value)) {
    return "object";
  }

  return "unknown";
}

export function parseJsonObject(input: string, parserName: string): JsonRecord {
  let parsed: unknown;
  try {
    parsed = JSON.parse(input);
  } catch {
    throw new Error(`${parserName} input must be valid JSON`);
  }

  if (!isRecord(parsed)) {
    throw new Error(`${parserName} input must be a JSON object; received ${valueKind(parsed)}`);
  }

  return parsed;
}

export function stringValue(value: unknown): string | null {
  if (typeof value === "string") {
    return value;
  }

  if (typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }

  return null;
}

export function numberValue(value: unknown): number | null {
  if (typeof value === "number" && Number.isFinite(value)) {
    return value;
  }

  if (typeof value === "string" && value.trim().length > 0 && /^-?\d+(?:\.\d+)?$/.test(value.trim())) {
    return Number(value.trim());
  }

  return null;
}

export function booleanValue(value: unknown): boolean | null {
  if (typeof value === "boolean") {
    return value;
  }

  if (typeof value === "string") {
    const normalized = value.trim().toLowerCase();
    if (normalized === "true") {
      return true;
    }
    if (normalized === "false") {
      return false;
    }
  }

  return null;
}

const blockedRecordPathKeys = new Set(["__proto__", "prototype", "constructor"]);

function ownDataValue(record: JsonRecord, key: string): unknown {
  if (blockedRecordPathKeys.has(key)) {
    return undefined;
  }

  const descriptor = Object.getOwnPropertyDescriptor(record, key);
  if (descriptor === undefined || !("value" in descriptor)) {
    return undefined;
  }

  return descriptor.value;
}

export function recordValue(record: JsonRecord, key: string): JsonRecord | null {
  const value = ownDataValue(record, key);
  return isRecord(value) ? value : null;
}

export function arrayValue(value: unknown): readonly unknown[] {
  return Array.isArray(value) ? value : [];
}

export function recordArray(value: unknown): JsonRecord[] {
  return arrayValue(value).filter((entry): entry is JsonRecord => isRecord(entry));
}

export function stringArray(value: unknown): string[] {
  return arrayValue(value)
    .map((entry) => stringValue(entry))
    .filter((entry): entry is string => entry !== null);
}

export function uniqueSorted(values: Iterable<string | null | undefined>): string[] {
  return [...new Set([...values].filter((value): value is string => typeof value === "string" && value.length > 0))].sort();
}

export function countBy(values: Iterable<string>): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const value of values) {
    counts[value] = (counts[value] ?? 0) + 1;
  }
  return Object.fromEntries(Object.entries(counts).sort(([left], [right]) => left.localeCompare(right)));
}

export function unknownKeys(record: JsonRecord, knownKeys: ReadonlySet<string>): string[] {
  return Object.keys(record).filter((key) => !knownKeys.has(key)).sort();
}

export function nestedString(record: JsonRecord | null, path: readonly string[]): string | null {
  let current: unknown = record;
  for (const key of path) {
    if (!isRecord(current)) {
      return null;
    }
    current = ownDataValue(current, key);
  }
  return stringValue(current);
}

export function nestedRecord(record: JsonRecord | null, path: readonly string[]): JsonRecord | null {
  let current: unknown = record;
  for (const key of path) {
    if (!isRecord(current)) {
      return null;
    }
    current = ownDataValue(current, key);
  }
  return isRecord(current) ? current : null;
}
