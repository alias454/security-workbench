import { createHash } from "node:crypto";
import type { Skill } from "@security-workbench/schemas";
import { localOnlyPermissions } from "./localOnlyPermissions.js";

export type TrufflehogNdjsonLineEnding = "lf" | "crlf" | "mixed" | "none";
export type TrufflehogVerificationStatus = "verified" | "unverified" | "unknown";
export type TrufflehogValueKind = "string" | "array" | "object" | "boolean" | "number" | "null" | "unknown";

export interface TrufflehogSecretObservation {
  readonly raw_present: boolean;
  readonly raw_v2_present: boolean;
  readonly raw_length: number | null;
  readonly raw_sha256: string | null;
  readonly redacted_present: boolean;
  readonly redacted_value: string | null;
  readonly redacted_generated: boolean;
}

export interface TrufflehogSourceObservation {
  readonly source_id: string | null;
  readonly source_type: string | null;
  readonly source_name: string | null;
  readonly repository: string | null;
  readonly file: string | null;
  readonly line: number | null;
  readonly commit: string | null;
  readonly link: string | null;
  readonly bucket: string | null;
  readonly key: string | null;
  readonly metadata_keys: readonly string[];
}

export interface TrufflehogResultObservation {
  readonly line_number: number;
  readonly detector_name: string | null;
  readonly detector_type: string | null;
  readonly decoder_name: string | null;
  readonly verified: boolean | null;
  readonly verification_status: TrufflehogVerificationStatus;
  readonly source: TrufflehogSourceObservation;
  readonly secret: TrufflehogSecretObservation;
  readonly extra_data_keys: readonly string[];
  readonly structured_data_keys: readonly string[];
  readonly unknown_top_level_keys: readonly string[];
}

export interface ParseTrufflehogNdjsonOutput {
  readonly artifact: {
    readonly id: "artifact_trufflehog_ndjson";
    readonly type: "trufflehog_ndjson";
  };
  readonly observed: {
    readonly line_ending: TrufflehogNdjsonLineEnding;
    readonly physical_line_count: number;
    readonly ndjson_line_count: number;
    readonly blank_line_count: number;
    readonly valid_record_count: number;
    readonly malformed_line_count: number;
    readonly non_object_line_count: number;
    readonly detector_names: readonly string[];
    readonly detector_types: readonly string[];
    readonly decoder_names: readonly string[];
    readonly source_names: readonly string[];
    readonly source_types: readonly string[];
    readonly repositories: readonly string[];
    readonly files: readonly string[];
    readonly file_line_refs: readonly string[];
    readonly verified_count: number;
    readonly unverified_count: number;
    readonly unknown_verification_count: number;
    readonly raw_secret_present_count: number;
    readonly raw_v2_secret_present_count: number;
    readonly redacted_secret_present_count: number;
    readonly result_records: readonly TrufflehogResultObservation[];
    readonly extra_data_keys: readonly string[];
    readonly structured_data_keys: readonly string[];
    readonly source_metadata_keys: readonly string[];
    readonly unknown_top_level_keys: readonly string[];
  };
  readonly warnings: readonly string[];
}

const KNOWN_TOP_LEVEL_KEYS = new Set([
  "DecoderName",
  "DetectorName",
  "DetectorType",
  "ExtraData",
  "Raw",
  "RawV2",
  "Redacted",
  "RotationGuide",
  "SourceID",
  "SourceMetadata",
  "SourceName",
  "SourceType",
  "StructuredData",
  "Verified",
]);

function normalizeInput(input: string): string {
  if (typeof input !== "string") {
    throw new Error("parse_trufflehog_ndjson input must be a string");
  }

  if (input.length === 0 || input.trim().length === 0) {
    throw new Error("parse_trufflehog_ndjson input must not be empty");
  }

  return input.charCodeAt(0) === 0xfeff ? input.slice(1) : input;
}

function detectLineEnding(text: string): TrufflehogNdjsonLineEnding {
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

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function valueKind(value: unknown): TrufflehogValueKind {
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

function uniqueSorted(values: Iterable<string>): string[] {
  return [...new Set(values)].filter((value) => value.length > 0).sort();
}

function scalarToString(value: unknown): string | null {
  if (typeof value === "string") {
    return value;
  }

  if (typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }

  return null;
}

function scalarNumber(value: unknown): number | null {
  if (typeof value === "number" && Number.isFinite(value)) {
    return value;
  }

  if (typeof value === "string" && /^\d+$/.test(value.trim())) {
    return Number(value.trim());
  }

  return null;
}

function getField(record: Record<string, unknown>, fieldName: string): unknown {
  if (Object.prototype.hasOwnProperty.call(record, fieldName)) {
    return record[fieldName];
  }

  const lowerFieldName = fieldName.toLowerCase();
  for (const [key, value] of Object.entries(record)) {
    if (key.toLowerCase() === lowerFieldName) {
      return value;
    }
  }

  return undefined;
}

function getStringField(record: Record<string, unknown>, fieldName: string): string | null {
  return scalarToString(getField(record, fieldName));
}

function getBooleanField(record: Record<string, unknown>, fieldName: string): boolean | null {
  const value = getField(record, fieldName);
  if (typeof value === "boolean") {
    return value;
  }

  if (typeof value === "string") {
    const lower = value.toLowerCase();
    if (lower === "true") {
      return true;
    }
    if (lower === "false") {
      return false;
    }
  }

  return null;
}

function sha256Hex(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function generatedRedaction(rawValue: string | null): string | null {
  if (rawValue === null) {
    return null;
  }

  return `[REDACTED:${rawValue.length}]`;
}

function verificationStatus(verified: boolean | null): TrufflehogVerificationStatus {
  if (verified === true) {
    return "verified";
  }

  if (verified === false) {
    return "unverified";
  }

  return "unknown";
}

function nestedKeyPaths(value: unknown, prefix = "", depth = 0, output: string[] = []): string[] {
  if (depth > 12) {
    return output;
  }

  if (Array.isArray(value)) {
    for (const entry of value.slice(0, 50)) {
      nestedKeyPaths(entry, prefix, depth + 1, output);
    }
    return output;
  }

  if (!isRecord(value)) {
    return output;
  }

  for (const [key, nestedValue] of Object.entries(value).slice(0, 200)) {
    const path = prefix.length > 0 ? `${prefix}.${key}` : key;
    output.push(path);
    nestedKeyPaths(nestedValue, path, depth + 1, output);
  }

  return output;
}

function firstNestedScalarByKeys(value: unknown, names: readonly string[], depth = 0): string | null {
  if (depth > 12) {
    return null;
  }

  if (Array.isArray(value)) {
    for (const entry of value.slice(0, 50)) {
      const nested = firstNestedScalarByKeys(entry, names, depth + 1);
      if (nested !== null) {
        return nested;
      }
    }
    return null;
  }

  if (!isRecord(value)) {
    return null;
  }

  const wanted = new Set(names.map((name) => name.toLowerCase()));
  for (const [key, nestedValue] of Object.entries(value)) {
    if (wanted.has(key.toLowerCase())) {
      const scalar = scalarToString(nestedValue);
      if (scalar !== null) {
        return scalar;
      }
    }
  }

  for (const nestedValue of Object.values(value)) {
    const nested = firstNestedScalarByKeys(nestedValue, names, depth + 1);
    if (nested !== null) {
      return nested;
    }
  }

  return null;
}

function firstNestedNumberByKeys(value: unknown, names: readonly string[], depth = 0): number | null {
  if (depth > 12) {
    return null;
  }

  if (Array.isArray(value)) {
    for (const entry of value.slice(0, 50)) {
      const nested = firstNestedNumberByKeys(entry, names, depth + 1);
      if (nested !== null) {
        return nested;
      }
    }
    return null;
  }

  if (!isRecord(value)) {
    return null;
  }

  const wanted = new Set(names.map((name) => name.toLowerCase()));
  for (const [key, nestedValue] of Object.entries(value)) {
    if (wanted.has(key.toLowerCase())) {
      const scalar = scalarNumber(nestedValue);
      if (scalar !== null) {
        return scalar;
      }
    }
  }

  for (const nestedValue of Object.values(value)) {
    const nested = firstNestedNumberByKeys(nestedValue, names, depth + 1);
    if (nested !== null) {
      return nested;
    }
  }

  return null;
}

function keyInventory(value: unknown): string[] {
  return isRecord(value) ? Object.keys(value).sort() : [];
}

function extractSource(record: Record<string, unknown>): TrufflehogSourceObservation {
  const sourceMetadata = getField(record, "SourceMetadata");
  const sourceMetadataKeys = uniqueSorted(nestedKeyPaths(sourceMetadata));
  const repository = firstNestedScalarByKeys(sourceMetadata, ["repository", "repo"]);
  const file = firstNestedScalarByKeys(sourceMetadata, ["file", "path"]);

  return {
    source_id: getStringField(record, "SourceID"),
    source_type: getStringField(record, "SourceType"),
    source_name: getStringField(record, "SourceName"),
    repository,
    file,
    line: firstNestedNumberByKeys(sourceMetadata, ["line", "lineNumber", "startLine"]),
    commit: firstNestedScalarByKeys(sourceMetadata, ["commit", "commitHash"]),
    link: firstNestedScalarByKeys(sourceMetadata, ["link", "url"]),
    bucket: firstNestedScalarByKeys(sourceMetadata, ["bucket"]),
    key: firstNestedScalarByKeys(sourceMetadata, ["key"]),
    metadata_keys: sourceMetadataKeys,
  };
}

function extractSecret(record: Record<string, unknown>): TrufflehogSecretObservation {
  const raw = getStringField(record, "Raw");
  const rawV2 = getStringField(record, "RawV2");
  const redacted = getStringField(record, "Redacted");
  const rawForMetadata = raw ?? rawV2;

  return {
    raw_present: raw !== null,
    raw_v2_present: rawV2 !== null,
    raw_length: rawForMetadata?.length ?? null,
    raw_sha256: rawForMetadata === null ? null : sha256Hex(rawForMetadata),
    redacted_present: redacted !== null,
    redacted_value: redacted ?? generatedRedaction(rawForMetadata),
    redacted_generated: redacted === null && rawForMetadata !== null,
  };
}

function unknownTopLevelKeys(record: Record<string, unknown>): string[] {
  const knownLower = new Set([...KNOWN_TOP_LEVEL_KEYS].map((key) => key.toLowerCase()));
  return Object.keys(record)
    .filter((key) => !knownLower.has(key.toLowerCase()))
    .sort();
}

function parseRecord(record: Record<string, unknown>, lineNumber: number): TrufflehogResultObservation {
  const verified = getBooleanField(record, "Verified");
  const extraData = getField(record, "ExtraData");
  const structuredData = getField(record, "StructuredData");

  return {
    line_number: lineNumber,
    detector_name: getStringField(record, "DetectorName"),
    detector_type: getStringField(record, "DetectorType"),
    decoder_name: getStringField(record, "DecoderName"),
    verified,
    verification_status: verificationStatus(verified),
    source: extractSource(record),
    secret: extractSecret(record),
    extra_data_keys: keyInventory(extraData),
    structured_data_keys: keyInventory(structuredData),
    unknown_top_level_keys: unknownTopLevelKeys(record),
  };
}

function fileLineRef(record: TrufflehogResultObservation): string | null {
  if (record.source.file === null) {
    return null;
  }

  if (record.source.line === null) {
    return record.source.file;
  }

  return `${record.source.file}:${record.source.line}`;
}

export function parseTrufflehogNdjson(input: string): ParseTrufflehogNdjsonOutput {
  const text = normalizeInput(input);
  const lineEnding = detectLineEnding(text);
  const lines = splitLines(text);
  const warnings: string[] = [];
  const resultRecords: TrufflehogResultObservation[] = [];
  let blankLineCount = 0;
  let malformedLineCount = 0;
  let nonObjectLineCount = 0;

  for (const [index, line] of lines.entries()) {
    const lineNumber = index + 1;
    const trimmed = line.trim();

    if (trimmed.length === 0) {
      blankLineCount += 1;
      continue;
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(trimmed) as unknown;
    } catch {
      malformedLineCount += 1;
      warnings.push(`TruffleHog NDJSON line ${lineNumber} is not valid JSON.`);
      continue;
    }

    if (!isRecord(parsed)) {
      nonObjectLineCount += 1;
      warnings.push(`TruffleHog NDJSON line ${lineNumber} is ${valueKind(parsed)}, not an object.`);
      continue;
    }

    resultRecords.push(parseRecord(parsed, lineNumber));
  }

  if (resultRecords.length === 0) {
    throw new Error("parse_trufflehog_ndjson input did not contain any valid result records");
  }

  if (lineEnding === "mixed") {
    warnings.push("TruffleHog NDJSON input contains mixed line endings.");
  }

  const detectors = uniqueSorted(resultRecords.map((record) => record.detector_name ?? ""));
  const detectorTypes = uniqueSorted(resultRecords.map((record) => record.detector_type ?? ""));
  const decoderNames = uniqueSorted(resultRecords.map((record) => record.decoder_name ?? ""));
  const sourceNames = uniqueSorted(resultRecords.map((record) => record.source.source_name ?? ""));
  const sourceTypes = uniqueSorted(resultRecords.map((record) => record.source.source_type ?? ""));
  const repositories = uniqueSorted(resultRecords.map((record) => record.source.repository ?? ""));
  const files = uniqueSorted(resultRecords.map((record) => record.source.file ?? ""));
  const fileLineRefs = uniqueSorted(resultRecords.map((record) => fileLineRef(record) ?? ""));
  const extraDataKeys = uniqueSorted(resultRecords.flatMap((record) => record.extra_data_keys));
  const structuredDataKeys = uniqueSorted(resultRecords.flatMap((record) => record.structured_data_keys));
  const sourceMetadataKeys = uniqueSorted(resultRecords.flatMap((record) => record.source.metadata_keys));
  const unknownKeys = uniqueSorted(resultRecords.flatMap((record) => record.unknown_top_level_keys));

  return {
    artifact: {
      id: "artifact_trufflehog_ndjson",
      type: "trufflehog_ndjson",
    },
    observed: {
      line_ending: lineEnding,
      physical_line_count: lines.length,
      ndjson_line_count: lines.length - blankLineCount,
      blank_line_count: blankLineCount,
      valid_record_count: resultRecords.length,
      malformed_line_count: malformedLineCount,
      non_object_line_count: nonObjectLineCount,
      detector_names: detectors,
      detector_types: detectorTypes,
      decoder_names: decoderNames,
      source_names: sourceNames,
      source_types: sourceTypes,
      repositories,
      files,
      file_line_refs: fileLineRefs,
      verified_count: resultRecords.filter((record) => record.verified === true).length,
      unverified_count: resultRecords.filter((record) => record.verified === false).length,
      unknown_verification_count: resultRecords.filter((record) => record.verified === null).length,
      raw_secret_present_count: resultRecords.filter((record) => record.secret.raw_present).length,
      raw_v2_secret_present_count: resultRecords.filter((record) => record.secret.raw_v2_present).length,
      redacted_secret_present_count: resultRecords.filter((record) => record.secret.redacted_present).length,
      result_records: resultRecords,
      extra_data_keys: extraDataKeys,
      structured_data_keys: structuredDataKeys,
      source_metadata_keys: sourceMetadataKeys,
      unknown_top_level_keys: unknownKeys,
    },
    warnings,
  };
}

export const parseTrufflehogNdjsonSkill: Skill<string, ParseTrufflehogNdjsonOutput> = {
  metadata: {
    name: "parse_trufflehog_ndjson",
    version: "0.1.0",
    category: "parser",
    description:
      "Parse TruffleHog NDJSON scanner output into structured result observations without exposing raw secrets or scoring risk.",
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
      max_input_mb: 5,
      risk: "medium",
      rationale: [
        "Parses attacker-controlled scanner output that may contain secrets or repository metadata.",
        "Does not perform network access, persist input, call external services, or execute artifact content.",
        "Raw secret values are not emitted; only length, SHA-256 hash, and redacted values are returned.",
        "Hosted exposure remains allowlist-only because scanner results can contain sensitive source metadata.",
      ],
    },
  },
  run(input: string): ParseTrufflehogNdjsonOutput {
    return parseTrufflehogNdjson(input);
  },
};
