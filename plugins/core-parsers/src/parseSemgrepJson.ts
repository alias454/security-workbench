import type { Skill } from "@security-workbench/schemas";
import { localOnlyPermissions } from "./localOnlyPermissions.js";
import {
  arrayValue,
  countBy,
  detectLineEnding,
  isRecord,
  nestedRecord,
  nestedString,
  normalizeTextInput,
  parseJsonObject,
  physicalLineCount,
  recordArray,
  recordValue,
  stringArray,
  stringValue,
  uniqueSorted,
  unknownKeys,
  type NativeJsonLineEnding,
} from "./nativeParserUtils.js";

export interface SemgrepPositionObservation {
  readonly line: number | null;
  readonly column: number | null;
  readonly offset: number | null;
}

export interface SemgrepResultObservation {
  readonly result_index: number;
  readonly check_id: string | null;
  readonly path: string | null;
  readonly start: SemgrepPositionObservation;
  readonly end: SemgrepPositionObservation;
  readonly message: string | null;
  readonly severity: string | null;
  readonly confidence: string | null;
  readonly likelihood: string | null;
  readonly impact: string | null;
  readonly category: string | null;
  readonly technology: readonly string[];
  readonly cwe: readonly string[];
  readonly owasp: readonly string[];
  readonly references: readonly string[];
  readonly fingerprint_present: boolean;
  readonly lines_present: boolean;
  readonly fix_present: boolean;
  readonly fix_regex_present: boolean;
  readonly ignored: boolean | null;
  readonly validation_state: string | null;
  readonly metadata_keys: readonly string[];
  readonly extra_keys: readonly string[];
  readonly unknown_top_level_keys: readonly string[];
}

export interface SemgrepErrorObservation {
  readonly error_index: number;
  readonly code: string | null;
  readonly level: string | null;
  readonly type: string | null;
  readonly message: string | null;
  readonly path: string | null;
  readonly spans_present: boolean;
  readonly unknown_top_level_keys: readonly string[];
}

export interface SemgrepSkippedPathObservation {
  readonly path: string | null;
  readonly reason: string | null;
  readonly details: string | null;
}

export interface ParseSemgrepJsonOutput {
  readonly artifact: {
    readonly id: "artifact_semgrep_json";
    readonly type: "semgrep_json";
    readonly version: string | null;
  };
  readonly observed: {
    readonly line_ending: NativeJsonLineEnding;
    readonly physical_line_count: number;
    readonly version: string | null;
    readonly result_count: number;
    readonly error_count: number;
    readonly scanned_path_count: number;
    readonly skipped_path_count: number;
    readonly rule_ids: readonly string[];
    readonly paths: readonly string[];
    readonly severities: Readonly<Record<string, number>>;
    readonly confidences: readonly string[];
    readonly categories: readonly string[];
    readonly technologies: readonly string[];
    readonly cwe_ids: readonly string[];
    readonly owasp_ids: readonly string[];
    readonly validation_states: readonly string[];
    readonly ignored_count: number;
    readonly fix_present_count: number;
    readonly fix_regex_present_count: number;
    readonly fingerprint_present_count: number;
    readonly metadata_keys: readonly string[];
    readonly extra_keys: readonly string[];
    readonly unknown_top_level_keys: readonly string[];
    readonly unknown_result_keys: readonly string[];
    readonly unknown_error_keys: readonly string[];
    readonly results: readonly SemgrepResultObservation[];
    readonly errors: readonly SemgrepErrorObservation[];
    readonly scanned_paths: readonly string[];
    readonly skipped_paths: readonly SemgrepSkippedPathObservation[];
  };
  readonly warnings: readonly string[];
}

const KNOWN_ROOT_KEYS = new Set([
  "version",
  "results",
  "errors",
  "paths",
  "time",
  "explanations",
  "interfile_languages_used",
  "skipped_rules",
  "profiling_results",
]);
const KNOWN_RESULT_KEYS = new Set([
  "check_id",
  "path",
  "start",
  "end",
  "extra",
  "fingerprint",
  "lines",
]);
const KNOWN_EXTRA_KEYS = new Set([
  "message",
  "severity",
  "metadata",
  "metavars",
  "fix",
  "fix_regex",
  "lines",
  "is_ignored",
  "validation_state",
  "sca_info",
  "dataflow_trace",
]);
const KNOWN_ERROR_KEYS = new Set([
  "code",
  "level",
  "type",
  "message",
  "path",
  "spans",
  "details",
]);

function position(value: unknown): SemgrepPositionObservation {
  const record = isRecord(value) ? value : {};
  return {
    line: typeof record.line === "number" ? record.line : null,
    column: typeof record.col === "number" ? record.col : typeof record.column === "number" ? record.column : null,
    offset: typeof record.offset === "number" ? record.offset : null,
  };
}

function metadataStrings(metadata: Record<string, unknown> | null, key: string): string[] {
  if (!metadata) {
    return [];
  }

  const value = metadata[key];
  if (Array.isArray(value)) {
    return value.map((entry) => stringValue(entry)).filter((entry): entry is string => entry !== null);
  }

  const scalar = stringValue(value);
  return scalar === null ? [] : [scalar];
}

function semgrepResult(result: Record<string, unknown>, resultIndex: number): SemgrepResultObservation {
  const extra = recordValue(result, "extra");
  const metadata = extra ? recordValue(extra, "metadata") : null;
  const metadataKeys = metadata ? Object.keys(metadata).sort() : [];

  return {
    result_index: resultIndex,
    check_id: stringValue(result.check_id),
    path: stringValue(result.path),
    start: position(result.start),
    end: position(result.end),
    message: extra ? stringValue(extra.message) : null,
    severity: extra ? stringValue(extra.severity) : null,
    confidence: metadata ? stringValue(metadata.confidence) : null,
    likelihood: metadata ? stringValue(metadata.likelihood) : null,
    impact: metadata ? stringValue(metadata.impact) : null,
    category: metadata ? stringValue(metadata.category) : null,
    technology: metadataStrings(metadata, "technology"),
    cwe: metadataStrings(metadata, "cwe"),
    owasp: metadataStrings(metadata, "owasp"),
    references: metadataStrings(metadata, "references"),
    fingerprint_present: typeof result.fingerprint === "string" && result.fingerprint.length > 0,
    lines_present: typeof result.lines === "string" || (extra !== null && typeof extra.lines === "string"),
    fix_present: extra !== null && typeof extra.fix === "string" && extra.fix.length > 0,
    fix_regex_present: extra !== null && extra.fix_regex !== undefined && extra.fix_regex !== null,
    ignored: extra !== null && typeof extra.is_ignored === "boolean" ? extra.is_ignored : null,
    validation_state: extra ? stringValue(extra.validation_state) : null,
    metadata_keys: metadataKeys,
    extra_keys: extra ? Object.keys(extra).sort() : [],
    unknown_top_level_keys: unknownKeys(result, KNOWN_RESULT_KEYS),
  };
}

function semgrepError(error: Record<string, unknown>, errorIndex: number): SemgrepErrorObservation {
  return {
    error_index: errorIndex,
    code: stringValue(error.code),
    level: stringValue(error.level),
    type: stringValue(error.type),
    message: stringValue(error.message),
    path: stringValue(error.path),
    spans_present: Array.isArray(error.spans) && error.spans.length > 0,
    unknown_top_level_keys: unknownKeys(error, KNOWN_ERROR_KEYS),
  };
}

function skippedPath(value: unknown): SemgrepSkippedPathObservation {
  if (typeof value === "string") {
    return { path: value, reason: null, details: null };
  }

  if (!isRecord(value)) {
    return { path: null, reason: null, details: null };
  }

  return {
    path: stringValue(value.path),
    reason: stringValue(value.reason),
    details: stringValue(value.details),
  };
}

export function parseSemgrepJson(input: string): ParseSemgrepJsonOutput {
  const normalized = normalizeTextInput(input, "parse_semgrep_json");
  const root = parseJsonObject(normalized, "parse_semgrep_json");
  const warnings: string[] = [];

  if (!Array.isArray(root.results)) {
    throw new Error('parse_semgrep_json input must contain a "results" array');
  }

  const resultRecords = recordArray(root.results);
  if (resultRecords.length !== root.results.length) {
    warnings.push('Semgrep field "results" contains non-object entries that were ignored.');
  }

  const results = resultRecords.map((result, index) => semgrepResult(result, index));
  const errorValue = root.errors;
  const errorRecords = errorValue === undefined ? [] : recordArray(errorValue);
  if (errorValue !== undefined && (!Array.isArray(errorValue) || errorRecords.length !== arrayValue(errorValue).length)) {
    warnings.push('Semgrep field "errors" should be an array of objects when present.');
  }
  const errors = errorRecords.map((error, index) => semgrepError(error, index));
  const paths = recordValue(root, "paths");
  const scannedPaths = paths ? stringArray(paths.scanned) : [];
  const skippedPaths = paths ? arrayValue(paths.skipped).map(skippedPath) : [];
  const metadataKeys = uniqueSorted(results.flatMap((result) => result.metadata_keys));
  const extraKeys = uniqueSorted(results.flatMap((result) => result.extra_keys));
  const unknownResultKeys = uniqueSorted(results.flatMap((result) => result.unknown_top_level_keys));
  const unknownErrorKeys = uniqueSorted(errors.flatMap((error) => error.unknown_top_level_keys));

  for (const result of resultRecords) {
    const extra = recordValue(result, "extra");
    if (extra !== null) {
      const unknownExtraKeys = unknownKeys(extra, KNOWN_EXTRA_KEYS);
      if (unknownExtraKeys.length > 0) {
        warnings.push(`Semgrep result extra contains unrecognized keys: ${unknownExtraKeys.join(", ")}.`);
      }
    }
  }

  return {
    artifact: {
      id: "artifact_semgrep_json",
      type: "semgrep_json",
      version: stringValue(root.version),
    },
    observed: {
      line_ending: detectLineEnding(normalized),
      physical_line_count: physicalLineCount(normalized),
      version: stringValue(root.version),
      result_count: results.length,
      error_count: errors.length,
      scanned_path_count: scannedPaths.length,
      skipped_path_count: skippedPaths.length,
      rule_ids: uniqueSorted(results.map((result) => result.check_id)),
      paths: uniqueSorted(results.map((result) => result.path)),
      severities: countBy(results.map((result) => result.severity ?? "unknown")),
      confidences: uniqueSorted(results.map((result) => result.confidence)),
      categories: uniqueSorted(results.map((result) => result.category)),
      technologies: uniqueSorted(results.flatMap((result) => result.technology)),
      cwe_ids: uniqueSorted(results.flatMap((result) => result.cwe)),
      owasp_ids: uniqueSorted(results.flatMap((result) => result.owasp)),
      validation_states: uniqueSorted(results.map((result) => result.validation_state)),
      ignored_count: results.filter((result) => result.ignored === true).length,
      fix_present_count: results.filter((result) => result.fix_present).length,
      fix_regex_present_count: results.filter((result) => result.fix_regex_present).length,
      fingerprint_present_count: results.filter((result) => result.fingerprint_present).length,
      metadata_keys: metadataKeys,
      extra_keys: extraKeys,
      unknown_top_level_keys: unknownKeys(root, KNOWN_ROOT_KEYS),
      unknown_result_keys: unknownResultKeys,
      unknown_error_keys: unknownErrorKeys,
      results,
      errors,
      scanned_paths: scannedPaths,
      skipped_paths: skippedPaths,
    },
    warnings,
  };
}

export const parseSemgrepJsonSkill: Skill<string, ParseSemgrepJsonOutput> = {
  metadata: {
    name: "parse_semgrep_json",
    version: "0.1.0",
    category: "parser",
    description:
      "Parse Semgrep native JSON into structured result, path, error, metadata, and warning observations without scoring risk.",
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
      max_input_mb: 10,
      risk: "medium",
      rationale: [
        "Parses attacker-controlled scanner output that may contain source paths, code snippets, and rule metadata.",
        "Does not perform network access, persist input, call external services, or execute artifact content.",
        "Parser output preserves native Semgrep observations without normalizing across scanners or assigning risk.",
      ],
    },
  },
  run(input: string): ParseSemgrepJsonOutput {
    return parseSemgrepJson(input);
  },
};
