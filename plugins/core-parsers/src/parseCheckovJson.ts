import type { Skill } from "@security-workbench/schemas";
import { localOnlyPermissions } from "./localOnlyPermissions.js";
import {
  arrayValue,
  countBy,
  detectLineEnding,
  isRecord,
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

export type CheckovResultStatus = "failed" | "passed" | "skipped";

export interface CheckovFileLineRangeObservation {
  readonly start: number | null;
  readonly end: number | null;
}

export interface CheckovCheckObservation {
  readonly result_index: number;
  readonly status: CheckovResultStatus;
  readonly check_id: string | null;
  readonly bc_check_id: string | null;
  readonly check_name: string | null;
  readonly check_class: string | null;
  readonly file_path: string | null;
  readonly file_abs_path_present: boolean;
  readonly repo_file_path: string | null;
  readonly file_line_range: CheckovFileLineRangeObservation;
  readonly resource: string | null;
  readonly resource_address: string | null;
  readonly guideline: string | null;
  readonly severity: string | null;
  readonly suppress_comment: string | null;
  readonly evaluations_present: boolean;
  readonly code_block_present: boolean;
  readonly caller_file_path: string | null;
  readonly caller_file_line_range: CheckovFileLineRangeObservation;
  readonly unknown_top_level_keys: readonly string[];
}

export interface CheckovParsingErrorObservation {
  readonly error_index: number;
  readonly value: string;
}

export interface ParseCheckovJsonOutput {
  readonly artifact: {
    readonly id: "artifact_checkov_json";
    readonly type: "checkov_json";
    readonly check_type: string | null;
  };
  readonly observed: {
    readonly line_ending: NativeJsonLineEnding;
    readonly physical_line_count: number;
    readonly check_type: string | null;
    readonly result_count: number;
    readonly failed_count: number;
    readonly passed_count: number;
    readonly skipped_count: number;
    readonly parsing_error_count: number;
    readonly check_ids: readonly string[];
    readonly bc_check_ids: readonly string[];
    readonly check_names: readonly string[];
    readonly check_classes: readonly string[];
    readonly file_paths: readonly string[];
    readonly repo_file_paths: readonly string[];
    readonly resources: readonly string[];
    readonly resource_addresses: readonly string[];
    readonly severities: Readonly<Record<string, number>>;
    readonly statuses: Readonly<Record<string, number>>;
    readonly unknown_top_level_keys: readonly string[];
    readonly unknown_result_keys: readonly string[];
    readonly summary_keys: readonly string[];
    readonly results: readonly CheckovCheckObservation[];
    readonly parsing_errors: readonly CheckovParsingErrorObservation[];
  };
  readonly warnings: readonly string[];
}

const KNOWN_ROOT_KEYS = new Set(["check_type", "results", "summary", "url", "repo_id"]);
const KNOWN_RESULTS_KEYS = new Set([
  "failed_checks",
  "passed_checks",
  "skipped_checks",
  "parsing_errors",
]);
const KNOWN_CHECK_KEYS = new Set([
  "check_id",
  "bc_check_id",
  "check_name",
  "check_result",
  "check_class",
  "file_path",
  "file_abs_path",
  "repo_file_path",
  "file_line_range",
  "resource",
  "resource_address",
  "guideline",
  "severity",
  "evaluations",
  "code_block",
  "caller_file_path",
  "caller_file_line_range",
  "suppress_comment",
  "short_description",
  "description",
  "vulnerability_details",
  "connected_node",
  "entity_tags",
]);

function lineRange(value: unknown): CheckovFileLineRangeObservation {
  if (!Array.isArray(value)) {
    return { start: null, end: null };
  }

  const start = typeof value[0] === "number" ? value[0] : null;
  const end = typeof value[1] === "number" ? value[1] : start;
  return { start, end };
}

function checkObservation(
  check: Record<string, unknown>,
  status: CheckovResultStatus,
  resultIndex: number
): CheckovCheckObservation {
  return {
    result_index: resultIndex,
    status,
    check_id: stringValue(check.check_id),
    bc_check_id: stringValue(check.bc_check_id),
    check_name: stringValue(check.check_name),
    check_class: stringValue(check.check_class),
    file_path: stringValue(check.file_path),
    file_abs_path_present: typeof check.file_abs_path === "string" && check.file_abs_path.length > 0,
    repo_file_path: stringValue(check.repo_file_path),
    file_line_range: lineRange(check.file_line_range),
    resource: stringValue(check.resource),
    resource_address: stringValue(check.resource_address),
    guideline: stringValue(check.guideline),
    severity: stringValue(check.severity),
    suppress_comment: stringValue(check.suppress_comment),
    evaluations_present: check.evaluations !== undefined && check.evaluations !== null,
    code_block_present: Array.isArray(check.code_block) && check.code_block.length > 0,
    caller_file_path: stringValue(check.caller_file_path),
    caller_file_line_range: lineRange(check.caller_file_line_range),
    unknown_top_level_keys: unknownKeys(check, KNOWN_CHECK_KEYS),
  };
}

function checksFrom(results: Record<string, unknown>, key: string, status: CheckovResultStatus): CheckovCheckObservation[] {
  return recordArray(results[key]).map((check, index) => checkObservation(check, status, index));
}

function parsingError(value: unknown, errorIndex: number): CheckovParsingErrorObservation {
  return { error_index: errorIndex, value: stringValue(value) ?? JSON.stringify(value) ?? String(value) };
}

export function parseCheckovJson(input: string): ParseCheckovJsonOutput {
  const normalized = normalizeTextInput(input, "parse_checkov_json");
  const root = parseJsonObject(normalized, "parse_checkov_json");
  const warnings: string[] = [];
  const resultsRoot = recordValue(root, "results");

  if (resultsRoot === null) {
    throw new Error('parse_checkov_json input must contain a "results" object');
  }

  for (const key of ["failed_checks", "passed_checks", "skipped_checks", "parsing_errors"] as const) {
    if (resultsRoot[key] !== undefined && !Array.isArray(resultsRoot[key])) {
      warnings.push(`Checkov results field "${key}" should be an array when present.`);
    }
  }

  const failed = checksFrom(resultsRoot, "failed_checks", "failed");
  const passed = checksFrom(resultsRoot, "passed_checks", "passed");
  const skipped = checksFrom(resultsRoot, "skipped_checks", "skipped");
  const allResults = [...failed, ...passed, ...skipped].map((result, index) => ({ ...result, result_index: index }));
  const parsingErrors = arrayValue(resultsRoot.parsing_errors).map(parsingError);
  const summary = recordValue(root, "summary");

  for (const [key, value] of Object.entries(resultsRoot)) {
    if (!KNOWN_RESULTS_KEYS.has(key)) {
      warnings.push(`Checkov results object contains unrecognized key "${key}".`);
    }
    if (KNOWN_RESULTS_KEYS.has(key) && key !== "parsing_errors" && Array.isArray(value)) {
      const nonObjects = value.length - recordArray(value).length;
      if (nonObjects > 0) {
        warnings.push(`Checkov results field "${key}" contains ${String(nonObjects)} non-object entries that were ignored.`);
      }
    }
  }

  return {
    artifact: {
      id: "artifact_checkov_json",
      type: "checkov_json",
      check_type: stringValue(root.check_type),
    },
    observed: {
      line_ending: detectLineEnding(normalized),
      physical_line_count: physicalLineCount(normalized),
      check_type: stringValue(root.check_type),
      result_count: allResults.length,
      failed_count: failed.length,
      passed_count: passed.length,
      skipped_count: skipped.length,
      parsing_error_count: parsingErrors.length,
      check_ids: uniqueSorted(allResults.map((result) => result.check_id)),
      bc_check_ids: uniqueSorted(allResults.map((result) => result.bc_check_id)),
      check_names: uniqueSorted(allResults.map((result) => result.check_name)),
      check_classes: uniqueSorted(allResults.map((result) => result.check_class)),
      file_paths: uniqueSorted(allResults.map((result) => result.file_path)),
      repo_file_paths: uniqueSorted(allResults.map((result) => result.repo_file_path)),
      resources: uniqueSorted(allResults.map((result) => result.resource)),
      resource_addresses: uniqueSorted(allResults.map((result) => result.resource_address)),
      severities: countBy(allResults.map((result) => result.severity ?? "unknown")),
      statuses: countBy(allResults.map((result) => result.status)),
      unknown_top_level_keys: unknownKeys(root, KNOWN_ROOT_KEYS),
      unknown_result_keys: uniqueSorted(allResults.flatMap((result) => result.unknown_top_level_keys)),
      summary_keys: summary ? Object.keys(summary).sort() : [],
      results: allResults,
      parsing_errors: parsingErrors,
    },
    warnings,
  };
}

export const parseCheckovJsonSkill: Skill<string, ParseCheckovJsonOutput> = {
  metadata: {
    name: "parse_checkov_json",
    version: "0.1.0",
    category: "parser",
    description:
      "Parse Checkov native JSON into structured check, resource, path, summary, and parsing-error observations without scoring risk.",
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
        "Parses attacker-controlled scanner output that may contain source paths, IaC resource metadata, and check messages.",
        "Does not perform network access, persist input, call external services, or execute artifact content.",
        "Parser output preserves native Checkov observations without normalizing across scanners or assigning risk.",
      ],
    },
  },
  run(input: string): ParseCheckovJsonOutput {
    return parseCheckovJson(input);
  },
};
