import type { Skill } from "@security-workbench/schemas";
import { localOnlyPermissions } from "./localOnlyPermissions.js";
import { countBy, isRecord, stringValue, uniqueSorted } from "./nativeParserUtils.js";

export type ScannerName = "semgrep" | "checkov" | "grype";
export type ScannerFamily = "sast" | "iac" | "sca";
export type NormalizedScannerSeverity = "critical" | "high" | "medium" | "low" | "informational" | "unknown";
export type NormalizedScannerStatus = "observed" | "failed" | "passed" | "skipped" | "ignored" | "unknown";
export type NormalizedScannerResultKind = "code_scan_result" | "iac_check_result" | "vulnerability_match";

export interface NormalizedScannerResultObservation {
  readonly id: string;
  readonly scanner: ScannerName;
  readonly scanner_family: ScannerFamily;
  readonly result_kind: NormalizedScannerResultKind;
  readonly source_artifact_type: "semgrep_json" | "checkov_json" | "grype_json";
  readonly source_result_index: number;
  readonly source_result_ref: string;
  readonly native_status: string | null;
  readonly normalized_status: NormalizedScannerStatus;
  readonly native_severity: string | null;
  readonly normalized_severity: NormalizedScannerSeverity;
  readonly rule_id: string | null;
  readonly rule_name: string | null;
  readonly title: string | null;
  readonly message: string | null;
  readonly category: string | null;
  readonly file_path: string | null;
  readonly start_line: number | null;
  readonly end_line: number | null;
  readonly resource: string | null;
  readonly resource_address: string | null;
  readonly package_name: string | null;
  readonly package_version: string | null;
  readonly package_type: string | null;
  readonly package_language: string | null;
  readonly purl: string | null;
  readonly vulnerability_id: string | null;
  readonly vulnerability_namespace: string | null;
  readonly related_vulnerability_ids: readonly string[];
  readonly cwe_ids: readonly string[];
  readonly owasp_ids: readonly string[];
  readonly references: readonly string[];
  readonly fixed_versions: readonly string[];
  readonly fix_available: boolean;
  readonly suppressed: boolean | null;
  readonly ignored: boolean | null;
  readonly evidence_fields: readonly string[];
  readonly dedupe_key: string;
}

export interface NormalizeScannerResultsOutput {
  readonly artifact: {
    readonly id: "artifact_normalized_scanner_results";
    readonly type: "normalized_scanner_results";
    readonly source_artifact_id: string | null;
    readonly source_artifact_type: "semgrep_json" | "checkov_json" | "grype_json";
    readonly scanner: ScannerName;
  };
  readonly observed: {
    readonly source_parser: "parse_semgrep_json" | "parse_checkov_json" | "parse_grype_json";
    readonly source_warning_count: number;
    readonly scanner: ScannerName;
    readonly scanner_family: ScannerFamily;
    readonly source_result_count: number;
    readonly normalized_result_count: number;
    readonly result_kinds: readonly NormalizedScannerResultKind[];
    readonly native_severities: Readonly<Record<string, number>>;
    readonly normalized_severities: Readonly<Record<string, number>>;
    readonly native_statuses: Readonly<Record<string, number>>;
    readonly normalized_statuses: Readonly<Record<string, number>>;
    readonly rule_ids: readonly string[];
    readonly rule_names: readonly string[];
    readonly file_paths: readonly string[];
    readonly resources: readonly string[];
    readonly resource_addresses: readonly string[];
    readonly package_names: readonly string[];
    readonly package_versions: readonly string[];
    readonly vulnerability_ids: readonly string[];
    readonly cwe_ids: readonly string[];
    readonly owasp_ids: readonly string[];
    readonly reference_urls: readonly string[];
    readonly fix_available_count: number;
    readonly ignored_count: number;
    readonly suppressed_count: number;
    readonly skipped_count: number;
    readonly passed_count: number;
    readonly failed_count: number;
    readonly results: readonly NormalizedScannerResultObservation[];
  };
  readonly warnings: readonly string[];
}

type JsonRecord = Record<string, unknown>;

interface ParsedScannerInput {
  readonly artifact: JsonRecord;
  readonly observed: JsonRecord;
  readonly warnings: readonly string[];
}

function parseJsonInput(input: string, skillName: string): unknown {
  try {
    return JSON.parse(input) as unknown;
  } catch {
    throw new Error(`${skillName} input must be parsed scanner output or a JSON run result from parse_semgrep_json, parse_checkov_json, or parse_grype_json`);
  }
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((entry): entry is string => typeof entry === "string" && entry.length > 0) : [];
}

function numberOrNull(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function booleanOrNull(value: unknown): boolean | null {
  return typeof value === "boolean" ? value : null;
}

function recordArray(value: unknown): JsonRecord[] {
  return Array.isArray(value) ? value.filter((entry): entry is JsonRecord => isRecord(entry)) : [];
}

function childRecord(record: JsonRecord, key: string): JsonRecord | null {
  const value = record[key];
  return isRecord(value) ? value : null;
}

function unwrapParsedScannerInput(input: unknown, skillName: string): ParsedScannerInput {
  const parsed = typeof input === "string" ? parseJsonInput(input, skillName) : input;
  const candidate = isRecord(parsed) && isRecord(parsed.output) ? parsed.output : parsed;

  if (!isRecord(candidate)) {
    throw new Error(`${skillName} input must be an object`);
  }

  const artifact = childRecord(candidate, "artifact");
  const observed = childRecord(candidate, "observed");
  if (!artifact || !observed) {
    throw new Error(`${skillName} input must contain artifact and observed objects`);
  }

  const type = stringValue(artifact.type);
  if (type !== "semgrep_json" && type !== "checkov_json" && type !== "grype_json") {
    throw new Error(`${skillName} input artifact.type must be semgrep_json, checkov_json, or grype_json`);
  }

  return {
    artifact,
    observed,
    warnings: stringArray(candidate.warnings),
  };
}

function sourceParserFor(type: string): "parse_semgrep_json" | "parse_checkov_json" | "parse_grype_json" {
  if (type === "semgrep_json") {
    return "parse_semgrep_json";
  }
  if (type === "checkov_json") {
    return "parse_checkov_json";
  }
  return "parse_grype_json";
}

function scannerFor(type: string): ScannerName {
  if (type === "semgrep_json") {
    return "semgrep";
  }
  if (type === "checkov_json") {
    return "checkov";
  }
  return "grype";
}

function familyFor(scanner: ScannerName): ScannerFamily {
  if (scanner === "checkov") {
    return "iac";
  }
  if (scanner === "grype") {
    return "sca";
  }
  return "sast";
}

function kindFor(scanner: ScannerName): NormalizedScannerResultKind {
  if (scanner === "checkov") {
    return "iac_check_result";
  }
  if (scanner === "grype") {
    return "vulnerability_match";
  }
  return "code_scan_result";
}

function normalizeSeverity(value: string | null): NormalizedScannerSeverity {
  const normalized = value?.trim().toLowerCase() ?? "";
  if (["critical", "crit"].includes(normalized)) {
    return "critical";
  }
  if (["high", "error", "err"].includes(normalized)) {
    return "high";
  }
  if (["medium", "med", "warning", "warn"].includes(normalized)) {
    return "medium";
  }
  if (["low", "note", "notice"].includes(normalized)) {
    return "low";
  }
  if (["info", "informational", "none", "negligible"].includes(normalized)) {
    return "informational";
  }
  return "unknown";
}

function dedupeToken(value: string | number | null | undefined): string {
  return value === null || value === undefined || value === "" ? "-" : String(value).trim().toLowerCase();
}

function stableDedupeKey(parts: readonly (string | number | null | undefined)[]): string {
  return parts.map(dedupeToken).join("|");
}

function evidenceFields(fields: Readonly<Record<string, unknown>>): string[] {
  return Object.entries(fields)
    .filter(([, value]) => {
      if (value === null || value === undefined || value === false) {
        return false;
      }
      if (Array.isArray(value)) {
        return value.length > 0;
      }
      return value !== "";
    })
    .map(([key]) => key)
    .sort();
}

function semgrepResults(observed: JsonRecord): NormalizedScannerResultObservation[] {
  return recordArray(observed.results).map((result, index) => {
    const sourceIndex = numberOrNull(result.result_index) ?? index;
    const start = childRecord(result, "start");
    const end = childRecord(result, "end");
    const ignored = booleanOrNull(result.ignored);
    const severity = stringValue(result.severity);
    const checkId = stringValue(result.check_id);
    const path = stringValue(result.path);
    const startLine = start ? numberOrNull(start.line) : null;
    const endLine = end ? numberOrNull(end.line) : null;
    const message = stringValue(result.message);
    const cweIds = stringArray(result.cwe);
    const owaspIds = stringArray(result.owasp);
    const references = stringArray(result.references);
    const fixAvailable = result.fix_present === true || result.fix_regex_present === true;
    const status: NormalizedScannerStatus = ignored === true ? "ignored" : "observed";
    const dedupeKey = stableDedupeKey(["semgrep", checkId, path, startLine, endLine, message]);

    return {
      id: `normalized_scanner_result_${String(index + 1).padStart(3, "0")}`,
      scanner: "semgrep",
      scanner_family: "sast",
      result_kind: "code_scan_result",
      source_artifact_type: "semgrep_json",
      source_result_index: sourceIndex,
      source_result_ref: `semgrep.results[${sourceIndex}]`,
      native_status: stringValue(result.validation_state),
      normalized_status: status,
      native_severity: severity,
      normalized_severity: normalizeSeverity(severity),
      rule_id: checkId,
      rule_name: null,
      title: checkId,
      message,
      category: stringValue(result.category),
      file_path: path,
      start_line: startLine,
      end_line: endLine,
      resource: null,
      resource_address: null,
      package_name: null,
      package_version: null,
      package_type: null,
      package_language: null,
      purl: null,
      vulnerability_id: null,
      vulnerability_namespace: null,
      related_vulnerability_ids: [],
      cwe_ids: cweIds,
      owasp_ids: owaspIds,
      references,
      fixed_versions: [],
      fix_available: fixAvailable,
      suppressed: null,
      ignored,
      evidence_fields: evidenceFields({ checkId, path, startLine, endLine, message, severity, cweIds, owaspIds, references, fixAvailable }),
      dedupe_key: dedupeKey,
    };
  });
}

function checkovResults(observed: JsonRecord): NormalizedScannerResultObservation[] {
  return recordArray(observed.results).map((result, index) => {
    const sourceIndex = numberOrNull(result.result_index) ?? index;
    const statusText = stringValue(result.status);
    const status: NormalizedScannerStatus = statusText === "failed" || statusText === "passed" || statusText === "skipped" ? statusText : "unknown";
    const lineRange = childRecord(result, "file_line_range");
    const startLine = lineRange ? numberOrNull(lineRange.start) : null;
    const endLine = lineRange ? numberOrNull(lineRange.end) : null;
    const severity = stringValue(result.severity);
    const checkId = stringValue(result.check_id);
    const checkName = stringValue(result.check_name);
    const filePath = stringValue(result.file_path);
    const resource = stringValue(result.resource);
    const resourceAddress = stringValue(result.resource_address);
    const guideline = stringValue(result.guideline);
    const suppressed = status === "skipped" || stringValue(result.suppress_comment) !== null;
    const dedupeKey = stableDedupeKey(["checkov", checkId, filePath, resourceAddress ?? resource, startLine]);

    return {
      id: `normalized_scanner_result_${String(index + 1).padStart(3, "0")}`,
      scanner: "checkov",
      scanner_family: "iac",
      result_kind: "iac_check_result",
      source_artifact_type: "checkov_json",
      source_result_index: sourceIndex,
      source_result_ref: `checkov.results[${sourceIndex}]`,
      native_status: statusText,
      normalized_status: status,
      native_severity: severity,
      normalized_severity: normalizeSeverity(severity),
      rule_id: checkId,
      rule_name: checkName,
      title: checkName ?? checkId,
      message: checkName,
      category: stringValue(result.check_class),
      file_path: filePath,
      start_line: startLine,
      end_line: endLine,
      resource,
      resource_address: resourceAddress,
      package_name: null,
      package_version: null,
      package_type: null,
      package_language: null,
      purl: null,
      vulnerability_id: null,
      vulnerability_namespace: null,
      related_vulnerability_ids: [],
      cwe_ids: [],
      owasp_ids: [],
      references: guideline ? [guideline] : [],
      fixed_versions: [],
      fix_available: false,
      suppressed,
      ignored: null,
      evidence_fields: evidenceFields({ checkId, checkName, filePath, startLine, endLine, resource, resourceAddress, guideline, severity, statusText }),
      dedupe_key: dedupeKey,
    };
  });
}

function grypeResults(observed: JsonRecord): NormalizedScannerResultObservation[] {
  return recordArray(observed.matches).map((match, index) => {
    const sourceIndex = numberOrNull(match.match_index) ?? index;
    const vulnerability = childRecord(match, "vulnerability") ?? {};
    const artifact = childRecord(match, "artifact") ?? {};
    const severity = stringValue(vulnerability.severity);
    const vulnerabilityId = stringValue(vulnerability.id);
    const packageName = stringValue(artifact.name);
    const packageVersion = stringValue(artifact.version);
    const purl = stringValue(artifact.purl);
    const locationPaths = stringArray(artifact.location_paths);
    const fixedVersions = stringArray(vulnerability.fixed_versions);
    const fixAvailable = fixedVersions.length > 0;
    const firstLocationPath = locationPaths[0] ?? null;
    const dedupeKey = stableDedupeKey(["grype", vulnerabilityId, packageName, packageVersion, purl ?? firstLocationPath]);

    return {
      id: `normalized_scanner_result_${String(index + 1).padStart(3, "0")}`,
      scanner: "grype",
      scanner_family: "sca",
      result_kind: "vulnerability_match",
      source_artifact_type: "grype_json",
      source_result_index: sourceIndex,
      source_result_ref: `grype.matches[${sourceIndex}]`,
      native_status: stringValue(vulnerability.fix_state),
      normalized_status: "observed",
      native_severity: severity,
      normalized_severity: normalizeSeverity(severity),
      rule_id: vulnerabilityId,
      rule_name: vulnerabilityId,
      title: vulnerabilityId,
      message: vulnerabilityId === null ? null : `Vulnerability match ${vulnerabilityId}`,
      category: stringValue(vulnerability.namespace),
      file_path: firstLocationPath,
      start_line: null,
      end_line: null,
      resource: purl ?? packageName,
      resource_address: null,
      package_name: packageName,
      package_version: packageVersion,
      package_type: stringValue(artifact.type),
      package_language: stringValue(artifact.language),
      purl,
      vulnerability_id: vulnerabilityId,
      vulnerability_namespace: stringValue(vulnerability.namespace),
      related_vulnerability_ids: stringArray(vulnerability.related_vulnerability_ids),
      cwe_ids: [],
      owasp_ids: [],
      references: stringArray(vulnerability.urls),
      fixed_versions: fixedVersions,
      fix_available: fixAvailable,
      suppressed: null,
      ignored: null,
      evidence_fields: evidenceFields({ vulnerabilityId, packageName, packageVersion, purl, firstLocationPath, severity, fixedVersions }),
      dedupe_key: dedupeKey,
    };
  });
}

function normalizeResults(scanner: ScannerName, observed: JsonRecord): NormalizedScannerResultObservation[] {
  if (scanner === "semgrep") {
    return semgrepResults(observed);
  }
  if (scanner === "checkov") {
    return checkovResults(observed);
  }
  return grypeResults(observed);
}

export function normalizeScannerResults(input: unknown): NormalizeScannerResultsOutput {
  const parsed = unwrapParsedScannerInput(input, "normalize_scanner_results");
  const sourceArtifactType = stringValue(parsed.artifact.type) as "semgrep_json" | "checkov_json" | "grype_json";
  const sourceArtifactId = stringValue(parsed.artifact.id);
  const scanner = scannerFor(sourceArtifactType);
  const scannerFamily = familyFor(scanner);
  const results = normalizeResults(scanner, parsed.observed);
  const warnings = [...parsed.warnings];

  if (results.length === 0) {
    warnings.push("Parsed scanner output contained no normalizable result records.");
  }

  return {
    artifact: {
      id: "artifact_normalized_scanner_results",
      type: "normalized_scanner_results",
      source_artifact_id: sourceArtifactId,
      source_artifact_type: sourceArtifactType,
      scanner,
    },
    observed: {
      source_parser: sourceParserFor(sourceArtifactType),
      source_warning_count: parsed.warnings.length,
      scanner,
      scanner_family: scannerFamily,
      source_result_count: results.length,
      normalized_result_count: results.length,
      result_kinds: uniqueSorted(results.map((result) => result.result_kind)) as NormalizedScannerResultKind[],
      native_severities: countBy(results.map((result) => result.native_severity ?? "unknown")),
      normalized_severities: countBy(results.map((result) => result.normalized_severity)),
      native_statuses: countBy(results.map((result) => result.native_status ?? "unknown")),
      normalized_statuses: countBy(results.map((result) => result.normalized_status)),
      rule_ids: uniqueSorted(results.map((result) => result.rule_id)),
      rule_names: uniqueSorted(results.map((result) => result.rule_name)),
      file_paths: uniqueSorted(results.map((result) => result.file_path)),
      resources: uniqueSorted(results.map((result) => result.resource)),
      resource_addresses: uniqueSorted(results.map((result) => result.resource_address)),
      package_names: uniqueSorted(results.map((result) => result.package_name)),
      package_versions: uniqueSorted(results.map((result) => result.package_version)),
      vulnerability_ids: uniqueSorted(results.map((result) => result.vulnerability_id)),
      cwe_ids: uniqueSorted(results.flatMap((result) => result.cwe_ids)),
      owasp_ids: uniqueSorted(results.flatMap((result) => result.owasp_ids)),
      reference_urls: uniqueSorted(results.flatMap((result) => result.references)),
      fix_available_count: results.filter((result) => result.fix_available).length,
      ignored_count: results.filter((result) => result.ignored === true || result.normalized_status === "ignored").length,
      suppressed_count: results.filter((result) => result.suppressed === true).length,
      skipped_count: results.filter((result) => result.normalized_status === "skipped").length,
      passed_count: results.filter((result) => result.normalized_status === "passed").length,
      failed_count: results.filter((result) => result.normalized_status === "failed").length,
      results,
    },
    warnings,
  };
}

export const normalizeScannerResultsSkill: Skill<unknown, NormalizeScannerResultsOutput> = {
  metadata: {
    name: "normalize_scanner_results",
    version: "0.1.0",
    category: "transform",
    description:
      "Normalize parsed Semgrep, Checkov, or Grype scanner output into a common observational scanner-result shape without scoring or dedupe.",
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
        "Processes parsed scanner output that may contain source paths, package metadata, vulnerability identifiers, or scanner messages.",
        "Does not run scanners, inspect source code, call external services, persist input, score risk, or generate findings.",
        "Preserves observed scanner fields while mapping scanner-native result shapes into a shared result container.",
      ],
    },
  },
  run(input: unknown): NormalizeScannerResultsOutput {
    return normalizeScannerResults(input);
  },
};
