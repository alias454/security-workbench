import type { Skill } from "@security-workbench/schemas";
import { localOnlyPermissions } from "./localOnlyPermissions.js";
import { countBy, isRecord, stringValue, uniqueSorted } from "./nativeParserUtils.js";
import type {
  NormalizedScannerResultKind,
  NormalizedScannerResultObservation,
  NormalizedScannerSeverity,
  NormalizedScannerStatus,
  ScannerFamily,
  ScannerName,
} from "./normalizeScannerResults.js";

export type ScannerSummarySourceArtifactType = "normalized_scanner_results" | "deduped_scanner_results" | "merged_scanner_results";

export interface ScannerSummaryRecordObservation {
  readonly id: string;
  readonly source_result_refs: readonly string[];
  readonly duplicate_count: number;
  readonly scanner: ScannerName;
  readonly scanner_family: ScannerFamily;
  readonly result_kind: NormalizedScannerResultKind;
  readonly normalized_severity: NormalizedScannerSeverity;
  readonly normalized_status: NormalizedScannerStatus;
  readonly rule_id: string | null;
  readonly file_path: string | null;
  readonly resource: string | null;
  readonly package_name: string | null;
  readonly package_version: string | null;
  readonly vulnerability_id: string | null;
  readonly fix_available: boolean;
  readonly suppressed: boolean | null;
  readonly ignored: boolean | null;
}

export interface ScannerSummaryOutput {
  readonly artifact: {
    readonly id: "artifact_scanner_summary";
    readonly type: "scanner_summary";
    readonly source_artifact_id: string | null;
    readonly source_artifact_type: ScannerSummarySourceArtifactType;
  };
  readonly observed: {
    readonly summary_template: "scanner_summary_v1";
    readonly source_result_count: number;
    readonly summarized_result_count: number;
    readonly duplicate_result_count: number;
    readonly scanner_count: number;
    readonly scanners: readonly string[];
    readonly scanner_families: readonly string[];
    readonly result_kinds: readonly string[];
    readonly normalized_severities: Readonly<Record<string, number>>;
    readonly normalized_statuses: Readonly<Record<string, number>>;
    readonly scanner_result_counts: Readonly<Record<string, number>>;
    readonly fix_available_count: number;
    readonly ignored_count: number;
    readonly suppressed_count: number;
    readonly skipped_count: number;
    readonly passed_count: number;
    readonly failed_count: number;
    readonly rule_count: number;
    readonly file_path_count: number;
    readonly resource_count: number;
    readonly package_count: number;
    readonly vulnerability_count: number;
    readonly rule_ids: readonly string[];
    readonly file_paths: readonly string[];
    readonly resources: readonly string[];
    readonly package_names: readonly string[];
    readonly vulnerability_ids: readonly string[];
    readonly limitations: readonly string[];
    readonly summary_records: readonly ScannerSummaryRecordObservation[];
  };
  readonly warnings: readonly string[];
}

type JsonRecord = Record<string, unknown>;

interface SummaryInputSource {
  readonly artifact: JsonRecord;
  readonly observed: JsonRecord;
  readonly warnings: readonly string[];
}

function parseJsonInput(input: string): unknown {
  try {
    return JSON.parse(input) as unknown;
  } catch {
    throw new Error("scanner_summary input must be normalized, deduplicated, or merged scanner output JSON");
  }
}

function childRecord(record: JsonRecord, key: string): JsonRecord | null {
  const value = record[key];
  return isRecord(value) ? value : null;
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((entry): entry is string => typeof entry === "string" && entry.length > 0) : [];
}

function numberOrDefault(value: unknown, fallback: number): number {
  return typeof value === "number" && Number.isFinite(value) ? value : fallback;
}

function unwrapRunResult(value: unknown): unknown {
  return isRecord(value) && isRecord(value.output) ? value.output : value;
}

function unwrapSummaryInput(input: unknown): SummaryInputSource {
  const parsed = typeof input === "string" ? parseJsonInput(input) : input;
  const candidate = unwrapRunResult(parsed);

  if (!isRecord(candidate)) {
    throw new Error("scanner_summary input must be an object");
  }

  const artifact = childRecord(candidate, "artifact");
  const observed = childRecord(candidate, "observed");
  if (!artifact || !observed) {
    throw new Error("scanner_summary input must contain artifact and observed objects");
  }

  if (
    artifact.type !== "normalized_scanner_results"
    && artifact.type !== "deduped_scanner_results"
    && artifact.type !== "merged_scanner_results"
  ) {
    throw new Error("scanner_summary input artifact.type must be normalized_scanner_results, deduped_scanner_results, or merged_scanner_results");
  }

  return {
    artifact,
    observed,
    warnings: stringArray(candidate.warnings),
  };
}

function normalizedResultArray(value: unknown): NormalizedScannerResultObservation[] {
  return Array.isArray(value)
    ? (value.filter((entry): entry is NormalizedScannerResultObservation => isRecord(entry)) as NormalizedScannerResultObservation[])
    : [];
}

function recordArray(value: unknown): JsonRecord[] {
  return Array.isArray(value) ? value.filter((entry): entry is JsonRecord => isRecord(entry)) : [];
}

function summaryRecordFromNormalized(result: NormalizedScannerResultObservation, index: number): ScannerSummaryRecordObservation {
  return {
    id: `scanner_summary_record_${String(index + 1).padStart(3, "0")}`,
    source_result_refs: [result.source_result_ref],
    duplicate_count: 1,
    scanner: result.scanner,
    scanner_family: result.scanner_family,
    result_kind: result.result_kind,
    normalized_severity: result.normalized_severity,
    normalized_status: result.normalized_status,
    rule_id: result.rule_id,
    file_path: result.file_path,
    resource: result.resource,
    package_name: result.package_name,
    package_version: result.package_version,
    vulnerability_id: result.vulnerability_id,
    fix_available: result.fix_available,
    suppressed: result.suppressed,
    ignored: result.ignored,
  };
}

function summaryRecordFromGrouped(record: JsonRecord, index: number): ScannerSummaryRecordObservation | null {
  const representative = record.representative_result;
  if (!isRecord(representative)) {
    return null;
  }

  const result = representative as unknown as NormalizedScannerResultObservation;
  return {
    id: `scanner_summary_record_${String(index + 1).padStart(3, "0")}`,
    source_result_refs: stringArray(record.source_result_refs),
    duplicate_count: numberOrDefault(record.duplicate_count, 1),
    scanner: result.scanner,
    scanner_family: result.scanner_family,
    result_kind: result.result_kind,
    normalized_severity: result.normalized_severity,
    normalized_status: result.normalized_status,
    rule_id: result.rule_id,
    file_path: result.file_path,
    resource: result.resource,
    package_name: result.package_name,
    package_version: result.package_version,
    vulnerability_id: result.vulnerability_id,
    fix_available: result.fix_available,
    suppressed: result.suppressed,
    ignored: result.ignored,
  };
}

function summaryRecords(source: SummaryInputSource): ScannerSummaryRecordObservation[] {
  if (source.artifact.type === "normalized_scanner_results") {
    return normalizedResultArray(source.observed.results).map((result, index) => summaryRecordFromNormalized(result, index));
  }

  const key = source.artifact.type === "deduped_scanner_results" ? "deduped_results" : "merged_results";
  return recordArray(source.observed[key])
    .map((record, index) => summaryRecordFromGrouped(record, index))
    .filter((record): record is ScannerSummaryRecordObservation => record !== null);
}

function weightedDuplicateCount(records: readonly ScannerSummaryRecordObservation[]): number {
  return records.reduce((total, record) => total + Math.max(0, record.duplicate_count - 1), 0);
}

export function scannerSummary(input: unknown): ScannerSummaryOutput {
  const source = unwrapSummaryInput(input);
  const records = summaryRecords(source);
  const warnings = [...source.warnings];

  if (records.length === 0) {
    warnings.push("Scanner summary input contained no result records to summarize.");
  }

  const ruleIds = uniqueSorted(records.map((record) => record.rule_id));
  const filePaths = uniqueSorted(records.map((record) => record.file_path));
  const resources = uniqueSorted(records.map((record) => record.resource));
  const packageNames = uniqueSorted(records.map((record) => record.package_name));
  const vulnerabilityIds = uniqueSorted(records.map((record) => record.vulnerability_id));

  return {
    artifact: {
      id: "artifact_scanner_summary",
      type: "scanner_summary",
      source_artifact_id: stringValue(source.artifact.id),
      source_artifact_type: source.artifact.type as ScannerSummarySourceArtifactType,
    },
    observed: {
      summary_template: "scanner_summary_v1",
      source_result_count: records.reduce((total, record) => total + record.duplicate_count, 0),
      summarized_result_count: records.length,
      duplicate_result_count: weightedDuplicateCount(records),
      scanner_count: uniqueSorted(records.map((record) => record.scanner)).length,
      scanners: uniqueSorted(records.map((record) => record.scanner)),
      scanner_families: uniqueSorted(records.map((record) => record.scanner_family)),
      result_kinds: uniqueSorted(records.map((record) => record.result_kind)),
      normalized_severities: countBy(records.map((record) => record.normalized_severity)),
      normalized_statuses: countBy(records.map((record) => record.normalized_status)),
      scanner_result_counts: countBy(records.map((record) => record.scanner)),
      fix_available_count: records.filter((record) => record.fix_available).length,
      ignored_count: records.filter((record) => record.ignored === true || record.normalized_status === "ignored").length,
      suppressed_count: records.filter((record) => record.suppressed === true).length,
      skipped_count: records.filter((record) => record.normalized_status === "skipped").length,
      passed_count: records.filter((record) => record.normalized_status === "passed").length,
      failed_count: records.filter((record) => record.normalized_status === "failed").length,
      rule_count: ruleIds.length,
      file_path_count: filePaths.length,
      resource_count: resources.length,
      package_count: packageNames.length,
      vulnerability_count: vulnerabilityIds.length,
      rule_ids: ruleIds,
      file_paths: filePaths,
      resources,
      package_names: packageNames,
      vulnerability_ids: vulnerabilityIds,
      limitations: [
        "Summary is derived from scanner artifacts only; source code, infrastructure state, and package registries were not inspected.",
        "Severity and status counts reflect scanner-provided fields mapped into normalized labels; this is not risk scoring.",
        "No exploitability, true-positive, false-positive, reputation, or maliciousness conclusion is made.",
      ],
      summary_records: records,
    },
    warnings,
  };
}

export const scannerSummarySkill: Skill<unknown, ScannerSummaryOutput> = {
  metadata: {
    name: "scanner_summary",
    version: "0.1.0",
    category: "transform",
    description:
      "Summarize normalized, deduplicated, or merged scanner-result observations without scoring risk or generating findings.",
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
        "Processes scanner summary input that may contain source paths, package metadata, vulnerability identifiers, or scanner messages.",
        "Does not run scanners, inspect source code, call external services, persist input, score risk, or generate findings.",
        "Produces count-based observational summaries and explicit limitations for downstream review.",
      ],
    },
  },
  run(input: unknown): ScannerSummaryOutput {
    return scannerSummary(input);
  },
};
