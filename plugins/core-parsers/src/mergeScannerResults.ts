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

export type MergeScannerSourceArtifactType = "normalized_scanner_results" | "deduped_scanner_results";

export interface ScannerMergeSourceObservation {
  readonly input_index: number;
  readonly artifact_type: MergeScannerSourceArtifactType;
  readonly artifact_id: string | null;
  readonly scanner: string | null;
  readonly source_result_count: number;
  readonly source_observation_count: number;
  readonly warning_count: number;
}

export interface MergedScannerResultObservation {
  readonly id: string;
  readonly dedupe_key: string;
  readonly duplicate_count: number;
  readonly source_result_ids: readonly string[];
  readonly source_result_refs: readonly string[];
  readonly scanners: readonly ScannerName[];
  readonly scanner_families: readonly ScannerFamily[];
  readonly result_kinds: readonly NormalizedScannerResultKind[];
  readonly normalized_severities: readonly NormalizedScannerSeverity[];
  readonly normalized_statuses: readonly NormalizedScannerStatus[];
  readonly rule_ids: readonly string[];
  readonly file_paths: readonly string[];
  readonly resources: readonly string[];
  readonly package_names: readonly string[];
  readonly package_versions: readonly string[];
  readonly vulnerability_ids: readonly string[];
  readonly representative_result: NormalizedScannerResultObservation;
}

export interface MergeScannerResultsOutput {
  readonly artifact: {
    readonly id: "artifact_merged_scanner_results";
    readonly type: "merged_scanner_results";
    readonly source_artifact_type: "scanner_result_collection";
  };
  readonly observed: {
    readonly source_input_count: number;
    readonly source_record_count: number;
    readonly source_observation_count: number;
    readonly merged_result_count: number;
    readonly duplicate_result_count: number;
    readonly duplicate_group_count: number;
    readonly scanners: readonly string[];
    readonly scanner_families: readonly string[];
    readonly result_kinds: readonly string[];
    readonly normalized_severities: Readonly<Record<string, number>>;
    readonly normalized_statuses: Readonly<Record<string, number>>;
    readonly rule_ids: readonly string[];
    readonly file_paths: readonly string[];
    readonly resources: readonly string[];
    readonly package_names: readonly string[];
    readonly package_versions: readonly string[];
    readonly vulnerability_ids: readonly string[];
    readonly sources: readonly ScannerMergeSourceObservation[];
    readonly merged_results: readonly MergedScannerResultObservation[];
  };
  readonly warnings: readonly string[];
}

type JsonRecord = Record<string, unknown>;

interface MergeInputSource {
  readonly artifact: JsonRecord;
  readonly observed: JsonRecord;
  readonly warnings: readonly string[];
}

interface SourceResultEntry {
  readonly result: NormalizedScannerResultObservation;
  readonly duplicate_count: number;
  readonly source_result_ids: readonly string[];
  readonly source_result_refs: readonly string[];
}

function parseJsonInput(input: string): unknown {
  try {
    return JSON.parse(input) as unknown;
  } catch {
    throw new Error("merge_scanner_results input must be scanner result output, an array of scanner result outputs, or JSON containing an inputs array");
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

function inputCandidates(input: unknown): unknown[] {
  const parsed = typeof input === "string" ? parseJsonInput(input) : input;
  const candidate = unwrapRunResult(parsed);

  if (Array.isArray(candidate)) {
    return candidate;
  }

  if (isRecord(candidate) && Array.isArray(candidate.inputs)) {
    return candidate.inputs;
  }

  if (isRecord(candidate)) {
    return [candidate];
  }

  throw new Error("merge_scanner_results input must be an object, array, or object with inputs array");
}

function unwrapSource(candidate: unknown, inputIndex: number): MergeInputSource {
  const source = unwrapRunResult(candidate);
  if (!isRecord(source)) {
    throw new Error(`merge_scanner_results input ${inputIndex} must be an object`);
  }

  const artifact = childRecord(source, "artifact");
  const observed = childRecord(source, "observed");
  if (!artifact || !observed) {
    throw new Error(`merge_scanner_results input ${inputIndex} must contain artifact and observed objects`);
  }

  if (artifact.type !== "normalized_scanner_results" && artifact.type !== "deduped_scanner_results") {
    throw new Error(`merge_scanner_results input ${inputIndex} artifact.type must be normalized_scanner_results or deduped_scanner_results`);
  }

  return {
    artifact,
    observed,
    warnings: stringArray(source.warnings),
  };
}

function normalizedResultArray(value: unknown): NormalizedScannerResultObservation[] {
  return Array.isArray(value)
    ? (value.filter((entry): entry is NormalizedScannerResultObservation => isRecord(entry)) as NormalizedScannerResultObservation[])
    : [];
}

function dedupedResultArray(value: unknown): JsonRecord[] {
  return Array.isArray(value) ? value.filter((entry): entry is JsonRecord => isRecord(entry)) : [];
}

function entriesForSource(source: MergeInputSource): SourceResultEntry[] {
  if (source.artifact.type === "normalized_scanner_results") {
    return normalizedResultArray(source.observed.results).map((result) => ({
      result,
      duplicate_count: 1,
      source_result_ids: [result.id],
      source_result_refs: [result.source_result_ref],
    }));
  }

  return dedupedResultArray(source.observed.deduped_results)
    .map((result): SourceResultEntry | null => {
      const representative = result.representative_result;
      if (!isRecord(representative)) {
        return null;
      }

      return {
        result: representative as unknown as NormalizedScannerResultObservation,
        duplicate_count: numberOrDefault(result.duplicate_count, 1),
        source_result_ids: stringArray(result.source_result_ids),
        source_result_refs: stringArray(result.source_result_refs),
      };
    })
    .filter((entry): entry is SourceResultEntry => entry !== null);
}

function groupByDedupeKey(entries: readonly SourceResultEntry[]): Map<string, SourceResultEntry[]> {
  const groups = new Map<string, SourceResultEntry[]>();
  for (const entry of entries) {
    const key = typeof entry.result.dedupe_key === "string" && entry.result.dedupe_key.length > 0 ? entry.result.dedupe_key : entry.result.id;
    const group = groups.get(key) ?? [];
    group.push(entry);
    groups.set(key, group);
  }
  return groups;
}

function representative(group: readonly SourceResultEntry[]): NormalizedScannerResultObservation {
  const first = group[0]?.result;
  if (!first) {
    throw new Error("merge_scanner_results internal error: empty scanner result group");
  }
  return first;
}

function mergedResult(dedupeKey: string, group: readonly SourceResultEntry[], index: number): MergedScannerResultObservation {
  const results = group.map((entry) => entry.result);
  const representativeResult = representative(group);

  return {
    id: `merged_scanner_result_${String(index + 1).padStart(3, "0")}`,
    dedupe_key: dedupeKey,
    duplicate_count: group.reduce((total, entry) => total + entry.duplicate_count, 0),
    source_result_ids: uniqueSorted(group.flatMap((entry) => entry.source_result_ids)),
    source_result_refs: uniqueSorted(group.flatMap((entry) => entry.source_result_refs)),
    scanners: uniqueSorted(results.map((result) => result.scanner)) as ScannerName[],
    scanner_families: uniqueSorted(results.map((result) => result.scanner_family)) as ScannerFamily[],
    result_kinds: uniqueSorted(results.map((result) => result.result_kind)) as NormalizedScannerResultKind[],
    normalized_severities: uniqueSorted(results.map((result) => result.normalized_severity)) as NormalizedScannerSeverity[],
    normalized_statuses: uniqueSorted(results.map((result) => result.normalized_status)) as NormalizedScannerStatus[],
    rule_ids: uniqueSorted(results.map((result) => result.rule_id)),
    file_paths: uniqueSorted(results.map((result) => result.file_path)),
    resources: uniqueSorted(results.map((result) => result.resource)),
    package_names: uniqueSorted(results.map((result) => result.package_name)),
    package_versions: uniqueSorted(results.map((result) => result.package_version)),
    vulnerability_ids: uniqueSorted(results.map((result) => result.vulnerability_id)),
    representative_result: representativeResult,
  };
}

export function mergeScannerResults(input: unknown): MergeScannerResultsOutput {
  const sources = inputCandidates(input).map((candidate, index) => unwrapSource(candidate, index));
  const warnings = sources.flatMap((source, index) => source.warnings.map((warning) => `input ${index}: ${warning}`));
  const sourceEntries = sources.map((source) => entriesForSource(source));
  const entries = sourceEntries.flat();
  const groups = [...groupByDedupeKey(entries).entries()].sort(([left], [right]) => left.localeCompare(right));
  const mergedResults = groups.map(([key, group], index) => mergedResult(key, group, index));
  const sourceObservationCount = entries.reduce((total, entry) => total + entry.duplicate_count, 0);

  if (sources.length === 0) {
    warnings.push("No scanner result inputs were provided to merge.");
  }
  if (entries.length === 0) {
    warnings.push("Scanner result inputs contained no mergeable result records.");
  }

  return {
    artifact: {
      id: "artifact_merged_scanner_results",
      type: "merged_scanner_results",
      source_artifact_type: "scanner_result_collection",
    },
    observed: {
      source_input_count: sources.length,
      source_record_count: entries.length,
      source_observation_count: sourceObservationCount,
      merged_result_count: mergedResults.length,
      duplicate_result_count: Math.max(0, sourceObservationCount - mergedResults.length),
      duplicate_group_count: mergedResults.filter((result) => result.duplicate_count > 1).length,
      scanners: uniqueSorted(mergedResults.flatMap((result) => result.scanners)),
      scanner_families: uniqueSorted(mergedResults.flatMap((result) => result.scanner_families)),
      result_kinds: uniqueSorted(mergedResults.flatMap((result) => result.result_kinds)),
      normalized_severities: countBy(mergedResults.map((result) => result.representative_result.normalized_severity)),
      normalized_statuses: countBy(mergedResults.map((result) => result.representative_result.normalized_status)),
      rule_ids: uniqueSorted(mergedResults.flatMap((result) => result.rule_ids)),
      file_paths: uniqueSorted(mergedResults.flatMap((result) => result.file_paths)),
      resources: uniqueSorted(mergedResults.flatMap((result) => result.resources)),
      package_names: uniqueSorted(mergedResults.flatMap((result) => result.package_names)),
      package_versions: uniqueSorted(mergedResults.flatMap((result) => result.package_versions)),
      vulnerability_ids: uniqueSorted(mergedResults.flatMap((result) => result.vulnerability_ids)),
      sources: sources.map((source, index) => ({
        input_index: index,
        artifact_type: source.artifact.type as MergeScannerSourceArtifactType,
        artifact_id: stringValue(source.artifact.id),
        scanner: stringValue(source.artifact.scanner),
        source_result_count: sourceEntries[index]?.length ?? 0,
        source_observation_count: sourceEntries[index]?.reduce((total, entry) => total + entry.duplicate_count, 0) ?? 0,
        warning_count: source.warnings.length,
      })),
      merged_results: mergedResults,
    },
    warnings,
  };
}

export const mergeScannerResultsSkill: Skill<unknown, MergeScannerResultsOutput> = {
  metadata: {
    name: "merge_scanner_results",
    version: "0.1.0",
    category: "transform",
    description:
      "Merge normalized or deduplicated scanner-result outputs into one observed scanner-result collection without scoring or finding generation.",
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
        "Processes normalized or deduplicated scanner output that may contain source paths, package metadata, vulnerability identifiers, or scanner messages.",
        "Does not run scanners, inspect source code, call external services, persist input, score risk, or generate findings.",
        "Combines observed scanner-result records and preserves source references for downstream review.",
      ],
    },
  },
  run(input: unknown): MergeScannerResultsOutput {
    return mergeScannerResults(input);
  },
};
