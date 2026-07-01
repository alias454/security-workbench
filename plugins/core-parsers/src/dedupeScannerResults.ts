import type { Skill } from "@security-workbench/schemas";
import { localOnlyPermissions } from "./localOnlyPermissions.js";
import { countBy, isRecord, stringValue, uniqueSorted } from "./nativeParserUtils.js";
import type {
  NormalizedScannerResultKind,
  NormalizedScannerResultObservation,
  NormalizedScannerSeverity,
  NormalizedScannerStatus,
  ScannerName,
} from "./normalizeScannerResults.js";

export interface DedupedScannerResultObservation {
  readonly id: string;
  readonly dedupe_key: string;
  readonly duplicate_count: number;
  readonly source_result_ids: readonly string[];
  readonly source_result_refs: readonly string[];
  readonly scanner: ScannerName;
  readonly result_kind: NormalizedScannerResultKind;
  readonly normalized_severity: NormalizedScannerSeverity;
  readonly normalized_status: NormalizedScannerStatus;
  readonly rule_id: string | null;
  readonly file_path: string | null;
  readonly resource: string | null;
  readonly package_name: string | null;
  readonly package_version: string | null;
  readonly vulnerability_id: string | null;
  readonly representative_result: NormalizedScannerResultObservation;
}

export interface ScannerDuplicateGroupObservation {
  readonly dedupe_key: string;
  readonly duplicate_count: number;
  readonly source_result_ids: readonly string[];
  readonly source_result_refs: readonly string[];
}

export interface DedupeScannerResultsOutput {
  readonly artifact: {
    readonly id: "artifact_deduped_scanner_results";
    readonly type: "deduped_scanner_results";
    readonly source_artifact_id: string | null;
    readonly source_artifact_type: "normalized_scanner_results";
  };
  readonly observed: {
    readonly source_normalizer: "normalize_scanner_results";
    readonly source_result_count: number;
    readonly unique_result_count: number;
    readonly duplicate_result_count: number;
    readonly duplicate_group_count: number;
    readonly scanners: readonly string[];
    readonly result_kinds: readonly string[];
    readonly normalized_severities: Readonly<Record<string, number>>;
    readonly normalized_statuses: Readonly<Record<string, number>>;
    readonly rule_ids: readonly string[];
    readonly file_paths: readonly string[];
    readonly resources: readonly string[];
    readonly package_names: readonly string[];
    readonly vulnerability_ids: readonly string[];
    readonly deduped_results: readonly DedupedScannerResultObservation[];
    readonly duplicate_groups: readonly ScannerDuplicateGroupObservation[];
  };
  readonly warnings: readonly string[];
}

type JsonRecord = Record<string, unknown>;

interface NormalizedInput {
  readonly artifact: JsonRecord;
  readonly observed: JsonRecord;
  readonly warnings: readonly string[];
}

function parseJsonInput(input: string): unknown {
  try {
    return JSON.parse(input) as unknown;
  } catch {
    throw new Error("dedupe_scanner_results input must be normalize_scanner_results output or a JSON run result from normalize_scanner_results");
  }
}

function childRecord(record: JsonRecord, key: string): JsonRecord | null {
  const value = record[key];
  return isRecord(value) ? value : null;
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((entry): entry is string => typeof entry === "string" && entry.length > 0) : [];
}

function resultArray(value: unknown): NormalizedScannerResultObservation[] {
  return Array.isArray(value) ? value.filter((entry): entry is NormalizedScannerResultObservation => isRecord(entry)) as NormalizedScannerResultObservation[] : [];
}

function unwrapNormalizedInput(input: unknown): NormalizedInput {
  const parsed = typeof input === "string" ? parseJsonInput(input) : input;
  const candidate = isRecord(parsed) && isRecord(parsed.output) ? parsed.output : parsed;

  if (!isRecord(candidate)) {
    throw new Error("dedupe_scanner_results input must be an object");
  }

  const artifact = childRecord(candidate, "artifact");
  const observed = childRecord(candidate, "observed");
  if (!artifact || !observed) {
    throw new Error("dedupe_scanner_results input must contain artifact and observed objects");
  }

  if (artifact.type !== "normalized_scanner_results") {
    throw new Error("dedupe_scanner_results input artifact.type must be normalized_scanner_results");
  }

  return {
    artifact,
    observed,
    warnings: stringArray(candidate.warnings),
  };
}

function groupByDedupeKey(results: readonly NormalizedScannerResultObservation[]): Map<string, NormalizedScannerResultObservation[]> {
  const groups = new Map<string, NormalizedScannerResultObservation[]>();
  for (const result of results) {
    const key = typeof result.dedupe_key === "string" && result.dedupe_key.length > 0 ? result.dedupe_key : result.id;
    const group = groups.get(key) ?? [];
    group.push(result);
    groups.set(key, group);
  }
  return groups;
}

function sourceIds(group: readonly NormalizedScannerResultObservation[]): string[] {
  return uniqueSorted(group.map((result) => result.id));
}

function sourceRefs(group: readonly NormalizedScannerResultObservation[]): string[] {
  return uniqueSorted(group.map((result) => result.source_result_ref));
}

function dedupedResult(dedupeKey: string, group: readonly NormalizedScannerResultObservation[], index: number): DedupedScannerResultObservation {
  const representative = group[0];
  if (!representative) {
    throw new Error("dedupe_scanner_results internal error: empty duplicate group");
  }

  return {
    id: `deduped_scanner_result_${String(index + 1).padStart(3, "0")}`,
    dedupe_key: dedupeKey,
    duplicate_count: group.length,
    source_result_ids: sourceIds(group),
    source_result_refs: sourceRefs(group),
    scanner: representative.scanner,
    result_kind: representative.result_kind,
    normalized_severity: representative.normalized_severity,
    normalized_status: representative.normalized_status,
    rule_id: representative.rule_id,
    file_path: representative.file_path,
    resource: representative.resource,
    package_name: representative.package_name,
    package_version: representative.package_version,
    vulnerability_id: representative.vulnerability_id,
    representative_result: representative,
  };
}

export function dedupeScannerResults(input: unknown): DedupeScannerResultsOutput {
  const parsed = unwrapNormalizedInput(input);
  const results = resultArray(parsed.observed.results);
  const groups = [...groupByDedupeKey(results).entries()].sort(([left], [right]) => left.localeCompare(right));
  const dedupedResults = groups.map(([key, group], index) => dedupedResult(key, group, index));
  const duplicateGroups = groups
    .filter(([, group]) => group.length > 1)
    .map(([dedupeKey, group]) => ({
      dedupe_key: dedupeKey,
      duplicate_count: group.length,
      source_result_ids: sourceIds(group),
      source_result_refs: sourceRefs(group),
    }));
  const warnings = [...parsed.warnings];

  if (results.length === 0) {
    warnings.push("Normalized scanner output contained no result records to dedupe.");
  }

  return {
    artifact: {
      id: "artifact_deduped_scanner_results",
      type: "deduped_scanner_results",
      source_artifact_id: stringValue(parsed.artifact.id),
      source_artifact_type: "normalized_scanner_results",
    },
    observed: {
      source_normalizer: "normalize_scanner_results",
      source_result_count: results.length,
      unique_result_count: dedupedResults.length,
      duplicate_result_count: results.length - dedupedResults.length,
      duplicate_group_count: duplicateGroups.length,
      scanners: uniqueSorted(results.map((result) => result.scanner)),
      result_kinds: uniqueSorted(results.map((result) => result.result_kind)),
      normalized_severities: countBy(dedupedResults.map((result) => result.normalized_severity)),
      normalized_statuses: countBy(dedupedResults.map((result) => result.normalized_status)),
      rule_ids: uniqueSorted(dedupedResults.map((result) => result.rule_id)),
      file_paths: uniqueSorted(dedupedResults.map((result) => result.file_path)),
      resources: uniqueSorted(dedupedResults.map((result) => result.resource)),
      package_names: uniqueSorted(dedupedResults.map((result) => result.package_name)),
      vulnerability_ids: uniqueSorted(dedupedResults.map((result) => result.vulnerability_id)),
      deduped_results: dedupedResults,
      duplicate_groups: duplicateGroups,
    },
    warnings,
  };
}

export const dedupeScannerResultsSkill: Skill<unknown, DedupeScannerResultsOutput> = {
  metadata: {
    name: "dedupe_scanner_results",
    version: "0.1.0",
    category: "transform",
    description:
      "Deduplicate normalized scanner results by stable observed identifiers while preserving source result references.",
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
        "Processes normalized scanner output that may contain source paths, package metadata, vulnerability identifiers, or scanner messages.",
        "Does not run scanners, inspect source code, call external services, persist input, score risk, or generate findings.",
        "Groups repeated normalized observations by stable keys and preserves original source result references.",
      ],
    },
  },
  run(input: unknown): DedupeScannerResultsOutput {
    return dedupeScannerResults(input);
  },
};
