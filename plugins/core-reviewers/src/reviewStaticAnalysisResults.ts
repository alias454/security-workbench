import type { EvidenceRecord, JsonObject, JsonValue, SignalRecord, Skill } from "@security-workbench/schemas";
import { localOnlyPermissions } from "./localOnlyPermissions.js";

type ReviewRecord = Record<string, unknown>;
type Confidence = "confirmed" | "high" | "medium" | "low" | "unknown";
type Severity = "informational" | "low" | "medium" | "high" | "critical";

export interface StaticAnalysisReviewResultObservation {
  readonly run_index: number;
  readonly result_index: number;
  readonly rule_id: string | null;
  readonly level: string | null;
  readonly kind: string | null;
  readonly baseline_state: string | null;
  readonly message_text: string | null;
  readonly location_count: number;
  readonly locations: readonly {
    readonly uri: string | null;
    readonly region_start_line: number | null;
    readonly logical_location_names: readonly string[];
  }[];
  readonly suppression_count: number;
  readonly fix_count: number;
  readonly fixes_present: boolean;
  readonly taxa_ids: readonly string[];
  readonly fingerprint_keys: readonly string[];
  readonly partial_fingerprint_keys: readonly string[];
}

export interface StaticAnalysisReviewOutput {
  readonly artifact: {
    readonly id: "artifact_static_analysis_review";
    readonly type: "static_analysis_review";
    readonly source_artifact_id: string | null;
    readonly source_artifact_type: string | null;
    readonly source_format: "sarif";
    readonly source_version: string | null;
  };
  readonly observed: {
    readonly source_parser: "parse_sarif";
    readonly source_warning_count: number;
    readonly run_count: number;
    readonly tool_driver_names: readonly string[];
    readonly rule_count: number;
    readonly result_count: number;
    readonly suppressed_result_count: number;
    readonly fix_available_count: number;
    readonly new_result_count: number;
    readonly result_levels: Readonly<Record<string, number>>;
    readonly reviewed_result_count: number;
    readonly evidence_count: number;
    readonly signal_count: number;
    readonly high_attention_result_count: number;
    readonly medium_attention_result_count: number;
    readonly low_attention_result_count: number;
    readonly informational_result_count: number;
    readonly unknown_attention_result_count: number;
    readonly affected_artifact_uris: readonly string[];
    readonly affected_rule_ids: readonly string[];
  };
  readonly evidence: readonly EvidenceRecord[];
  readonly signals: readonly SignalRecord[];
  readonly warnings: readonly string[];
}

interface ParsedSarifForReview {
  readonly artifact: {
    readonly id?: string;
    readonly type?: string;
    readonly version?: string | null;
  };
  readonly observed: ReviewRecord;
  readonly warnings?: readonly string[];
}

function isRecord(value: unknown): value is ReviewRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function parseJsonString(input: string): unknown {
  try {
    return JSON.parse(input) as unknown;
  } catch {
    throw new Error("review_static_analysis_results input must be parsed SARIF JSON or a JSON run result from parse_sarif");
  }
}

function childRecord(record: ReviewRecord, key: string): ReviewRecord | undefined {
  const value = record[key];
  return isRecord(value) ? value : undefined;
}

function stringOrNull(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}

function numberOrZero(value: unknown): number {
  return typeof value === "number" && Number.isFinite(value) ? value : 0;
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((entry): entry is string => typeof entry === "string") : [];
}

function recordOfNumbers(value: unknown): Record<string, number> {
  if (!isRecord(value)) {
    return {};
  }

  return Object.fromEntries(
    Object.entries(value)
      .filter((entry): entry is [string, number] => typeof entry[1] === "number" && Number.isFinite(entry[1]))
      .sort(([left], [right]) => left.localeCompare(right)),
  );
}

function uniqueSorted(values: readonly string[]): string[] {
  return [...new Set(values.filter((value) => value.length > 0))].sort((left, right) => left.localeCompare(right));
}

function evidenceValue(value: unknown): JsonValue {
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "number" ||
    typeof value === "boolean" ||
    Array.isArray(value) ||
    isRecord(value)
  ) {
    return value as JsonValue;
  }

  return String(value);
}

function unwrapInput(input: unknown): ParsedSarifForReview {
  const parsed = typeof input === "string" ? parseJsonString(input) : input;
  const candidate = isRecord(parsed) && isRecord(parsed.output) ? parsed.output : parsed;

  if (!isRecord(candidate)) {
    throw new Error("review_static_analysis_results input must be an object");
  }

  const artifact = childRecord(candidate, "artifact");
  const observed = childRecord(candidate, "observed");

  if (!artifact || !observed) {
    throw new Error("review_static_analysis_results input must be parse_sarif output with artifact and observed fields");
  }

  if (artifact.type !== "sarif") {
    throw new Error("review_static_analysis_results input artifact.type must be sarif");
  }

  return {
    artifact: {
      id: stringOrNull(artifact.id) ?? undefined,
      type: stringOrNull(artifact.type) ?? undefined,
      version: stringOrNull(artifact.version),
    },
    observed,
    warnings: stringArray(candidate.warnings),
  };
}

function resultObservations(observed: ReviewRecord): StaticAnalysisReviewResultObservation[] {
  const results = Array.isArray(observed.results) ? observed.results : [];

  return results.filter(isRecord).map((result) => {
    const locations = Array.isArray(result.locations) ? result.locations : [];
    return {
      run_index: numberOrZero(result.run_index),
      result_index: numberOrZero(result.result_index),
      rule_id: stringOrNull(result.rule_id),
      level: stringOrNull(result.level),
      kind: stringOrNull(result.kind),
      baseline_state: stringOrNull(result.baseline_state),
      message_text: stringOrNull(result.message_text),
      location_count: numberOrZero(result.location_count),
      locations: locations.filter(isRecord).map((location) => ({
        uri: stringOrNull(location.uri),
        region_start_line: typeof location.region_start_line === "number" ? location.region_start_line : null,
        logical_location_names: stringArray(location.logical_location_names),
      })),
      suppression_count: numberOrZero(result.suppression_count),
      fix_count: numberOrZero(result.fix_count),
      fixes_present: result.fixes_present === true,
      taxa_ids: stringArray(result.taxa_ids),
      fingerprint_keys: stringArray(result.fingerprint_keys),
      partial_fingerprint_keys: stringArray(result.partial_fingerprint_keys),
    };
  });
}

function severityForResult(result: StaticAnalysisReviewResultObservation): Severity {
  const level = result.level?.toLowerCase() ?? "";

  if (level === "error") {
    return "high";
  }
  if (level === "warning") {
    return "medium";
  }
  if (level === "note") {
    return "low";
  }
  if (level === "none" || level === "informational") {
    return "informational";
  }

  return "low";
}

function attentionKind(result: StaticAnalysisReviewResultObservation): "high" | "medium" | "low" | "informational" | "unknown" {
  if (result.suppression_count > 0) {
    return "informational";
  }

  const severity = severityForResult(result);
  if (severity === "high" || severity === "critical") {
    return "high";
  }
  if (severity === "medium") {
    return "medium";
  }
  if (severity === "low") {
    return "low";
  }
  if (severity === "informational") {
    return "informational";
  }

  return "unknown";
}

function confidenceForResult(result: StaticAnalysisReviewResultObservation): Confidence {
  if (result.suppression_count > 0) {
    return "medium";
  }
  if (result.fingerprint_keys.length > 0 || result.partial_fingerprint_keys.length > 0) {
    return "high";
  }
  if (result.location_count > 0) {
    return "medium";
  }
  return "low";
}

function primaryLocation(result: StaticAnalysisReviewResultObservation): string | null {
  const location = result.locations[0];
  if (!location?.uri) {
    return null;
  }
  if (location.region_start_line !== null) {
    return `${location.uri}:${location.region_start_line}`;
  }
  return location.uri;
}

function createEvidenceBuilder(sourceArtifactId: string | null) {
  const evidence: EvidenceRecord[] = [];

  function addEvidence(type: string, path: string, value: unknown, description: string): string {
    const id = `evidence_static_analysis_${String(evidence.length + 1).padStart(3, "0")}`;
    evidence.push({
      id,
      type,
      artifact_ref: sourceArtifactId ?? undefined,
      path,
      value: evidenceValue(value),
      value_kind: "metadata",
      sensitivity: "medium",
      description,
    });
    return id;
  }

  return { evidence, addEvidence };
}

function addSignal(
  signals: SignalRecord[],
  input: {
    type: string;
    summary: string;
    evidenceRefs: readonly string[];
    severity: Severity;
    confidence: Confidence;
    observed: JsonObject;
    tags: readonly string[];
  },
): void {
  signals.push({
    id: `signal_static_analysis_${String(signals.length + 1).padStart(3, "0")}`,
    type: input.type,
    summary: input.summary,
    severity: input.severity,
    confidence: input.confidence,
    evidence_refs: input.evidenceRefs,
    observed: input.observed,
    tags: input.tags,
  });
}

export function reviewStaticAnalysisResults(input: unknown): StaticAnalysisReviewOutput {
  const parsed = unwrapInput(input);
  const observed = parsed.observed;
  const sourceArtifactId = stringOrNull(parsed.artifact.id);
  const { evidence, addEvidence } = createEvidenceBuilder(sourceArtifactId);
  const signals: SignalRecord[] = [];
  const warnings: string[] = [];
  const results = resultObservations(observed);

  for (const result of results) {
    const attention = attentionKind(result);
    const severity = severityForResult(result);
    const location = primaryLocation(result);
    const ruleId = result.rule_id ?? "unknown-rule";
    const evidenceRef = addEvidence(
      "static_analysis_result",
      `observed.results[${result.result_index}]`,
      {
        rule_id: result.rule_id,
        level: result.level,
        kind: result.kind,
        baseline_state: result.baseline_state,
        location,
        message_text: result.message_text,
        suppression_count: result.suppression_count,
        fixes_present: result.fixes_present,
      },
      "Parsed SARIF result selected for static-analysis triage.",
    );

    const signalType = result.suppression_count > 0
      ? "static_analysis.suppressed_result_present"
      : `static_analysis.${attention}_attention_result_present`;

    addSignal(signals, {
      type: signalType,
      summary: `Static-analysis result ${ruleId} reported${location ? ` at ${location}` : ""}.`,
      evidenceRefs: [evidenceRef],
      severity,
      confidence: confidenceForResult(result),
      observed: {
        rule_id: ruleId,
        level: result.level ?? "unknown",
        kind: result.kind ?? "unknown",
        baseline_state: result.baseline_state ?? "unknown",
        location: location ?? "unknown",
        message_text: result.message_text ?? "unknown",
        suppression_count: result.suppression_count,
        fixes_present: result.fixes_present,
      },
      tags: ["static-analysis", "sarif", attention],
    });
  }

  if ((parsed.warnings?.length ?? 0) > 0) {
    warnings.push(`Source parser emitted ${parsed.warnings?.length ?? 0} warning(s); review output preserves source_warning_count only.`);
  }

  const affectedUris = uniqueSorted(results.flatMap((result) => result.locations.map((location) => location.uri ?? "")));
  const affectedRuleIds = uniqueSorted(results.map((result) => result.rule_id ?? ""));
  const attentionCounts = results.reduce(
    (counts, result) => {
      counts[attentionKind(result)] += 1;
      return counts;
    },
    { high: 0, medium: 0, low: 0, informational: 0, unknown: 0 },
  );

  return {
    artifact: {
      id: "artifact_static_analysis_review",
      type: "static_analysis_review",
      source_artifact_id: parsed.artifact.id ?? null,
      source_artifact_type: parsed.artifact.type ?? null,
      source_format: "sarif",
      source_version: parsed.artifact.version ?? null,
    },
    observed: {
      source_parser: "parse_sarif",
      source_warning_count: parsed.warnings?.length ?? 0,
      run_count: numberOrZero(observed.run_count),
      tool_driver_names: stringArray(observed.tool_driver_names),
      rule_count: numberOrZero(observed.rule_count),
      result_count: numberOrZero(observed.result_count),
      suppressed_result_count: results.filter((result) => result.suppression_count > 0).length,
      fix_available_count: results.filter((result) => result.fixes_present).length,
      new_result_count: results.filter((result) => result.baseline_state === "new").length,
      result_levels: recordOfNumbers(observed.result_levels),
      reviewed_result_count: results.length,
      evidence_count: evidence.length,
      signal_count: signals.length,
      high_attention_result_count: attentionCounts.high,
      medium_attention_result_count: attentionCounts.medium,
      low_attention_result_count: attentionCounts.low,
      informational_result_count: attentionCounts.informational,
      unknown_attention_result_count: attentionCounts.unknown,
      affected_artifact_uris: affectedUris,
      affected_rule_ids: affectedRuleIds,
    },
    evidence,
    signals,
    warnings,
  };
}

export const reviewStaticAnalysisResultsSkill: Skill<unknown, StaticAnalysisReviewOutput> = {
  metadata: {
    name: "review_static_analysis_results",
    version: "0.1.0",
    category: "reviewer",
    description: "Review parsed SARIF static-analysis observations and emit evidence-backed local triage signals without scoring risk.",
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
        "Reviews already parsed SARIF observations from scanner output.",
        "Does not read source files, contact scanner services, perform network lookups, or decide true-positive status.",
        "Output may include repository paths, rule IDs, and scanner messages from attacker-controlled artifacts.",
      ],
    },
  },
  run: reviewStaticAnalysisResults,
};
