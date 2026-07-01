import type { ConfidenceLevel, RiskAssessment, SignalRecord, Skill } from "@security-workbench/schemas";
import { localOnlyPermissions } from "./localOnlyPermissions.js";

type ScoreRecord = Record<string, unknown>;
type RiskLevel = "informational" | "low" | "medium" | "high" | "critical" | "unknown";

type StaticAnalysisSignalForScoring = Pick<SignalRecord, "id" | "type" | "summary" | "severity" | "confidence" | "evidence_refs" | "observed" | "tags">;

export interface StaticAnalysisAttentionContribution {
  readonly id: string;
  readonly category: string;
  readonly signal_ref: string;
  readonly signal_type: string;
  readonly points: number;
  readonly rationale: string;
  readonly evidence_refs: readonly string[];
}

export interface StaticAnalysisAttentionScoreOutput {
  readonly artifact: {
    readonly id: "artifact_static_analysis_attention_score";
    readonly type: "static_analysis_attention_score";
    readonly source_review_artifact_id: string | null;
    readonly source_artifact_id: string | null;
    readonly source_artifact_type: string | null;
    readonly source_format: string | null;
  };
  readonly observed: {
    readonly source_reviewer: "review_static_analysis_results";
    readonly score_model: "static_analysis_attention_v1";
    readonly score: number;
    readonly max_score: 100;
    readonly raw_score: number;
    readonly capped: boolean;
    readonly review_attention_level: "none" | "low" | "medium" | "high" | "critical";
    readonly risk_level: RiskLevel;
    readonly confidence: ConfidenceLevel;
    readonly review_signal_count: number;
    readonly review_evidence_count: number | null;
    readonly contributing_signal_count: number;
    readonly source_warning_count: number;
    readonly review_warning_count: number;
    readonly category_scores: Readonly<Record<string, number>>;
    readonly contributing_signal_types: readonly string[];
    readonly unmatched_signal_types: readonly string[];
    readonly evidence_refs: readonly string[];
  };
  readonly risk: RiskAssessment;
  readonly contributions: readonly StaticAnalysisAttentionContribution[];
  readonly limitations: readonly string[];
  readonly warnings: readonly string[];
}

interface StaticAnalysisReviewForScoring {
  readonly artifact: {
    readonly id?: string;
    readonly type?: string;
    readonly source_artifact_id?: string | null;
    readonly source_artifact_type?: string | null;
    readonly source_format?: string | null;
  };
  readonly observed: ScoreRecord;
  readonly evidence?: readonly unknown[];
  readonly signals: readonly StaticAnalysisSignalForScoring[];
  readonly warnings?: readonly string[];
}

interface ScoringRule {
  readonly signalType: string;
  readonly category: string;
  readonly points: number;
  readonly rationale: string;
}

const scoringRules: readonly ScoringRule[] = [
  {
    signalType: "static_analysis.high_attention_result_present",
    category: "result-severity",
    points: 30,
    rationale: "Scanner reported a high-attention result.",
  },
  {
    signalType: "static_analysis.medium_attention_result_present",
    category: "result-severity",
    points: 15,
    rationale: "Scanner reported a medium-attention result.",
  },
  {
    signalType: "static_analysis.low_attention_result_present",
    category: "result-severity",
    points: 5,
    rationale: "Scanner reported a low-attention result.",
  },
  {
    signalType: "static_analysis.suppressed_result_present",
    category: "suppression",
    points: 1,
    rationale: "Scanner result is suppressed and retained as informational triage context.",
  },
];

function isRecord(value: unknown): value is ScoreRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function parseJsonString(input: string): unknown {
  try {
    return JSON.parse(input) as unknown;
  } catch {
    throw new Error("score_static_analysis_attention input must be static-analysis review JSON or a JSON run result from review_static_analysis_results");
  }
}

function stringOrNull(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}

function numberOrNull(record: ScoreRecord, key: string): number | null {
  const value = record[key];
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((entry): entry is string => typeof entry === "string") : [];
}

function uniqueSorted(values: readonly string[]): string[] {
  return [...new Set(values.filter((value) => value.length > 0))].sort((left, right) => left.localeCompare(right));
}

function unwrapInput(input: unknown): StaticAnalysisReviewForScoring {
  const parsed = typeof input === "string" ? parseJsonString(input) : input;
  const candidate = isRecord(parsed) && isRecord(parsed.output) ? parsed.output : parsed;

  if (!isRecord(candidate)) {
    throw new Error("score_static_analysis_attention input must be an object");
  }

  const artifact = candidate.artifact;
  const observed = candidate.observed;

  if (!isRecord(artifact) || !isRecord(observed)) {
    throw new Error("score_static_analysis_attention input must be review_static_analysis_results output with artifact and observed fields");
  }

  if (artifact.type !== "static_analysis_review") {
    throw new Error("score_static_analysis_attention input artifact.type must be static_analysis_review");
  }

  const signals = Array.isArray(candidate.signals)
    ? candidate.signals.filter((entry): entry is StaticAnalysisSignalForScoring => isRecord(entry) && typeof entry.id === "string" && typeof entry.type === "string" && Array.isArray(entry.evidence_refs))
    : [];

  return {
    artifact: {
      id: stringOrNull(artifact.id) ?? undefined,
      type: stringOrNull(artifact.type) ?? undefined,
      source_artifact_id: stringOrNull(artifact.source_artifact_id),
      source_artifact_type: stringOrNull(artifact.source_artifact_type),
      source_format: stringOrNull(artifact.source_format),
    },
    observed,
    evidence: Array.isArray(candidate.evidence) ? candidate.evidence : [],
    signals,
    warnings: stringArray(candidate.warnings),
  };
}

function scoreForSignal(signal: StaticAnalysisSignalForScoring): ScoringRule | null {
  return scoringRules.find((rule) => rule.signalType === signal.type) ?? null;
}

function riskLevelForScore(score: number): RiskLevel {
  if (score >= 90) {
    return "critical";
  }
  if (score >= 60) {
    return "high";
  }
  if (score >= 30) {
    return "medium";
  }
  if (score > 0) {
    return "low";
  }
  return "informational";
}

function attentionLevelForScore(score: number): "none" | "low" | "medium" | "high" | "critical" {
  if (score >= 90) {
    return "critical";
  }
  if (score >= 60) {
    return "high";
  }
  if (score >= 30) {
    return "medium";
  }
  if (score > 0) {
    return "low";
  }
  return "none";
}

function confidenceForScore(warningCount: number, unmatchedSignalCount: number, signalCount: number): ConfidenceLevel {
  if (warningCount > 0) {
    return "medium";
  }
  if (signalCount === 0) {
    return "confirmed";
  }
  if (unmatchedSignalCount > 0) {
    return "medium";
  }
  return "high";
}

function categoryScores(contributions: readonly StaticAnalysisAttentionContribution[]): Record<string, number> {
  const scores: Record<string, number> = {};

  for (const contribution of contributions) {
    scores[contribution.category] = (scores[contribution.category] ?? 0) + contribution.points;
  }

  return Object.fromEntries(Object.entries(scores).sort(([left], [right]) => left.localeCompare(right)));
}

export function scoreStaticAnalysisAttention(input: unknown): StaticAnalysisAttentionScoreOutput {
  const review = unwrapInput(input);
  const warnings: string[] = [];
  const contributions: StaticAnalysisAttentionContribution[] = [];

  for (const signal of review.signals) {
    const rule = scoreForSignal(signal);
    if (!rule) {
      continue;
    }

    contributions.push({
      id: `contribution_static_analysis_${String(contributions.length + 1).padStart(3, "0")}`,
      category: rule.category,
      signal_ref: signal.id,
      signal_type: signal.type,
      points: rule.points,
      rationale: rule.rationale,
      evidence_refs: [...signal.evidence_refs],
    });
  }

  const knownSignalTypes = new Set(scoringRules.map((rule) => rule.signalType));
  const unmatchedSignalTypes = uniqueSorted(review.signals.map((signal) => signal.type).filter((type) => !knownSignalTypes.has(type)));
  const rawScore = contributions.reduce((sum, contribution) => sum + contribution.points, 0);
  const score = Math.min(rawScore, 100);
  const riskLevel = riskLevelForScore(score);
  const attentionLevel = attentionLevelForScore(score);
  const sourceWarningCount = numberOrNull(review.observed, "source_warning_count") ?? 0;
  const reviewWarningCount = review.warnings?.length ?? 0;
  const confidence = confidenceForScore(sourceWarningCount + reviewWarningCount, unmatchedSignalTypes.length, review.signals.length);
  const evidenceRefs = uniqueSorted(contributions.flatMap((contribution) => [...contribution.evidence_refs]));
  const contributingSignalTypes = uniqueSorted(contributions.map((contribution) => contribution.signal_type));
  const limitations = [
    "Score prioritizes scanner output for review attention only; it does not verify true-positive status.",
    "Source code, reachability, exploitability, asset criticality, and compensating controls were not inspected.",
    "Different scanners and SARIF producers may use levels and rule metadata inconsistently.",
  ];
  const rationale = contributions.length === 0
    ? ["No scored static-analysis review signals were present."]
    : contributions.map((contribution) => `${contribution.signal_type}: +${contribution.points} (${contribution.category})`);

  const risk: RiskAssessment = {
    score,
    level: riskLevel,
    confidence,
    rationale,
    signal_refs: contributions.map((contribution) => contribution.signal_ref),
    evidence_refs: evidenceRefs,
    limitations,
  };

  return {
    artifact: {
      id: "artifact_static_analysis_attention_score",
      type: "static_analysis_attention_score",
      source_review_artifact_id: review.artifact.id ?? null,
      source_artifact_id: review.artifact.source_artifact_id ?? null,
      source_artifact_type: review.artifact.source_artifact_type ?? null,
      source_format: review.artifact.source_format ?? null,
    },
    observed: {
      source_reviewer: "review_static_analysis_results",
      score_model: "static_analysis_attention_v1",
      score,
      max_score: 100,
      raw_score: rawScore,
      capped: rawScore > 100,
      review_attention_level: attentionLevel,
      risk_level: riskLevel,
      confidence,
      review_signal_count: review.signals.length,
      review_evidence_count: Array.isArray(review.evidence) ? review.evidence.length : null,
      contributing_signal_count: contributions.length,
      source_warning_count: sourceWarningCount,
      review_warning_count: reviewWarningCount,
      category_scores: categoryScores(contributions),
      contributing_signal_types: contributingSignalTypes,
      unmatched_signal_types: unmatchedSignalTypes,
      evidence_refs: evidenceRefs,
    },
    risk,
    contributions,
    limitations,
    warnings,
  };
}

export const scoreStaticAnalysisAttentionSkill: Skill<unknown, StaticAnalysisAttentionScoreOutput> = {
  metadata: {
    name: "score_static_analysis_attention",
    version: "0.1.0",
    category: "scoring",
    description: "Score static-analysis review signals into a deterministic review-attention assessment without enrichment or finding generation.",
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
      max_input_mb: 2,
      risk: "low",
      rationale: [
        "Scores already reviewed SARIF static-analysis signals.",
        "Does not inspect source code, contact scanner services, perform enrichment, or verify exploitability.",
        "Output is a review-attention score and must not be interpreted as a vulnerability verdict.",
      ],
    },
  },
  run: scoreStaticAnalysisAttention,
};
