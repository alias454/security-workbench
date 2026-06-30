import type { JsonObject, RiskAssessment, RiskLevel, SignalRecord, Skill } from "@security-workbench/schemas";
import { localOnlyPermissions } from "./localOnlyPermissions.js";

type ScoreRecord = Record<string, unknown>;
type ReviewAttentionLevel = "none" | "low" | "medium" | "high" | "very_high";
type ScoreConfidence = "high" | "medium" | "low" | "unknown";

export type ParsedBrowserExtensionPermissionReviewForScoring = {
  artifact: {
    id?: string;
    type?: string;
    source_artifact_id?: string | null;
    source_artifact_type?: string | null;
    name?: string | null;
    version?: string | null;
    manifest_version?: number | null;
  };
  observed: ScoreRecord;
  signals: SignalRecord[];
  warnings?: readonly string[];
};

export type BrowserExtensionRiskContribution = {
  id: string;
  category: string;
  signal_ref: string;
  signal_type: string;
  points: number;
  rationale: string;
  evidence_refs: string[];
};

export type BrowserExtensionRiskScoreOutput = {
  artifact: {
    id: "artifact_browser_extension_risk_score";
    type: "browser_extension_risk_score";
    source_review_artifact_id: string | null;
    source_artifact_id: string | null;
    source_artifact_type: string | null;
    name: string | null;
    version: string | null;
    manifest_version: number | null;
  };
  observed: {
    source_reviewer: "review_browser_extension_permissions";
    score_model: "browser_extension_review_attention_v1";
    score: number;
    max_score: 100;
    raw_score: number;
    capped: boolean;
    review_attention_level: ReviewAttentionLevel;
    risk_level: RiskLevel;
    confidence: ScoreConfidence;
    review_signal_count: number;
    review_evidence_count: number;
    contributing_signal_count: number;
    source_warning_count: number;
    review_warning_count: number;
    category_scores: Record<string, number>;
    contributing_signal_types: string[];
    unmatched_signal_types: string[];
    evidence_refs: string[];
  };
  risk: RiskAssessment;
  contributions: BrowserExtensionRiskContribution[];
  limitations: string[];
  warnings: string[];
};

type ScoringRule = {
  signalType: string;
  points: number;
  category: string;
  rationale: string;
};

const scoringRules: readonly ScoringRule[] = [
  {
    signalType: "browser_extension.all_urls_permission_present",
    points: 20,
    category: "host_access",
    rationale: "<all_urls> host access usually warrants focused review because it can apply across all sites.",
  },
  {
    signalType: "browser_extension.broad_host_permissions_present",
    points: 14,
    category: "host_access",
    rationale: "Broad required host permissions increase the review surface for extension behavior.",
  },
  {
    signalType: "browser_extension.broad_optional_host_permissions_present",
    points: 8,
    category: "host_access",
    rationale: "Broad optional host permissions can expand the extension surface after user approval.",
  },
  {
    signalType: "browser_extension.notable_api_permissions_present",
    points: 12,
    category: "api_permissions",
    rationale: "Notable API permissions commonly require closer permission and data-flow review.",
  },
  {
    signalType: "browser_extension.notable_optional_api_permissions_present",
    points: 5,
    category: "api_permissions",
    rationale: "Optional notable API permissions are not always active but still expand potential capability.",
  },
  {
    signalType: "browser_extension.broad_content_script_matches_present",
    points: 16,
    category: "content_scripts",
    rationale: "Broad content script matches increase the number of pages where extension code may run.",
  },
  {
    signalType: "browser_extension.background_context_present",
    points: 6,
    category: "extension_runtime",
    rationale: "A background context can maintain extension runtime behavior outside page-local content scripts.",
  },
  {
    signalType: "browser_extension.externally_connectable_present",
    points: 10,
    category: "external_connectivity",
    rationale: "externally_connectable entries expose an integration surface that warrants review.",
  },
  {
    signalType: "browser_extension.web_accessible_resources_present",
    points: 8,
    category: "web_accessible_resources",
    rationale: "Web-accessible resources expose extension packaged resources to web origins listed by the manifest.",
  },
  {
    signalType: "browser_extension.update_url_present",
    points: 4,
    category: "distribution",
    rationale: "An update_url entry affects update provenance review and extension distribution expectations.",
  },
  {
    signalType: "browser_extension.oauth2_present",
    points: 4,
    category: "identity",
    rationale: "oauth2 configuration indicates identity or authorization flows that warrant review.",
  },
  {
    signalType: "browser_extension.content_security_policy_not_observed",
    points: 6,
    category: "policy_surface",
    rationale: "No explicit content_security_policy was observed in the parsed manifest output.",
  },
] as const;

const ruleBySignalType = new Map(scoringRules.map((rule) => [rule.signalType, rule]));

const limitations = [
  "Score is a deterministic review-attention score, not a maliciousness verdict.",
  "Score uses parsed manifest review signals only; extension source code and runtime behavior are not inspected.",
  "No browser-store reputation, publisher reputation, remote host reputation, or external enrichment is performed.",
  "No extension installation, execution, or dynamic analysis is performed.",
] as const;

function isRecord(value: unknown): value is ScoreRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function stringOrNull(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}

function numberOrNull(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function numberValue(record: ScoreRecord, key: string): number {
  const value = record[key];
  return typeof value === "number" && Number.isFinite(value) ? value : 0;
}

function uniqueSorted(values: readonly string[]): string[] {
  return [...new Set(values)].sort((left, right) => left.localeCompare(right));
}

function parseJsonString(input: string): unknown {
  try {
    return JSON.parse(input) as unknown;
  } catch {
    throw new Error("score_browser_extension_risk input must be permission review JSON or a JSON run result from review_browser_extension_permissions");
  }
}

function unwrapInput(input: unknown): ParsedBrowserExtensionPermissionReviewForScoring {
  const parsed = typeof input === "string" ? parseJsonString(input) : input;
  const candidate = isRecord(parsed) && isRecord(parsed.output) ? parsed.output : parsed;

  if (!isRecord(candidate)) {
    throw new Error("score_browser_extension_risk input must be an object");
  }

  const artifact = candidate.artifact;
  const observed = candidate.observed;
  const signals = candidate.signals;

  if (!isRecord(artifact) || !isRecord(observed) || !Array.isArray(signals)) {
    throw new Error("score_browser_extension_risk input must be review_browser_extension_permissions output with artifact, observed, and signals fields");
  }

  if (artifact.type !== "browser_extension_permission_review") {
    throw new Error("score_browser_extension_risk input artifact.type must be browser_extension_permission_review");
  }

  return {
    artifact: {
      id: stringOrNull(artifact.id) ?? undefined,
      type: stringOrNull(artifact.type) ?? undefined,
      source_artifact_id: stringOrNull(artifact.source_artifact_id),
      source_artifact_type: stringOrNull(artifact.source_artifact_type),
      name: stringOrNull(artifact.name),
      version: stringOrNull(artifact.version),
      manifest_version: numberOrNull(artifact.manifest_version),
    },
    observed,
    signals: signals.filter((signal): signal is SignalRecord => isRecord(signal) && typeof signal.id === "string" && typeof signal.type === "string" && Array.isArray(signal.evidence_refs)),
    warnings: Array.isArray(candidate.warnings) ? candidate.warnings.filter((entry): entry is string => typeof entry === "string") : [],
  };
}

function riskLevelForScore(score: number): RiskLevel {
  if (score === 0) {
    return "informational";
  }

  if (score <= 20) {
    return "low";
  }

  if (score <= 50) {
    return "medium";
  }

  if (score <= 80) {
    return "high";
  }

  return "critical";
}

function attentionLevelForScore(score: number): ReviewAttentionLevel {
  if (score === 0) {
    return "none";
  }

  if (score <= 20) {
    return "low";
  }

  if (score <= 50) {
    return "medium";
  }

  if (score <= 80) {
    return "high";
  }

  return "very_high";
}

function confidenceForScore(sourceWarningCount: number, unmatchedSignalCount: number): ScoreConfidence {
  if (sourceWarningCount > 0) {
    return "medium";
  }

  if (unmatchedSignalCount > 0) {
    return "medium";
  }

  return "high";
}

function addCategoryScore(scores: Record<string, number>, category: string, points: number): void {
  scores[category] = (scores[category] ?? 0) + points;
}

export function scoreBrowserExtensionRisk(input: unknown): BrowserExtensionRiskScoreOutput {
  const review = unwrapInput(input);
  const sourceWarningCount = numberValue(review.observed, "source_warning_count");
  const reviewWarningCount = review.warnings?.length ?? 0;
  const categoryScores: Record<string, number> = {};
  const usedSignalTypes = new Set<string>();
  const contributions: BrowserExtensionRiskContribution[] = [];

  for (const signal of review.signals) {
    if (usedSignalTypes.has(signal.type)) {
      continue;
    }

    const rule = ruleBySignalType.get(signal.type);
    if (!rule) {
      continue;
    }

    usedSignalTypes.add(signal.type);
    addCategoryScore(categoryScores, rule.category, rule.points);

    contributions.push({
      id: `contribution_browser_extension_${String(contributions.length + 1).padStart(3, "0")}`,
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
  const confidence = confidenceForScore(sourceWarningCount + reviewWarningCount, unmatchedSignalTypes.length);
  const evidenceRefs = uniqueSorted(contributions.flatMap((contribution) => contribution.evidence_refs));
  const contributingSignalTypes = uniqueSorted(contributions.map((contribution) => contribution.signal_type));
  const warnings: string[] = [];

  if (sourceWarningCount > 0 || reviewWarningCount > 0) {
    warnings.push("Source review or parser warnings were present; score confidence was reduced to medium.");
  }

  if (unmatchedSignalTypes.length > 0) {
    warnings.push(`Unmodeled review signal type(s) were observed and not scored: ${unmatchedSignalTypes.join(", ")}.`);
  }

  const rationale = contributions.length === 0
    ? ["No scored browser extension review signals were present."]
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
      id: "artifact_browser_extension_risk_score",
      type: "browser_extension_risk_score",
      source_review_artifact_id: review.artifact.id ?? null,
      source_artifact_id: review.artifact.source_artifact_id ?? null,
      source_artifact_type: review.artifact.source_artifact_type ?? null,
      name: review.artifact.name ?? null,
      version: review.artifact.version ?? null,
      manifest_version: review.artifact.manifest_version ?? null,
    },
    observed: {
      source_reviewer: "review_browser_extension_permissions",
      score_model: "browser_extension_review_attention_v1",
      score,
      max_score: 100,
      raw_score: rawScore,
      capped: rawScore > 100,
      review_attention_level: attentionLevel,
      risk_level: riskLevel,
      confidence,
      review_signal_count: review.signals.length,
      review_evidence_count: numberValue(review.observed, "evidence_count"),
      contributing_signal_count: contributions.length,
      source_warning_count: sourceWarningCount,
      review_warning_count: reviewWarningCount,
      category_scores: categoryScores,
      contributing_signal_types: contributingSignalTypes,
      unmatched_signal_types: unmatchedSignalTypes,
      evidence_refs: evidenceRefs,
    },
    risk,
    contributions,
    limitations: [...limitations],
    warnings,
  };
}

export const scoreBrowserExtensionRiskSkill: Skill<unknown, BrowserExtensionRiskScoreOutput> = {
  metadata: {
    name: "score_browser_extension_risk",
    version: "0.1.0",
    category: "scoring",
    description: "Score browser extension permission review signals into a deterministic review-attention risk assessment without enrichment or finding generation.",
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
      max_input_mb: 1,
      risk: "low",
      rationale: [
        "Scores already reviewed browser extension permission signals.",
        "Does not install extensions, execute extension code, contact browser stores, or perform network lookups.",
        "Output is a review-attention score and must not be interpreted as a maliciousness verdict.",
      ],
    },
  },
  run: scoreBrowserExtensionRisk,
};
