import type { ConfidenceLevel, FindingRecord, RiskAssessment, Skill } from "@security-workbench/schemas";
import { localOnlyPermissions } from "./localOnlyPermissions.js";

type OutputRecord = Record<string, unknown>;

type StaticAnalysisContributionForSummary = {
  readonly id?: string;
  readonly category?: string;
  readonly signal_ref?: string;
  readonly signal_type?: string;
  readonly points?: number;
  readonly rationale?: string;
  readonly evidence_refs?: readonly string[];
};

export interface StaticAnalysisScoreForSummary {
  readonly artifact: {
    readonly id?: string;
    readonly type?: string;
    readonly source_review_artifact_id?: string | null;
    readonly source_artifact_id?: string | null;
    readonly source_artifact_type?: string | null;
    readonly source_format?: string | null;
  };
  readonly observed: OutputRecord;
  readonly risk?: RiskAssessment;
  readonly contributions: readonly StaticAnalysisContributionForSummary[];
  readonly limitations: readonly string[];
  readonly warnings: readonly string[];
}

export interface StaticAnalysisTriageSummaryOutput {
  readonly artifact: {
    readonly id: "artifact_static_analysis_triage_summary";
    readonly type: "static_analysis_triage_summary";
    readonly source_score_artifact_id: string | null;
    readonly source_review_artifact_id: string | null;
    readonly source_artifact_id: string | null;
    readonly source_artifact_type: string | null;
    readonly source_format: string | null;
  };
  readonly observed: {
    readonly source_scorer: "score_static_analysis_attention";
    readonly source_score_model: string | null;
    readonly summary_template: "static_analysis_triage_summary_v1";
    readonly score: number | null;
    readonly max_score: number | null;
    readonly review_attention_level: string | null;
    readonly risk_level: string | null;
    readonly confidence: ConfidenceLevel;
    readonly contribution_count: number;
    readonly evidence_ref_count: number;
    readonly signal_ref_count: number;
    readonly limitation_count: number;
    readonly markdown_line_count: number;
  };
  readonly finding: FindingRecord;
  readonly markdown: string;
  readonly limitations: readonly string[];
  readonly warnings: readonly string[];
}

function isRecord(value: unknown): value is OutputRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function parseJsonString(input: string): unknown {
  try {
    return JSON.parse(input) as unknown;
  } catch {
    throw new Error("generate_static_analysis_triage_summary input must be static-analysis score JSON or a JSON run result from score_static_analysis_attention");
  }
}

function stringOrNull(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}

function numberOrNull(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function confidenceOrUnknown(value: unknown): ConfidenceLevel {
  if (value === "low" || value === "medium" || value === "high" || value === "confirmed" || value === "unknown") {
    return value;
  }

  return "unknown";
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((entry): entry is string => typeof entry === "string") : [];
}

function uniqueSorted(values: readonly string[]): string[] {
  return [...new Set(values.filter((value) => value.length > 0))].sort((left, right) => left.localeCompare(right));
}

function unwrapInput(input: unknown): StaticAnalysisScoreForSummary {
  const parsed = typeof input === "string" ? parseJsonString(input) : input;
  const candidate = isRecord(parsed) && isRecord(parsed.output) ? parsed.output : parsed;

  if (!isRecord(candidate)) {
    throw new Error("generate_static_analysis_triage_summary input must be an object");
  }

  const artifact = candidate.artifact;
  const observed = candidate.observed;

  if (!isRecord(artifact) || !isRecord(observed)) {
    throw new Error("generate_static_analysis_triage_summary input must be score_static_analysis_attention output with artifact and observed fields");
  }

  if (artifact.type !== "static_analysis_attention_score") {
    throw new Error("generate_static_analysis_triage_summary input artifact.type must be static_analysis_attention_score");
  }

  const risk = isRecord(candidate.risk) ? (candidate.risk as unknown as RiskAssessment) : undefined;
  const contributions = Array.isArray(candidate.contributions)
    ? candidate.contributions.filter((entry): entry is StaticAnalysisContributionForSummary => isRecord(entry))
    : [];

  return {
    artifact: {
      id: stringOrNull(artifact.id) ?? undefined,
      type: stringOrNull(artifact.type) ?? undefined,
      source_review_artifact_id: stringOrNull(artifact.source_review_artifact_id),
      source_artifact_id: stringOrNull(artifact.source_artifact_id),
      source_artifact_type: stringOrNull(artifact.source_artifact_type),
      source_format: stringOrNull(artifact.source_format),
    },
    observed,
    risk,
    contributions,
    limitations: stringArray(candidate.limitations),
    warnings: stringArray(candidate.warnings),
  };
}

function markdownEscape(value: string): string {
  return value.replace(/[\\`*_{}[\]()#+.!|-]/g, "\\$&");
}

function markdownValue(value: string | null | undefined): string {
  if (!value || value.trim().length === 0) {
    return "unknown";
  }

  return markdownEscape(value);
}

function contributionSummary(contribution: StaticAnalysisContributionForSummary): string {
  const signalType = markdownValue(contribution.signal_type ?? "unknown");
  const points = typeof contribution.points === "number" ? String(contribution.points) : "unknown";
  const category = markdownValue(contribution.category ?? "unknown");
  const rationale = markdownValue(contribution.rationale ?? "No rationale provided.");
  return `- ${signalType}: +${points} (${category}) — ${rationale}`;
}

function openQuestions(score: number | null): string[] {
  const questions = [
    "Which findings are reachable in production or exposed deployment paths?",
    "Which findings affect internet-facing, privileged, or sensitive-data-handling code?",
    "Which findings are known false positives, accepted risk, or already tracked elsewhere?",
  ];

  if (score !== null && score >= 60) {
    questions.push("Should any high-attention findings block release until reviewed by the owning team?");
  }

  return questions;
}

function mitigations(score: number | null): string[] {
  const actions = [
    "Deduplicate findings by rule, location, fingerprint, and ownership before assigning remediation work.",
    "Validate high-attention scanner results against source context before treating them as confirmed vulnerabilities.",
  ];

  if (score !== null && score >= 30) {
    actions.push("Route high and medium attention findings to the owning service or application team for triage.");
  }

  return actions;
}

function detectionOpportunities(): string[] {
  return [
    "Track repeated static-analysis rules across pull requests and releases.",
    "Monitor newly introduced findings separately from pre-existing baseline findings.",
    "Preserve scanner fingerprints so suppressions and deduplication decisions can be reviewed later.",
  ];
}

function renderMarkdown(input: {
  readonly title: string;
  readonly finding: FindingRecord;
  readonly score: number | null;
  readonly maxScore: number | null;
  readonly reviewAttentionLevel: string | null;
  readonly contributions: readonly StaticAnalysisContributionForSummary[];
  readonly limitations: readonly string[];
}): string {
  const lines = [
    `# ${markdownEscape(input.title)}`,
    "",
    "## Summary",
    "",
    markdownEscape(input.finding.summary),
    "",
    "## Assessment",
    "",
    `- Score: ${input.score === null ? "unknown" : String(input.score)}/${input.maxScore === null ? "unknown" : String(input.maxScore)}`,
    `- Review attention: ${markdownValue(input.reviewAttentionLevel)}`,
    `- Risk level: ${markdownValue(input.finding.risk?.level ?? "unknown")}`,
    `- Confidence: ${markdownValue(input.finding.confidence ?? "unknown")}`,
    "",
    "## Observed behavior",
    "",
    ...(input.finding.observed_behavior?.map((entry) => `- ${markdownEscape(entry)}`) ?? ["- none"]),
    "",
    "## Inferred risk",
    "",
    ...(input.finding.inferred_risk?.map((entry) => `- ${markdownEscape(entry)}`) ?? ["- none"]),
    "",
    "## Score contributions",
    "",
    ...(input.contributions.length > 0 ? input.contributions.map(contributionSummary) : ["- No scored static-analysis review signals were present."]),
    "",
    "## Recommended triage actions",
    "",
    ...(input.finding.mitigations?.map((entry) => `- ${markdownEscape(entry)}`) ?? ["- none"]),
    "",
    "## Open questions",
    "",
    ...(input.finding.open_questions?.map((entry) => `- ${markdownEscape(entry)}`) ?? ["- none"]),
    "",
    "## Detection opportunities",
    "",
    ...(input.finding.detection_opportunities?.map((entry) => `- ${markdownEscape(entry)}`) ?? ["- none"]),
    "",
    "## Limitations",
    "",
    ...(input.limitations.map((entry) => `- ${markdownEscape(entry)}`)),
  ];

  return lines.join("\n");
}

export function generateStaticAnalysisTriageSummary(input: unknown): StaticAnalysisTriageSummaryOutput {
  const scoreOutput = unwrapInput(input);
  const score = numberOrNull(scoreOutput.observed.score);
  const maxScore = numberOrNull(scoreOutput.observed.max_score);
  const reviewAttentionLevel = stringOrNull(scoreOutput.observed.review_attention_level);
  const riskLevel = stringOrNull(scoreOutput.observed.risk_level) ?? scoreOutput.risk?.level ?? "unknown";
  const confidence = confidenceOrUnknown(scoreOutput.observed.confidence ?? scoreOutput.risk?.confidence);
  const sourceArtifactId = scoreOutput.artifact.source_artifact_id ?? null;
  const sourceFormat = scoreOutput.artifact.source_format ?? null;
  const scoreModel = stringOrNull(scoreOutput.observed.score_model);
  const evidenceRefs = uniqueSorted(scoreOutput.contributions.flatMap((contribution) => [...(contribution.evidence_refs ?? [])]));
  const signalRefs = uniqueSorted(scoreOutput.contributions.map((contribution) => contribution.signal_ref ?? ""));
  const limitations = scoreOutput.limitations.length > 0
    ? [...scoreOutput.limitations]
    : [
        "Summary is generated from parsed SARIF review and scoring outputs only.",
        "Source code, scanner configuration, ownership, asset criticality, and exploitability were not inspected.",
      ];
  const title = "Static-analysis triage summary";
  const observedBehavior = [
    `Static-analysis score model ${scoreModel ?? "unknown"} produced score ${score === null ? "unknown" : String(score)} of ${maxScore === null ? "unknown" : String(maxScore)}.`,
    `Review attention level is ${reviewAttentionLevel ?? "unknown"}.`,
    `Scored contribution count is ${scoreOutput.contributions.length}.`,
  ];
  const inferredRisk = [
    "Static-analysis findings may represent security defects requiring owner triage.",
    "Scanner severity and confidence should be validated against source context before remediation prioritization.",
  ];
  const finding: FindingRecord = {
    id: "finding_static_analysis_triage_summary",
    title,
    summary: `Static-analysis output produced ${reviewAttentionLevel ?? "unknown"} review attention with score ${score === null ? "unknown" : String(score)} of ${maxScore === null ? "unknown" : String(maxScore)}.`,
    status: "draft",
    artifact_refs: uniqueSorted([sourceArtifactId ?? "", scoreOutput.artifact.source_review_artifact_id ?? "", scoreOutput.artifact.id ?? ""]),
    evidence_refs: evidenceRefs,
    signal_refs: signalRefs,
    risk: scoreOutput.risk ?? {
      score: score ?? undefined,
      level: riskLevel === "informational" || riskLevel === "low" || riskLevel === "medium" || riskLevel === "high" || riskLevel === "critical" ? riskLevel : "unknown",
      confidence,
      rationale: ["No risk assessment object was provided by score_static_analysis_attention."],
      evidence_refs: evidenceRefs,
      signal_refs: signalRefs,
      limitations,
    },
    confidence,
    observed_behavior: observedBehavior,
    inferred_risk: inferredRisk,
    affected_users_or_systems: ["Source artifacts represented in the static-analysis output."],
    detection_opportunities: detectionOpportunities(),
    mitigations: mitigations(score),
    open_questions: openQuestions(score),
  };
  const markdown = renderMarkdown({
    title,
    finding,
    score,
    maxScore,
    reviewAttentionLevel,
    contributions: scoreOutput.contributions,
    limitations,
  });

  return {
    artifact: {
      id: "artifact_static_analysis_triage_summary",
      type: "static_analysis_triage_summary",
      source_score_artifact_id: scoreOutput.artifact.id ?? null,
      source_review_artifact_id: scoreOutput.artifact.source_review_artifact_id ?? null,
      source_artifact_id: sourceArtifactId,
      source_artifact_type: scoreOutput.artifact.source_artifact_type ?? null,
      source_format: sourceFormat,
    },
    observed: {
      source_scorer: "score_static_analysis_attention",
      source_score_model: scoreModel,
      summary_template: "static_analysis_triage_summary_v1",
      score,
      max_score: maxScore,
      review_attention_level: reviewAttentionLevel,
      risk_level: riskLevel,
      confidence,
      contribution_count: scoreOutput.contributions.length,
      evidence_ref_count: evidenceRefs.length,
      signal_ref_count: signalRefs.length,
      limitation_count: limitations.length,
      markdown_line_count: markdown.split("\n").length,
    },
    finding,
    markdown,
    limitations,
    warnings: [...scoreOutput.warnings],
  };
}

export const generateStaticAnalysisTriageSummarySkill: Skill<unknown, StaticAnalysisTriageSummaryOutput> = {
  metadata: {
    name: "generate_static_analysis_triage_summary",
    version: "0.1.0",
    category: "output",
    description: "Generate a draft static-analysis triage finding and Markdown summary from deterministic static-analysis attention scoring output.",
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
      risk: "medium",
      rationale: [
        "Generates triage output from already scored SARIF static-analysis review data.",
        "Does not inspect source code, contact scanner services, perform enrichment, or publish findings externally.",
        "Markdown output is generated from attacker-controlled scanner metadata and must be escaped by renderers and agents.",
      ],
    },
  },
  run: generateStaticAnalysisTriageSummary,
};
