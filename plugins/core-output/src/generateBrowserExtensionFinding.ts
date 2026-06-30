import type { ConfidenceLevel, FindingRecord, RiskAssessment, Skill } from "@security-workbench/schemas";
import { localOnlyPermissions } from "./localOnlyPermissions.js";

type OutputRecord = Record<string, unknown>;

type BrowserExtensionContributionForFinding = {
  id?: string;
  category?: string;
  signal_ref?: string;
  signal_type?: string;
  points?: number;
  rationale?: string;
  evidence_refs?: readonly string[];
};

export type BrowserExtensionScoreForFinding = {
  artifact: {
    id?: string;
    type?: string;
    source_review_artifact_id?: string | null;
    source_artifact_id?: string | null;
    source_artifact_type?: string | null;
    name?: string | null;
    version?: string | null;
    manifest_version?: number | null;
  };
  observed: OutputRecord;
  risk?: RiskAssessment;
  contributions: readonly BrowserExtensionContributionForFinding[];
  limitations: readonly string[];
  warnings: readonly string[];
};

export type BrowserExtensionFindingOutput = {
  artifact: {
    id: "artifact_browser_extension_finding";
    type: "browser_extension_finding";
    source_score_artifact_id: string | null;
    source_review_artifact_id: string | null;
    source_artifact_id: string | null;
    source_artifact_type: string | null;
    name: string | null;
    version: string | null;
    manifest_version: number | null;
  };
  observed: {
    source_scorer: "score_browser_extension_risk";
    source_score_model: string | null;
    finding_template: "browser_extension_permission_review_v1";
    score: number | null;
    max_score: number | null;
    review_attention_level: string | null;
    risk_level: string | null;
    confidence: ConfidenceLevel;
    contribution_count: number;
    evidence_ref_count: number;
    signal_ref_count: number;
    limitation_count: number;
    markdown_line_count: number;
  };
  finding: FindingRecord;
  markdown: string;
  limitations: string[];
  warnings: string[];
};

function isRecord(value: unknown): value is OutputRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function parseJsonString(input: string): unknown {
  try {
    return JSON.parse(input) as unknown;
  } catch {
    throw new Error("generate_browser_extension_finding input must be browser extension score JSON or a JSON run result from score_browser_extension_risk");
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
  if (!Array.isArray(value)) {
    return [];
  }

  return value.filter((entry): entry is string => typeof entry === "string");
}

function uniqueSorted(values: readonly string[]): string[] {
  return [...new Set(values)].sort((left, right) => left.localeCompare(right));
}

function unwrapInput(input: unknown): BrowserExtensionScoreForFinding {
  const parsed = typeof input === "string" ? parseJsonString(input) : input;
  const candidate = isRecord(parsed) && isRecord(parsed.output) ? parsed.output : parsed;

  if (!isRecord(candidate)) {
    throw new Error("generate_browser_extension_finding input must be an object");
  }

  const artifact = candidate.artifact;
  const observed = candidate.observed;

  if (!isRecord(artifact) || !isRecord(observed)) {
    throw new Error("generate_browser_extension_finding input must be score_browser_extension_risk output with artifact and observed fields");
  }

  if (artifact.type !== "browser_extension_risk_score") {
    throw new Error("generate_browser_extension_finding input artifact.type must be browser_extension_risk_score");
  }

  const risk = isRecord(candidate.risk) ? (candidate.risk as unknown as RiskAssessment) : undefined;
  const contributions = Array.isArray(candidate.contributions)
    ? candidate.contributions.filter((entry): entry is BrowserExtensionContributionForFinding => isRecord(entry))
    : [];

  return {
    artifact: {
      id: stringOrNull(artifact.id) ?? undefined,
      type: stringOrNull(artifact.type) ?? undefined,
      source_review_artifact_id: stringOrNull(artifact.source_review_artifact_id),
      source_artifact_id: stringOrNull(artifact.source_artifact_id),
      source_artifact_type: stringOrNull(artifact.source_artifact_type),
      name: stringOrNull(artifact.name),
      version: stringOrNull(artifact.version),
      manifest_version: numberOrNull(artifact.manifest_version),
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

function contributionSummary(contribution: BrowserExtensionContributionForFinding): string {
  const signalType = markdownValue(contribution.signal_type ?? "unknown");
  const points = typeof contribution.points === "number" ? String(contribution.points) : "unknown";
  const category = markdownValue(contribution.category ?? "unknown");
  const rationale = markdownValue(contribution.rationale ?? "No rationale provided.");
  return `- ${signalType}: +${points} (${category}) — ${rationale}`;
}

function openQuestionsForScore(score: number | null, contributions: readonly BrowserExtensionContributionForFinding[]): string[] {
  const questions = [
    "Is each declared permission required for the extension's documented purpose?",
    "Do content scripts and host permissions align with the intended browser surface?",
    "Has extension source code been reviewed for data collection, messaging, and remote update behavior?",
  ];

  if (score !== null && score > 50) {
    questions.push("Should broad permission grants be reduced or moved behind optional user approval?");
  }

  if (contributions.some((contribution) => contribution.signal_type === "browser_extension.externally_connectable_present")) {
    questions.push("Are externally_connectable origins or extension IDs intentionally scoped and documented?");
  }

  return questions;
}

function detectionOpportunities(contributions: readonly BrowserExtensionContributionForFinding[]): string[] {
  const opportunities = [
    "Track manifest permission changes during extension updates.",
    "Review broad host access and content script changes before approval.",
  ];

  if (contributions.some((contribution) => contribution.signal_type === "browser_extension.update_url_present")) {
    opportunities.push("Monitor update_url provenance and unexpected distribution changes.");
  }

  if (contributions.some((contribution) => contribution.signal_type === "browser_extension.oauth2_present")) {
    opportunities.push("Review OAuth client scopes, redirect behavior, and token handling during source review.");
  }

  return opportunities;
}

function mitigationsForScore(score: number | null): string[] {
  const mitigations = [
    "Validate that declared permissions are required and least-privilege for the extension purpose.",
    "Review extension source code before relying on manifest-only observations.",
  ];

  if (score !== null && score > 50) {
    mitigations.push("Consider reducing broad host access, broad content script matches, or optionalizing sensitive capabilities where possible.");
  }

  return mitigations;
}

function renderMarkdown(input: {
  title: string;
  finding: FindingRecord;
  score: number | null;
  maxScore: number | null;
  reviewAttentionLevel: string | null;
  contributions: readonly BrowserExtensionContributionForFinding[];
  limitations: readonly string[];
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
    ...(input.contributions.length > 0 ? input.contributions.map(contributionSummary) : ["- No scored review signals were present."]),
    "",
    "## Recommended review actions",
    "",
    ...(input.finding.mitigations?.map((entry) => `- ${markdownEscape(entry)}`) ?? ["- none"]),
    "",
    "## Open questions",
    "",
    ...(input.finding.open_questions?.map((entry) => `- ${markdownEscape(entry)}`) ?? ["- none"]),
    "",
    "## Limitations",
    "",
    ...(input.limitations.length > 0 ? input.limitations.map((entry) => `- ${markdownEscape(entry)}`) : ["- none"]),
  ];

  return lines.join("\n");
}

export function generateBrowserExtensionFinding(input: unknown): BrowserExtensionFindingOutput {
  const scoreOutput = unwrapInput(input);
  const observed = scoreOutput.observed;
  const risk = scoreOutput.risk;
  const score = numberOrNull(observed.score);
  const maxScore = numberOrNull(observed.max_score);
  const reviewAttentionLevel = stringOrNull(observed.review_attention_level);
  const scoreModel = stringOrNull(observed.score_model);
  const riskLevel = stringOrNull(observed.risk_level) ?? risk?.level ?? null;
  const confidence = confidenceOrUnknown(observed.confidence ?? risk?.confidence);
  const contributionSignalRefs = uniqueSorted(scoreOutput.contributions.map((contribution) => contribution.signal_ref).filter((value): value is string => typeof value === "string"));
  const contributionEvidenceRefs = uniqueSorted(scoreOutput.contributions.flatMap((contribution) => stringArray(contribution.evidence_refs)));
  const evidenceRefs = uniqueSorted([...(risk?.evidence_refs ?? []), ...contributionEvidenceRefs]);
  const sourceArtifactId = scoreOutput.artifact.source_artifact_id ?? null;
  const artifactRefs = uniqueSorted([sourceArtifactId, scoreOutput.artifact.source_review_artifact_id ?? null, scoreOutput.artifact.id ?? null].filter((value): value is string => typeof value === "string" && value.length > 0));
  const displayName = scoreOutput.artifact.name ?? "Browser extension";
  const title = `Browser extension permission review: ${displayName}`;
  const scoreText = score === null ? "unknown" : String(score);
  const maxScoreText = maxScore === null ? "unknown" : String(maxScore);

  const observedBehavior = [
    `Reviewer produced ${String(observed.review_signal_count ?? "unknown")} permission or exposure signal(s).`,
    `Scorer produced ${String(scoreOutput.contributions.length)} scored contribution(s).`,
    `Review-attention score is ${scoreText}/${maxScoreText}.`,
  ];

  const inferredRisk = [
    `Deterministic review-attention level is ${reviewAttentionLevel ?? "unknown"}.`,
    `Risk level is ${riskLevel ?? "unknown"} based on manifest-derived review signals only.`,
  ];

  const finding: FindingRecord = {
    id: "finding_browser_extension_permission_review",
    title,
    summary: `Browser extension manifest review produced a ${reviewAttentionLevel ?? "unknown"} review-attention level with score ${scoreText}/${maxScoreText}.`,
    status: "draft",
    artifact_refs: artifactRefs,
    evidence_refs: evidenceRefs,
    signal_refs: contributionSignalRefs,
    risk,
    confidence,
    observed_behavior: observedBehavior,
    inferred_risk: inferredRisk,
    detection_opportunities: detectionOpportunities(scoreOutput.contributions),
    mitigations: mitigationsForScore(score),
    open_questions: openQuestionsForScore(score, scoreOutput.contributions),
  };

  const limitations = scoreOutput.limitations.length > 0
    ? [...scoreOutput.limitations]
    : [
        "Finding is generated from parsed manifest, reviewer, and scorer outputs only.",
        "Extension source code, runtime behavior, publisher reputation, and browser-store context were not inspected.",
      ];

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
      id: "artifact_browser_extension_finding",
      type: "browser_extension_finding",
      source_score_artifact_id: scoreOutput.artifact.id ?? null,
      source_review_artifact_id: scoreOutput.artifact.source_review_artifact_id ?? null,
      source_artifact_id: sourceArtifactId,
      source_artifact_type: scoreOutput.artifact.source_artifact_type ?? null,
      name: scoreOutput.artifact.name ?? null,
      version: scoreOutput.artifact.version ?? null,
      manifest_version: scoreOutput.artifact.manifest_version ?? null,
    },
    observed: {
      source_scorer: "score_browser_extension_risk",
      source_score_model: scoreModel,
      finding_template: "browser_extension_permission_review_v1",
      score,
      max_score: maxScore,
      review_attention_level: reviewAttentionLevel,
      risk_level: riskLevel,
      confidence,
      contribution_count: scoreOutput.contributions.length,
      evidence_ref_count: evidenceRefs.length,
      signal_ref_count: contributionSignalRefs.length,
      limitation_count: limitations.length,
      markdown_line_count: markdown.split("\n").length,
    },
    finding,
    markdown,
    limitations,
    warnings: [...(scoreOutput.warnings ?? [])],
  };
}

export const generateBrowserExtensionFindingSkill: Skill<unknown, BrowserExtensionFindingOutput> = {
  metadata: {
    name: "generate_browser_extension_finding",
    version: "0.1.0",
    category: "output",
    description: "Generate a draft browser extension permission finding and Markdown summary from deterministic browser extension score output.",
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
        "Generates finding output from already scored browser extension review data.",
        "Does not inspect extension source code, install extensions, contact browser stores, or perform network lookups.",
        "Markdown output is generated from attacker-controlled artifact metadata and must be escaped by renderers and agents.",
      ],
    },
  },
  run: generateBrowserExtensionFinding,
};
