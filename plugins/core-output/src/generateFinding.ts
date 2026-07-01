import type { ConfidenceLevel, FindingRecord, RiskAssessment, RiskLevel, Skill } from "@security-workbench/schemas";
import { isConfidenceLevel, isFindingStatus, isRiskLevel } from "@security-workbench/schemas";
import { localOnlyPermissions } from "./localOnlyPermissions.js";

type OutputRecord = Record<string, unknown>;

export interface GenericFindingOutput {
  readonly artifact: {
    readonly id: "artifact_generic_finding";
    readonly type: "generic_finding";
    readonly source_artifact_id: string | null;
    readonly source_artifact_type: string | null;
  };
  readonly observed: {
    readonly generator: "generate_finding";
    readonly finding_template: "generic_finding_v1";
    readonly source_kind: string;
    readonly evidence_ref_count: number;
    readonly signal_ref_count: number;
    readonly artifact_ref_count: number;
  };
  readonly finding: FindingRecord;
  readonly limitations: string[];
  readonly warnings: string[];
}

function isRecord(value: unknown): value is OutputRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function parseJsonString(input: string): unknown {
  try {
    return JSON.parse(input) as unknown;
  } catch {
    throw new Error("generate_finding input must be JSON or an object containing finding/evidence/signal/risk data");
  }
}

function unwrapInput(input: unknown): { value: unknown; sourceKind: string } {
  const parsed = typeof input === "string" ? parseJsonString(input) : input;

  if (isRecord(parsed) && "output" in parsed) {
    return {
      value: parsed.output,
      sourceKind: "skill_run_result",
    };
  }

  return {
    value: parsed,
    sourceKind: "direct_value",
  };
}

function stringOrNull(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((entry): entry is string => typeof entry === "string") : [];
}

function uniqueSorted(values: readonly string[]): string[] {
  return [...new Set(values.filter((value) => value.length > 0))].sort((left, right) => left.localeCompare(right));
}

function isFindingLike(value: unknown): value is FindingRecord {
  return isRecord(value)
    && typeof value.id === "string"
    && typeof value.title === "string"
    && typeof value.summary === "string"
    && Array.isArray(value.artifact_refs)
    && Array.isArray(value.evidence_refs);
}

function existingFinding(value: unknown): FindingRecord | undefined {
  if (isFindingLike(value)) {
    return value;
  }

  if (!isRecord(value)) {
    return undefined;
  }

  if (isFindingLike(value.finding)) {
    return value.finding;
  }

  if (Array.isArray(value.findings)) {
    return value.findings.find(isFindingLike);
  }

  return undefined;
}

function idsFromArray(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return [];
  }

  return value.flatMap((entry) => isRecord(entry) && typeof entry.id === "string" ? [entry.id] : []);
}

function riskFromValue(value: unknown): RiskAssessment | undefined {
  if (!isRecord(value)) {
    return undefined;
  }

  const risk = isRecord(value.risk) ? value.risk : undefined;
  if (!risk) {
    return undefined;
  }

  const level: RiskLevel = isRiskLevel(risk.level) ? risk.level : "unknown";
  const confidence: ConfidenceLevel | undefined = isConfidenceLevel(risk.confidence) ? risk.confidence : undefined;
  const rationale = stringArray(risk.rationale);

  return {
    score: typeof risk.score === "number" && Number.isFinite(risk.score) ? risk.score : undefined,
    level,
    confidence,
    rationale: rationale.length > 0 ? rationale : ["Risk object was present but did not include rationale entries."],
    evidence_refs: stringArray(risk.evidence_refs),
    signal_refs: stringArray(risk.signal_refs),
    limitations: stringArray(risk.limitations),
  };
}

function sourceArtifact(record: unknown): { id: string | null; type: string | null; name: string | null } {
  if (!isRecord(record)) {
    return {
      id: null,
      type: null,
      name: null,
    };
  }

  const artifact = isRecord(record.artifact) ? record.artifact : undefined;
  return {
    id: stringOrNull(artifact?.id),
    type: stringOrNull(artifact?.type),
    name: stringOrNull(artifact?.name),
  };
}

function normalizeExistingFinding(finding: FindingRecord): FindingRecord {
  return {
    ...finding,
    status: isFindingStatus(finding.status) ? finding.status : "draft",
    artifact_refs: uniqueSorted([...finding.artifact_refs]),
    evidence_refs: uniqueSorted([...finding.evidence_refs]),
    signal_refs: finding.signal_refs ? uniqueSorted([...finding.signal_refs]) : [],
  };
}

function buildGenericFinding(value: unknown): FindingRecord {
  if (!isRecord(value)) {
    throw new Error("generate_finding input must be an object or a JSON run result object");
  }

  const artifact = sourceArtifact(value);
  const risk = riskFromValue(value);
  const evidenceRefs = uniqueSorted([
    ...idsFromArray(value.evidence),
    ...(risk?.evidence_refs ?? []),
  ]);
  const signalRefs = uniqueSorted([
    ...idsFromArray(value.signals),
    ...(risk?.signal_refs ?? []),
  ]);
  const artifactRefs = uniqueSorted([artifact.id ?? ""]);
  const title = artifact.name
    ? `Security review finding: ${artifact.name}`
    : `Security review finding: ${artifact.type ?? "unknown artifact"}`;
  const riskLevel = risk?.level ?? "unknown";

  return {
    id: "finding_generic_review",
    title,
    summary: `Local analysis output produced a draft finding for ${artifact.type ?? "an unknown artifact"} with risk level ${riskLevel}.`,
    status: "draft",
    artifact_refs: artifactRefs,
    evidence_refs: evidenceRefs,
    signal_refs: signalRefs,
    risk,
    confidence: risk?.confidence ?? "unknown",
    observed_behavior: [
      `Evidence records: ${String(evidenceRefs.length)}.`,
      `Signal records: ${String(signalRefs.length)}.`,
    ],
    inferred_risk: [
      `Risk level is ${riskLevel} based on provided local analysis output.`,
    ],
    mitigations: [
      "Review the referenced evidence and signals before publishing or assigning remediation work.",
    ],
    open_questions: [
      "Which owner or system should receive this finding?",
      "Does source context confirm the inferred risk?",
    ],
  };
}

export function generateFinding(input: unknown): GenericFindingOutput {
  const { value, sourceKind } = unwrapInput(input);
  const candidate = existingFinding(value);
  const finding = candidate ? normalizeExistingFinding(candidate) : buildGenericFinding(value);
  const source = sourceArtifact(value);

  return {
    artifact: {
      id: "artifact_generic_finding",
      type: "generic_finding",
      source_artifact_id: source.id,
      source_artifact_type: source.type,
    },
    observed: {
      generator: "generate_finding",
      finding_template: "generic_finding_v1",
      source_kind: sourceKind,
      evidence_ref_count: finding.evidence_refs.length,
      signal_ref_count: finding.signal_refs?.length ?? 0,
      artifact_ref_count: finding.artifact_refs.length,
    },
    finding,
    limitations: [
      "Generic finding generation preserves provided finding data when present and otherwise creates a draft from local analysis output only.",
      "It does not verify true-positive status, assign ownership, perform enrichment, publish, or persist findings.",
    ],
    warnings: isRecord(value) ? stringArray(value.warnings) : [],
  };
}

export const generateFindingSkill: Skill<unknown, GenericFindingOutput> = {
  metadata: {
    name: "generate_finding",
    version: "0.1.0",
    category: "output",
    description: "Generate or normalize a generic draft FindingRecord from local analysis output without publishing or enrichment.",
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
        "Generates draft finding structure from local analysis output only.",
        "Does not publish findings, write tickets, persist data, or perform external enrichment.",
      ],
    },
  },
  run: generateFinding,
};
