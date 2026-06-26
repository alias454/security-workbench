import type { RiskAssessment } from "./risk.js";
import type { ConfidenceLevel } from "./signal.js";

export const findingStatuses = ["draft", "reviewed", "published", "suppressed"] as const;
export type FindingStatus = (typeof findingStatuses)[number];

export interface FindingRecord {
  readonly id: string;
  readonly title: string;
  readonly summary: string;
  readonly status?: FindingStatus;
  readonly artifact_refs: readonly string[];
  readonly evidence_refs: readonly string[];
  readonly signal_refs?: readonly string[];
  readonly risk?: RiskAssessment;
  readonly confidence?: ConfidenceLevel;
  readonly observed_behavior?: readonly string[];
  readonly inferred_risk?: readonly string[];
  readonly affected_users_or_systems?: readonly string[];
  readonly detection_opportunities?: readonly string[];
  readonly mitigations?: readonly string[];
  readonly open_questions?: readonly string[];
}

export function isFindingStatus(value: unknown): value is FindingStatus {
  return typeof value === "string" && findingStatuses.includes(value as FindingStatus);
}
