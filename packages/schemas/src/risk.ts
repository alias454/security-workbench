import type { ConfidenceLevel } from "./signal.js";

export const riskLevels = ["informational", "low", "medium", "high", "critical", "unknown"] as const;
export type RiskLevel = (typeof riskLevels)[number];

export interface RiskAssessment {
  readonly score?: number;
  readonly level: RiskLevel;
  readonly confidence?: ConfidenceLevel;
  readonly rationale: readonly string[];
  readonly signal_refs?: readonly string[];
  readonly evidence_refs?: readonly string[];
  readonly limitations?: readonly string[];
}

export function isRiskLevel(value: unknown): value is RiskLevel {
  return typeof value === "string" && riskLevels.includes(value as RiskLevel);
}
