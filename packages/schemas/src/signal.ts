import type { JsonObject } from "./json.js";

export const severityLevels = ["informational", "low", "medium", "high", "critical"] as const;
export type SeverityLevel = (typeof severityLevels)[number];

export const confidenceLevels = ["low", "medium", "high", "confirmed", "unknown"] as const;
export type ConfidenceLevel = (typeof confidenceLevels)[number];

export interface SignalRecord {
  readonly id: string;
  readonly type: string;
  readonly summary: string;
  readonly severity?: SeverityLevel;
  readonly confidence?: ConfidenceLevel;
  readonly artifact_refs?: readonly string[];
  readonly evidence_refs: readonly string[];
  readonly observed?: JsonObject;
  readonly inferred?: JsonObject;
  readonly tags?: readonly string[];
}

export function isSeverityLevel(value: unknown): value is SeverityLevel {
  return typeof value === "string" && severityLevels.includes(value as SeverityLevel);
}

export function isConfidenceLevel(value: unknown): value is ConfidenceLevel {
  return typeof value === "string" && confidenceLevels.includes(value as ConfidenceLevel);
}
