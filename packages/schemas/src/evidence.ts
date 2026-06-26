import type { JsonPath, JsonValue, SensitivityLevel, SourceLocation } from "./json.js";

export const evidenceValueKinds = ["raw", "redacted", "hash", "presence", "metadata"] as const;
export type EvidenceValueKind = (typeof evidenceValueKinds)[number];

export interface EvidenceRecord {
  readonly id: string;
  readonly type: string;
  readonly artifact_ref?: string;
  readonly path?: JsonPath;
  readonly location?: SourceLocation;
  readonly value?: JsonValue;
  readonly value_kind?: EvidenceValueKind;
  readonly value_redacted?: boolean;
  readonly sha256?: string;
  readonly sensitivity?: SensitivityLevel;
  readonly description?: string;
}

export function isEvidenceValueKind(value: unknown): value is EvidenceValueKind {
  return typeof value === "string" && evidenceValueKinds.includes(value as EvidenceValueKind);
}
