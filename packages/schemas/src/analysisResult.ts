import type { ArtifactSummary } from "./artifact.js";
import type { EvidenceRecord } from "./evidence.js";
import type { FindingRecord } from "./finding.js";
import type { StructuredParseError } from "./parseError.js";
import type { RiskAssessment } from "./risk.js";
import type { SignalRecord } from "./signal.js";

export interface AnalysisResult {
  readonly artifact?: ArtifactSummary;
  readonly artifacts?: readonly ArtifactSummary[];
  readonly evidence?: readonly EvidenceRecord[];
  readonly signals?: readonly SignalRecord[];
  readonly risk?: RiskAssessment;
  readonly finding?: FindingRecord;
  readonly findings?: readonly FindingRecord[];
  readonly parse_errors?: readonly StructuredParseError[];
  readonly warnings?: readonly string[];
}
