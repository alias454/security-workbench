import { scoreBrowserExtensionRiskSkill } from "./scoreBrowserExtensionRisk.js";
import { scoreStaticAnalysisAttentionSkill } from "./scoreStaticAnalysisAttention.js";

export {
  scoreBrowserExtensionRisk,
  scoreBrowserExtensionRiskSkill,
} from "./scoreBrowserExtensionRisk.js";
export type {
  BrowserExtensionRiskContribution,
  BrowserExtensionRiskScoreOutput,
  ParsedBrowserExtensionPermissionReviewForScoring,
} from "./scoreBrowserExtensionRisk.js";
export {
  scoreStaticAnalysisAttention,
  scoreStaticAnalysisAttentionSkill,
} from "./scoreStaticAnalysisAttention.js";
export type {
  StaticAnalysisAttentionContribution,
  StaticAnalysisAttentionScoreOutput,
} from "./scoreStaticAnalysisAttention.js";

export const skills = [scoreBrowserExtensionRiskSkill, scoreStaticAnalysisAttentionSkill] as const;
