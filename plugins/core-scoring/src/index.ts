import { scoreBrowserExtensionRiskSkill } from "./scoreBrowserExtensionRisk.js";

export {
  scoreBrowserExtensionRisk,
  scoreBrowserExtensionRiskSkill,
} from "./scoreBrowserExtensionRisk.js";
export type {
  BrowserExtensionRiskContribution,
  BrowserExtensionRiskScoreOutput,
  ParsedBrowserExtensionPermissionReviewForScoring,
} from "./scoreBrowserExtensionRisk.js";

export const skills = [scoreBrowserExtensionRiskSkill] as const;
