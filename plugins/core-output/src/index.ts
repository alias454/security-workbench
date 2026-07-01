import { generateBrowserExtensionFindingSkill } from "./generateBrowserExtensionFinding.js";
import { generateStaticAnalysisTriageSummarySkill } from "./generateStaticAnalysisTriageSummary.js";

export {
  generateBrowserExtensionFinding,
  generateBrowserExtensionFindingSkill,
} from "./generateBrowserExtensionFinding.js";
export type {
  BrowserExtensionFindingOutput,
  BrowserExtensionScoreForFinding,
} from "./generateBrowserExtensionFinding.js";
export {
  generateStaticAnalysisTriageSummary,
  generateStaticAnalysisTriageSummarySkill,
} from "./generateStaticAnalysisTriageSummary.js";
export type {
  StaticAnalysisScoreForSummary,
  StaticAnalysisTriageSummaryOutput,
} from "./generateStaticAnalysisTriageSummary.js";

export const skills = [generateBrowserExtensionFindingSkill, generateStaticAnalysisTriageSummarySkill] as const;
