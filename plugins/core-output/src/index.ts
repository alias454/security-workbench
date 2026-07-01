import { exportJsonSkill } from "./exportJson.js";
import { exportMarkdownSkill } from "./exportMarkdown.js";
import { generateBrowserExtensionFindingSkill } from "./generateBrowserExtensionFinding.js";
import { generateFindingSkill } from "./generateFinding.js";
import { generateStaticAnalysisTriageSummarySkill } from "./generateStaticAnalysisTriageSummary.js";

export {
  exportJson,
  exportJsonSkill,
} from "./exportJson.js";
export type { JsonExportOutput } from "./exportJson.js";
export {
  exportMarkdown,
  exportMarkdownSkill,
} from "./exportMarkdown.js";
export type { MarkdownExportOutput } from "./exportMarkdown.js";
export {
  generateBrowserExtensionFinding,
  generateBrowserExtensionFindingSkill,
} from "./generateBrowserExtensionFinding.js";
export type {
  BrowserExtensionFindingOutput,
  BrowserExtensionScoreForFinding,
} from "./generateBrowserExtensionFinding.js";
export {
  generateFinding,
  generateFindingSkill,
} from "./generateFinding.js";
export type { GenericFindingOutput } from "./generateFinding.js";
export {
  generateStaticAnalysisTriageSummary,
  generateStaticAnalysisTriageSummarySkill,
} from "./generateStaticAnalysisTriageSummary.js";
export type {
  StaticAnalysisScoreForSummary,
  StaticAnalysisTriageSummaryOutput,
} from "./generateStaticAnalysisTriageSummary.js";

export const skills = [
  generateBrowserExtensionFindingSkill,
  generateStaticAnalysisTriageSummarySkill,
  generateFindingSkill,
  exportMarkdownSkill,
  exportJsonSkill,
] as const;
