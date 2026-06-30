import { generateBrowserExtensionFindingSkill } from "./generateBrowserExtensionFinding.js";

export {
  generateBrowserExtensionFinding,
  generateBrowserExtensionFindingSkill,
} from "./generateBrowserExtensionFinding.js";
export type {
  BrowserExtensionFindingOutput,
  BrowserExtensionScoreForFinding,
} from "./generateBrowserExtensionFinding.js";

export const skills = [generateBrowserExtensionFindingSkill] as const;
