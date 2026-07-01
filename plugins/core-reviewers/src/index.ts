import { reviewBrowserExtensionPermissionsSkill } from "./reviewBrowserExtensionPermissions.js";
import { reviewStaticAnalysisResultsSkill } from "./reviewStaticAnalysisResults.js";

export {
  reviewBrowserExtensionPermissions,
  reviewBrowserExtensionPermissionsSkill,
} from "./reviewBrowserExtensionPermissions.js";
export type {
  BrowserExtensionPermissionReviewEvidence,
  BrowserExtensionPermissionReviewOutput,
  BrowserExtensionPermissionReviewSignal,
  ParsedBrowserExtensionManifestForReview,
} from "./reviewBrowserExtensionPermissions.js";
export {
  reviewStaticAnalysisResults,
  reviewStaticAnalysisResultsSkill,
} from "./reviewStaticAnalysisResults.js";
export type {
  StaticAnalysisReviewOutput,
  StaticAnalysisReviewResultObservation,
} from "./reviewStaticAnalysisResults.js";

export const skills = [reviewBrowserExtensionPermissionsSkill, reviewStaticAnalysisResultsSkill] as const;
