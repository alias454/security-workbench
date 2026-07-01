import { reviewBrowserExtensionPermissionsSkill } from "./reviewBrowserExtensionPermissions.js";
import { reviewStaticAnalysisResultsSkill } from "./reviewStaticAnalysisResults.js";
import { reviewCertificateSkill } from "./reviewCertificate.js";
import { reviewJwtSkill } from "./reviewJwt.js";

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
export { reviewCertificate, reviewCertificateSkill } from "./reviewCertificate.js";
export { reviewJwt, reviewJwtSkill } from "./reviewJwt.js";
export type {
  StaticAnalysisReviewOutput,
  StaticAnalysisReviewResultObservation,
} from "./reviewStaticAnalysisResults.js";
export type {
  CertificateReviewCertificateObservation,
  CertificateReviewOutput,
} from "./reviewCertificate.js";
export type { JwtReviewOutput } from "./reviewJwt.js";

export const skills = [
  reviewBrowserExtensionPermissionsSkill,
  reviewStaticAnalysisResultsSkill,
  reviewCertificateSkill,
  reviewJwtSkill,
] as const;
