export const toolSurfaceValues = ["cli", "api", "web", "mcp"] as const;
export type ToolSurface = (typeof toolSurfaceValues)[number];

export const deploymentProfileValues = ["local", "self_hosted", "hosted"] as const;
export type DeploymentProfile = (typeof deploymentProfileValues)[number];

export const exposureDefaultValues = ["enabled", "disabled", "allowlist_only"] as const;
export type ExposureDefault = (typeof exposureDefaultValues)[number];

export const exposureRiskValues = ["low", "medium", "high"] as const;
export type ExposureRisk = (typeof exposureRiskValues)[number];

export interface SkillExposurePolicy {
  /** Surfaces where this skill may eventually be exposed by adapters. */
  surfaces: ToolSurface[];

  /** Default exposure for local-first adapters unless a profile overrides it. */
  default_exposure: ExposureDefault;

  /** Default exposure when the workbench is deployed as a hosted or shared service. */
  hosted_default: ExposureDefault;

  /** Whether non-local callers should be authenticated before invoking this skill. */
  requires_authentication: boolean;

  /** Whether API/MCP/web adapters should rate limit this skill. */
  rate_limit_recommended: boolean;

  /** Whether invocations should be captured in an audit log when exposed outside local CLI. */
  audit_required: boolean;

  /** Optional adapter-level input limit recommendation for exposed surfaces. */
  max_input_mb?: number;

  /** Exposure risk level for adapter allowlist and review decisions. */
  risk: ExposureRisk;

  /** Human-readable reasons for the exposure posture. */
  rationale: string[];
}

export interface ExposureDecision {
  surface: ToolSurface;
  profile: DeploymentProfile;
  exposure: ExposureDefault;
  requires_authentication: boolean;
  rate_limit_recommended: boolean;
  audit_required: boolean;
  max_input_mb?: number;
  risk: ExposureRisk;
  rationale: string[];
}

function isOneOf<T extends readonly string[]>(values: T, value: unknown): value is T[number] {
  return typeof value === "string" && values.includes(value);
}

export function isToolSurface(value: unknown): value is ToolSurface {
  return isOneOf(toolSurfaceValues, value);
}

export function isDeploymentProfile(value: unknown): value is DeploymentProfile {
  return isOneOf(deploymentProfileValues, value);
}

export function isExposureDefault(value: unknown): value is ExposureDefault {
  return isOneOf(exposureDefaultValues, value);
}

export function isExposureRisk(value: unknown): value is ExposureRisk {
  return isOneOf(exposureRiskValues, value);
}

export function exposureForProfile(
  policy: SkillExposurePolicy,
  surface: ToolSurface,
  profile: DeploymentProfile,
): ExposureDecision {
  const surfaceConfigured = policy.surfaces.includes(surface);
  const exposure = surfaceConfigured
    ? profile === "hosted"
      ? policy.hosted_default
      : policy.default_exposure
    : "disabled";

  return {
    surface,
    profile,
    exposure,
    requires_authentication: policy.requires_authentication,
    rate_limit_recommended: policy.rate_limit_recommended,
    audit_required: policy.audit_required,
    max_input_mb: policy.max_input_mb,
    risk: policy.risk,
    rationale: surfaceConfigured
      ? policy.rationale
      : [...policy.rationale, `Skill does not declare support for ${surface} exposure.`],
  };
}
