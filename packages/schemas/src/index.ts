import type { SkillExposurePolicy } from "./exposure.js";
export const skillCategoryValues = [
  "transform",
  "parser",
  "reviewer",
  "enrichment",
  "scoring",
  "output",
] as const;

export type SkillCategory = (typeof skillCategoryValues)[number];

export function isSkillCategory(value: unknown): value is SkillCategory {
  return typeof value === "string" && skillCategoryValues.includes(value as SkillCategory);
}

export type ExecutionMode =
  | "local_only"
  | "network_optional"
  | "network_required";

export type NetworkAccess = "none" | "optional" | "required";

export type FilesystemAccess =
  | "none"
  | "read_input_only"
  | "read_write";

export interface SkillExecution {
  mode: ExecutionMode;
  network_access: NetworkAccess;
  deterministic: boolean;
}

export interface SkillPermissions {
  network: NetworkAccess;
  filesystem: FilesystemAccess;
  sends: string[];
  persists: boolean;
  runs_external_binaries: boolean;
}

export interface SkillMetadata {
  name: string;
  version: string;
  category: SkillCategory;
  description: string;
  execution: SkillExecution;
  permissions?: SkillPermissions;
  exposure?: SkillExposurePolicy;
}

export interface Skill<Input = unknown, Output = unknown> {
  metadata: SkillMetadata;
  run(input: Input): Promise<Output> | Output;
}

export interface RunPolicy {
  allow_network: boolean;
  persist_inputs: boolean;
  redact_secrets: boolean;
  max_artifact_size_mb: number;
  approved_sinks: string[];
}

export type SkillRunStatus =
  | "completed"
  | "failed"
  | "refused";

export interface SkillRunResult<Output = unknown> {
  run_id: string;
  status: SkillRunStatus;
  skill: {
    name: string;
    version: string;
  };
  policy: {
    allow_network: boolean;
    network_used: boolean;
    external_sinks: string[];
  };
  output?: Output;
  errors: string[];
  warnings: string[];
}

export * from "./json.js";
export * from "./artifact.js";
export * from "./evidence.js";
export * from "./signal.js";
export * from "./risk.js";
export * from "./finding.js";
export * from "./parseError.js";
export * from "./analysisResult.js";
export * from "./jsonParse.js";
export * from "./exposure.js";
export * from "./workflow.js";
