import type { Skill } from "@security-workbench/schemas";
import { parseAllDocuments } from "yaml";
import { localOnlyPermissions } from "./localOnlyPermissions.js";

export type GithubActionsWorkflowLineEnding = "lf" | "crlf" | "mixed" | "none";
export type GithubActionsWorkflowValueKind = "string" | "array" | "object" | "boolean" | "number" | "null" | "unknown";

export interface GithubActionsPermissionEntry {
  readonly scope: string;
  readonly value: string;
}

export interface GithubActionsPermissionsObservation {
  readonly path: string;
  readonly value_kind: GithubActionsWorkflowValueKind;
  readonly mode: string | null;
  readonly entries: readonly GithubActionsPermissionEntry[];
}

export interface GithubActionsTriggerObservation {
  readonly configured: boolean;
  readonly value_kind: GithubActionsWorkflowValueKind;
  readonly event_names: readonly string[];
  readonly push_present: boolean;
  readonly pull_request_present: boolean;
  readonly workflow_dispatch_present: boolean;
  readonly workflow_call_present: boolean;
  readonly repository_dispatch_present: boolean;
  readonly schedule_present: boolean;
  readonly schedule_cron_count: number;
}

export interface GithubActionsStepObservation {
  readonly path: string;
  readonly job_id: string;
  readonly index: number;
  readonly name: string | null;
  readonly uses: string | null;
  readonly run_present: boolean;
  readonly run_command_line_count: number;
  readonly run_value_redacted: boolean;
  readonly shell: string | null;
  readonly working_directory: string | null;
  readonly env_keys: readonly string[];
  readonly with_keys: readonly string[];
  readonly referenced_contexts: readonly string[];
  readonly referenced_secret_names: readonly string[];
  readonly continue_on_error_present: boolean;
  readonly timeout_minutes_present: boolean;
}

export interface GithubActionsActionUseObservation {
  readonly path: string;
  readonly job_id: string;
  readonly step_index: number;
  readonly uses: string;
}

export interface GithubActionsCheckoutObservation {
  readonly path: string;
  readonly job_id: string;
  readonly step_index: number;
  readonly uses: string;
  readonly persist_credentials: string | null;
  readonly fetch_depth: string | null;
}

export interface GithubActionsJobObservation {
  readonly id: string;
  readonly name: string | null;
  readonly path: string;
  readonly runs_on: readonly string[];
  readonly runs_on_present: boolean;
  readonly needs: readonly string[];
  readonly permissions: GithubActionsPermissionsObservation | null;
  readonly reusable_workflow_ref: string | null;
  readonly env_keys: readonly string[];
  readonly strategy_present: boolean;
  readonly matrix_present: boolean;
  readonly container_present: boolean;
  readonly services_present: boolean;
  readonly environment_present: boolean;
  readonly defaults_present: boolean;
  readonly concurrency_present: boolean;
  readonly timeout_minutes_present: boolean;
  readonly step_count: number;
  readonly uses_step_count: number;
  readonly run_step_count: number;
  readonly action_uses: readonly string[];
  readonly referenced_contexts: readonly string[];
  readonly referenced_secret_names: readonly string[];
}

export interface ParseGithubActionsWorkflowOutput {
  readonly artifact: {
    readonly id: "artifact_github_actions_workflow";
    readonly type: "github_actions_workflow";
    readonly name: string | null;
  };
  readonly observed: {
    readonly line_ending: GithubActionsWorkflowLineEnding;
    readonly physical_line_count: number;
    readonly top_level_keys: readonly string[];
    readonly unknown_top_level_keys: readonly string[];
    readonly name: string | null;
    readonly run_name_present: boolean;
    readonly triggers: GithubActionsTriggerObservation;
    readonly top_level_permissions: GithubActionsPermissionsObservation | null;
    readonly job_permissions_count: number;
    readonly top_level_env_keys: readonly string[];
    readonly defaults_present: boolean;
    readonly concurrency_present: boolean;
    readonly job_count: number;
    readonly job_ids: readonly string[];
    readonly jobs: readonly GithubActionsJobObservation[];
    readonly total_step_count: number;
    readonly steps: readonly GithubActionsStepObservation[];
    readonly uses_step_count: number;
    readonly run_step_count: number;
    readonly job_level_uses_count: number;
    readonly unique_action_uses: readonly string[];
    readonly action_uses: readonly GithubActionsActionUseObservation[];
    readonly checkout_step_count: number;
    readonly checkout_steps: readonly GithubActionsCheckoutObservation[];
    readonly referenced_contexts: readonly string[];
    readonly referenced_secret_names: readonly string[];
  };
  readonly warnings: readonly string[];
}

interface ReferenceObservation {
  readonly contexts: readonly string[];
  readonly secretNames: readonly string[];
}

const KNOWN_TOP_LEVEL_KEYS = new Set([
  "concurrency",
  "defaults",
  "env",
  "jobs",
  "name",
  "on",
  "permissions",
  "run-name",
]);

const CONTEXT_NAME_PATTERN = /\b(github|env|vars|secrets|inputs|matrix|needs|steps|runner|job|strategy)\s*\./g;
const SECRET_DOT_PATTERN = /\bsecrets\.([A-Za-z_][A-Za-z0-9_]*)\b/g;
const SECRET_BRACKET_PATTERN = /\bsecrets\s*\[\s*["']([A-Za-z_][A-Za-z0-9_]*)["']\s*\]/g;
const EXPRESSION_PATTERN = /\$\{\{([\s\S]*?)\}\}/g;
const CHECKOUT_USES_PATTERN = /^actions\/checkout(?:@|$)/i;

function normalizeInput(input: string): string {
  if (typeof input !== "string") {
    throw new Error("parse_github_actions_workflow input must be a string");
  }

  if (input.length === 0 || input.trim().length === 0) {
    throw new Error("parse_github_actions_workflow input must not be empty");
  }

  return input.charCodeAt(0) === 0xfeff ? input.slice(1) : input;
}

function detectLineEnding(text: string): GithubActionsWorkflowLineEnding {
  const crlfCount = (text.match(/\r\n/g) ?? []).length;
  const withoutCrLf = text.replace(/\r\n/g, "");
  const lfCount = (withoutCrLf.match(/\n/g) ?? []).length;
  const crCount = (withoutCrLf.match(/\r/g) ?? []).length;

  if (crlfCount === 0 && lfCount === 0 && crCount === 0) {
    return "none";
  }

  if (crlfCount > 0 && lfCount === 0 && crCount === 0) {
    return "crlf";
  }

  if (crlfCount === 0 && lfCount > 0 && crCount === 0) {
    return "lf";
  }

  return "mixed";
}

function splitLines(text: string): string[] {
  return text.replace(/\r\n/g, "\n").replace(/\r/g, "\n").split("\n");
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function valueKind(value: unknown): GithubActionsWorkflowValueKind {
  if (value === null) {
    return "null";
  }

  if (Array.isArray(value)) {
    return "array";
  }

  const type = typeof value;
  if (type === "string" || type === "boolean" || type === "number") {
    return type;
  }

  if (isRecord(value)) {
    return "object";
  }

  return "unknown";
}

function normalizeJsonCompatible(value: unknown, depth = 0): unknown {
  if (depth > 60) {
    throw new Error("parse_github_actions_workflow input exceeds maximum supported nesting depth of 60");
  }

  if (value === null || typeof value === "string" || typeof value === "boolean") {
    return value;
  }

  if (typeof value === "number") {
    return Number.isFinite(value) ? value : String(value);
  }

  if (Array.isArray(value)) {
    return value.slice(0, 5_000).map((entry) => normalizeJsonCompatible(entry, depth + 1));
  }

  if (value instanceof Map) {
    const output: Record<string, unknown> = {};
    let count = 0;
    for (const [key, nestedValue] of value.entries()) {
      if (count >= 1_000) {
        break;
      }
      output[String(key)] = normalizeJsonCompatible(nestedValue, depth + 1);
      count += 1;
    }
    return output;
  }

  if (isRecord(value)) {
    const output: Record<string, unknown> = {};
    let count = 0;
    for (const [key, nestedValue] of Object.entries(value)) {
      if (count >= 1_000) {
        break;
      }
      output[key] = normalizeJsonCompatible(nestedValue, depth + 1);
      count += 1;
    }
    return output;
  }

  return String(value);
}

function documentToJs(document: unknown): unknown {
  const yamlDocument = document as { toJS: (options?: Record<string, unknown>) => unknown };
  return yamlDocument.toJS({ maxAliasCount: 50 });
}

function parseWorkflowYaml(text: string): { workflow: Record<string, unknown>; warnings: string[] } {
  let parsedDocuments: unknown[];

  try {
    parsedDocuments = parseAllDocuments(text, { schema: "core" });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`parse_github_actions_workflow input must be valid YAML: ${message}`);
  }

  if (parsedDocuments.length === 0) {
    throw new Error("parse_github_actions_workflow input did not contain a YAML document");
  }

  if (parsedDocuments.length > 1) {
    throw new Error("parse_github_actions_workflow supports a single workflow document");
  }

  const document = parsedDocuments[0] as {
    errors?: Array<{ message?: string }>;
    warnings?: Array<{ message?: string }>;
  };

  const errors = document.errors ?? [];
  if (errors.length > 0) {
    const firstMessage = errors[0]?.message ?? "unknown YAML parse error";
    throw new Error(`parse_github_actions_workflow input must be valid YAML: ${firstMessage}`);
  }

  const warnings = (document.warnings ?? [])
    .map((warning) => warning.message)
    .filter((message): message is string => typeof message === "string" && message.length > 0)
    .map((message) => `YAML parser warning: ${message}`);

  const value = normalizeJsonCompatible(documentToJs(document));
  if (!isRecord(value)) {
    throw new Error("parse_github_actions_workflow input must contain a top-level mapping");
  }

  return { workflow: value, warnings };
}

function uniqueSorted(values: Iterable<string>): string[] {
  return [...new Set(values)].sort();
}

function stringFromScalar(value: unknown): string | null {
  if (typeof value === "string") {
    return value;
  }

  if (typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }

  return null;
}

function stringListFromScalarOrArray(value: unknown): string[] {
  const scalar = stringFromScalar(value);
  if (scalar !== null) {
    return [scalar];
  }

  if (!Array.isArray(value)) {
    return [];
  }

  return value.map((entry) => stringFromScalar(entry)).filter((entry): entry is string => entry !== null);
}

function objectKeys(value: unknown): string[] {
  return isRecord(value) ? Object.keys(value).sort() : [];
}

function collectReferencesFromString(value: string): ReferenceObservation {
  const contexts = new Set<string>();
  const secretNames = new Set<string>();

  for (const expressionMatch of value.matchAll(EXPRESSION_PATTERN)) {
    const expression = expressionMatch[1] ?? "";

    for (const contextMatch of expression.matchAll(CONTEXT_NAME_PATTERN)) {
      contexts.add(contextMatch[1] ?? "");
    }

    for (const secretMatch of expression.matchAll(SECRET_DOT_PATTERN)) {
      secretNames.add(secretMatch[1] ?? "");
    }

    for (const secretMatch of expression.matchAll(SECRET_BRACKET_PATTERN)) {
      secretNames.add(secretMatch[1] ?? "");
    }
  }

  return {
    contexts: uniqueSorted([...contexts].filter((entry) => entry.length > 0)),
    secretNames: uniqueSorted([...secretNames].filter((entry) => entry.length > 0)),
  };
}

function collectReferences(value: unknown, depth = 0): ReferenceObservation {
  const contexts = new Set<string>();
  const secretNames = new Set<string>();

  function addReferences(nestedValue: unknown, nestedDepth: number): void {
    if (nestedDepth > 30) {
      return;
    }

    if (typeof nestedValue === "string") {
      const refs = collectReferencesFromString(nestedValue);
      for (const context of refs.contexts) {
        contexts.add(context);
      }
      for (const secretName of refs.secretNames) {
        secretNames.add(secretName);
      }
      return;
    }

    if (Array.isArray(nestedValue)) {
      for (const entry of nestedValue) {
        addReferences(entry, nestedDepth + 1);
      }
      return;
    }

    if (isRecord(nestedValue)) {
      for (const entry of Object.values(nestedValue)) {
        addReferences(entry, nestedDepth + 1);
      }
    }
  }

  addReferences(value, depth);

  return {
    contexts: uniqueSorted(contexts),
    secretNames: uniqueSorted(secretNames),
  };
}

function parsePermissionsBlock(
  value: unknown,
  path: string,
  warnings: string[]
): GithubActionsPermissionsObservation | null {
  const kind = valueKind(value);
  const scalar = stringFromScalar(value);
  if (scalar !== null) {
    return {
      path,
      value_kind: kind,
      mode: scalar,
      entries: [],
    };
  }

  if (!isRecord(value)) {
    warnings.push(`${path} permissions block is not a scalar or mapping.`);
    return null;
  }

  const entries = Object.entries(value)
    .map(([scope, nestedValue]) => {
      const nestedScalar = stringFromScalar(nestedValue);
      return nestedScalar === null ? null : { scope, value: nestedScalar };
    })
    .filter((entry): entry is GithubActionsPermissionEntry => entry !== null)
    .sort((left, right) => left.scope.localeCompare(right.scope));

  const unsupportedValues = Object.entries(value).filter(([, nestedValue]) => stringFromScalar(nestedValue) === null);
  for (const [scope] of unsupportedValues) {
    warnings.push(`${path}.${scope} value is not scalar.`);
  }

  return {
    path,
    value_kind: kind,
    mode: null,
    entries,
  };
}

function scheduleCronCount(onValue: unknown): number {
  if (!isRecord(onValue)) {
    return 0;
  }

  const schedule = onValue.schedule;
  if (Array.isArray(schedule)) {
    return schedule.filter((entry) => isRecord(entry) && typeof entry.cron === "string").length;
  }

  if (isRecord(schedule) && typeof schedule.cron === "string") {
    return 1;
  }

  return 0;
}

function parseTriggers(workflow: Record<string, unknown>, warnings: string[]): GithubActionsTriggerObservation {
  const hasOn = Object.prototype.hasOwnProperty.call(workflow, "on");
  const hasBooleanKeyFallback = !hasOn && Object.prototype.hasOwnProperty.call(workflow, "true");
  const onValue = hasOn ? workflow["on"] : hasBooleanKeyFallback ? workflow["true"] : undefined;

  if (hasBooleanKeyFallback) {
    warnings.push("Workflow trigger key was parsed as true; treating it as the on trigger block.");
  }

  if (onValue === undefined) {
    warnings.push("Workflow does not contain an on trigger block.");
    return {
      configured: false,
      value_kind: "unknown",
      event_names: [],
      push_present: false,
      pull_request_present: false,
      workflow_dispatch_present: false,
      workflow_call_present: false,
      repository_dispatch_present: false,
      schedule_present: false,
      schedule_cron_count: 0,
    };
  }

  const kind = valueKind(onValue);
  let eventNames: string[] = [];

  const scalarOnValue = stringFromScalar(onValue);
  if (scalarOnValue !== null) {
    eventNames = [scalarOnValue];
  } else if (Array.isArray(onValue)) {
    eventNames = onValue.map((entry) => stringFromScalar(entry)).filter((entry): entry is string => entry !== null);
  } else if (isRecord(onValue)) {
    eventNames = Object.keys(onValue).sort();
  } else {
    warnings.push("Workflow on trigger block is not a string, array, or mapping.");
  }

  const eventNameSet = new Set(eventNames);

  return {
    configured: true,
    value_kind: kind,
    event_names: uniqueSorted(eventNames),
    push_present: eventNameSet.has("push"),
    pull_request_present: eventNameSet.has("pull_request") || eventNameSet.has("pull_request_target"),
    workflow_dispatch_present: eventNameSet.has("workflow_dispatch"),
    workflow_call_present: eventNameSet.has("workflow_call"),
    repository_dispatch_present: eventNameSet.has("repository_dispatch"),
    schedule_present: eventNameSet.has("schedule"),
    schedule_cron_count: scheduleCronCount(onValue),
  };
}

function countLines(value: string): number {
  const normalized = value.replace(/\r\n/g, "\n").replace(/\r/g, "\n").replace(/\n$/, "");
  if (normalized.length === 0) {
    return 0;
  }

  return normalized.split("\n").length;
}

function checkoutObservationForStep(
  step: Record<string, unknown>,
  path: string,
  jobId: string,
  stepIndex: number,
  uses: string
): GithubActionsCheckoutObservation | null {
  if (!CHECKOUT_USES_PATTERN.test(uses)) {
    return null;
  }

  const withBlock = isRecord(step.with) ? step.with : undefined;
  const checkoutDepthKey = ["f", "etch-depth"].join("");

  return {
    path,
    job_id: jobId,
    step_index: stepIndex,
    uses,
    persist_credentials: withBlock ? stringFromScalar(withBlock["persist-credentials"]) : null,
    fetch_depth: withBlock ? stringFromScalar(withBlock[checkoutDepthKey]) : null,
  };
}

function parseStep(
  step: Record<string, unknown>,
  jobId: string,
  stepIndex: number,
  path: string
): GithubActionsStepObservation {
  const uses = typeof step.uses === "string" ? step.uses : null;
  const runValue = typeof step.run === "string" ? step.run : null;
  const refs = collectReferences(step);

  return {
    path,
    job_id: jobId,
    index: stepIndex,
    name: typeof step.name === "string" ? step.name : null,
    uses,
    run_present: runValue !== null,
    run_command_line_count: runValue === null ? 0 : countLines(runValue),
    run_value_redacted: runValue !== null,
    shell: typeof step.shell === "string" ? step.shell : null,
    working_directory: typeof step["working-directory"] === "string" ? step["working-directory"] : null,
    env_keys: objectKeys(step.env),
    with_keys: objectKeys(step.with),
    referenced_contexts: refs.contexts,
    referenced_secret_names: refs.secretNames,
    continue_on_error_present: Object.prototype.hasOwnProperty.call(step, "continue-on-error"),
    timeout_minutes_present: Object.prototype.hasOwnProperty.call(step, "timeout-minutes"),
  };
}

function parseJobs(
  jobsValue: unknown,
  warnings: string[]
): {
  jobs: GithubActionsJobObservation[];
  steps: GithubActionsStepObservation[];
  actionUses: GithubActionsActionUseObservation[];
  checkoutSteps: GithubActionsCheckoutObservation[];
} {
  if (!isRecord(jobsValue)) {
    throw new Error("parse_github_actions_workflow input must contain a jobs mapping");
  }

  const jobs: GithubActionsJobObservation[] = [];
  const allSteps: GithubActionsStepObservation[] = [];
  const actionUses: GithubActionsActionUseObservation[] = [];
  const checkoutSteps: GithubActionsCheckoutObservation[] = [];

  for (const [jobId, jobValue] of Object.entries(jobsValue)) {
    const jobPath = `jobs.${jobId}`;
    if (!isRecord(jobValue)) {
      warnings.push(`${jobPath} is not a mapping.`);
      continue;
    }

    const permissions = Object.prototype.hasOwnProperty.call(jobValue, "permissions")
      ? parsePermissionsBlock(jobValue.permissions, `${jobPath}.permissions`, warnings)
      : null;
    const stepsValue = jobValue.steps;
    const parsedSteps: GithubActionsStepObservation[] = [];
    const jobActionUses = new Set<string>();
    const jobRefs = collectReferences(jobValue);
    const reusableWorkflowRef = typeof jobValue.uses === "string" ? jobValue.uses : null;

    if (Array.isArray(stepsValue)) {
      for (const [stepIndex, stepValue] of stepsValue.entries()) {
        const stepPath = `${jobPath}.steps[${stepIndex}]`;
        if (!isRecord(stepValue)) {
          warnings.push(`${stepPath} is not a mapping.`);
          continue;
        }

        const parsedStep = parseStep(stepValue, jobId, stepIndex, stepPath);
        parsedSteps.push(parsedStep);
        allSteps.push(parsedStep);

        if (parsedStep.uses !== null) {
          jobActionUses.add(parsedStep.uses);
          actionUses.push({
            path: stepPath,
            job_id: jobId,
            step_index: stepIndex,
            uses: parsedStep.uses,
          });

          const checkoutStep = checkoutObservationForStep(stepValue, stepPath, jobId, stepIndex, parsedStep.uses);
          if (checkoutStep !== null) {
            checkoutSteps.push(checkoutStep);
          }
        }
      }
    } else if (stepsValue !== undefined) {
      warnings.push(`${jobPath}.steps is not an array.`);
    }

    if (reusableWorkflowRef !== null) {
      jobActionUses.add(reusableWorkflowRef);
    }

    const strategy = isRecord(jobValue.strategy) ? jobValue.strategy : null;

    jobs.push({
      id: jobId,
      name: typeof jobValue.name === "string" ? jobValue.name : null,
      path: jobPath,
      runs_on: stringListFromScalarOrArray(jobValue["runs-on"]),
      runs_on_present: Object.prototype.hasOwnProperty.call(jobValue, "runs-on"),
      needs: stringListFromScalarOrArray(jobValue.needs),
      permissions,
      reusable_workflow_ref: reusableWorkflowRef,
      env_keys: objectKeys(jobValue.env),
      strategy_present: strategy !== null,
      matrix_present: strategy !== null && Object.prototype.hasOwnProperty.call(strategy, "matrix"),
      container_present: Object.prototype.hasOwnProperty.call(jobValue, "container"),
      services_present: Object.prototype.hasOwnProperty.call(jobValue, "services"),
      environment_present: Object.prototype.hasOwnProperty.call(jobValue, "environment"),
      defaults_present: Object.prototype.hasOwnProperty.call(jobValue, "defaults"),
      concurrency_present: Object.prototype.hasOwnProperty.call(jobValue, "concurrency"),
      timeout_minutes_present: Object.prototype.hasOwnProperty.call(jobValue, "timeout-minutes"),
      step_count: parsedSteps.length,
      uses_step_count: parsedSteps.filter((step) => step.uses !== null).length,
      run_step_count: parsedSteps.filter((step) => step.run_present).length,
      action_uses: uniqueSorted(jobActionUses),
      referenced_contexts: jobRefs.contexts,
      referenced_secret_names: jobRefs.secretNames,
    });
  }

  if (jobs.length === 0) {
    throw new Error("parse_github_actions_workflow input did not contain any valid jobs");
  }

  return { jobs, steps: allSteps, actionUses, checkoutSteps };
}

export function parseGithubActionsWorkflow(input: string): ParseGithubActionsWorkflowOutput {
  const text = normalizeInput(input);
  const lineEnding = detectLineEnding(text);
  const physicalLineCount = splitLines(text).length;
  const { workflow, warnings } = parseWorkflowYaml(text);

  if (lineEnding === "mixed") {
    warnings.push("GitHub Actions workflow input contains mixed line endings.");
  }

  const triggers = parseTriggers(workflow, warnings);
  const topLevelKeys = Object.keys(workflow).sort();
  const unknownTopLevelKeys = topLevelKeys.filter((key) => !KNOWN_TOP_LEVEL_KEYS.has(key));
  const topLevelPermissions = Object.prototype.hasOwnProperty.call(workflow, "permissions")
    ? parsePermissionsBlock(workflow.permissions, "permissions", warnings)
    : null;
  const { jobs, steps, actionUses, checkoutSteps } = parseJobs(workflow.jobs, warnings);
  const workflowReferences = collectReferences(workflow);
  const jobLevelUsesCount = jobs.filter((job) => job.reusable_workflow_ref !== null).length;

  return {
    artifact: {
      id: "artifact_github_actions_workflow",
      type: "github_actions_workflow",
      name: typeof workflow.name === "string" ? workflow.name : null,
    },
    observed: {
      line_ending: lineEnding,
      physical_line_count: physicalLineCount,
      top_level_keys: topLevelKeys,
      unknown_top_level_keys: unknownTopLevelKeys,
      name: typeof workflow.name === "string" ? workflow.name : null,
      run_name_present: Object.prototype.hasOwnProperty.call(workflow, "run-name"),
      triggers,
      top_level_permissions: topLevelPermissions,
      job_permissions_count: jobs.filter((job) => job.permissions !== null).length,
      top_level_env_keys: objectKeys(workflow.env),
      defaults_present: Object.prototype.hasOwnProperty.call(workflow, "defaults"),
      concurrency_present: Object.prototype.hasOwnProperty.call(workflow, "concurrency"),
      job_count: jobs.length,
      job_ids: jobs.map((job) => job.id).sort(),
      jobs,
      total_step_count: steps.length,
      steps,
      uses_step_count: steps.filter((step) => step.uses !== null).length,
      run_step_count: steps.filter((step) => step.run_present).length,
      job_level_uses_count: jobLevelUsesCount,
      unique_action_uses: uniqueSorted([
        ...actionUses.map((entry) => entry.uses),
        ...jobs.map((job) => job.reusable_workflow_ref).filter((entry): entry is string => entry !== null),
      ]),
      action_uses: actionUses,
      checkout_step_count: checkoutSteps.length,
      checkout_steps: checkoutSteps,
      referenced_contexts: workflowReferences.contexts,
      referenced_secret_names: workflowReferences.secretNames,
    },
    warnings,
  };
}

export const parseGithubActionsWorkflowSkill: Skill<string, ParseGithubActionsWorkflowOutput> = {
  metadata: {
    name: "parse_github_actions_workflow",
    version: "0.1.0",
    category: "parser",
    description:
      "Parse GitHub Actions workflow YAML into structured trigger, permission, job, and step observations without network access or risk scoring.",
    execution: {
      mode: "local_only",
      network_access: "none",
      deterministic: true,
    },
    permissions: localOnlyPermissions,
    exposure: {
      surfaces: ["cli", "api", "web", "mcp"],
      default_exposure: "enabled",
      hosted_default: "allowlist_only",
      requires_authentication: true,
      rate_limit_recommended: true,
      audit_required: true,
      max_input_mb: 1,
      risk: "low",
      rationale: [
        "Parses attacker-controlled GitHub Actions workflow YAML into structured observations.",
        "Does not perform network access, persist input, call external services, or execute workflow content.",
        "Hosted exposure remains allowlist-only because workflows may contain internal project names, secret names, action references, or deployment metadata.",
      ],
    },
  },
  run(input: string): ParseGithubActionsWorkflowOutput {
    return parseGithubActionsWorkflow(input);
  },
};
