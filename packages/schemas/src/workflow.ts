export type WorkflowStepInputRef = "initial" | string;

export interface WorkflowStep {
  readonly id: string;
  readonly skill: string;
  readonly input_from?: WorkflowStepInputRef;
}

export interface WorkflowDefinition {
  readonly name: string;
  readonly version: string;
  readonly description: string;
  readonly steps: readonly WorkflowStep[];
}

export interface WorkflowValidationOptions {
  readonly knownSkillNames?: readonly string[];
}

export interface WorkflowValidationResult {
  readonly valid: boolean;
  readonly errors: readonly string[];
}

export type WorkflowRunStatus = "completed" | "failed" | "refused";

export interface WorkflowStepRunResult<Output = unknown> {
  readonly id: string;
  readonly skill: {
    readonly name: string;
    readonly version: string;
  };
  readonly run_id: string;
  readonly status: WorkflowRunStatus;
  readonly output?: Output;
  readonly errors: readonly string[];
  readonly warnings: readonly string[];
}

export interface WorkflowRunResult<Output = unknown> {
  readonly run_id: string;
  readonly status: WorkflowRunStatus;
  readonly workflow: {
    readonly name: string;
    readonly version: string;
    readonly description?: string;
    readonly step_count?: number;
  };
  readonly policy: {
    readonly allow_network: boolean;
    readonly network_used: boolean;
    readonly external_sinks: readonly string[];
  };
  readonly steps: readonly WorkflowStepRunResult[];
  readonly output?: Output;
  readonly errors: readonly string[];
  readonly warnings: readonly string[];
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

function formatWorkflowName(value: unknown): string {
  return isNonEmptyString(value) ? value : "<unknown>";
}

export function validateWorkflowDefinition(
  workflow: unknown,
  options: WorkflowValidationOptions = {},
): WorkflowValidationResult {
  const errors: string[] = [];

  if (!isRecord(workflow)) {
    return {
      valid: false,
      errors: ["Workflow definition must be an object."],
    };
  }

  const workflowName = formatWorkflowName(workflow.name);

  if (!isNonEmptyString(workflow.name)) {
    errors.push("Workflow name must be a non-empty string.");
  }

  if (!isNonEmptyString(workflow.version)) {
    errors.push(`Workflow '${workflowName}' version must be a non-empty string.`);
  }

  if (!isNonEmptyString(workflow.description)) {
    errors.push(`Workflow '${workflowName}' description must be a non-empty string.`);
  }

  if (!Array.isArray(workflow.steps)) {
    errors.push(`Workflow '${workflowName}' steps must be a non-empty array.`);
    return {
      valid: errors.length === 0,
      errors,
    };
  }

  if (workflow.steps.length === 0) {
    errors.push(`Workflow '${workflowName}' must define at least one step.`);
  }

  const knownSkillNames = options.knownSkillNames ? new Set(options.knownSkillNames) : undefined;
  const stepIds = new Set<string>();
  const availableInputRefs = new Set<string>(["initial"]);

  workflow.steps.forEach((step, index) => {
    const path = `Workflow '${workflowName}' step[${index}]`;

    if (!isRecord(step)) {
      errors.push(`${path} must be an object.`);
      return;
    }

    const stepId = step.id;
    const skillName = step.skill;

    if (!isNonEmptyString(stepId)) {
      errors.push(`${path} id must be a non-empty string.`);
    } else if (stepIds.has(stepId)) {
      errors.push(`Workflow '${workflowName}' has duplicate step id: ${stepId}.`);
    }

    if (!isNonEmptyString(skillName)) {
      errors.push(`${path} skill must be a non-empty string.`);
    } else if (knownSkillNames && !knownSkillNames.has(skillName)) {
      errors.push(`Workflow '${workflowName}' step '${isNonEmptyString(stepId) ? stepId : index}' references unknown skill: ${skillName}.`);
    }

    if ("input_from" in step) {
      if (!isNonEmptyString(step.input_from)) {
        errors.push(`${path} input_from must be a non-empty string when provided.`);
      } else if (!availableInputRefs.has(step.input_from)) {
        errors.push(`Workflow '${workflowName}' step '${isNonEmptyString(stepId) ? stepId : index}' references unknown input_from step: ${step.input_from}.`);
      }
    }

    if (isNonEmptyString(stepId)) {
      stepIds.add(stepId);
      availableInputRefs.add(stepId);
    }
  });

  return {
    valid: errors.length === 0,
    errors,
  };
}

export function assertValidWorkflowDefinition(
  workflow: unknown,
  options: WorkflowValidationOptions = {},
): asserts workflow is WorkflowDefinition {
  const result = validateWorkflowDefinition(workflow, options);

  if (!result.valid) {
    throw new Error(result.errors.join("\n"));
  }
}
