import { randomUUID } from "node:crypto";
import type {
  RunPolicy,
  SkillRunResult,
  WorkflowRunResult,
  WorkflowRunStatus,
  WorkflowStepRunResult,
} from "@security-workbench/schemas";
import { defaultPolicy } from "./policy.js";
import { redactValue } from "./redaction.js";
import { SkillRegistry } from "./registry.js";
import { SkillRunner } from "./runner.js";
import { WorkflowRegistry } from "./workflowRegistry.js";

function workflowStatus(status: SkillRunResult["status"]): WorkflowRunStatus {
  return status;
}

function unique(values: readonly string[]): string[] {
  return [...new Set(values)];
}

function workflowMetadata(workflow: { name: string; version: string; description?: string; steps?: readonly unknown[] }): WorkflowRunResult["workflow"] {
  return {
    name: workflow.name,
    version: workflow.version,
    description: workflow.description,
    step_count: workflow.steps?.length,
  };
}

function maybeRedact(value: unknown, redactSecrets: boolean): unknown {
  return redactSecrets ? redactValue(value) : value;
}

function maybeRedactStrings(values: readonly string[], redactSecrets: boolean): string[] {
  return values.map((value) => String(maybeRedact(value, redactSecrets)));
}

function stepResultFromSkillResult(
  id: string,
  result: SkillRunResult,
  redactSecrets: boolean,
): WorkflowStepRunResult {
  return {
    id,
    skill: result.skill,
    run_id: result.run_id,
    status: workflowStatus(result.status),
    output: maybeRedact(result.output, redactSecrets),
    errors: maybeRedactStrings(result.errors, redactSecrets),
    warnings: maybeRedactStrings(result.warnings, redactSecrets),
  };
}

export class WorkflowRunner {
  constructor(
    private readonly workflows: WorkflowRegistry,
    private readonly skills: SkillRegistry,
  ) {}

  async run(
    workflowName: string,
    input: unknown,
    policy: Partial<RunPolicy> = {},
  ): Promise<WorkflowRunResult> {
    const mergedPolicy = { ...defaultPolicy, ...policy };
    const run_id = `workflow_run_${randomUUID()}`;
    const steps: WorkflowStepRunResult[] = [];
    const stepResults = new Map<string, SkillRunResult>();
    const runner = new SkillRunner(this.skills);
    const externalSinks: string[] = [];
    let networkUsed = false;

    try {
      const workflow = this.workflows.get(workflowName);

      for (const step of workflow.steps) {
        const source = step.input_from ?? "initial";
        const stepInput = source === "initial" ? input : stepResults.get(source);

        if (stepInput === undefined) {
          throw new Error(`Workflow '${workflow.name}' step '${step.id}' references unknown input_from step: ${source}`);
        }

        const result = await runner.run(step.skill, stepInput, {
          ...mergedPolicy,
          redact_secrets: false,
        });
        const displayStep = stepResultFromSkillResult(step.id, result, mergedPolicy.redact_secrets);

        stepResults.set(step.id, result);
        steps.push(displayStep);
        networkUsed = networkUsed || result.policy.network_used;
        externalSinks.push(...result.policy.external_sinks);

        if (result.status !== "completed") {
          return {
            run_id,
            status: workflowStatus(result.status),
            workflow: workflowMetadata(workflow),
            policy: {
              allow_network: mergedPolicy.allow_network,
              network_used: networkUsed,
              external_sinks: unique(externalSinks),
            },
            steps,
            errors: [
              `Workflow '${workflow.name}' stopped at step '${step.id}' (${step.skill}): ${displayStep.errors.join("; ")}`,
            ],
            warnings: steps.flatMap((entry) => entry.warnings),
          };
        }
      }

      return {
        run_id,
        status: "completed",
        workflow: workflowMetadata(workflow),
        policy: {
          allow_network: mergedPolicy.allow_network,
          network_used: networkUsed,
          external_sinks: unique(externalSinks),
        },
        steps,
        output: steps.at(-1)?.output,
        errors: [],
        warnings: steps.flatMap((entry) => entry.warnings),
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);

      return {
        run_id,
        status: "failed",
        workflow: {
          name: workflowName,
          version: "unknown",
        },
        policy: {
          allow_network: mergedPolicy.allow_network,
          network_used: networkUsed,
          external_sinks: unique(externalSinks),
        },
        steps,
        errors: [String(maybeRedact(message, mergedPolicy.redact_secrets))],
        warnings: steps.flatMap((entry) => entry.warnings),
      };
    }
  }
}
