import type { WorkflowRunResult } from "@security-workbench/schemas";
import type { CliRunFormat } from "./args.js";
import { formatSkillRunResult } from "./runFormat.js";

export interface WorkflowRunFormatOptions {
  format: CliRunFormat;
  unsafe?: boolean;
}

function formatPretty(result: WorkflowRunResult, options: WorkflowRunFormatOptions): string {
  const lines = [
    "Workflow Run",
    "------------",
    `Run ID: ${result.run_id}`,
    `Workflow: ${result.workflow.name}@${result.workflow.version}`,
    `Status: ${result.status}`,
    `Network used: ${result.policy.network_used ? "yes" : "no"}`,
    `External sinks: ${result.policy.external_sinks.length === 0 ? "[]" : result.policy.external_sinks.join(", ")}`,
    "",
    `Steps (${result.steps.length})`,
    ...result.steps.map((step) => `- ${step.id}: ${step.skill.name}@${step.skill.version} (${step.status})`),
  ];

  if (result.errors.length > 0) {
    lines.push("", "Errors", ...result.errors.map((error) => `- ${error}`));
  }

  if (result.warnings.length > 0) {
    lines.push("", "Warnings", ...result.warnings.map((warning) => `- ${warning}`));
  }

  if (result.output !== undefined) {
    const finalStep = result.steps.at(-1);

    lines.push("", "Final Output", "------------");
    lines.push(
      formatSkillRunResult(
        {
          run_id: result.run_id,
          status: result.status,
          skill: finalStep?.skill ?? {
            name: result.workflow.name,
            version: result.workflow.version,
          },
          policy: {
            allow_network: result.policy.allow_network,
            network_used: result.policy.network_used,
            external_sinks: [...result.policy.external_sinks],
          },
          output: result.output,
          errors: result.errors,
          warnings: result.warnings,
        },
        { format: "pretty", unsafe: options.unsafe },
      ),
    );
  }

  return lines.join("\n");
}

export function formatWorkflowRunResult(
  result: WorkflowRunResult,
  options: WorkflowRunFormatOptions,
): string {
  if (options.format === "json") {
    return JSON.stringify(result, null, 2);
  }

  return formatPretty(result, options);
}
