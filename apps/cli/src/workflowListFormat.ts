import type { WorkflowDefinition } from "@security-workbench/schemas";
import type { CliListFormat } from "./args.js";

export interface WorkflowListFormatOptions {
  format: CliListFormat;
}

interface ListedWorkflow {
  name: string;
  version: string;
  steps: number;
  description: string;
}

function toListedWorkflow(workflow: WorkflowDefinition): ListedWorkflow {
  return {
    name: workflow.name,
    version: workflow.version,
    steps: workflow.steps.length,
    description: workflow.description,
  };
}

function pad(value: string, width: number): string {
  return value.padEnd(width, " ");
}

function formatTable(workflows: readonly ListedWorkflow[]): string {
  if (workflows.length === 0) {
    return "";
  }

  const headers = ["Workflow", "Version", "Steps", "Description"] as const;
  const rows = workflows.map((workflow) => [
    workflow.name,
    workflow.version,
    String(workflow.steps),
    workflow.description,
  ] as const);

  const widths = headers.map((header, index) =>
    Math.max(header.length, ...rows.map((row) => row[index].length))
  );

  return [
    headers.map((header, index) => pad(header, widths[index])).join("  "),
    headers.map((header, index) => pad("-".repeat(header.length), widths[index])).join("  "),
    ...rows.map((row) => row.map((value, index) => pad(value, widths[index])).join("  ")),
  ].join("\n");
}

export function formatWorkflowList(
  workflows: readonly WorkflowDefinition[],
  options: WorkflowListFormatOptions,
): string {
  const listed = workflows.map(toListedWorkflow);

  if (options.format === "json") {
    return JSON.stringify(listed, null, 2);
  }

  if (options.format === "table") {
    return formatTable(listed);
  }

  return listed
    .map((workflow) => `${workflow.name}\t${workflow.description}`)
    .join("\n");
}
