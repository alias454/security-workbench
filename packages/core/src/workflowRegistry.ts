import type { WorkflowDefinition } from "@security-workbench/schemas";

export class WorkflowRegistry {
  private workflows = new Map<string, WorkflowDefinition>();

  register(workflow: WorkflowDefinition): void {
    if (this.workflows.has(workflow.name)) {
      throw new Error(`Workflow already registered: ${workflow.name}`);
    }

    if (workflow.steps.length === 0) {
      throw new Error(`Workflow must define at least one step: ${workflow.name}`);
    }

    const stepIds = new Set<string>();
    for (const step of workflow.steps) {
      if (stepIds.has(step.id)) {
        throw new Error(`Workflow '${workflow.name}' has duplicate step id: ${step.id}`);
      }

      stepIds.add(step.id);
    }

    this.workflows.set(workflow.name, workflow);
  }

  list(): WorkflowDefinition[] {
    return [...this.workflows.values()];
  }

  get(name: string): WorkflowDefinition {
    const workflow = this.workflows.get(name);

    if (!workflow) {
      throw new Error(`Unknown workflow: ${name}`);
    }

    return workflow;
  }
}
