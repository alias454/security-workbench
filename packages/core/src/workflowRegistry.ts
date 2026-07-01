import {
  assertValidWorkflowDefinition,
  type WorkflowDefinition,
} from "@security-workbench/schemas";

export interface WorkflowRegistryRegisterOptions {
  readonly knownSkillNames?: readonly string[];
}

export class WorkflowRegistry {
  private workflows = new Map<string, WorkflowDefinition>();

  register(workflow: WorkflowDefinition, options: WorkflowRegistryRegisterOptions = {}): void {
    assertValidWorkflowDefinition(workflow, options);

    if (this.workflows.has(workflow.name)) {
      throw new Error(`Workflow already registered: ${workflow.name}`);
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
