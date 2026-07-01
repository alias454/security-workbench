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
