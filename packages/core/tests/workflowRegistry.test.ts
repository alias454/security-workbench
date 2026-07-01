import { describe, expect, it } from "vitest";
import type { WorkflowDefinition } from "@security-workbench/schemas";
import { WorkflowRegistry } from "../src/workflowRegistry.js";

const fakeWorkflow: WorkflowDefinition = {
  name: "fake_workflow",
  version: "0.1.0",
  description: "Fake workflow.",
  steps: [
    {
      id: "echo",
      skill: "echo",
    },
  ],
};

describe("WorkflowRegistry", () => {
  it("registers and lists workflows", () => {
    const registry = new WorkflowRegistry();

    registry.register(fakeWorkflow);

    expect(registry.list()).toEqual([fakeWorkflow]);
  });

  it("gets a registered workflow by name", () => {
    const registry = new WorkflowRegistry();

    registry.register(fakeWorkflow);

    expect(registry.get("fake_workflow")).toBe(fakeWorkflow);
  });

  it("rejects duplicate workflow names", () => {
    const registry = new WorkflowRegistry();

    registry.register(fakeWorkflow);

    expect(() => registry.register(fakeWorkflow)).toThrow(
      "Workflow already registered: fake_workflow",
    );
  });

  it("rejects unknown workflows", () => {
    const registry = new WorkflowRegistry();

    expect(() => registry.get("missing_workflow")).toThrow(
      "Unknown workflow: missing_workflow",
    );
  });

  it("rejects workflows with no steps", () => {
    const registry = new WorkflowRegistry();

    expect(() =>
      registry.register({
        name: "empty_workflow",
        version: "0.1.0",
        description: "No steps.",
        steps: [],
      }),
    ).toThrow("Workflow must define at least one step: empty_workflow");
  });

  it("rejects duplicate step ids", () => {
    const registry = new WorkflowRegistry();

    expect(() =>
      registry.register({
        name: "duplicate_steps",
        version: "0.1.0",
        description: "Duplicate steps.",
        steps: [
          { id: "step", skill: "one" },
          { id: "step", skill: "two" },
        ],
      }),
    ).toThrow("Workflow 'duplicate_steps' has duplicate step id: step");
  });
});
