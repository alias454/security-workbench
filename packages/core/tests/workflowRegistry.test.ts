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

  it("rejects workflows with missing required fields", () => {
    const registry = new WorkflowRegistry();

    expect(() =>
      registry.register({
        name: "",
        description: "Missing version and name.",
        steps: [{ id: "step", skill: "echo" }],
      } as unknown as WorkflowDefinition),
    ).toThrow("Workflow name must be a non-empty string.");
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
    ).toThrow("Workflow 'empty_workflow' must define at least one step.");
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
    ).toThrow("Workflow 'duplicate_steps' has duplicate step id: step.");
  });

  it("rejects unknown skill names when known skills are supplied", () => {
    const registry = new WorkflowRegistry();

    expect(() => registry.register(fakeWorkflow, { knownSkillNames: ["other"] })).toThrow(
      "Workflow 'fake_workflow' step 'echo' references unknown skill: echo.",
    );
  });

  it("accepts workflow skill names when known skills are supplied", () => {
    const registry = new WorkflowRegistry();

    registry.register(fakeWorkflow, { knownSkillNames: ["echo"] });

    expect(registry.list()).toEqual([fakeWorkflow]);
  });

  it("rejects input_from references to later or missing steps", () => {
    const registry = new WorkflowRegistry();

    expect(() =>
      registry.register({
        name: "bad_refs",
        version: "0.1.0",
        description: "Bad references.",
        steps: [
          { id: "first", skill: "one", input_from: "second" },
          { id: "second", skill: "two" },
        ],
      }),
    ).toThrow("Workflow 'bad_refs' step 'first' references unknown input_from step: second.");
  });
});
