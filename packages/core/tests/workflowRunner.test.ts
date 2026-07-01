import { describe, expect, it } from "vitest";
import type { Skill, WorkflowDefinition } from "@security-workbench/schemas";
import { SkillRegistry } from "../src/registry.js";
import { WorkflowRegistry } from "../src/workflowRegistry.js";
import { WorkflowRunner } from "../src/workflowRunner.js";

function skill(name: string, run: (input: unknown) => unknown): Skill<unknown, unknown> {
  return {
    metadata: {
      name,
      version: "0.1.0",
      category: "transform",
      description: `${name} test skill.`,
      execution: {
        mode: "local_only",
        network_access: "none",
        deterministic: true,
      },
      permissions: {
        network: "none",
        filesystem: "none",
        sends: [],
        persists: false,
        runs_external_binaries: false,
      },
    },
    run,
  };
}

function buildRunner(workflow: WorkflowDefinition, skills: readonly Skill<unknown, unknown>[]): WorkflowRunner {
  const workflowRegistry = new WorkflowRegistry();
  const skillRegistry = new SkillRegistry();
  for (const candidate of skills) {
    skillRegistry.register(candidate);
  }

  workflowRegistry.register(workflow, {
    knownSkillNames: skillRegistry.list().map((candidate) => candidate.metadata.name),
  });

  return new WorkflowRunner(workflowRegistry, skillRegistry);
}

describe("WorkflowRunner", () => {
  it("runs steps in order and passes prior step results", async () => {
    const first = skill("first", (input) => ({ received: input, value: "one" }));
    const second = skill("second", (input) => {
      const record = input as { output?: { value?: string } };
      return { previous: record.output?.value, value: "two" };
    });

    const runner = buildRunner(
      {
        name: "two_step",
        version: "0.1.0",
        description: "Two step workflow.",
        steps: [
          { id: "first", skill: "first" },
          { id: "second", skill: "second", input_from: "first" },
        ],
      },
      [first, second],
    );

    const result = await runner.run("two_step", "hello");

    expect(result.status).toBe("completed");
    expect(result.workflow).toEqual({
      name: "two_step",
      version: "0.1.0",
      description: "Two step workflow.",
      step_count: 2,
    });
    expect(result.steps.map((step) => step.id)).toEqual(["first", "second"]);
    expect(result.steps[0].output).toEqual({ received: "hello", value: "one" });
    expect(result.output).toEqual({ previous: "one", value: "two" });
    expect(result.errors).toEqual([]);
  });

  it("stops when a step fails", async () => {
    const ok = skill("ok", () => ({ ok: true }));
    const fail = skill("fail", () => {
      throw new Error("boom");
    });

    const runner = buildRunner(
      {
        name: "failing_workflow",
        version: "0.1.0",
        description: "Failing workflow.",
        steps: [
          { id: "ok", skill: "ok" },
          { id: "fail", skill: "fail", input_from: "ok" },
          { id: "never", skill: "ok", input_from: "fail" },
        ],
      },
      [ok, fail],
    );

    const result = await runner.run("failing_workflow", "hello");

    expect(result.status).toBe("failed");
    expect(result.steps.map((step) => step.id)).toEqual(["ok", "fail"]);
    expect(result.errors[0]).toContain("stopped at step 'fail'");
    expect(result.errors[0]).toContain("boom");
  });
});
