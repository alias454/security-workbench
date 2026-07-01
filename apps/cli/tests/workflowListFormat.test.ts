import { describe, expect, it } from "vitest";
import type { WorkflowDefinition } from "@security-workbench/schemas";
import { formatWorkflowList } from "../src/workflowListFormat.js";

const workflows: WorkflowDefinition[] = [
  {
    name: "browser_extension_review",
    version: "0.1.0",
    description: "Review browser extension permissions.",
    steps: [
      { id: "parse", skill: "parse_browser_extension_manifest" },
      { id: "review", skill: "review_browser_extension_permissions", input_from: "parse" },
    ],
  },
];

describe("formatWorkflowList", () => {
  it("formats default TSV as name and description", () => {
    expect(formatWorkflowList(workflows, { format: "tsv" })).toBe(
      "browser_extension_review\tReview browser extension permissions.",
    );
  });

  it("formats table output", () => {
    const output = formatWorkflowList(workflows, { format: "table" });

    expect(output).toContain("Workflow");
    expect(output).toContain("Version");
    expect(output).toContain("Steps");
    expect(output).toContain("browser_extension_review");
    expect(output).toContain("0.1.0");
  });

  it("formats JSON output", () => {
    const parsed = JSON.parse(formatWorkflowList(workflows, { format: "json" })) as Array<Record<string, unknown>>;

    expect(parsed).toEqual([
      {
        name: "browser_extension_review",
        version: "0.1.0",
        steps: 2,
        description: "Review browser extension permissions.",
      },
    ]);
  });
});
