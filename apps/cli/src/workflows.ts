import type { WorkflowDefinition } from "@security-workbench/schemas";

export const browserExtensionReviewWorkflow: WorkflowDefinition = {
  name: "browser_extension_review",
  version: "0.1.0",
  description: "Parse, review, score, and generate a draft finding for a browser extension manifest.",
  steps: [
    {
      id: "parse",
      skill: "parse_browser_extension_manifest",
    },
    {
      id: "review",
      skill: "review_browser_extension_permissions",
      input_from: "parse",
    },
    {
      id: "score",
      skill: "score_browser_extension_risk",
      input_from: "review",
    },
    {
      id: "finding",
      skill: "generate_browser_extension_finding",
      input_from: "score",
    },
  ],
};

export const workflows = [browserExtensionReviewWorkflow] as const;
