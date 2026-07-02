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

export const staticAnalysisTriageWorkflow: WorkflowDefinition = {
  name: "static_analysis_triage",
  version: "0.1.0",
  description: "Parse SARIF, review scanner results, score review attention, and generate a triage summary.",
  steps: [
    {
      id: "parse",
      skill: "parse_sarif",
    },
    {
      id: "review",
      skill: "review_static_analysis_results",
      input_from: "parse",
    },
    {
      id: "score",
      skill: "score_static_analysis_attention",
      input_from: "review",
    },
    {
      id: "summary",
      skill: "generate_static_analysis_triage_summary",
      input_from: "score",
    },
  ],
};

export const certificateReviewWorkflow: WorkflowDefinition = {
  name: "certificate_review",
  version: "0.1.0",
  description: "Parse a PEM certificate artifact and review observed certificate metadata.",
  steps: [
    {
      id: "parse",
      skill: "parse_pem_certificate",
    },
    {
      id: "review",
      skill: "review_certificate",
      input_from: "parse",
    },
  ],
};

export const jwtReviewWorkflow: WorkflowDefinition = {
  name: "jwt_review",
  version: "0.1.0",
  description: "Parse a JWT and review observed header, claim, and signature metadata.",
  steps: [
    {
      id: "parse",
      skill: "parse_jwt",
    },
    {
      id: "review",
      skill: "review_jwt",
      input_from: "parse",
    },
  ],
};

export const sbomReviewWorkflow: WorkflowDefinition = {
  name: "sbom_review",
  version: "0.1.0",
  description: "Parse a CycloneDX or SPDX SBOM and review observed inventory quality.",
  steps: [
    {
      id: "parse",
      skill: "parse_sbom",
    },
    {
      id: "review",
      skill: "review_sbom",
      input_from: "parse",
    },
  ],
};

export const workflows = [
  browserExtensionReviewWorkflow,
  staticAnalysisTriageWorkflow,
  certificateReviewWorkflow,
  jwtReviewWorkflow,
  sbomReviewWorkflow,
] as const;
