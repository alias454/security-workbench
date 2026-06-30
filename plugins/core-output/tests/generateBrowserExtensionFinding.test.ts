import { describe, expect, it } from "vitest";
import { generateBrowserExtensionFinding, generateBrowserExtensionFindingSkill, skills } from "../src/index.js";

const scoreOutput = {
  artifact: {
    id: "artifact_browser_extension_risk_score",
    type: "browser_extension_risk_score",
    source_review_artifact_id: "artifact_browser_extension_permission_review",
    source_artifact_id: "artifact_browser_extension_manifest",
    source_artifact_type: "browser_extension_manifest",
    name: "Fixture Extension",
    version: "1.0.0",
    manifest_version: 2,
  },
  observed: {
    source_scorer: "score_browser_extension_risk",
    score_model: "browser_extension_review_attention_v1",
    score: 58,
    max_score: 100,
    raw_score: 58,
    capped: false,
    review_attention_level: "high",
    risk_level: "high",
    confidence: "high",
    review_signal_count: 5,
    review_evidence_count: 5,
    contributing_signal_count: 4,
    source_warning_count: 0,
    review_warning_count: 0,
    category_scores: { host_access: 34, content_scripts: 16, policy_surface: 6, distribution: 2 },
    contributing_signal_types: [
      "browser_extension.all_urls_permission_present",
      "browser_extension.broad_host_permissions_present",
      "browser_extension.broad_content_script_matches_present",
      "browser_extension.content_security_policy_not_observed",
    ],
    unmatched_signal_types: [],
    evidence_refs: ["evidence_browser_extension_001", "evidence_browser_extension_002"],
  },
  risk: {
    score: 58,
    level: "high",
    confidence: "high",
    rationale: [
      "browser_extension.all_urls_permission_present: +20 (host_access)",
      "browser_extension.broad_host_permissions_present: +14 (host_access)",
    ],
    signal_refs: ["signal_browser_extension_001", "signal_browser_extension_002"],
    evidence_refs: ["evidence_browser_extension_001", "evidence_browser_extension_002"],
    limitations: ["Score is a deterministic review-attention score, not a maliciousness verdict."],
  },
  contributions: [
    {
      id: "contribution_browser_extension_001",
      category: "host_access",
      signal_ref: "signal_browser_extension_001",
      signal_type: "browser_extension.all_urls_permission_present",
      points: 20,
      rationale: "<all_urls> host access usually warrants focused review because it can apply across all sites.",
      evidence_refs: ["evidence_browser_extension_001"],
    },
    {
      id: "contribution_browser_extension_002",
      category: "host_access",
      signal_ref: "signal_browser_extension_002",
      signal_type: "browser_extension.broad_host_permissions_present",
      points: 14,
      rationale: "Broad required host permissions increase the review surface for extension behavior.",
      evidence_refs: ["evidence_browser_extension_002"],
    },
  ],
  limitations: [
    "Score is a deterministic review-attention score, not a maliciousness verdict.",
    "Score uses parsed manifest review signals only; extension source code and runtime behavior are not inspected.",
  ],
  warnings: [],
};

describe("generate_browser_extension_finding", () => {
  it("exports the output skill with local-only permissions", () => {
    expect(skills).toContain(generateBrowserExtensionFindingSkill);
    expect(generateBrowserExtensionFindingSkill.metadata.name).toBe("generate_browser_extension_finding");
    expect(generateBrowserExtensionFindingSkill.metadata.category).toBe("output");
    expect(generateBrowserExtensionFindingSkill.metadata.execution.network_access).toBe("none");
    expect(generateBrowserExtensionFindingSkill.metadata.permissions?.network).toBe("none");
    expect(generateBrowserExtensionFindingSkill.metadata.permissions?.persists).toBe(false);
  });

  it("generates a draft finding and Markdown summary from browser extension score output", () => {
    const output = generateBrowserExtensionFinding(scoreOutput);

    expect(output.artifact.type).toBe("browser_extension_finding");
    expect(output.artifact.source_score_artifact_id).toBe("artifact_browser_extension_risk_score");
    expect(output.observed.source_scorer).toBe("score_browser_extension_risk");
    expect(output.observed.finding_template).toBe("browser_extension_permission_review_v1");
    expect(output.observed.score).toBe(58);
    expect(output.observed.review_attention_level).toBe("high");
    expect(output.finding.status).toBe("draft");
    expect(output.finding.risk?.level).toBe("high");
    expect(output.finding.artifact_refs).toEqual([
      "artifact_browser_extension_manifest",
      "artifact_browser_extension_permission_review",
      "artifact_browser_extension_risk_score",
    ]);
    expect(output.finding.signal_refs).toEqual([
      "signal_browser_extension_001",
      "signal_browser_extension_002",
    ]);
    expect(output.finding.evidence_refs).toEqual([
      "evidence_browser_extension_001",
      "evidence_browser_extension_002",
    ]);
    expect(output.markdown).toContain("# Browser extension permission review: Fixture Extension");
    expect(output.markdown).toContain("Review attention: high");
    expect(output.markdown).toContain("browser\\_extension\\.all\\_urls\\_permission\\_present");
    expect(output.markdown).not.toContain("This extension is malicious");
  });

  it("accepts a JSON run result wrapper", () => {
    const output = generateBrowserExtensionFinding(JSON.stringify({ output: scoreOutput }));

    expect(output.finding.title).toBe("Browser extension permission review: Fixture Extension");
    expect(output.observed.contribution_count).toBe(2);
  });

  it("escapes Markdown-sensitive artifact names", () => {
    const output = generateBrowserExtensionFinding({
      ...scoreOutput,
      artifact: {
        ...scoreOutput.artifact,
        name: "[Fixture](example.test) Extension",
      },
    });

    expect(output.markdown).toContain("\\[Fixture\\]\\(example\\.test\\) Extension");
    expect(output.finding.title).toBe("Browser extension permission review: [Fixture](example.test) Extension");
  });

  it("rejects raw manifests and malformed score inputs", () => {
    expect(() => generateBrowserExtensionFinding({ manifest_version: 3, name: "Raw" })).toThrow(
      /artifact and observed fields/
    );
    expect(() => generateBrowserExtensionFinding({ artifact: { type: "browser_extension_manifest" }, observed: {} })).toThrow(
      /artifact.type must be browser_extension_risk_score/
    );
    expect(() => generateBrowserExtensionFinding("{bad json}")).toThrow(/score JSON/);
  });
});
