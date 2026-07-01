import { describe, expect, it } from "vitest";
import {
  generateStaticAnalysisTriageSummary,
  generateStaticAnalysisTriageSummarySkill,
} from "../src/generateStaticAnalysisTriageSummary.js";

const scoreOutput = {
  artifact: {
    id: "artifact_static_analysis_attention_score",
    type: "static_analysis_attention_score",
    source_review_artifact_id: "artifact_static_analysis_review",
    source_artifact_id: "artifact_sarif",
    source_artifact_type: "sarif",
    source_format: "sarif",
  },
  observed: {
    source_reviewer: "review_static_analysis_results",
    score_model: "static_analysis_attention_v1",
    score: 31,
    max_score: 100,
    review_attention_level: "medium",
    risk_level: "medium",
    confidence: "high",
  },
  risk: {
    score: 31,
    level: "medium",
    confidence: "high",
    rationale: ["static_analysis.high_attention_result_present: +30 (result-severity)"],
    signal_refs: ["signal_static_analysis_001"],
    evidence_refs: ["evidence_static_analysis_001"],
    limitations: ["Score prioritizes scanner output for review attention only."],
  },
  contributions: [
    {
      id: "contribution_static_analysis_001",
      category: "result-severity",
      signal_ref: "signal_static_analysis_001",
      signal_type: "static_analysis.high_attention_result_present",
      points: 30,
      rationale: "Scanner reported a high-attention result.",
      evidence_refs: ["evidence_static_analysis_001"],
    },
  ],
  limitations: ["Score prioritizes scanner output for review attention only."],
  warnings: [],
} as const;

describe("generate_static_analysis_triage_summary", () => {
  it("exports the output skill with local-only permissions", () => {
    expect(generateStaticAnalysisTriageSummarySkill.metadata.name).toBe("generate_static_analysis_triage_summary");
    expect(generateStaticAnalysisTriageSummarySkill.metadata.category).toBe("output");
    expect(generateStaticAnalysisTriageSummarySkill.metadata.execution).toEqual({
      mode: "local_only",
      network_access: "none",
      deterministic: true,
    });
  });

  it("generates a draft finding and Markdown summary", () => {
    const output = generateStaticAnalysisTriageSummary(scoreOutput);

    expect(output.artifact).toMatchObject({
      type: "static_analysis_triage_summary",
      source_score_artifact_id: "artifact_static_analysis_attention_score",
      source_review_artifact_id: "artifact_static_analysis_review",
      source_artifact_id: "artifact_sarif",
      source_artifact_type: "sarif",
    });
    expect(output.observed.score).toBe(31);
    expect(output.observed.review_attention_level).toBe("medium");
    expect(output.finding.status).toBe("draft");
    expect(output.finding.evidence_refs).toEqual(["evidence_static_analysis_001"]);
    expect(output.finding.signal_refs).toEqual(["signal_static_analysis_001"]);
    expect(output.markdown).toContain("# Static\\-analysis triage summary");
    expect(output.markdown).toContain("## Recommended triage actions");
  });

  it("accepts a JSON run result from score_static_analysis_attention", () => {
    const runResult = {
      run_id: "run_score",
      status: "completed",
      skill: { name: "score_static_analysis_attention", version: "0.1.0" },
      output: scoreOutput,
      errors: [],
      warnings: [],
    };

    const output = generateStaticAnalysisTriageSummary(JSON.stringify(runResult));

    expect(output.observed.source_scorer).toBe("score_static_analysis_attention");
    expect(output.observed.contribution_count).toBe(1);
  });

  it("rejects non-static-analysis score output", () => {
    expect(() =>
      generateStaticAnalysisTriageSummary({
        artifact: { id: "artifact_browser_extension_risk_score", type: "browser_extension_risk_score" },
        observed: {},
        contributions: [],
        limitations: [],
        warnings: [],
      }),
    ).toThrow("generate_static_analysis_triage_summary input artifact.type must be static_analysis_attention_score");
  });
});
