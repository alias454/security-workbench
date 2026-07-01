import { describe, expect, it } from "vitest";
import {
  scoreStaticAnalysisAttention,
  scoreStaticAnalysisAttentionSkill,
} from "../src/scoreStaticAnalysisAttention.js";

const reviewOutput = {
  artifact: {
    id: "artifact_static_analysis_review",
    type: "static_analysis_review",
    source_artifact_id: "artifact_sarif",
    source_artifact_type: "sarif",
    source_format: "sarif",
  },
  observed: {
    source_warning_count: 0,
    evidence_count: 2,
  },
  evidence: [
    { id: "evidence_static_analysis_001", type: "static_analysis_result" },
    { id: "evidence_static_analysis_002", type: "static_analysis_result" },
  ],
  signals: [
    {
      id: "signal_static_analysis_001",
      type: "static_analysis.high_attention_result_present",
      summary: "Static-analysis result js/sql-injection reported at src/app.ts:42.",
      severity: "high",
      confidence: "high",
      evidence_refs: ["evidence_static_analysis_001"],
      observed: { rule_id: "js/sql-injection" },
      tags: ["static-analysis", "sarif", "high"],
    },
    {
      id: "signal_static_analysis_002",
      type: "static_analysis.suppressed_result_present",
      summary: "Static-analysis result js/hardcoded-credential reported at src/config.ts:7.",
      severity: "medium",
      confidence: "medium",
      evidence_refs: ["evidence_static_analysis_002"],
      observed: { rule_id: "js/hardcoded-credential" },
      tags: ["static-analysis", "sarif", "informational"],
    },
  ],
  warnings: [],
} as const;

describe("score_static_analysis_attention", () => {
  it("exports the scoring skill with local-only permissions", () => {
    expect(scoreStaticAnalysisAttentionSkill.metadata.name).toBe("score_static_analysis_attention");
    expect(scoreStaticAnalysisAttentionSkill.metadata.category).toBe("scoring");
    expect(scoreStaticAnalysisAttentionSkill.metadata.execution).toEqual({
      mode: "local_only",
      network_access: "none",
      deterministic: true,
    });
  });

  it("scores static-analysis review signals", () => {
    const output = scoreStaticAnalysisAttention(reviewOutput);

    expect(output.artifact).toMatchObject({
      type: "static_analysis_attention_score",
      source_review_artifact_id: "artifact_static_analysis_review",
      source_artifact_id: "artifact_sarif",
      source_artifact_type: "sarif",
    });
    expect(output.observed.score).toBe(31);
    expect(output.observed.review_attention_level).toBe("medium");
    expect(output.observed.risk_level).toBe("medium");
    expect(output.observed.contributing_signal_count).toBe(2);
    expect(output.observed.evidence_refs).toEqual([
      "evidence_static_analysis_001",
      "evidence_static_analysis_002",
    ]);
    expect(output.risk.signal_refs).toEqual([
      "signal_static_analysis_001",
      "signal_static_analysis_002",
    ]);
  });

  it("accepts a JSON run result from review_static_analysis_results", () => {
    const runResult = {
      run_id: "run_review",
      status: "completed",
      skill: { name: "review_static_analysis_results", version: "0.1.0" },
      output: reviewOutput,
      errors: [],
      warnings: [],
    };

    const output = scoreStaticAnalysisAttention(JSON.stringify(runResult));

    expect(output.observed.source_reviewer).toBe("review_static_analysis_results");
    expect(output.contributions.length).toBe(2);
  });

  it("returns an informational score for empty reviews", () => {
    const output = scoreStaticAnalysisAttention({
      artifact: { id: "artifact_static_analysis_review", type: "static_analysis_review" },
      observed: { source_warning_count: 0, evidence_count: 0 },
      evidence: [],
      signals: [],
      warnings: [],
    });

    expect(output.observed.score).toBe(0);
    expect(output.observed.review_attention_level).toBe("none");
    expect(output.risk.level).toBe("informational");
  });
});
