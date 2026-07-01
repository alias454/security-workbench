import { describe, expect, it } from "vitest";
import { generateFinding, generateFindingSkill, skills } from "../src/index.js";

const finding = {
  id: "finding_existing",
  title: "Existing finding",
  summary: "Existing summary.",
  status: "draft",
  artifact_refs: ["artifact_source"],
  evidence_refs: ["evidence_001"],
  signal_refs: ["signal_001"],
  risk: {
    level: "high",
    confidence: "high",
    rationale: ["Existing rationale."],
    evidence_refs: ["evidence_001"],
    signal_refs: ["signal_001"],
  },
  confidence: "high",
} as const;

describe("generate_finding", () => {
  it("exports the output skill with local-only permissions", () => {
    expect(skills).toContain(generateFindingSkill);
    expect(generateFindingSkill.metadata.name).toBe("generate_finding");
    expect(generateFindingSkill.metadata.category).toBe("output");
    expect(generateFindingSkill.metadata.execution.network_access).toBe("none");
    expect(generateFindingSkill.metadata.permissions?.network).toBe("none");
    expect(generateFindingSkill.metadata.permissions?.persists).toBe(false);
  });

  it("normalizes an existing finding from a run result", () => {
    const output = generateFinding(JSON.stringify({
      output: {
        artifact: { id: "artifact_output", type: "static_analysis_triage_summary" },
        finding,
      },
    }));

    expect(output.artifact.type).toBe("generic_finding");
    expect(output.artifact.source_artifact_id).toBe("artifact_output");
    expect(output.observed.source_kind).toBe("skill_run_result");
    expect(output.finding.id).toBe("finding_existing");
    expect(output.finding.evidence_refs).toEqual(["evidence_001"]);
    expect(output.finding.signal_refs).toEqual(["signal_001"]);
  });

  it("creates a draft finding from generic analysis output", () => {
    const output = generateFinding({
      artifact: { id: "artifact_example", type: "sarif", name: "Example SARIF" },
      evidence: [{ id: "evidence_001", type: "location" }],
      signals: [{ id: "signal_001", type: "example", summary: "Example signal", evidence_refs: ["evidence_001"] }],
      risk: {
        score: 42,
        level: "medium",
        confidence: "high",
        rationale: ["Example rationale."],
        evidence_refs: ["evidence_001"],
        signal_refs: ["signal_001"],
      },
    });

    expect(output.finding.id).toBe("finding_generic_review");
    expect(output.finding.title).toBe("Security review finding: Example SARIF");
    expect(output.finding.risk?.level).toBe("medium");
    expect(output.finding.evidence_refs).toEqual(["evidence_001"]);
    expect(output.finding.signal_refs).toEqual(["signal_001"]);
  });

  it("rejects malformed non-JSON input", () => {
    expect(() => generateFinding("not json")).toThrow(/input must be JSON/);
  });
});
