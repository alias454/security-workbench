import { describe, expect, it } from "vitest";
import { exportMarkdown, exportMarkdownSkill, skills } from "../src/index.js";

const finding = {
  id: "finding_example",
  title: "Example finding",
  summary: "Example summary.",
  status: "draft",
  artifact_refs: ["artifact_example"],
  evidence_refs: ["evidence_001"],
  signal_refs: ["signal_001"],
  risk: {
    level: "medium",
    confidence: "high",
    rationale: ["Example rationale."],
    evidence_refs: ["evidence_001"],
    signal_refs: ["signal_001"],
  },
  confidence: "high",
  observed_behavior: ["Observed behavior."],
  inferred_risk: ["Inferred risk."],
  mitigations: ["Recommended action."],
  open_questions: ["Open question?"],
} as const;

describe("export_markdown", () => {
  it("exports the output skill with local-only permissions", () => {
    expect(skills).toContain(exportMarkdownSkill);
    expect(exportMarkdownSkill.metadata.name).toBe("export_markdown");
    expect(exportMarkdownSkill.metadata.category).toBe("output");
    expect(exportMarkdownSkill.metadata.execution.network_access).toBe("none");
    expect(exportMarkdownSkill.metadata.permissions?.network).toBe("none");
    expect(exportMarkdownSkill.metadata.permissions?.persists).toBe(false);
  });

  it("passes through existing markdown from a skill run result", () => {
    const output = exportMarkdown(JSON.stringify({
      output: {
        artifact: { id: "artifact_source", type: "static_analysis_triage_summary" },
        finding,
        markdown: "# Existing Markdown\n\nBody.",
        warnings: ["source warning"],
      },
    }));

    expect(output.artifact.type).toBe("markdown_export");
    expect(output.artifact.source_artifact_id).toBe("artifact_source");
    expect(output.observed.source_kind).toBe("skill_run_result");
    expect(output.observed.finding_count).toBe(1);
    expect(output.markdown).toBe("# Existing Markdown\n\nBody.");
    expect(output.warnings).toEqual(["source warning"]);
  });

  it("renders a FindingRecord as Markdown", () => {
    const output = exportMarkdown({ finding });

    expect(output.markdown).toContain("# Example finding");
    expect(output.markdown).toContain("## Recommended actions");
    expect(output.observed.finding_count).toBe(1);
  });

  it("falls back to a JSON code block", () => {
    const output = exportMarkdown({ ok: true });

    expect(output.markdown).toContain("# Markdown export");
    expect(output.markdown).toContain("````json");
    expect(output.markdown).toContain('"ok": true');
  });
});
