import { describe, expect, it } from "vitest";
import {
  artifactKinds,
  confidenceLevels,
  createParseError,
  isArtifactKind,
  isConfidenceLevel,
  isRiskLevel,
  isSkillCategory,
  isSeverityLevel,
  isStructuredParseError,
  parseErrorCodes,
  skillCategoryValues,
  riskLevels,
  severityLevels,
} from "../src/index.js";
import type {
  AnalysisResult,
  ArtifactSummary,
  EvidenceRecord,
  FindingRecord,
  RiskAssessment,
  SignalRecord,
  StructuredParseError,
} from "../src/index.js";

describe("common schema contract exports", () => {
  it("exports stable artifact and level vocabularies", () => {
    expect(artifactKinds).toContain("json");
    expect(artifactKinds).toContain("csv");
    expect(artifactKinds).toContain("yaml");
    expect(artifactKinds).toContain("browser_extension_manifest");
    expect(severityLevels).toEqual(["informational", "low", "medium", "high", "critical"]);
    expect(confidenceLevels).toContain("confirmed");
    expect(riskLevels).toContain("unknown");
    expect(skillCategoryValues).toEqual(["transform", "parser", "reviewer", "enrichment", "scoring", "output"]);
  });

  it("provides narrow runtime guards for common vocabularies", () => {
    expect(isArtifactKind("package_json")).toBe(true);
    expect(isArtifactKind("package-lock-json")).toBe(false);
    expect(isSeverityLevel("high")).toBe(true);
    expect(isSeverityLevel("severe")).toBe(false);
    expect(isConfidenceLevel("confirmed")).toBe(true);
    expect(isConfidenceLevel("certain")).toBe(false);
    expect(isRiskLevel("critical")).toBe(true);
    expect(isRiskLevel("p0")).toBe(false);
    expect(isSkillCategory("enrichment")).toBe(true);
    expect(isSkillCategory("generator")).toBe(false);
  });

  it("creates and recognizes structured parse errors", () => {
    const parseError = createParseError({
      code: "INVALID_JSON",
      message: "Input must be valid JSON.",
      recoverable: false,
      location: { line: 1, column: 2 },
    });

    expect(parseErrorCodes).toContain("INVALID_JSON");
    expect(isStructuredParseError(parseError)).toBe(true);
    expect(isStructuredParseError({ code: "INVALID_JSON" })).toBe(false);
  });

  it("supports evidence-backed analysis result composition", () => {
    const artifact: ArtifactSummary = {
      id: "artifact_001",
      type: "browser_extension_manifest",
      source: "inline",
      sensitivity: "medium",
    };

    const evidence: EvidenceRecord = {
      id: "ev_001",
      type: "manifest_field",
      artifact_ref: artifact.id,
      path: "$.host_permissions[0]",
      value: "<all_urls>",
      value_kind: "raw",
    };

    const signal: SignalRecord = {
      id: "sig_001",
      type: "extension.host_permissions.all_urls",
      summary: "Extension requests broad host access.",
      severity: "high",
      confidence: "high",
      artifact_refs: [artifact.id],
      evidence_refs: [evidence.id],
      observed: { host_permission: "<all_urls>" },
    };

    const risk: RiskAssessment = {
      score: 82,
      level: "high",
      confidence: "high",
      rationale: ["Broad host permissions"],
      signal_refs: [signal.id],
      evidence_refs: [evidence.id],
    };

    const finding: FindingRecord = {
      id: "finding_001",
      title: "Extension requests broad host access",
      summary: "The manifest includes broad host permissions.",
      status: "draft",
      artifact_refs: [artifact.id],
      evidence_refs: [evidence.id],
      signal_refs: [signal.id],
      risk,
      confidence: "high",
      observed_behavior: ["host_permissions includes <all_urls>"],
      inferred_risk: ["May access page content across many sites"],
    };

    const result: AnalysisResult = {
      artifact,
      evidence: [evidence],
      signals: [signal],
      risk,
      finding,
      warnings: [],
    };

    expect(result.finding?.evidence_refs).toEqual(["ev_001"]);
    expect(result.signals?.[0]?.observed).toEqual({ host_permission: "<all_urls>" });
  });

  it("keeps custom parser errors representable without requiring a validation library", () => {
    const parseError: StructuredParseError = {
      code: "CSV_UNTERMINATED_QUOTE",
      message: "CSV contains an unterminated quoted field.",
      recoverable: false,
      location: { line: 12, column: 8 },
    };

    expect(isStructuredParseError(parseError)).toBe(true);
  });
});
