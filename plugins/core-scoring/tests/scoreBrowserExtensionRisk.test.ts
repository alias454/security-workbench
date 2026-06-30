import { describe, expect, it } from "vitest";
import {
  scoreBrowserExtensionRisk,
  scoreBrowserExtensionRiskSkill,
} from "../src/scoreBrowserExtensionRisk.js";

const reviewedManifestOutput = {
  artifact: {
    id: "artifact_browser_extension_permission_review",
    type: "browser_extension_permission_review",
    source_artifact_id: "artifact_browser_extension_manifest",
    source_artifact_type: "browser_extension_manifest",
    name: "Fixture Extension",
    version: "1.0.0",
    manifest_version: 3,
  },
  observed: {
    source_reviewer: "review_browser_extension_permissions",
    source_warning_count: 0,
    evidence_count: 12,
    signal_count: 12,
  },
  evidence: [
    { id: "evidence_browser_extension_001", type: "browser_extension_all_urls_permission" },
    { id: "evidence_browser_extension_002", type: "browser_extension_broad_host_permissions" },
    { id: "evidence_browser_extension_003", type: "browser_extension_broad_optional_host_permissions" },
    { id: "evidence_browser_extension_004", type: "browser_extension_notable_api_permissions" },
    { id: "evidence_browser_extension_005", type: "browser_extension_notable_optional_api_permissions" },
    { id: "evidence_browser_extension_006", type: "browser_extension_broad_content_script_matches" },
    { id: "evidence_browser_extension_007", type: "browser_extension_background_context" },
    { id: "evidence_browser_extension_008", type: "browser_extension_externally_connectable" },
    { id: "evidence_browser_extension_009", type: "browser_extension_web_accessible_resources" },
    { id: "evidence_browser_extension_010", type: "browser_extension_update_url_present" },
    { id: "evidence_browser_extension_011", type: "browser_extension_oauth2_present" },
    { id: "evidence_browser_extension_012", type: "browser_extension_csp_not_observed" },
  ],
  signals: [
    {
      id: "signal_browser_extension_001",
      type: "browser_extension.all_urls_permission_present",
      summary: "Browser extension manifest declares <all_urls> host access.",
      confidence: "confirmed",
      evidence_refs: ["evidence_browser_extension_001"],
    },
    {
      id: "signal_browser_extension_002",
      type: "browser_extension.broad_host_permissions_present",
      summary: "Browser extension manifest declares broad required host permissions.",
      confidence: "confirmed",
      evidence_refs: ["evidence_browser_extension_002"],
    },
    {
      id: "signal_browser_extension_003",
      type: "browser_extension.broad_optional_host_permissions_present",
      summary: "Browser extension manifest declares broad optional host permissions.",
      confidence: "confirmed",
      evidence_refs: ["evidence_browser_extension_003"],
    },
    {
      id: "signal_browser_extension_004",
      type: "browser_extension.notable_api_permissions_present",
      summary: "Browser extension manifest declares API permissions that commonly warrant review.",
      confidence: "confirmed",
      evidence_refs: ["evidence_browser_extension_004"],
    },
    {
      id: "signal_browser_extension_005",
      type: "browser_extension.notable_optional_api_permissions_present",
      summary: "Browser extension manifest declares optional API permissions that commonly warrant review.",
      confidence: "confirmed",
      evidence_refs: ["evidence_browser_extension_005"],
    },
    {
      id: "signal_browser_extension_006",
      type: "browser_extension.broad_content_script_matches_present",
      summary: "Browser extension content scripts are declared for broad host patterns.",
      confidence: "confirmed",
      evidence_refs: ["evidence_browser_extension_006"],
    },
    {
      id: "signal_browser_extension_007",
      type: "browser_extension.background_context_present",
      summary: "Browser extension manifest declares a background context.",
      confidence: "confirmed",
      evidence_refs: ["evidence_browser_extension_007"],
    },
    {
      id: "signal_browser_extension_008",
      type: "browser_extension.externally_connectable_present",
      summary: "Browser extension manifest declares externally_connectable entries.",
      confidence: "confirmed",
      evidence_refs: ["evidence_browser_extension_008"],
    },
    {
      id: "signal_browser_extension_009",
      type: "browser_extension.web_accessible_resources_present",
      summary: "Browser extension manifest declares web accessible resources.",
      confidence: "confirmed",
      evidence_refs: ["evidence_browser_extension_009"],
    },
    {
      id: "signal_browser_extension_010",
      type: "browser_extension.update_url_present",
      summary: "Browser extension manifest declares update_url presence.",
      confidence: "confirmed",
      evidence_refs: ["evidence_browser_extension_010"],
    },
    {
      id: "signal_browser_extension_011",
      type: "browser_extension.oauth2_present",
      summary: "Browser extension manifest declares oauth2 configuration presence.",
      confidence: "confirmed",
      evidence_refs: ["evidence_browser_extension_011"],
    },
    {
      id: "signal_browser_extension_012",
      type: "browser_extension.content_security_policy_not_observed",
      summary: "Browser extension manifest did not include an explicit content_security_policy entry.",
      confidence: "confirmed",
      evidence_refs: ["evidence_browser_extension_012"],
    },
  ],
  warnings: [],
} as const;

describe("score_browser_extension_risk", () => {
  it("exports the scoring skill with local-only permissions", () => {
    expect(scoreBrowserExtensionRiskSkill.metadata.name).toBe("score_browser_extension_risk");
    expect(scoreBrowserExtensionRiskSkill.metadata.category).toBe("scoring");
    expect(scoreBrowserExtensionRiskSkill.metadata.execution).toEqual({
      mode: "local_only",
      network_access: "none",
      deterministic: true,
    });
    expect(scoreBrowserExtensionRiskSkill.metadata.permissions).toEqual({
      network: "none",
      filesystem: "none",
      sends: [],
      persists: false,
      runs_external_binaries: false,
    });
  });

  it("scores reviewed browser extension signals with transparent contributions", () => {
    const output = scoreBrowserExtensionRisk(reviewedManifestOutput);

    expect(output.artifact).toMatchObject({
      id: "artifact_browser_extension_risk_score",
      type: "browser_extension_risk_score",
      source_review_artifact_id: "artifact_browser_extension_permission_review",
      source_artifact_id: "artifact_browser_extension_manifest",
      name: "Fixture Extension",
      version: "1.0.0",
      manifest_version: 3,
    });

    expect(output.observed.score_model).toBe("browser_extension_review_attention_v1");
    expect(output.observed.raw_score).toBe(113);
    expect(output.observed.score).toBe(100);
    expect(output.observed.capped).toBe(true);
    expect(output.observed.review_attention_level).toBe("very_high");
    expect(output.observed.risk_level).toBe("critical");
    expect(output.observed.confidence).toBe("high");
    expect(output.observed.contributing_signal_count).toBe(12);
    expect(output.observed.evidence_refs).toContain("evidence_browser_extension_001");
    expect(output.observed.category_scores).toEqual({
      api_permissions: 17,
      content_scripts: 16,
      distribution: 4,
      extension_runtime: 6,
      external_connectivity: 10,
      host_access: 42,
      identity: 4,
      policy_surface: 6,
      web_accessible_resources: 8,
    });
    expect(output.contributions).toHaveLength(12);
    expect(output.risk).toMatchObject({
      score: 100,
      level: "critical",
      confidence: "high",
    });
    expect(output.risk.signal_refs).toContain("signal_browser_extension_001");
    expect(output.risk.limitations?.[0]).toContain("review-attention score");
  });

  it("accepts a JSON run result from review_browser_extension_permissions", () => {
    const runResult = {
      run_id: "run_review",
      status: "completed",
      skill: { name: "review_browser_extension_permissions", version: "0.1.0" },
      output: reviewedManifestOutput,
      errors: [],
      warnings: [],
    };

    const output = scoreBrowserExtensionRisk(JSON.stringify(runResult));

    expect(output.observed.source_reviewer).toBe("review_browser_extension_permissions");
    expect(output.observed.score).toBe(100);
  });

  it("returns an informational score when no scored review signals are present", () => {
    const output = scoreBrowserExtensionRisk({
      artifact: {
        id: "artifact_browser_extension_permission_review",
        type: "browser_extension_permission_review",
        source_artifact_id: "artifact_browser_extension_manifest",
        source_artifact_type: "browser_extension_manifest",
        name: "Minimal",
        version: "1.0.0",
        manifest_version: 3,
      },
      observed: {
        source_reviewer: "review_browser_extension_permissions",
        source_warning_count: 0,
        evidence_count: 0,
        signal_count: 0,
      },
      evidence: [],
      signals: [],
      warnings: [],
    });

    expect(output.observed.score).toBe(0);
    expect(output.observed.raw_score).toBe(0);
    expect(output.observed.review_attention_level).toBe("none");
    expect(output.observed.risk_level).toBe("informational");
    expect(output.contributions).toEqual([]);
    expect(output.risk.rationale).toEqual(["No scored browser extension review signals were present."]);
  });

  it("reduces confidence when source warnings are present", () => {
    const output = scoreBrowserExtensionRisk({
      ...reviewedManifestOutput,
      observed: { ...reviewedManifestOutput.observed, source_warning_count: 1 },
    });

    expect(output.observed.confidence).toBe("medium");
    expect(output.warnings).toEqual([
      "Source review or parser warnings were present; score confidence was reduced to medium.",
    ]);
  });

  it("reports unmodeled signal types without scoring them", () => {
    const output = scoreBrowserExtensionRisk({
      ...reviewedManifestOutput,
      signals: [
        ...reviewedManifestOutput.signals,
        {
          id: "signal_browser_extension_999",
          type: "browser_extension.future_signal_present",
          summary: "Future signal.",
          evidence_refs: ["evidence_browser_extension_999"],
        },
      ],
    });

    expect(output.observed.unmatched_signal_types).toEqual(["browser_extension.future_signal_present"]);
    expect(output.observed.confidence).toBe("medium");
    expect(output.warnings).toEqual([
      "Unmodeled review signal type(s) were observed and not scored: browser_extension.future_signal_present.",
    ]);
  });

  it("rejects raw parsed manifest JSON that has not been reviewed", () => {
    expect(() => scoreBrowserExtensionRisk('{"artifact":{"type":"browser_extension_manifest"},"observed":{}}')).toThrow(
      "score_browser_extension_risk input must be review_browser_extension_permissions output with artifact, observed, and signals fields"
    );
  });

  it("rejects invalid JSON strings", () => {
    expect(() => scoreBrowserExtensionRisk("{bad json}")).toThrow(
      "score_browser_extension_risk input must be permission review JSON or a JSON run result from review_browser_extension_permissions"
    );
  });

  it("rejects non-reviewer output", () => {
    expect(() =>
      scoreBrowserExtensionRisk({
        artifact: { id: "artifact_package_json", type: "package_json" },
        observed: {},
        signals: [],
      })
    ).toThrow("score_browser_extension_risk input artifact.type must be browser_extension_permission_review");
  });
});
