import { describe, expect, it } from "vitest";
import type { SkillMetadata } from "../src/index.js";
import {
  deploymentProfileValues,
  exposureDefaultValues,
  exposureForProfile,
  exposureRiskValues,
  isDeploymentProfile,
  isExposureDefault,
  isExposureRisk,
  isToolSurface,
  toolSurfaceValues,
  type SkillExposurePolicy,
} from "../src/exposure.js";

describe("exposure policy contracts", () => {
  const parserExposure: SkillExposurePolicy = {
    surfaces: ["cli", "api", "web", "mcp"],
    default_exposure: "enabled",
    hosted_default: "allowlist_only",
    requires_authentication: true,
    rate_limit_recommended: true,
    audit_required: true,
    max_input_mb: 1,
    risk: "low",
    rationale: [
      "Parses attacker-controlled artifact text.",
      "Does not perform network calls, persistence, or external process execution.",
    ],
  };

  it("exports stable surface, profile, exposure, and risk vocabularies", () => {
    expect(toolSurfaceValues).toEqual(["cli", "api", "web", "mcp"]);
    expect(deploymentProfileValues).toEqual(["local", "self_hosted", "hosted"]);
    expect(exposureDefaultValues).toEqual(["enabled", "disabled", "allowlist_only"]);
    expect(exposureRiskValues).toEqual(["low", "medium", "high"]);
  });

  it("provides narrow runtime guards for exposure vocabularies", () => {
    expect(isToolSurface("mcp")).toBe(true);
    expect(isToolSurface("shell")).toBe(false);
    expect(isDeploymentProfile("hosted")).toBe(true);
    expect(isDeploymentProfile("public_cloud")).toBe(false);
    expect(isExposureDefault("allowlist_only")).toBe(true);
    expect(isExposureDefault("public")).toBe(false);
    expect(isExposureRisk("medium")).toBe(true);
    expect(isExposureRisk("critical")).toBe(false);
  });

  it("uses hosted_default for hosted exposure decisions", () => {
    expect(exposureForProfile(parserExposure, "mcp", "hosted")).toEqual({
      surface: "mcp",
      profile: "hosted",
      exposure: "allowlist_only",
      requires_authentication: true,
      rate_limit_recommended: true,
      audit_required: true,
      max_input_mb: 1,
      risk: "low",
      rationale: parserExposure.rationale,
    });
  });

  it("disables undeclared surfaces even when the skill has a default exposure", () => {
    const cliOnly: SkillExposurePolicy = {
      ...parserExposure,
      surfaces: ["cli"],
    };

    const decision = exposureForProfile(cliOnly, "mcp", "self_hosted");

    expect(decision.exposure).toBe("disabled");
    expect(decision.rationale).toContain("Skill does not declare support for mcp exposure.");
  });

  it("allows SkillMetadata to carry optional exposure policy without changing runtime behavior", () => {
    const metadata: SkillMetadata = {
      name: "parse_example",
      version: "0.1.0",
      category: "parser",
      description: "Parse an example artifact.",
      execution: {
        mode: "local_only",
        network_access: "none",
        deterministic: true,
      },
      permissions: {
        network: "none",
        filesystem: "none",
        sends: [],
        persists: false,
        runs_external_binaries: false,
      },
      exposure: parserExposure,
    };

    expect(metadata.exposure?.hosted_default).toBe("allowlist_only");
  });
});
