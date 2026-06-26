import { describe, expect, it } from "vitest";
import type { Skill } from "@security-workbench/schemas";
import { SkillRegistry } from "../src/registry.js";
import { SkillRunner } from "../src/runner.js";

const localSkill: Skill<string, { echoed: string }> = {
  metadata: {
    name: "echo",
    version: "0.1.0",
    category: "transform",
    description: "Echo input.",
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
  },

  run(input: string) {
    if (typeof input !== "string") {
      throw new Error("echo input must be a string");
    }

    return { echoed: input };
  },
};

const networkOptionalSkill: Skill<string, { ok: boolean }> = {
  metadata: {
    name: "network_optional_test",
    version: "0.1.0",
    category: "enrichment",
    description: "Network-optional test skill.",
    execution: {
      mode: "network_optional",
      network_access: "optional",
      deterministic: true,
    },
    permissions: {
      network: "optional",
      filesystem: "none",
      sends: ["domain"],
      persists: false,
      runs_external_binaries: false,
    },
  },

  run() {
    return { ok: true };
  },
};

const networkRequiredSkill: Skill<string, { ok: boolean }> = {
  metadata: {
    name: "network_required_test",
    version: "0.1.0",
    category: "enrichment",
    description: "Network-required test skill.",
    execution: {
      mode: "network_required",
      network_access: "required",
      deterministic: true,
    },
    permissions: {
      network: "required",
      filesystem: "none",
      sends: ["input"],
      persists: false,
      runs_external_binaries: false,
    },
  },

  run() {
    return { ok: true };
  },
};

const invalidSendsSkill: Skill<string, { ok: boolean }> = {
  metadata: {
    name: "invalid_sends_test",
    version: "0.1.0",
    category: "transform",
    description: "Invalid sends test skill.",
    execution: {
      mode: "local_only",
      network_access: "none",
      deterministic: true,
    },
    permissions: {
      network: "none",
      filesystem: "none",
      sends: ["domain"],
      persists: false,
      runs_external_binaries: false,
    },
  },

  run() {
    return { ok: true };
  },
};

const missingNetworkPermissionsSkill: Skill<string, { ok: boolean }> = {
  metadata: {
    name: "missing_network_permissions_test",
    version: "0.1.0",
    category: "enrichment",
    description: "Missing network permissions test skill.",
    execution: {
      mode: "network_optional",
      network_access: "optional",
      deterministic: true,
    },
  },

  run() {
    return { ok: true };
  },
};

const secretEchoSkill: Skill<string, { echoed: string }> = {
  metadata: {
    name: "secret_echo",
    version: "0.1.0",
    category: "transform",
    description: "Echo secret-like input.",
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
  },

  run(input: string) {
    return { echoed: input };
  },
};

describe("SkillRunner", () => {
  it("returns completed result for a valid skill", async () => {
    const registry = new SkillRegistry();
    registry.register(localSkill);

    const runner = new SkillRunner(registry);
    const result = await runner.run("echo", "hello");

    expect(result.status).toBe("completed");
    expect(result.skill).toEqual({
      name: "echo",
      version: "0.1.0",
    });
    expect(result.policy).toEqual({
      allow_network: false,
      network_used: false,
      external_sinks: [],
    });
    expect(result.output).toEqual({ echoed: "hello" });
    expect(result.errors).toEqual([]);
  });

  it("returns failed result with known skill metadata when execution throws", async () => {
    const registry = new SkillRegistry();
    registry.register(localSkill);

    const runner = new SkillRunner(registry);
    const result = await runner.run("echo", 123);

    expect(result.status).toBe("failed");
    expect(result.skill).toEqual({
      name: "echo",
      version: "0.1.0",
    });
    expect(result.errors).toEqual(["echo input must be a string"]);
  });

  it("returns failed result for an unknown skill", async () => {
    const registry = new SkillRegistry();
    const runner = new SkillRunner(registry);

    const result = await runner.run("missing_skill", "hello");

    expect(result.status).toBe("failed");
    expect(result.skill).toEqual({
      name: "missing_skill",
      version: "unknown",
    });
    expect(result.errors).toEqual(["Unknown skill: missing_skill"]);
  });

  it("refuses network-optional skills when network is disabled", async () => {
    const registry = new SkillRegistry();
    registry.register(networkOptionalSkill);

    const runner = new SkillRunner(registry);
    const result = await runner.run("network_optional_test", "example.com");

    expect(result.status).toBe("refused");
    expect(result.skill).toEqual({
      name: "network_optional_test",
      version: "0.1.0",
    });
    expect(result.errors).toEqual([
      "Policy refused skill 'network_optional_test': network access is optional but disabled",
    ]);
  });

  it("refuses network-required skills when network is disabled", async () => {
    const registry = new SkillRegistry();
    registry.register(networkRequiredSkill);

    const runner = new SkillRunner(registry);
    const result = await runner.run("network_required_test", "hello");

    expect(result.status).toBe("refused");
    expect(result.skill).toEqual({
      name: "network_required_test",
      version: "0.1.0",
    });
    expect(result.errors).toEqual([
      "Policy refused skill 'network_required_test': network access is required but disabled",
    ]);
  });

  it("refuses network skills with unapproved external sinks", async () => {
    const registry = new SkillRegistry();
    registry.register(networkOptionalSkill);

    const runner = new SkillRunner(registry);
    const result = await runner.run("network_optional_test", "example.com", {
      allow_network: true,
    });

    expect(result.status).toBe("refused");
    expect(result.errors).toEqual([
      "Policy refused skill 'network_optional_test': external sinks not approved: domain",
    ]);
  });

  it("allows network-optional skills when network and sinks are approved", async () => {
    const registry = new SkillRegistry();
    registry.register(networkOptionalSkill);

    const runner = new SkillRunner(registry);
    const result = await runner.run("network_optional_test", "example.com", {
      allow_network: true,
      approved_sinks: ["domain"],
    });

    expect(result.status).toBe("completed");
    expect(result.policy).toEqual({
      allow_network: true,
      network_used: true,
      external_sinks: ["domain"],
    });
    expect(result.output).toEqual({ ok: true });
  });

  it("allows network-required skills when network and sinks are approved", async () => {
    const registry = new SkillRegistry();
    registry.register(networkRequiredSkill);

    const runner = new SkillRunner(registry);
    const result = await runner.run("network_required_test", "hello", {
      allow_network: true,
      approved_sinks: ["input"],
    });

    expect(result.status).toBe("completed");
    expect(result.output).toEqual({ ok: true });
  });

  it("fails invalid metadata when sends are declared without network access", async () => {
    const registry = new SkillRegistry();
    registry.register(invalidSendsSkill);

    const runner = new SkillRunner(registry);
    const result = await runner.run("invalid_sends_test", "example.com");

    expect(result.status).toBe("failed");
    expect(result.errors).toEqual([
      "Invalid skill metadata for 'invalid_sends_test': permissions.sends requires network access declaration",
    ]);
  });

  it("fails network-capable skills without permissions metadata", async () => {
    const registry = new SkillRegistry();
    registry.register(missingNetworkPermissionsSkill);

    const runner = new SkillRunner(registry);
    const result = await runner.run("missing_network_permissions_test", "example.com", {
      allow_network: true,
    });

    expect(result.status).toBe("failed");
    expect(result.errors).toEqual([
      "Invalid skill metadata for 'missing_network_permissions_test': network-capable skills require permissions metadata",
    ]);
  });

  it("refuses oversized input before running a skill", async () => {
    const registry = new SkillRegistry();
    registry.register(localSkill);

    const runner = new SkillRunner(registry);
    const result = await runner.run("echo", "too-large", {
      max_artifact_size_mb: 0.000001,
    });

    expect(result.status).toBe("refused");
    expect(result.errors[0]).toMatch(/Input refused:/);
  });

  it("redacts secret-like output by default", async () => {
    const registry = new SkillRegistry();
    registry.register(secretEchoSkill);

    const runner = new SkillRunner(registry);
    const result = await runner.run(
      "secret_echo",
      "https://user:pass@example.com/path"
    );

    expect(result.output).toEqual({
      echoed: "https://[REDACTED]@example.com/path",
    });
  });
});
