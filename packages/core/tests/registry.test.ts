import { describe, expect, it } from "vitest";
import type { Skill } from "@security-workbench/schemas";
import { SkillRegistry } from "../src/registry.js";

const fakeSkill: Skill<string, { ok: boolean }> = {
  metadata: {
    name: "fake_skill",
    version: "0.1.0",
    category: "transform",
    description: "Fake test skill.",
    execution: {
      mode: "local_only",
      network_access: "none",
      deterministic: true,
    },
  },

  run() {
    return { ok: true };
  },
};

describe("SkillRegistry", () => {
  it("registers and lists skills", () => {
    const registry = new SkillRegistry();

    registry.register(fakeSkill);

    expect(registry.list()).toEqual([fakeSkill]);
  });

  it("gets a registered skill by name", () => {
    const registry = new SkillRegistry();

    registry.register(fakeSkill);

    expect(registry.get("fake_skill")).toBe(fakeSkill);
  });

  it("rejects duplicate skill names", () => {
    const registry = new SkillRegistry();

    registry.register(fakeSkill);

    expect(() => registry.register(fakeSkill)).toThrow(
      "Skill already registered: fake_skill"
    );
  });

  it("rejects unknown skills", () => {
    const registry = new SkillRegistry();

    expect(() => registry.get("missing_skill")).toThrow(
      "Unknown skill: missing_skill"
    );
  });
});
