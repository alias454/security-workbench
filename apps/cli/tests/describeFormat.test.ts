import { describe, expect, it } from "vitest";
import type { Skill } from "@security-workbench/schemas";
import { formatSkillDescription } from "../src/describeFormat.js";

function fakeSkill(): Skill<unknown, unknown> {
  return {
    metadata: {
      name: "parse_jwt",
      version: "0.1.0",
      category: "parser",
      description:
        "Decode JWT header and payload without verifying the signature or exposing the raw signature.",
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
    run: () => ({ ok: true }),
  } as unknown as Skill<unknown, unknown>;
}

describe("formatSkillDescription", () => {
  it("formats table output as property/value rows", () => {
    const output = formatSkillDescription(fakeSkill(), { format: "table" });

    expect(output).toContain("Property");
    expect(output).toContain("Value");
    expect(output).toContain("Name");
    expect(output).toContain("parse_jwt");
    expect(output).toContain("Category");
    expect(output).toContain("parser");
    expect(output).toContain("Network access");
    expect(output).toContain("none");
    expect(output).toContain("Permission: external binaries");
    expect(output).toContain("false");
  });

  it("formats JSON output as structured metadata", () => {
    const output = formatSkillDescription(fakeSkill(), { format: "json" });
    const parsed = JSON.parse(output) as Record<string, unknown>;

    expect(parsed).toEqual({
      name: "parse_jwt",
      version: "0.1.0",
      category: "parser",
      description:
        "Decode JWT header and payload without verifying the signature or exposing the raw signature.",
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
    });
  });

  it("formats TSV output as property/value rows", () => {
    const output = formatSkillDescription(fakeSkill(), { format: "tsv" });

    expect(output).toContain("Name\tparse_jwt");
    expect(output).toContain("Category\tparser");
    expect(output).toContain("Permission: sends\t[]");
    expect(output).toContain("Permission: persists\tfalse");
  });
});
