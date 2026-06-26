import { describe, expect, it } from "vitest";
import type { Skill } from "@security-workbench/schemas";
import { formatSkillList } from "../src/listFormat.js";

function fakeSkill(
  name: string,
  category: string,
  description: string,
  networkAccess = "none"
): Skill<unknown, unknown> {
  return {
    metadata: {
      name,
      version: "0.1.0",
      category,
      description,
      execution: {
        mode: "local_only",
        network_access: networkAccess,
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

const skills = [
  fakeSkill("base64_decode", "transform", "Decode Base64."),
  fakeSkill("parse_url", "parser", "Parse a URL."),
  fakeSkill("parse_jwt", "parser", "Parse a JWT."),
];

describe("formatSkillList", () => {
  it("formats default TSV as name and description only", () => {
    expect(formatSkillList(skills, { format: "tsv" })).toBe(
      [
        "base64_decode\tDecode Base64.",
        "parse_url\tParse a URL.",
        "parse_jwt\tParse a JWT.",
      ].join("\n")
    );
  });

  it("filters TSV output by category", () => {
    expect(formatSkillList(skills, { format: "tsv", category: "parser" })).toBe(
      ["parse_url\tParse a URL.", "parse_jwt\tParse a JWT."].join("\n")
    );
  });

  it("formats table output with category and network columns", () => {
    const output = formatSkillList(skills, { format: "table" });

    expect(output).toContain("Skill");
    expect(output).toContain("Category");
    expect(output).toContain("Network");
    expect(output).toContain("Description");
    expect(output).toContain("base64_decode");
    expect(output).toContain("transform");
    expect(output).toContain("parse_url");
    expect(output).toContain("parser");
  });

  it("filters table output by category", () => {
    const output = formatSkillList(skills, { format: "table", category: "parser" });

    expect(output).toContain("parse_url");
    expect(output).toContain("parse_jwt");
    expect(output).not.toContain("base64_decode");
  });

  it("formats JSON output with structured metadata", () => {
    const output = formatSkillList(skills, { format: "json", category: "parser" });
    const parsed = JSON.parse(output) as Array<Record<string, unknown>>;

    expect(parsed).toEqual([
      {
        name: "parse_url",
        version: "0.1.0",
        category: "parser",
        network_access: "none",
        description: "Parse a URL.",
      },
      {
        name: "parse_jwt",
        version: "0.1.0",
        category: "parser",
        network_access: "none",
        description: "Parse a JWT.",
      },
    ]);
  });

  it("returns empty TSV for empty selections", () => {
    expect(formatSkillList(skills, { format: "tsv", category: "output" })).toBe("");
  });

  it("returns an empty JSON array for empty selections", () => {
    expect(formatSkillList(skills, { format: "json", category: "output" })).toBe("[]");
  });
});
