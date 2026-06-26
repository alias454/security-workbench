import { describe, expect, it } from "vitest";
import { parseCliArgs } from "../src/args.js";

describe("parseCliArgs skills describe", () => {
  it("parses skills describe with default table format", () => {
    expect(parseCliArgs(["skills", "describe", "parse_jwt"])).toEqual({
      kind: "skills_describe",
      skillName: "parse_jwt",
      options: { format: "table" },
    });
  });

  it("parses skills describe with JSON format", () => {
    expect(
      parseCliArgs(["skills", "describe", "parse_jwt", "--format", "json"])
    ).toEqual({
      kind: "skills_describe",
      skillName: "parse_jwt",
      options: { format: "json" },
    });
  });

  it("parses skills describe with TSV format", () => {
    expect(
      parseCliArgs(["skills", "describe", "parse_jwt", "--format", "tsv"])
    ).toEqual({
      kind: "skills_describe",
      skillName: "parse_jwt",
      options: { format: "tsv" },
    });
  });

  it("rejects missing skill name", () => {
    expect(() => parseCliArgs(["skills", "describe"])).toThrow(
      "Usage: skills describe <skill_name> [--format table|json|tsv]"
    );
  });

  it("rejects unsupported formats", () => {
    expect(() =>
      parseCliArgs(["skills", "describe", "parse_jwt", "--format", "markdown"])
    ).toThrow("Unsupported --format value: markdown");
  });

  it("rejects duplicate format flags", () => {
    expect(() =>
      parseCliArgs([
        "skills",
        "describe",
        "parse_jwt",
        "--format",
        "table",
        "--format",
        "json",
      ])
    ).toThrow("Duplicate --format flag");
  });

  it("rejects category filters on describe", () => {
    expect(() =>
      parseCliArgs(["skills", "describe", "parse_jwt", "--category", "parser"])
    ).toThrow("Unknown flag: --category");
  });

  it("rejects unexpected describe positionals", () => {
    expect(() =>
      parseCliArgs(["skills", "describe", "parse_jwt", "extra"])
    ).toThrow("Unexpected argument: extra");
  });
});
