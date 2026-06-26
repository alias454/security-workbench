import { describe, expect, it } from "vitest";
import {
  countLinesSkill,
  dedupeLinesSkill,
  removeEmptyLinesSkill,
  sortLinesSkill,
  trimLinesSkill,
} from "../src/lineUtils.js";

describe("trim_lines", () => {
  it("trims each logical line and preserves trailing newline", async () => {
    const result = await trimLinesSkill.run(" one \n\ttwo\t\n");

    expect(result).toEqual({
      text: "one\ntwo\n",
      original_line_count: 2,
      changed_line_count: 2,
    });
  });

  it("handles empty input", async () => {
    const result = await trimLinesSkill.run("");

    expect(result).toEqual({
      text: "",
      original_line_count: 0,
      changed_line_count: 0,
    });
  });

  it("rejects non-string input", async () => {
    await expect(
      async () => await trimLinesSkill.run(123 as unknown as string)
    ).rejects.toThrow("trim_lines input must be a string");
  });
});

describe("remove_empty_lines", () => {
  it("removes empty and whitespace-only lines", async () => {
    const result = await removeEmptyLinesSkill.run("alpha\n\n  \nbeta\n");

    expect(result).toEqual({
      text: "alpha\nbeta\n",
      original_line_count: 4,
      kept_line_count: 2,
      removed_line_count: 2,
      removes_whitespace_only_lines: true,
    });
  });

  it("returns empty output when all lines are empty", async () => {
    const result = await removeEmptyLinesSkill.run("\n  \n\t\n");

    expect(result).toEqual({
      text: "",
      original_line_count: 3,
      kept_line_count: 0,
      removed_line_count: 3,
      removes_whitespace_only_lines: true,
    });
  });

  it("rejects non-string input", async () => {
    await expect(
      async () => await removeEmptyLinesSkill.run(123 as unknown as string)
    ).rejects.toThrow("remove_empty_lines input must be a string");
  });
});

describe("dedupe_lines", () => {
  it("deduplicates exact lines while preserving first-seen order", async () => {
    const result = await dedupeLinesSkill.run("beta\nalpha\nbeta\nAlpha\nalpha\n");

    expect(result).toEqual({
      text: "beta\nalpha\nAlpha\n",
      original_line_count: 5,
      unique_line_count: 3,
      removed_line_count: 2,
      case_sensitive: true,
    });
  });

  it("handles empty input", async () => {
    const result = await dedupeLinesSkill.run("");

    expect(result).toEqual({
      text: "",
      original_line_count: 0,
      unique_line_count: 0,
      removed_line_count: 0,
      case_sensitive: true,
    });
  });

  it("rejects non-string input", async () => {
    await expect(
      async () => await dedupeLinesSkill.run(123 as unknown as string)
    ).rejects.toThrow("dedupe_lines input must be a string");
  });
});

describe("sort_lines", () => {
  it("sorts lines using deterministic case-sensitive code-unit order", async () => {
    const result = await sortLinesSkill.run("beta\nalpha\nAlpha\n192.168.1.10\n");

    expect(result).toEqual({
      text: "192.168.1.10\nAlpha\nalpha\nbeta\n",
      original_line_count: 4,
      sorted_line_count: 4,
      order: "ascending",
      case_sensitive: true,
    });
  });

  it("rejects non-string input", async () => {
    await expect(
      async () => await sortLinesSkill.run(123 as unknown as string)
    ).rejects.toThrow("sort_lines input must be a string");
  });
});

describe("count_lines", () => {
  it("counts total, empty, and non-empty logical lines", async () => {
    const result = await countLinesSkill.run("alpha\n\n  \nbeta\n");

    expect(result).toEqual({
      line_count: 4,
      non_empty_line_count: 2,
      empty_line_count: 2,
      trailing_newline: true,
    });
  });

  it("counts empty input as zero lines", async () => {
    const result = await countLinesSkill.run("");

    expect(result).toEqual({
      line_count: 0,
      non_empty_line_count: 0,
      empty_line_count: 0,
      trailing_newline: false,
    });
  });

  it("normalizes CRLF and CR line endings", async () => {
    const result = await countLinesSkill.run("alpha\r\nbeta\rgamma");

    expect(result).toEqual({
      line_count: 3,
      non_empty_line_count: 3,
      empty_line_count: 0,
      trailing_newline: false,
    });
  });

  it("rejects non-string input", async () => {
    await expect(
      async () => await countLinesSkill.run(123 as unknown as string)
    ).rejects.toThrow("count_lines input must be a string");
  });
});
