import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { describe, expect, it } from "vitest";
import { parseCliArgs, readBoundedUtf8File } from "../src/args.js";

describe("parseCliArgs", () => {
  it("parses skills list with default TSV format", () => {
    expect(parseCliArgs(["skills", "list"])).toEqual({
      kind: "skills_list",
      options: { format: "tsv", category: undefined },
    });
  });

  it("parses skills list with table format", () => {
    expect(parseCliArgs(["skills", "list", "--format", "table"])).toEqual({
      kind: "skills_list",
      options: { format: "table", category: undefined },
    });
  });

  it("parses skills list with JSON format", () => {
    expect(parseCliArgs(["skills", "list", "--format", "json"])).toEqual({
      kind: "skills_list",
      options: { format: "json", category: undefined },
    });
  });

  it("parses skills list with TSV format", () => {
    expect(parseCliArgs(["skills", "list", "--format", "tsv"])).toEqual({
      kind: "skills_list",
      options: { format: "tsv", category: undefined },
    });
  });

  it("parses skills list with category filter", () => {
    expect(parseCliArgs(["skills", "list", "--category", "parser"])).toEqual({
      kind: "skills_list",
      options: { format: "tsv", category: "parser" },
    });
  });

  it("parses skills list with category filter and format", () => {
    expect(
      parseCliArgs([
        "skills",
        "list",
        "--category",
        "transform",
        "--format",
        "table",
      ])
    ).toEqual({
      kind: "skills_list",
      options: { format: "table", category: "transform" },
    });
  });

  it("rejects unsupported list formats", () => {
    expect(() =>
      parseCliArgs(["skills", "list", "--format", "markdown"])
    ).toThrow("Unsupported --format value: markdown");
  });

  it("rejects unsupported list categories", () => {
    expect(() =>
      parseCliArgs(["skills", "list", "--category", "banana"])
    ).toThrow("Unsupported --category value: banana");
  });

  it("rejects duplicate --format flags on skills list", () => {
    expect(() =>
      parseCliArgs([
        "skills",
        "list",
        "--format",
        "table",
        "--format",
        "json",
      ])
    ).toThrow("Duplicate --format flag");
  });

  it("rejects duplicate --category flags", () => {
    expect(() =>
      parseCliArgs([
        "skills",
        "list",
        "--category",
        "parser",
        "--category",
        "transform",
      ])
    ).toThrow("Duplicate --category flag");
  });

  it("rejects unexpected skills list positionals", () => {
    expect(() => parseCliArgs(["skills", "list", "extra"])).toThrow(
      "Unexpected argument: extra"
    );
  });

  it("parses skills run with inline input and default JSON format", () => {
    expect(
      parseCliArgs(["skills", "run", "base64_decode", "--input", "SGVsbG8="])
    ).toEqual({
      kind: "skills_run",
      skillName: "base64_decode",
      input_source: { kind: "inline", value: "SGVsbG8=" },
      options: { format: "json" },
    });
  });

  it("parses skills run with file input and default JSON format", () => {
    expect(
      parseCliArgs(["skills", "run", "json_format", "--input-file", "input.json"])
    ).toEqual({
      kind: "skills_run",
      skillName: "json_format",
      input_source: { kind: "file", path: "input.json" },
      options: { format: "json" },
    });
  });

  it("parses skills run with explicit JSON format", () => {
    expect(
      parseCliArgs([
        "skills",
        "run",
        "base64_encode",
        "--input",
        "Hello",
        "--format",
        "json",
      ])
    ).toEqual({
      kind: "skills_run",
      skillName: "base64_encode",
      input_source: { kind: "inline", value: "Hello" },
      options: { format: "json" },
    });
  });

  it("parses skills run with pretty format", () => {
    expect(
      parseCliArgs([
        "skills",
        "run",
        "base64_encode",
        "--format",
        "pretty",
        "--input",
        "Hello",
      ])
    ).toEqual({
      kind: "skills_run",
      skillName: "base64_encode",
      input_source: { kind: "inline", value: "Hello" },
      options: { format: "pretty" },
    });
  });

  it("parses skills run with pretty format and unsafe display", () => {
    expect(
      parseCliArgs([
        "skills",
        "run",
        "extract_iocs",
        "--format",
        "pretty",
        "--unsafe",
        "--input",
        "https://evil.example.com",
      ])
    ).toEqual({
      kind: "skills_run",
      skillName: "extract_iocs",
      input_source: { kind: "inline", value: "https://evil.example.com" },
      options: { format: "pretty", unsafe: true },
    });
  });

  it("rejects unsafe display with JSON run output", () => {
    expect(() =>
      parseCliArgs([
        "skills",
        "run",
        "extract_iocs",
        "--input",
        "https://evil.example.com",
        "--format",
        "json",
        "--unsafe",
      ])
    ).toThrow("--unsafe is only supported with --format pretty");
  });

  it("rejects duplicate unsafe flags on skills run", () => {
    expect(() =>
      parseCliArgs([
        "skills",
        "run",
        "extract_iocs",
        "--input",
        "https://evil.example.com",
        "--format",
        "pretty",
        "--unsafe",
        "--unsafe",
      ])
    ).toThrow("Duplicate --unsafe flag");
  });

  it("rejects unsupported skills run formats", () => {
    expect(() =>
      parseCliArgs(["skills", "run", "json_format", "--input", "{}", "--format", "table"])
    ).toThrow("Unsupported --format value: table");
  });

  it("rejects duplicate --format flags on skills run", () => {
    expect(() =>
      parseCliArgs([
        "skills",
        "run",
        "json_format",
        "--input",
        "{}",
        "--format",
        "json",
        "--format",
        "pretty",
      ])
    ).toThrow("Duplicate --format flag");
  });

  it("rejects category filters on skills run", () => {
    expect(() =>
      parseCliArgs(["skills", "run", "json_format", "--input", "{}", "--category", "transform"])
    ).toThrow("Unknown flag: --category");
  });

  it("rejects both inline and file input", () => {
    expect(() =>
      parseCliArgs([
        "skills",
        "run",
        "json_format",
        "--input",
        "{}",
        "--input-file",
        "input.json",
      ])
    ).toThrow("Use either --input or --input-file, not both");
  });

  it("rejects missing input source", () => {
    expect(() => parseCliArgs(["skills", "run", "json_format"])).toThrow(
      "Usage: skills run <skill_name> (--input <value> | --input-file <path>) [--format json|pretty] [--unsafe]"
    );
  });

  it("rejects unknown flags", () => {
    expect(() =>
      parseCliArgs(["skills", "run", "base64_decode", "--wat", "SGVsbG8="])
    ).toThrow("Unknown flag: --wat");
  });

  it("rejects duplicate --input flags", () => {
    expect(() =>
      parseCliArgs([
        "skills",
        "run",
        "base64_decode",
        "--input",
        "one",
        "--input",
        "two",
      ])
    ).toThrow("Duplicate --input flag");
  });

  it("rejects duplicate --input-file flags", () => {
    expect(() =>
      parseCliArgs([
        "skills",
        "run",
        "json_format",
        "--input-file",
        "one.json",
        "--input-file",
        "two.json",
      ])
    ).toThrow("Duplicate --input-file flag");
  });
});

describe("readBoundedUtf8File", () => {
  it("reads a bounded UTF-8 file", async () => {
    const dir = await mkdtemp(join(tmpdir(), "security-workbench-cli-"));

    try {
      const file = join(dir, "input.txt");
      await writeFile(file, "Hello from file", "utf8");

      await expect(readBoundedUtf8File(file, 1024)).resolves.toBe(
        "Hello from file"
      );
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("rejects directories", async () => {
    const dir = await mkdtemp(join(tmpdir(), "security-workbench-cli-"));

    try {
      await expect(readBoundedUtf8File(dir, 1024)).rejects.toThrow(
        "--input-file must point to a regular file"
      );
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("rejects oversized files before read", async () => {
    const dir = await mkdtemp(join(tmpdir(), "security-workbench-cli-"));

    try {
      const file = join(dir, "oversized.txt");
      await writeFile(file, "12345", "utf8");

      await expect(readBoundedUtf8File(file, 4)).rejects.toThrow(
        "Input file exceeds maximum size of 4 bytes before read"
      );
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("rejects invalid UTF-8", async () => {
    const dir = await mkdtemp(join(tmpdir(), "security-workbench-cli-"));

    try {
      const file = join(dir, "invalid.bin");
      await writeFile(file, Buffer.from([0xff, 0xfe, 0xfd]));

      await expect(readBoundedUtf8File(file, 1024)).rejects.toThrow(
        "Input file must be valid UTF-8"
      );
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("rejects empty file paths", async () => {
    await expect(readBoundedUtf8File("   ", 1024)).rejects.toThrow(
      "--input-file requires a non-empty path"
    );
  });
});
