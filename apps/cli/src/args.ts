import { readFile, stat } from "node:fs/promises";
import { TextDecoder } from "node:util";
import { UsageError } from "@security-workbench/core";
import { skillCategoryValues, type SkillCategory } from "@security-workbench/schemas";

export const CLI_LIST_FORMATS = ["tsv", "table", "json"] as const;
export type CliListFormat = (typeof CLI_LIST_FORMATS)[number];

export const CLI_RUN_FORMATS = ["json", "pretty"] as const;
export type CliRunFormat = (typeof CLI_RUN_FORMATS)[number];

export const CLI_LIST_CATEGORIES = skillCategoryValues;
export type CliListCategory = SkillCategory;

export interface CliSkillsListOptions {
  format: CliListFormat;
  category?: CliListCategory;
}

export interface CliSkillsDescribeOptions {
  format: CliListFormat;
}

export interface CliSkillsRunOptions {
  format: CliRunFormat;
  unsafe?: boolean;
}

export type CliInputSource =
  | { kind: "inline"; value: string }
  | { kind: "file"; path: string };

export type CliCommand =
  | { kind: "help" }
  | { kind: "skills_list"; options: CliSkillsListOptions }
  | { kind: "skills_describe"; skillName: string; options: CliSkillsDescribeOptions }
  | {
      kind: "skills_run";
      skillName: string;
      input_source: CliInputSource;
      options: CliSkillsRunOptions;
    };

const SKILLS_RUN_USAGE =
  "Usage: skills run <skill_name> (--input <value> | --input-file <path>) [--format json|pretty] [--unsafe]";
const SKILLS_LIST_USAGE =
  "Usage: skills list [--category <category>] [--format table|json|tsv]";
const SKILLS_DESCRIBE_USAGE =
  "Usage: skills describe <skill_name> [--format table|json|tsv]";

function requireFlagValue(argv: string[], index: number, flag: string): string {
  const value = argv[index + 1];

  if (value === undefined) {
    throw new UsageError(`${flag} requires a value`);
  }

  return value;
}

function parseListFormat(value: string): CliListFormat {
  if ((CLI_LIST_FORMATS as readonly string[]).includes(value)) {
    return value as CliListFormat;
  }

  throw new UsageError(
    `Unsupported --format value: ${value}. Supported values: ${CLI_LIST_FORMATS.join(", ")}`
  );
}

function parseRunFormat(value: string): CliRunFormat {
  if ((CLI_RUN_FORMATS as readonly string[]).includes(value)) {
    return value as CliRunFormat;
  }

  throw new UsageError(
    `Unsupported --format value: ${value}. Supported values: ${CLI_RUN_FORMATS.join(", ")}`
  );
}

function parseListCategory(value: string): CliListCategory {
  if ((CLI_LIST_CATEGORIES as readonly string[]).includes(value)) {
    return value as CliListCategory;
  }

  throw new UsageError(
    `Unsupported --category value: ${value}. Supported values: ${CLI_LIST_CATEGORIES.join(", ")}`
  );
}

function parseSkillsListArgs(argv: string[]): CliCommand {
  let format: CliListFormat = "tsv";
  let category: CliListCategory | undefined;
  let seenFormat = false;
  let seenCategory = false;

  for (let index = 2; index < argv.length; index += 1) {
    const token = argv[index];

    if (token === "--format") {
      if (seenFormat) {
        throw new UsageError("Duplicate --format flag");
      }

      format = parseListFormat(requireFlagValue(argv, index, "--format"));
      seenFormat = true;
      index += 1;
      continue;
    }

    if (token === "--category") {
      if (seenCategory) {
        throw new UsageError("Duplicate --category flag");
      }

      category = parseListCategory(requireFlagValue(argv, index, "--category"));
      seenCategory = true;
      index += 1;
      continue;
    }

    if (token.startsWith("--")) {
      throw new UsageError(`Unknown flag: ${token}`);
    }

    throw new UsageError(`${SKILLS_LIST_USAGE}. Unexpected argument: ${token}`);
  }

  return { kind: "skills_list", options: { format, category } };
}

function parseSkillsDescribeArgs(argv: string[]): CliCommand {
  const skillName = argv[2];

  if (!skillName || skillName.startsWith("--")) {
    throw new UsageError(SKILLS_DESCRIBE_USAGE);
  }

  let format: CliListFormat = "table";
  let seenFormat = false;

  for (let index = 3; index < argv.length; index += 1) {
    const token = argv[index];

    if (token === "--format") {
      if (seenFormat) {
        throw new UsageError("Duplicate --format flag");
      }

      format = parseListFormat(requireFlagValue(argv, index, "--format"));
      seenFormat = true;
      index += 1;
      continue;
    }

    if (token.startsWith("--")) {
      throw new UsageError(`Unknown flag: ${token}`);
    }

    throw new UsageError(`${SKILLS_DESCRIBE_USAGE}. Unexpected argument: ${token}`);
  }

  return { kind: "skills_describe", skillName, options: { format } };
}

function parseSkillsRunArgs(argv: string[]): CliCommand {
  const skillName = argv[2];

  if (!skillName) {
    throw new UsageError(SKILLS_RUN_USAGE);
  }

  let inlineInput: string | undefined;
  let inputFile: string | undefined;
  let format: CliRunFormat = "json";
  let seenFormat = false;
  let seenUnsafe = false;

  for (let index = 3; index < argv.length; index += 1) {
    const token = argv[index];

    if (token === "--input") {
      if (inlineInput !== undefined) {
        throw new UsageError("Duplicate --input flag");
      }

      inlineInput = requireFlagValue(argv, index, "--input");
      index += 1;
      continue;
    }

    if (token === "--input-file") {
      if (inputFile !== undefined) {
        throw new UsageError("Duplicate --input-file flag");
      }

      inputFile = requireFlagValue(argv, index, "--input-file");
      index += 1;
      continue;
    }

    if (token === "--format") {
      if (seenFormat) {
        throw new UsageError("Duplicate --format flag");
      }

      format = parseRunFormat(requireFlagValue(argv, index, "--format"));
      seenFormat = true;
      index += 1;
      continue;
    }

    if (token === "--unsafe") {
      if (seenUnsafe) {
        throw new UsageError("Duplicate --unsafe flag");
      }

      seenUnsafe = true;
      continue;
    }

    if (token.startsWith("--")) {
      throw new UsageError(`Unknown flag: ${token}`);
    }

    throw new UsageError(`Unexpected argument: ${token}`);
  }

  if (inlineInput !== undefined && inputFile !== undefined) {
    throw new UsageError("Use either --input or --input-file, not both");
  }

  if (inlineInput === undefined && inputFile === undefined) {
    throw new UsageError(SKILLS_RUN_USAGE);
  }

  if (seenUnsafe && format !== "pretty") {
    throw new UsageError("--unsafe is only supported with --format pretty");
  }

  return {
    kind: "skills_run",
    skillName,
    input_source:
      inputFile !== undefined
        ? { kind: "file", path: inputFile }
        : { kind: "inline", value: inlineInput as string },
    options: seenUnsafe ? { format, unsafe: true } : { format },
  };
}

export function parseCliArgs(argv: string[]): CliCommand {
  if (argv.length === 0 || argv[0] === "--help" || argv[0] === "-h") {
    return { kind: "help" };
  }

  const [command, subcommand] = argv;

  if (command !== "skills") {
    throw new UsageError(`Unknown command: ${command}`);
  }

  if (subcommand === "list") {
    return parseSkillsListArgs(argv);
  }

  if (subcommand === "describe") {
    return parseSkillsDescribeArgs(argv);
  }

  if (subcommand === "run") {
    return parseSkillsRunArgs(argv);
  }

  throw new UsageError(`Unknown skills command: ${subcommand ?? ""}`.trim());
}

export async function readBoundedUtf8File(
  filePath: string,
  maxBytes: number
): Promise<string> {
  if (filePath.trim() === "") {
    throw new UsageError("--input-file requires a non-empty path");
  }

  if (!Number.isSafeInteger(maxBytes) || maxBytes <= 0) {
    throw new UsageError("Input file byte limit must be a positive safe integer");
  }

  let fileStat;

  try {
    fileStat = await stat(filePath);
  } catch (error) {
    throw new UsageError(
      `Unable to stat input file: ${error instanceof Error ? error.message : String(error)}`
    );
  }

  if (!fileStat.isFile()) {
    throw new UsageError("--input-file must point to a regular file");
  }

  if (fileStat.size > maxBytes) {
    throw new UsageError(
      `Input file exceeds maximum size of ${maxBytes} bytes before read`
    );
  }

  let content: Buffer;

  try {
    content = await readFile(filePath);
  } catch (error) {
    throw new UsageError(
      `Unable to read input file: ${error instanceof Error ? error.message : String(error)}`
    );
  }

  if (content.byteLength > maxBytes) {
    throw new UsageError(
      `Input file exceeds maximum size of ${maxBytes} bytes after read`
    );
  }

  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(content);
  } catch {
    throw new UsageError("Input file must be valid UTF-8");
  }
}
