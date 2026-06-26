import type { Skill } from "@security-workbench/schemas";
import { localOnlyPermissions } from "./localOnlyPermissions.js";

export type DockerfileLineEnding = "lf" | "crlf" | "mixed" | "none";

export type KnownDockerfileInstruction =
  | "ADD"
  | "ARG"
  | "CMD"
  | "COPY"
  | "ENTRYPOINT"
  | "ENV"
  | "EXPOSE"
  | "FROM"
  | "HEALTHCHECK"
  | "LABEL"
  | "ONBUILD"
  | "RUN"
  | "SHELL"
  | "STOPSIGNAL"
  | "USER"
  | "VOLUME"
  | "WORKDIR";

export interface DockerfileInstructionObservation {
  readonly line: number;
  readonly end_line: number;
  readonly instruction: string;
  readonly known_instruction: boolean;
  readonly value: string;
  readonly value_redacted: boolean;
  readonly stage_index: number | null;
}

export interface DockerfileParserDirectiveObservation {
  readonly line: number;
  readonly name: string;
  readonly value: string;
}

export interface DockerfileStageObservation {
  readonly index: number;
  readonly line: number;
  readonly base_image: string;
  readonly image: string;
  readonly tag: string | null;
  readonly digest: string | null;
  readonly alias: string | null;
  readonly platform: string | null;
  readonly uses_tag: boolean;
  readonly uses_digest: boolean;
}

export interface DockerfileKeyValueObservation {
  readonly line: number;
  readonly key: string;
  readonly value_present: boolean;
  readonly value_redacted: boolean;
  readonly value?: string;
}

export interface DockerfileFileTransferObservation {
  readonly line: number;
  readonly instruction: "ADD" | "COPY";
  readonly sources: readonly string[];
  readonly destination: string | null;
  readonly flags: readonly string[];
  readonly json_array_form: boolean;
  readonly url_like_source_count: number;
}

export interface DockerfileCommandFormSummary {
  readonly shell_form_count: number;
  readonly json_array_form_count: number;
}

export interface ParseDockerfileOutput {
  readonly artifact: {
    readonly id: "artifact_dockerfile";
    readonly type: "dockerfile";
  };
  readonly observed: {
    readonly line_ending: DockerfileLineEnding;
    readonly physical_line_count: number;
    readonly logical_instruction_count: number;
    readonly blank_line_count: number;
    readonly comment_line_count: number;
    readonly parser_directives: readonly DockerfileParserDirectiveObservation[];
    readonly instruction_counts: Readonly<Record<string, number>>;
    readonly instructions: readonly DockerfileInstructionObservation[];
    readonly unknown_instructions: readonly DockerfileInstructionObservation[];
    readonly stages: readonly DockerfileStageObservation[];
    readonly stage_count: number;
    readonly final_stage_index: number | null;
    readonly base_images: readonly DockerfileStageObservation[];
    readonly exposed_ports: readonly string[];
    readonly declared_users: readonly string[];
    readonly final_user: string | null;
    readonly workdirs: readonly string[];
    readonly env_keys: readonly string[];
    readonly env: readonly DockerfileKeyValueObservation[];
    readonly arg_keys: readonly string[];
    readonly args: readonly DockerfileKeyValueObservation[];
    readonly labels: readonly DockerfileKeyValueObservation[];
    readonly copied_paths: readonly DockerfileFileTransferObservation[];
    readonly added_paths: readonly DockerfileFileTransferObservation[];
    readonly add_url_like_sources: readonly string[];
    readonly healthcheck_present: boolean;
    readonly healthcheck_disabled: boolean;
    readonly entrypoint_present: boolean;
    readonly cmd_present: boolean;
    readonly shell_instruction_present: boolean;
    readonly command_forms: {
      readonly run: DockerfileCommandFormSummary;
      readonly cmd: DockerfileCommandFormSummary;
      readonly entrypoint: DockerfileCommandFormSummary;
      readonly shell: DockerfileCommandFormSummary;
    };
  };
  readonly warnings: readonly string[];
}

interface LogicalInstruction {
  readonly line: number;
  readonly end_line: number;
  readonly text: string;
}

interface CollectedInstructions {
  readonly logicalInstructions: readonly LogicalInstruction[];
  readonly parserDirectives: readonly DockerfileParserDirectiveObservation[];
  readonly blankLineCount: number;
  readonly commentLineCount: number;
  readonly warnings: readonly string[];
}

const KNOWN_INSTRUCTIONS = new Set<string>([
  "ADD",
  "ARG",
  "CMD",
  "COPY",
  "ENTRYPOINT",
  "ENV",
  "EXPOSE",
  "FROM",
  "HEALTHCHECK",
  "LABEL",
  "ONBUILD",
  "RUN",
  "SHELL",
  "STOPSIGNAL",
  "USER",
  "VOLUME",
  "WORKDIR",
]);

const INSTRUCTION_PATTERN = /^([A-Za-z][A-Za-z0-9_-]*)(?:\s+(.*))?$/s;
const DIRECTIVE_PATTERN = /^#\s*([A-Za-z][A-Za-z0-9_-]*)\s*=\s*(.*?)\s*$/;
const SENSITIVE_KEY_PATTERN = /(?:secret|token|password|passwd|pwd|api[-_]?key|access[-_]?key|private[-_]?key|credential|auth|bearer|session|cookie)/i;
const URL_LIKE_PATTERN = /^[A-Za-z][A-Za-z0-9+.-]*:\/\//;

function normalizeInput(input: string): string {
  if (typeof input !== "string") {
    throw new Error("parse_dockerfile input must be a string");
  }

  if (input.length === 0 || input.trim().length === 0) {
    throw new Error("parse_dockerfile input must not be empty");
  }

  return input.charCodeAt(0) === 0xfeff ? input.slice(1) : input;
}

function detectLineEnding(text: string): DockerfileLineEnding {
  const crlfCount = (text.match(/\r\n/g) ?? []).length;
  const withoutCrLf = text.replace(/\r\n/g, "");
  const lfCount = (withoutCrLf.match(/\n/g) ?? []).length;
  const crCount = (withoutCrLf.match(/\r/g) ?? []).length;

  if (crlfCount === 0 && lfCount === 0 && crCount === 0) {
    return "none";
  }

  if (crlfCount > 0 && lfCount === 0 && crCount === 0) {
    return "crlf";
  }

  if (crlfCount === 0 && lfCount > 0 && crCount === 0) {
    return "lf";
  }

  return "mixed";
}

function splitLines(text: string): string[] {
  return text.replace(/\r\n/g, "\n").replace(/\r/g, "\n").split("\n");
}

function lineHasContinuation(line: string, escapeChar: string): boolean {
  const trimmedRight = line.trimEnd();
  return trimmedRight.length > 0 && trimmedRight.endsWith(escapeChar);
}

function removeTrailingContinuation(line: string, escapeChar: string): string {
  const trimmedRight = line.trimEnd();
  return trimmedRight.endsWith(escapeChar) ? trimmedRight.slice(0, -escapeChar.length) : trimmedRight;
}

function logicalText(lines: readonly string[], escapeChar: string): string {
  return lines
    .map((line, index) => {
      const withoutContinuation = index < lines.length - 1 ? removeTrailingContinuation(line, escapeChar) : line;
      return withoutContinuation.trim();
    })
    .filter((line) => line.length > 0)
    .join(" ");
}

function collectInstructions(text: string): CollectedInstructions {
  const physicalLines = splitLines(text);
  const logicalInstructions: LogicalInstruction[] = [];
  const parserDirectives: DockerfileParserDirectiveObservation[] = [];
  const warnings: string[] = [];
  let blankLineCount = 0;
  let commentLineCount = 0;
  let escapeChar = "\\";
  let firstInstructionSeen = false;
  let pendingStartLine: number | null = null;
  let pendingLines: string[] = [];

  for (const [index, rawLine] of physicalLines.entries()) {
    const lineNumber = index + 1;
    const trimmed = rawLine.trim();

    if (pendingStartLine === null) {
      if (trimmed.length === 0) {
        blankLineCount += 1;
        continue;
      }

      if (trimmed.startsWith("#")) {
        commentLineCount += 1;
        if (!firstInstructionSeen) {
          const directiveMatch = trimmed.match(DIRECTIVE_PATTERN);
          if (directiveMatch) {
            const directive = {
              line: lineNumber,
              name: (directiveMatch[1] ?? "").toLowerCase(),
              value: directiveMatch[2] ?? "",
            };
            parserDirectives.push(directive);
            if (directive.name === "escape" && directive.value.length > 0) {
              escapeChar = directive.value.charAt(0);
            }
          }
        }
        continue;
      }

      firstInstructionSeen = true;
      pendingStartLine = lineNumber;
      pendingLines = [rawLine];
    } else {
      pendingLines.push(rawLine);
    }

    if (!lineHasContinuation(rawLine, escapeChar)) {
      logicalInstructions.push({
        line: pendingStartLine,
        end_line: lineNumber,
        text: logicalText(pendingLines, escapeChar),
      });
      pendingStartLine = null;
      pendingLines = [];
    }
  }

  if (pendingStartLine !== null) {
    warnings.push(`Dockerfile line ${pendingStartLine} starts an instruction with an unterminated continuation.`);
    logicalInstructions.push({
      line: pendingStartLine,
      end_line: physicalLines.length,
      text: logicalText(pendingLines, escapeChar),
    });
  }

  return {
    logicalInstructions,
    parserDirectives,
    blankLineCount,
    commentLineCount,
    warnings,
  };
}

function tokenizeWords(value: string): string[] {
  const tokens: string[] = [];
  let current = "";
  let quote: '"' | "'" | null = null;
  let escaped = false;

  for (const char of value) {
    if (escaped) {
      current += char;
      escaped = false;
      continue;
    }

    if (char === "\\" && quote !== "'") {
      escaped = true;
      continue;
    }

    if ((char === '"' || char === "'") && (quote === null || quote === char)) {
      quote = quote === null ? char : null;
      continue;
    }

    if (/\s/.test(char) && quote === null) {
      if (current.length > 0) {
        tokens.push(current);
        current = "";
      }
      continue;
    }

    current += char;
  }

  if (escaped) {
    current += "\\";
  }

  if (current.length > 0) {
    tokens.push(current);
  }

  return tokens;
}

function readFirstWord(value: string): { readonly word: string; readonly endIndex: number } | null {
  const trimmedStart = value.match(/^\s*/)?.[0].length ?? 0;
  let quote: '"' | "'" | null = null;
  let escaped = false;

  for (let index = trimmedStart; index < value.length; index += 1) {
    const char = value[index] ?? "";

    if (escaped) {
      escaped = false;
      continue;
    }

    if (char === "\\" && quote !== "'") {
      escaped = true;
      continue;
    }

    if ((char === '"' || char === "'") && (quote === null || quote === char)) {
      quote = quote === null ? char : null;
      continue;
    }

    if (/\s/.test(char) && quote === null) {
      return { word: value.slice(trimmedStart, index), endIndex: index };
    }
  }

  const word = value.slice(trimmedStart);
  return word.length === 0 ? null : { word, endIndex: value.length };
}

function stripLeadingFlags(value: string): { readonly flags: readonly string[]; readonly rest: string } {
  const flags: string[] = [];
  let rest = value.trim();

  while (rest.startsWith("--")) {
    const first = readFirstWord(rest);
    if (first === null) {
      break;
    }

    flags.push(first.word);
    rest = rest.slice(first.endIndex).trim();
  }

  return { flags, rest };
}

function parseJsonStringArray(value: string): string[] | null {
  if (!value.trimStart().startsWith("[")) {
    return null;
  }

  try {
    const parsed = JSON.parse(value) as unknown;
    if (Array.isArray(parsed) && parsed.every((entry) => typeof entry === "string")) {
      return parsed;
    }
  } catch {
    return null;
  }

  return null;
}

function uniqueSorted(values: Iterable<string>): string[] {
  return [...new Set(values)].sort();
}

function incrementCount(counts: Map<string, number>, name: string): void {
  counts.set(name, (counts.get(name) ?? 0) + 1);
}

function sortedCountRecord(counts: Map<string, number>): Record<string, number> {
  return Object.fromEntries([...counts.entries()].sort(([left], [right]) => left.localeCompare(right)));
}

function isSensitiveKey(key: string): boolean {
  return SENSITIVE_KEY_PATTERN.test(key);
}

function sanitizeKeyValueToken(token: string): string {
  const separatorIndex = token.indexOf("=");
  if (separatorIndex <= 0) {
    return token;
  }

  const key = token.slice(0, separatorIndex);
  return isSensitiveKey(key) ? `${key}=[REDACTED]` : token;
}

function sanitizeEnvOrArgValue(instruction: "ARG" | "ENV", value: string): { readonly value: string; readonly redacted: boolean } {
  const tokens = tokenizeWords(value);
  if (tokens.length === 0) {
    return { value, redacted: false };
  }

  if (instruction === "ARG") {
    const sanitized = sanitizeKeyValueToken(tokens[0] ?? "");
    return {
      value: sanitized,
      redacted: sanitized !== tokens[0],
    };
  }

  if (tokens.some((token) => token.includes("="))) {
    const sanitizedTokens = tokens.map((token) => sanitizeKeyValueToken(token));
    return {
      value: sanitizedTokens.join(" "),
      redacted: sanitizedTokens.some((token, index) => token !== tokens[index]),
    };
  }

  const key = tokens[0] ?? "";
  if (isSensitiveKey(key) && tokens.length > 1) {
    return { value: `${key} [REDACTED]`, redacted: true };
  }

  return { value, redacted: false };
}

function parseKeyValueInstruction(
  line: number,
  instruction: "ARG" | "ENV" | "LABEL",
  value: string,
  warnings: string[]
): DockerfileKeyValueObservation[] {
  const tokens = tokenizeWords(value);
  const observations: DockerfileKeyValueObservation[] = [];

  if (tokens.length === 0) {
    warnings.push(`Dockerfile line ${line} has ${instruction} without a key.`);
    return observations;
  }

  if (instruction === "ARG") {
    const token = tokens[0] ?? "";
    const separatorIndex = token.indexOf("=");
    const key = separatorIndex === -1 ? token : token.slice(0, separatorIndex);
    const defaultValue = separatorIndex === -1 ? undefined : token.slice(separatorIndex + 1);
    if (key.length === 0) {
      warnings.push(`Dockerfile line ${line} has ARG without a key.`);
      return observations;
    }

    const redacted = defaultValue !== undefined && isSensitiveKey(key);
    observations.push({
      line,
      key,
      value_present: defaultValue !== undefined,
      value_redacted: redacted,
      ...(defaultValue !== undefined && !redacted ? { value: defaultValue } : {}),
    });
    return observations;
  }

  if (tokens.some((token) => token.includes("="))) {
    for (const token of tokens) {
      const separatorIndex = token.indexOf("=");
      if (separatorIndex <= 0) {
        warnings.push(`Dockerfile line ${line} has ${instruction} token without key=value form.`);
        continue;
      }

      const key = token.slice(0, separatorIndex);
      const parsedValue = token.slice(separatorIndex + 1);
      const redacted = isSensitiveKey(key);
      observations.push({
        line,
        key,
        value_present: true,
        value_redacted: redacted,
        ...(!redacted ? { value: parsedValue } : {}),
      });
    }
    return observations;
  }

  const key = tokens[0] ?? "";
  const parsedValue = tokens.slice(1).join(" ");
  if (key.length === 0 || parsedValue.length === 0) {
    warnings.push(`Dockerfile line ${line} has ${instruction} without a key/value pair.`);
    return observations;
  }

  const redacted = isSensitiveKey(key);
  observations.push({
    line,
    key,
    value_present: true,
    value_redacted: redacted,
    ...(!redacted ? { value: parsedValue } : {}),
  });
  return observations;
}

function parseFromInstruction(
  line: number,
  value: string,
  stageIndex: number,
  warnings: string[]
): DockerfileStageObservation | null {
  const tokens = tokenizeWords(value);
  const flags: string[] = [];
  let cursor = 0;

  while ((tokens[cursor] ?? "").startsWith("--")) {
    flags.push(tokens[cursor] ?? "");
    cursor += 1;
  }

  const baseImage = tokens[cursor];
  if (baseImage === undefined || baseImage.length === 0) {
    warnings.push(`Dockerfile line ${line} has FROM without a base image.`);
    return null;
  }

  let alias: string | null = null;
  if ((tokens[cursor + 1] ?? "").toUpperCase() === "AS" && tokens[cursor + 2] !== undefined) {
    alias = tokens[cursor + 2] ?? null;
  }

  const platformFlag = flags.find((flag) => flag.startsWith("--platform="));
  const platform = platformFlag ? platformFlag.slice("--platform=".length) : null;
  const digestSeparator = baseImage.indexOf("@");
  const imageAndTag = digestSeparator === -1 ? baseImage : baseImage.slice(0, digestSeparator);
  const digest = digestSeparator === -1 ? null : baseImage.slice(digestSeparator + 1);
  const lastSlashIndex = imageAndTag.lastIndexOf("/");
  const lastColonIndex = imageAndTag.lastIndexOf(":");
  const hasTag = lastColonIndex > lastSlashIndex;
  const image = hasTag ? imageAndTag.slice(0, lastColonIndex) : imageAndTag;
  const tag = hasTag ? imageAndTag.slice(lastColonIndex + 1) : null;

  return {
    index: stageIndex,
    line,
    base_image: baseImage,
    image,
    tag,
    digest,
    alias,
    platform,
    uses_tag: tag !== null,
    uses_digest: digest !== null,
  };
}

function parseFileTransfer(
  line: number,
  instruction: "ADD" | "COPY",
  value: string,
  warnings: string[]
): DockerfileFileTransferObservation {
  const { flags, rest } = stripLeadingFlags(value);
  const jsonValues = parseJsonStringArray(rest);
  const operands = jsonValues ?? tokenizeWords(rest);
  const sources = operands.length > 1 ? operands.slice(0, -1) : [];
  const destination = operands.length > 0 ? operands[operands.length - 1] ?? null : null;

  if (operands.length < 2) {
    warnings.push(`Dockerfile line ${line} has ${instruction} with fewer than two path operands.`);
  }

  return {
    line,
    instruction,
    sources,
    destination,
    flags,
    json_array_form: jsonValues !== null,
    url_like_source_count: sources.filter((source) => URL_LIKE_PATTERN.test(source)).length,
  };
}

function commandForm(value: string): "json_array" | "shell" {
  return parseJsonStringArray(value) === null ? "shell" : "json_array";
}

function commandSummary(shellFormCount: number, jsonArrayFormCount: number): DockerfileCommandFormSummary {
  return {
    shell_form_count: shellFormCount,
    json_array_form_count: jsonArrayFormCount,
  };
}

export function parseDockerfile(input: string): ParseDockerfileOutput {
  const text = normalizeInput(input);
  const lineEnding = detectLineEnding(text);
  const physicalLines = splitLines(text);
  const collected = collectInstructions(text);
  const warnings = [...collected.warnings];
  const instructionCounts = new Map<string, number>();
  const instructions: DockerfileInstructionObservation[] = [];
  const unknownInstructions: DockerfileInstructionObservation[] = [];
  const stages: DockerfileStageObservation[] = [];
  const exposedPorts: string[] = [];
  const declaredUsers: string[] = [];
  const workdirs: string[] = [];
  const env: DockerfileKeyValueObservation[] = [];
  const args: DockerfileKeyValueObservation[] = [];
  const labels: DockerfileKeyValueObservation[] = [];
  const copiedPaths: DockerfileFileTransferObservation[] = [];
  const addedPaths: DockerfileFileTransferObservation[] = [];
  let currentStageIndex: number | null = null;
  let healthcheckPresent = false;
  let healthcheckDisabled = false;
  let entrypointPresent = false;
  let cmdPresent = false;
  let shellInstructionPresent = false;
  let runShellFormCount = 0;
  let runJsonArrayFormCount = 0;
  let cmdShellFormCount = 0;
  let cmdJsonArrayFormCount = 0;
  let entrypointShellFormCount = 0;
  let entrypointJsonArrayFormCount = 0;
  let shellShellFormCount = 0;
  let shellJsonArrayFormCount = 0;

  for (const logicalInstruction of collected.logicalInstructions) {
    const match = logicalInstruction.text.trim().match(INSTRUCTION_PATTERN);
    if (!match) {
      warnings.push(`Dockerfile line ${logicalInstruction.line} does not start with a valid instruction name.`);
      continue;
    }

    const instruction = (match[1] ?? "").toUpperCase();
    const rawValue = (match[2] ?? "").trim();
    const knownInstruction = KNOWN_INSTRUCTIONS.has(instruction);
    let value = rawValue;
    let valueRedacted = false;

    if (instruction === "ARG" || instruction === "ENV") {
      const sanitized = sanitizeEnvOrArgValue(instruction, rawValue);
      value = sanitized.value;
      valueRedacted = sanitized.redacted;
    }

    const instructionStageIndex = instruction === "FROM" ? stages.length : currentStageIndex;
    const observation: DockerfileInstructionObservation = {
      line: logicalInstruction.line,
      end_line: logicalInstruction.end_line,
      instruction,
      known_instruction: knownInstruction,
      value,
      value_redacted: valueRedacted,
      stage_index: instructionStageIndex,
    };

    instructions.push(observation);
    incrementCount(instructionCounts, instruction);

    if (!knownInstruction) {
      unknownInstructions.push(observation);
      warnings.push(`Dockerfile line ${logicalInstruction.line} uses unmodeled instruction ${instruction}.`);
      continue;
    }

    switch (instruction as KnownDockerfileInstruction) {
      case "FROM": {
        const nextStageIndex = stages.length;
        const stage = parseFromInstruction(logicalInstruction.line, rawValue, nextStageIndex, warnings);
        if (stage !== null) {
          stages.push(stage);
          currentStageIndex = stage.index;
        }
        break;
      }
      case "EXPOSE":
        exposedPorts.push(...tokenizeWords(rawValue));
        break;
      case "USER":
        if (rawValue.length > 0) {
          declaredUsers.push(rawValue);
        } else {
          warnings.push(`Dockerfile line ${logicalInstruction.line} has USER without a value.`);
        }
        break;
      case "WORKDIR":
        if (rawValue.length > 0) {
          workdirs.push(rawValue);
        } else {
          warnings.push(`Dockerfile line ${logicalInstruction.line} has WORKDIR without a value.`);
        }
        break;
      case "ENV":
        env.push(...parseKeyValueInstruction(logicalInstruction.line, "ENV", rawValue, warnings));
        break;
      case "ARG":
        args.push(...parseKeyValueInstruction(logicalInstruction.line, "ARG", rawValue, warnings));
        break;
      case "LABEL":
        labels.push(...parseKeyValueInstruction(logicalInstruction.line, "LABEL", rawValue, warnings));
        break;
      case "COPY":
        copiedPaths.push(parseFileTransfer(logicalInstruction.line, "COPY", rawValue, warnings));
        break;
      case "ADD":
        addedPaths.push(parseFileTransfer(logicalInstruction.line, "ADD", rawValue, warnings));
        break;
      case "HEALTHCHECK":
        healthcheckPresent = true;
        healthcheckDisabled = rawValue.toUpperCase() === "NONE";
        break;
      case "ENTRYPOINT":
        entrypointPresent = true;
        if (commandForm(rawValue) === "json_array") {
          entrypointJsonArrayFormCount += 1;
        } else {
          entrypointShellFormCount += 1;
        }
        break;
      case "CMD":
        cmdPresent = true;
        if (commandForm(rawValue) === "json_array") {
          cmdJsonArrayFormCount += 1;
        } else {
          cmdShellFormCount += 1;
        }
        break;
      case "RUN":
        if (commandForm(rawValue) === "json_array") {
          runJsonArrayFormCount += 1;
        } else {
          runShellFormCount += 1;
        }
        break;
      case "SHELL":
        shellInstructionPresent = true;
        if (commandForm(rawValue) === "json_array") {
          shellJsonArrayFormCount += 1;
        } else {
          shellShellFormCount += 1;
        }
        break;
      default:
        break;
    }
  }

  if (instructions.length === 0) {
    throw new Error("parse_dockerfile input did not contain any valid Dockerfile instructions");
  }

  if (stages.length === 0) {
    warnings.push("Dockerfile input contains no FROM instruction.");
  }

  if (lineEnding === "mixed") {
    warnings.push("Dockerfile input contains mixed line endings.");
  }

  const addUrlLikeSources = addedPaths.flatMap((path) => path.sources.filter((source) => URL_LIKE_PATTERN.test(source)));

  return {
    artifact: {
      id: "artifact_dockerfile",
      type: "dockerfile",
    },
    observed: {
      line_ending: lineEnding,
      physical_line_count: physicalLines.length,
      logical_instruction_count: instructions.length,
      blank_line_count: collected.blankLineCount,
      comment_line_count: collected.commentLineCount,
      parser_directives: collected.parserDirectives,
      instruction_counts: sortedCountRecord(instructionCounts),
      instructions,
      unknown_instructions: unknownInstructions,
      stages,
      stage_count: stages.length,
      final_stage_index: stages.length > 0 ? stages[stages.length - 1]?.index ?? null : null,
      base_images: stages,
      exposed_ports: exposedPorts,
      declared_users: declaredUsers,
      final_user: declaredUsers.length > 0 ? declaredUsers[declaredUsers.length - 1] ?? null : null,
      workdirs,
      env_keys: uniqueSorted(env.map((entry) => entry.key)),
      env,
      arg_keys: uniqueSorted(args.map((entry) => entry.key)),
      args,
      labels,
      copied_paths: copiedPaths,
      added_paths: addedPaths,
      add_url_like_sources: addUrlLikeSources,
      healthcheck_present: healthcheckPresent,
      healthcheck_disabled: healthcheckDisabled,
      entrypoint_present: entrypointPresent,
      cmd_present: cmdPresent,
      shell_instruction_present: shellInstructionPresent,
      command_forms: {
        run: commandSummary(runShellFormCount, runJsonArrayFormCount),
        cmd: commandSummary(cmdShellFormCount, cmdJsonArrayFormCount),
        entrypoint: commandSummary(entrypointShellFormCount, entrypointJsonArrayFormCount),
        shell: commandSummary(shellShellFormCount, shellJsonArrayFormCount),
      },
    },
    warnings,
  };
}

export const parseDockerfileSkill: Skill<string, ParseDockerfileOutput> = {
  metadata: {
    name: "parse_dockerfile",
    version: "0.1.0",
    category: "parser",
    description:
      "Parse Dockerfile text into structured build-stage and instruction observations without network access or risk scoring.",
    execution: {
      mode: "local_only",
      network_access: "none",
      deterministic: true,
    },
    permissions: localOnlyPermissions,
    exposure: {
      surfaces: ["cli", "api", "web", "mcp"],
      default_exposure: "enabled",
      hosted_default: "allowlist_only",
      requires_authentication: true,
      rate_limit_recommended: true,
      audit_required: true,
      max_input_mb: 1,
      risk: "low",
      rationale: [
        "Parses attacker-controlled Dockerfile text into structured observations.",
        "Does not perform network access, persist input, call external services, or execute artifact content.",
        "Hosted exposure remains allowlist-only because Dockerfiles may contain internal image names, build paths, or embedded configuration values.",
      ],
    },
  },
  run(input: string): ParseDockerfileOutput {
    return parseDockerfile(input);
  },
};
