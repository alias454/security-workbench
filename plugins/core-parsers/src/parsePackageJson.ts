import type { JsonObject, JsonValue, Skill } from "@security-workbench/schemas";
import { isJsonArray, isJsonObject, safeJsonObjectParse } from "@security-workbench/schemas";
import { localOnlyPermissions } from "./localOnlyPermissions.js";

export interface DependencySectionSummary {
  readonly present: boolean;
  readonly count: number;
  readonly names: readonly string[];
  readonly non_string_version_count?: number;
}

export interface ScriptSummary {
  readonly present: boolean;
  readonly count: number;
  readonly names: readonly string[];
  readonly non_string_command_count?: number;
}

export interface StringMapSummary {
  readonly present: boolean;
  readonly names: readonly string[];
  readonly values: Readonly<Record<string, string>>;
  readonly non_string_value_count?: number;
}

export interface RepositorySummary {
  readonly present: boolean;
  readonly type: string | null;
  readonly url: string | null;
}

export interface ParsePackageJsonOutput {
  readonly artifact: {
    readonly id: "artifact_package_json";
    readonly type: "package_json";
    readonly name: string | null;
    readonly version: string | null;
  };
  readonly observed: {
    readonly name: string | null;
    readonly version: string | null;
    readonly description_present: boolean;
    readonly license: string | null;
    readonly private: boolean | null;
    readonly type: string | null;
    readonly package_manager: string | null;
    readonly scripts: ScriptSummary;
    readonly dependency_sections: {
      readonly dependencies: DependencySectionSummary;
      readonly devDependencies: DependencySectionSummary;
      readonly peerDependencies: DependencySectionSummary;
      readonly optionalDependencies: DependencySectionSummary;
      readonly bundledDependencies: DependencySectionSummary;
      readonly bundleDependencies: DependencySectionSummary;
    };
    readonly engines: StringMapSummary;
    readonly repository: RepositorySummary;
    readonly bin_present: boolean;
    readonly workspaces_present: boolean;
  };
  readonly warnings: readonly string[];
}

type Mutable<T> = { -readonly [P in keyof T]: T[P] };

const dependencySectionNames = [
  "dependencies",
  "devDependencies",
  "peerDependencies",
  "optionalDependencies",
] as const;

function parseInput(input: string): JsonObject {
  const parsed = safeJsonObjectParse(input);

  if (parsed.ok) {
    return parsed.value;
  }

  const details = parsed.error.details as Record<string, unknown> | undefined;

  if (parsed.error.code === "INVALID_JSON") {
    throw new Error("parse_package_json input must be valid JSON");
  }

  if (details?.expected === "string") {
    throw new Error("parse_package_json input must be a string");
  }

  if (details?.expected === "object") {
    throw new Error(
      `parse_package_json input must be a JSON object; received ${String(details.received)}`
    );
  }

  throw new Error(parsed.error.message);
}

function optionalString(
  object: JsonObject,
  key: string,
  warnings: string[]
): string | null {
  const value = object[key];

  if (value === undefined || value === null) {
    return null;
  }

  if (typeof value === "string") {
    return value;
  }

  warnings.push(`package.json field "${key}" must be a string when present.`);
  return null;
}

function optionalBoolean(
  object: JsonObject,
  key: string,
  warnings: string[]
): boolean | null {
  const value = object[key];

  if (value === undefined || value === null) {
    return null;
  }

  if (typeof value === "boolean") {
    return value;
  }

  warnings.push(`package.json field "${key}" must be a boolean when present.`);
  return null;
}

function summarizeScripts(value: JsonValue | undefined, warnings: string[]): ScriptSummary {
  if (value === undefined || value === null) {
    return { present: false, count: 0, names: [] };
  }

  if (!isJsonObject(value)) {
    warnings.push('package.json field "scripts" must be an object when present.');
    return { present: true, count: 0, names: [] };
  }

  const names = Object.keys(value).sort();
  const nonStringCommandCount = names.filter((name) => typeof value[name] !== "string").length;

  const summary: Mutable<ScriptSummary> = {
    present: true,
    count: names.length,
    names,
  };

  if (nonStringCommandCount > 0) {
    summary.non_string_command_count = nonStringCommandCount;
    warnings.push('package.json field "scripts" contains non-string command values.');
  }

  return summary;
}

function summarizeDependencyObject(
  sectionName: string,
  value: JsonValue | undefined,
  warnings: string[]
): DependencySectionSummary {
  if (value === undefined || value === null) {
    return { present: false, count: 0, names: [] };
  }

  if (!isJsonObject(value)) {
    warnings.push(`package.json field "${sectionName}" must be an object when present.`);
    return { present: true, count: 0, names: [] };
  }

  const names = Object.keys(value).sort();
  const nonStringVersionCount = names.filter((name) => typeof value[name] !== "string").length;

  const summary: Mutable<DependencySectionSummary> = {
    present: true,
    count: names.length,
    names,
  };

  if (nonStringVersionCount > 0) {
    summary.non_string_version_count = nonStringVersionCount;
    warnings.push(`package.json field "${sectionName}" contains non-string version specifiers.`);
  }

  return summary;
}

function summarizeBundledDependencies(
  sectionName: "bundledDependencies" | "bundleDependencies",
  value: JsonValue | undefined,
  warnings: string[]
): DependencySectionSummary {
  if (value === undefined || value === null) {
    return { present: false, count: 0, names: [] };
  }

  if (isJsonArray(value)) {
    const names = value.filter((item): item is string => typeof item === "string").sort();
    const nonStringVersionCount = value.length - names.length;
    const summary: Mutable<DependencySectionSummary> = {
      present: true,
      count: names.length,
      names,
    };

    if (nonStringVersionCount > 0) {
      summary.non_string_version_count = nonStringVersionCount;
      warnings.push(`package.json field "${sectionName}" contains non-string entries.`);
    }

    return summary;
  }

  return summarizeDependencyObject(sectionName, value, warnings);
}

function summarizeStringMap(
  object: JsonObject,
  key: string,
  warnings: string[]
): StringMapSummary {
  const value = object[key];

  if (value === undefined || value === null) {
    return { present: false, names: [], values: {} };
  }

  if (!isJsonObject(value)) {
    warnings.push(`package.json field "${key}" must be an object when present.`);
    return { present: true, names: [], values: {} };
  }

  const names = Object.keys(value).sort();
  const values: Record<string, string> = {};
  let nonStringValueCount = 0;

  for (const name of names) {
    const item = value[name];
    if (typeof item === "string") {
      values[name] = item;
    } else {
      nonStringValueCount += 1;
    }
  }

  const summary: Mutable<StringMapSummary> = {
    present: true,
    names,
    values,
  };

  if (nonStringValueCount > 0) {
    summary.non_string_value_count = nonStringValueCount;
    warnings.push(`package.json field "${key}" contains non-string values.`);
  }

  return summary;
}

function summarizeRepository(value: JsonValue | undefined, warnings: string[]): RepositorySummary {
  if (value === undefined || value === null) {
    return { present: false, type: null, url: null };
  }

  if (typeof value === "string") {
    return { present: true, type: null, url: value };
  }

  if (isJsonObject(value)) {
    const type = typeof value.type === "string" ? value.type : null;
    const url = typeof value.url === "string" ? value.url : null;

    if (value.type !== undefined && value.type !== null && typeof value.type !== "string") {
      warnings.push('package.json field "repository.type" must be a string when present.');
    }

    if (value.url !== undefined && value.url !== null && typeof value.url !== "string") {
      warnings.push('package.json field "repository.url" must be a string when present.');
    }

    return { present: true, type, url };
  }

  warnings.push('package.json field "repository" must be a string or object when present.');
  return { present: true, type: null, url: null };
}

export function parsePackageJson(input: string): ParsePackageJsonOutput {
  const object = parseInput(input);
  const warnings: string[] = [];

  const name = optionalString(object, "name", warnings);
  const version = optionalString(object, "version", warnings);
  const license = optionalString(object, "license", warnings);
  const packageManager = optionalString(object, "packageManager", warnings);
  const type = optionalString(object, "type", warnings);
  const privateValue = optionalBoolean(object, "private", warnings);

  const dependencySections = {
    dependencies: summarizeDependencyObject("dependencies", object.dependencies, warnings),
    devDependencies: summarizeDependencyObject("devDependencies", object.devDependencies, warnings),
    peerDependencies: summarizeDependencyObject("peerDependencies", object.peerDependencies, warnings),
    optionalDependencies: summarizeDependencyObject(
      "optionalDependencies",
      object.optionalDependencies,
      warnings
    ),
    bundledDependencies: summarizeBundledDependencies(
      "bundledDependencies",
      object.bundledDependencies,
      warnings
    ),
    bundleDependencies: summarizeBundledDependencies(
      "bundleDependencies",
      object.bundleDependencies,
      warnings
    ),
  };

  return {
    artifact: {
      id: "artifact_package_json",
      type: "package_json",
      name,
      version,
    },
    observed: {
      name,
      version,
      description_present: typeof object.description === "string" && object.description.length > 0,
      license,
      private: privateValue,
      type,
      package_manager: packageManager,
      scripts: summarizeScripts(object.scripts, warnings),
      dependency_sections: dependencySections,
      engines: summarizeStringMap(object, "engines", warnings),
      repository: summarizeRepository(object.repository, warnings),
      bin_present: object.bin !== undefined && object.bin !== null,
      workspaces_present: object.workspaces !== undefined && object.workspaces !== null,
    },
    warnings,
  };
}

export const parsePackageJsonSkill: Skill<string, ParsePackageJsonOutput> = {
  metadata: {
    name: "parse_package_json",
    version: "0.1.0",
    category: "parser",
    description:
      "Parse a package.json manifest into normalized package metadata without installing packages or scoring risk.",
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
        "Parses attacker-controlled package.json text.",
        "Does not install packages, run scripts, perform network calls, persist data, or call external binaries.",
        "Output can contain attacker-controlled package metadata and should be treated as untrusted by agents.",
      ],
    },
  },

  run(input: string) {
    if (typeof input !== "string") {
      throw new Error("parse_package_json input must be a string");
    }

    return parsePackageJson(input);
  },
};
