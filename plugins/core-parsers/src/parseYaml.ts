import type { Skill } from "@security-workbench/schemas";
import { parseAllDocuments } from "yaml";
import { localOnlyPermissions } from "./localOnlyPermissions.js";

export type ParseYamlValueType = "object" | "array" | "string" | "number" | "boolean" | "null" | "multiple";

export interface ParseYamlDocumentSummary {
  document_index: number;
  value_type: Exclude<ParseYamlValueType, "multiple">;
  keys: string[];
}

export interface ParseYamlOutput {
  artifact: {
    id: "artifact_yaml";
    type: "yaml";
  };
  observed: {
    document_count: number;
    value_type: ParseYamlValueType;
    keys: string[];
    value: unknown | null;
    documents: unknown[];
    document_summaries: ParseYamlDocumentSummary[];
  };
  warnings: string[];
}

const MAX_DOCUMENTS = 20;
const MAX_ALIAS_COUNT = 50;
const MAX_DEPTH = 60;
const MAX_KEYS_PER_OBJECT = 1_000;
const MAX_ARRAY_ITEMS = 5_000;

const ALLOWED_EXPLICIT_TAGS = new Set(["!!str", "!!int", "!!float", "!!bool", "!!null", "!!map", "!!seq"]);

const ALLOWED_NODE_TAGS = new Set([
  "tag:yaml.org,2002:map",
  "tag:yaml.org,2002:seq",
  "tag:yaml.org,2002:str",
  "tag:yaml.org,2002:int",
  "tag:yaml.org,2002:float",
  "tag:yaml.org,2002:bool",
  "tag:yaml.org,2002:null",
  "tag:yaml.org,2002:merge",
]);

function normalizeInput(input: string): string {
  if (typeof input !== "string") {
    throw new Error("parse_yaml input must be a string");
  }

  if (input.trim().length === 0) {
    throw new Error("parse_yaml input must not be empty");
  }

  return input.charCodeAt(0) === 0xfeff ? input.slice(1) : input;
}

function rejectExplicitCustomTags(input: string): void {
  const tagPattern = /(^|[\s:[{,])(!(?:![A-Za-z][A-Za-z0-9_-]*|<[^>\r\n]+>|[A-Za-z][^\s,\]}#]*))/g;

  for (const match of input.matchAll(tagPattern)) {
    const tag = match[2];
    if (!tag || ALLOWED_EXPLICIT_TAGS.has(tag)) {
      continue;
    }

    throw new Error(`parse_yaml custom tags are not supported: ${tag}`);
  }
}

function collectUnsafeNodeTags(node: unknown, unsafeTags: Set<string>, depth = 0): void {
  if (node === null || typeof node !== "object" || depth > MAX_DEPTH) {
    return;
  }

  const value = node as {
    tag?: unknown;
    items?: unknown;
    key?: unknown;
    value?: unknown;
    srcToken?: unknown;
  };

  if (typeof value.tag === "string" && !ALLOWED_NODE_TAGS.has(value.tag)) {
    unsafeTags.add(value.tag);
  }

  if (Array.isArray(value.items)) {
    for (const item of value.items) {
      collectUnsafeNodeTags(item, unsafeTags, depth + 1);
    }
  }

  if ("key" in value) {
    collectUnsafeNodeTags(value.key, unsafeTags, depth + 1);
  }

  if ("value" in value) {
    collectUnsafeNodeTags(value.value, unsafeTags, depth + 1);
  }
}

function valueType(value: unknown): Exclude<ParseYamlValueType, "multiple"> {
  if (value === null) {
    return "null";
  }

  if (Array.isArray(value)) {
    return "array";
  }

  const type = typeof value;
  if (type === "string" || type === "number" || type === "boolean") {
    return type;
  }

  return "object";
}

function topLevelKeys(value: unknown): string[] {
  if (value instanceof Map) {
    return Array.from(value.keys()).map((key) => String(key));
  }

  if (value !== null && typeof value === "object" && !Array.isArray(value)) {
    return Object.keys(value as Record<string, unknown>);
  }

  return [];
}

function normalizeJsonCompatible(value: unknown, depth = 0): unknown {
  if (depth > MAX_DEPTH) {
    throw new Error(`parse_yaml input exceeds maximum supported nesting depth of ${MAX_DEPTH}`);
  }

  if (value === null || typeof value === "string" || typeof value === "boolean") {
    return value;
  }

  if (typeof value === "number") {
    return Number.isFinite(value) ? value : String(value);
  }

  if (Array.isArray(value)) {
    return value.slice(0, MAX_ARRAY_ITEMS).map((item) => normalizeJsonCompatible(item, depth + 1));
  }

  if (value instanceof Map) {
    const output: Record<string, unknown> = {};
    let count = 0;
    for (const [key, nestedValue] of value.entries()) {
      if (count >= MAX_KEYS_PER_OBJECT) {
        break;
      }
      output[String(key)] = normalizeJsonCompatible(nestedValue, depth + 1);
      count += 1;
    }
    return output;
  }

  if (typeof value === "object") {
    const output: Record<string, unknown> = {};
    let count = 0;
    for (const [key, nestedValue] of Object.entries(value as Record<string, unknown>)) {
      if (count >= MAX_KEYS_PER_OBJECT) {
        break;
      }
      output[key] = normalizeJsonCompatible(nestedValue, depth + 1);
      count += 1;
    }
    return output;
  }

  return String(value);
}

function documentToJs(document: unknown): unknown {
  const yamlDocument = document as { toJS: (options?: Record<string, unknown>) => unknown };
  return yamlDocument.toJS({ maxAliasCount: MAX_ALIAS_COUNT });
}

function parseYaml(input: string): ParseYamlOutput {
  const text = normalizeInput(input);
  rejectExplicitCustomTags(text);

  let parsedDocuments: unknown[];

  try {
    parsedDocuments = parseAllDocuments(text, { schema: "core" });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`parse_yaml input must be valid YAML: ${message}`);
  }

  if (parsedDocuments.length === 0) {
    throw new Error("parse_yaml input did not contain any documents");
  }

  if (parsedDocuments.length > MAX_DOCUMENTS) {
    throw new Error(`parse_yaml supports at most ${MAX_DOCUMENTS} documents`);
  }

  const warnings: string[] = [];
  const unsafeTags = new Set<string>();
  const values: unknown[] = [];

  for (const [documentIndex, document] of parsedDocuments.entries()) {
    const yamlDocument = document as {
      contents?: unknown;
      errors?: Array<{ message?: string }>;
      warnings?: Array<{ message?: string }>;
    };

    const errors = yamlDocument.errors ?? [];
    if (errors.length > 0) {
      const firstMessage = errors[0]?.message ?? "unknown YAML parse error";
      throw new Error(`parse_yaml input must be valid YAML: ${firstMessage}`);
    }

    for (const parserWarning of yamlDocument.warnings ?? []) {
      warnings.push(`YAML parser warning in document ${documentIndex}: ${parserWarning.message ?? "unknown warning"}`);
    }

    collectUnsafeNodeTags(yamlDocument.contents, unsafeTags);
    values.push(normalizeJsonCompatible(documentToJs(document)));
  }

  if (unsafeTags.size > 0) {
    throw new Error(`parse_yaml custom tags are not supported: ${Array.from(unsafeTags).sort().join(", ")}`);
  }

  if (values.length > 1) {
    warnings.push("YAML input contained multiple documents; observed.value is null and observed.documents contains parsed documents.");
  }

  const documentSummaries = values.map((value, index) => ({
    document_index: index,
    value_type: valueType(value),
    keys: topLevelKeys(value),
  }));

  const singleValue = values.length === 1 ? values[0] : null;

  return {
    artifact: {
      id: "artifact_yaml",
      type: "yaml",
    },
    observed: {
      document_count: values.length,
      value_type: values.length === 1 ? valueType(values[0]) : "multiple",
      keys: values.length === 1 ? topLevelKeys(values[0]) : [],
      value: singleValue,
      documents: values,
      document_summaries: documentSummaries,
    },
    warnings,
  };
}

export const parseYamlSkill: Skill<string, ParseYamlOutput> = {
  metadata: {
    name: "parse_yaml",
    version: "0.1.0",
    category: "parser",
    description: "Parse YAML text into JSON-compatible values and structural metadata without custom tags or remote includes.",
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
        "YAML parsing is local-only and rejects custom tags while returning JSON-compatible values for downstream workflows.",
        "Hosted exposure remains allowlist-only because YAML inputs may contain sensitive configuration data and should be gated before API, web, or MCP exposure.",
      ],
    },
  },
  run(input: string): ParseYamlOutput {
    return parseYaml(input);
  },
};
