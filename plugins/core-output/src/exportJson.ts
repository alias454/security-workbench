import type { Skill } from "@security-workbench/schemas";
import { localOnlyPermissions } from "./localOnlyPermissions.js";

type OutputRecord = Record<string, unknown>;

export interface JsonExportOutput {
  readonly artifact: {
    readonly id: "artifact_json_export";
    readonly type: "json_export";
    readonly source_artifact_id: string | null;
    readonly source_artifact_type: string | null;
  };
  readonly observed: {
    readonly exporter: "export_json";
    readonly source_kind: string;
    readonly json_line_count: number;
    readonly byte_length: number;
  };
  readonly json: string;
  readonly warnings: string[];
}

function isRecord(value: unknown): value is OutputRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function parseJsonString(input: string): unknown {
  try {
    return JSON.parse(input) as unknown;
  } catch {
    return input;
  }
}

function unwrapInput(input: unknown): { value: unknown; sourceKind: string } {
  const parsed = typeof input === "string" ? parseJsonString(input) : input;

  if (isRecord(parsed) && "output" in parsed) {
    return {
      value: parsed.output,
      sourceKind: "skill_run_result",
    };
  }

  return {
    value: parsed,
    sourceKind: typeof parsed === "string" ? "text" : "direct_value",
  };
}

function stringOrNull(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((entry): entry is string => typeof entry === "string") : [];
}

function sourceArtifact(record: unknown): { source_artifact_id: string | null; source_artifact_type: string | null } {
  if (!isRecord(record)) {
    return {
      source_artifact_id: null,
      source_artifact_type: null,
    };
  }

  const artifact = isRecord(record.artifact) ? record.artifact : undefined;
  return {
    source_artifact_id: stringOrNull(artifact?.id),
    source_artifact_type: stringOrNull(artifact?.type),
  };
}

export function exportJson(input: unknown): JsonExportOutput {
  const { value, sourceKind } = unwrapInput(input);
  const json = JSON.stringify(value === undefined ? null : value, null, 2);
  const source = sourceArtifact(value);

  return {
    artifact: {
      id: "artifact_json_export",
      type: "json_export",
      source_artifact_id: source.source_artifact_id,
      source_artifact_type: source.source_artifact_type,
    },
    observed: {
      exporter: "export_json",
      source_kind: sourceKind,
      json_line_count: json.split("\n").length,
      byte_length: Buffer.byteLength(json, "utf8"),
    },
    json,
    warnings: isRecord(value) ? stringArray(value.warnings) : [],
  };
}

export const exportJsonSkill: Skill<unknown, JsonExportOutput> = {
  metadata: {
    name: "export_json",
    version: "0.1.0",
    category: "output",
    description: "Export a JSON-compatible value or skill run output as deterministic pretty-printed JSON text.",
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
      max_input_mb: 2,
      risk: "low",
      rationale: [
        "Formats local analysis output as JSON text.",
        "Does not persist output or send it to external systems.",
      ],
    },
  },
  run: exportJson,
};
