import type { FindingRecord, Skill } from "@security-workbench/schemas";
import { localOnlyPermissions } from "./localOnlyPermissions.js";

type OutputRecord = Record<string, unknown>;

export interface MarkdownExportOutput {
  readonly artifact: {
    readonly id: "artifact_markdown_export";
    readonly type: "markdown_export";
    readonly source_artifact_id: string | null;
    readonly source_artifact_type: string | null;
  };
  readonly observed: {
    readonly exporter: "export_markdown";
    readonly source_kind: string;
    readonly markdown_line_count: number;
    readonly finding_count: number;
    readonly warning_count: number;
  };
  readonly markdown: string;
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

function markdownEscape(value: string): string {
  return value.replace(/[\\`*_{}[\]()#+.!|-]/g, "\\$&");
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

function isFindingLike(value: unknown): value is FindingRecord {
  return isRecord(value)
    && typeof value.id === "string"
    && typeof value.title === "string"
    && typeof value.summary === "string"
    && Array.isArray(value.artifact_refs)
    && Array.isArray(value.evidence_refs);
}

function findingsFromValue(value: unknown): FindingRecord[] {
  if (isFindingLike(value)) {
    return [value];
  }

  if (!isRecord(value)) {
    return [];
  }

  if (isFindingLike(value.finding)) {
    return [value.finding];
  }

  if (Array.isArray(value.findings)) {
    return value.findings.filter(isFindingLike);
  }

  return [];
}

function renderFinding(finding: FindingRecord): string {
  const lines = [
    `# ${markdownEscape(finding.title)}`,
    "",
    "## Summary",
    "",
    markdownEscape(finding.summary),
    "",
    "## Metadata",
    "",
    `- Finding ID: ${markdownEscape(finding.id)}`,
    `- Status: ${markdownEscape(String(finding.status ?? "unknown"))}`,
    `- Risk level: ${markdownEscape(String(finding.risk?.level ?? "unknown"))}`,
    `- Confidence: ${markdownEscape(String(finding.confidence ?? finding.risk?.confidence ?? "unknown"))}`,
    "",
    "## Observed behavior",
    "",
    ...(finding.observed_behavior?.map((entry) => `- ${markdownEscape(entry)}`) ?? ["- none"]),
    "",
    "## Inferred risk",
    "",
    ...(finding.inferred_risk?.map((entry) => `- ${markdownEscape(entry)}`) ?? ["- none"]),
    "",
    "## Recommended actions",
    "",
    ...(finding.mitigations?.map((entry) => `- ${markdownEscape(entry)}`) ?? ["- none"]),
    "",
    "## Open questions",
    "",
    ...(finding.open_questions?.map((entry) => `- ${markdownEscape(entry)}`) ?? ["- none"]),
  ];

  return lines.join("\n");
}

function renderFindings(findings: readonly FindingRecord[]): string {
  return findings.map(renderFinding).join("\n\n---\n\n");
}

function renderJsonFallback(value: unknown): string {
  return [
    "# Markdown export",
    "",
    "Input did not contain an existing Markdown field or FindingRecord. JSON-compatible content is included for review.",
    "",
    "````json",
    JSON.stringify(value === undefined ? null : value, null, 2),
    "````",
  ].join("\n");
}

export function exportMarkdown(input: unknown): MarkdownExportOutput {
  const { value, sourceKind } = unwrapInput(input);

  if (typeof value === "string") {
    return {
      artifact: {
        id: "artifact_markdown_export",
        type: "markdown_export",
        source_artifact_id: null,
        source_artifact_type: "text",
      },
      observed: {
        exporter: "export_markdown",
        source_kind: sourceKind,
        markdown_line_count: value.split("\n").length,
        finding_count: 0,
        warning_count: 0,
      },
      markdown: value,
      warnings: [],
    };
  }

  const warnings = isRecord(value) ? stringArray(value.warnings) : [];
  const findings = findingsFromValue(value);
  const markdown = isRecord(value) && typeof value.markdown === "string"
    ? value.markdown
    : findings.length > 0
      ? renderFindings(findings)
      : renderJsonFallback(value);
  const source = sourceArtifact(value);

  return {
    artifact: {
      id: "artifact_markdown_export",
      type: "markdown_export",
      source_artifact_id: source.source_artifact_id,
      source_artifact_type: source.source_artifact_type,
    },
    observed: {
      exporter: "export_markdown",
      source_kind: sourceKind,
      markdown_line_count: markdown.split("\n").length,
      finding_count: findings.length,
      warning_count: warnings.length,
    },
    markdown,
    warnings,
  };
}

export const exportMarkdownSkill: Skill<unknown, MarkdownExportOutput> = {
  metadata: {
    name: "export_markdown",
    version: "0.1.0",
    category: "output",
    description: "Export an existing Markdown field, FindingRecord, or JSON-compatible value as local Markdown text.",
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
      risk: "medium",
      rationale: [
        "Formats already generated local analysis output as Markdown.",
        "Does not persist output or send it to external systems.",
        "Markdown output can contain attacker-controlled artifact text and must be escaped or rendered safely by adapters.",
      ],
    },
  },
  run: exportMarkdown,
};
