import type { Skill } from "@security-workbench/schemas";
import type { CliListFormat } from "./args.js";

export interface SkillDescribeFormatOptions {
  format: CliListFormat;
}

interface DescribedSkill {
  name: string;
  version: string;
  category: string;
  description: string;
  execution: {
    mode: string;
    network_access: string;
    deterministic: boolean;
  };
  permissions: {
    network: string;
    filesystem: string;
    sends: string[];
    persists: boolean;
    runs_external_binaries: boolean;
  };
}

function toDescribedSkill(skill: Skill<unknown, unknown>): DescribedSkill {
  return {
    name: skill.metadata.name,
    version: skill.metadata.version,
    category: skill.metadata.category,
    description: skill.metadata.description,
    execution: {
      mode: skill.metadata.execution.mode,
      network_access: skill.metadata.execution.network_access,
      deterministic: skill.metadata.execution.deterministic,
    },
    permissions: {
      network: skill.metadata.permissions?.network ?? "none",
      filesystem: skill.metadata.permissions?.filesystem ?? "none",
      sends: [...(skill.metadata.permissions?.sends ?? [])],
      persists: skill.metadata.permissions?.persists ?? false,
      runs_external_binaries: skill.metadata.permissions?.runs_external_binaries ?? false,
    },
  };
}

function pad(value: string, width: number): string {
  return value.padEnd(width, " ");
}

function displayValue(value: string | boolean | readonly string[]): string {
  if (Array.isArray(value)) {
    return value.length === 0 ? "[]" : value.join(", ");
  }

  return String(value);
}

function descriptionRows(skill: DescribedSkill): Array<[string, string | boolean | readonly string[]]> {
  return [
    ["Name", skill.name],
    ["Version", skill.version],
    ["Category", skill.category],
    ["Description", skill.description],
    ["Execution mode", skill.execution.mode],
    ["Network access", skill.execution.network_access],
    ["Deterministic", skill.execution.deterministic],
    ["Permission: network", skill.permissions.network],
    ["Permission: filesystem", skill.permissions.filesystem],
    ["Permission: sends", skill.permissions.sends],
    ["Permission: persists", skill.permissions.persists],
    ["Permission: external binaries", skill.permissions.runs_external_binaries],
  ];
}

function formatTable(skill: DescribedSkill): string {
  const rows = descriptionRows(skill);
  const keyHeader = "Property";
  const valueHeader = "Value";
  const keyWidth = Math.max(keyHeader.length, ...rows.map(([key]) => key.length));

  return [
    `${pad(keyHeader, keyWidth)}  ${valueHeader}`,
    `${pad("-".repeat(keyHeader.length), keyWidth)}  ${"-".repeat(valueHeader.length)}`,
    ...rows.map(([key, value]) => `${pad(key, keyWidth)}  ${displayValue(value)}`),
  ].join("\n");
}

function formatTsv(skill: DescribedSkill): string {
  return descriptionRows(skill)
    .map(([key, value]) => `${key}\t${displayValue(value)}`)
    .join("\n");
}

function formatJson(skill: DescribedSkill): string {
  return JSON.stringify(skill, null, 2);
}

export function formatSkillDescription(
  skill: Skill<unknown, unknown>,
  options: SkillDescribeFormatOptions
): string {
  const described = toDescribedSkill(skill);

  if (options.format === "json") {
    return formatJson(described);
  }

  if (options.format === "tsv") {
    return formatTsv(described);
  }

  return formatTable(described);
}
