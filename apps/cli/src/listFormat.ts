import type { Skill } from "@security-workbench/schemas";
import type { CliListCategory, CliListFormat } from "./args.js";

export interface SkillListFormatOptions {
  format: CliListFormat;
  category?: CliListCategory;
}

interface ListedSkill {
  name: string;
  version: string;
  category: string;
  network_access: string;
  description: string;
}

function toListedSkill(skill: Skill<unknown, unknown>): ListedSkill {
  return {
    name: skill.metadata.name,
    version: skill.metadata.version,
    category: skill.metadata.category,
    network_access: skill.metadata.execution.network_access,
    description: skill.metadata.description,
  };
}

function selectSkills(
  skills: readonly Skill<unknown, unknown>[],
  category?: CliListCategory
): ListedSkill[] {
  return skills
    .map(toListedSkill)
    .filter((skill) => category === undefined || skill.category === category);
}

function formatTsv(skills: readonly ListedSkill[]): string {
  return skills.map((skill) => `${skill.name}\t${skill.description}`).join("\n");
}

function pad(value: string, width: number): string {
  return value.padEnd(width, " ");
}

function formatTable(skills: readonly ListedSkill[]): string {
  const headers = {
    name: "Skill",
    category: "Category",
    network_access: "Network",
    description: "Description",
  };

  const nameWidth = Math.max(
    headers.name.length,
    ...skills.map((skill) => skill.name.length)
  );
  const categoryWidth = Math.max(
    headers.category.length,
    ...skills.map((skill) => skill.category.length)
  );
  const networkWidth = Math.max(
    headers.network_access.length,
    ...skills.map((skill) => skill.network_access.length)
  );

  const lines = [
    `${pad(headers.name, nameWidth)}  ${pad(headers.category, categoryWidth)}  ${pad(headers.network_access, networkWidth)}  ${headers.description}`,
    `${pad("-".repeat(headers.name.length), nameWidth)}  ${pad("-".repeat(headers.category.length), categoryWidth)}  ${pad("-".repeat(headers.network_access.length), networkWidth)}  ${"-".repeat(headers.description.length)}`,
  ];

  for (const skill of skills) {
    lines.push(
      `${pad(skill.name, nameWidth)}  ${pad(skill.category, categoryWidth)}  ${pad(skill.network_access, networkWidth)}  ${skill.description}`
    );
  }

  return lines.join("\n");
}

function formatJson(skills: readonly ListedSkill[]): string {
  return JSON.stringify(skills, null, 2);
}

export function formatSkillList(
  skills: readonly Skill<unknown, unknown>[],
  options: SkillListFormatOptions
): string {
  const selected = selectSkills(skills, options.category);

  if (options.format === "json") {
    return formatJson(selected);
  }

  if (options.format === "table") {
    return formatTable(selected);
  }

  return formatTsv(selected);
}
