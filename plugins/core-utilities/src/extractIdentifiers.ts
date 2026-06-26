import { type Skill } from "@security-workbench/schemas";

import { localOnlyPermissions } from "./localOnlyPermissions.js";

type ExtractCvesOutput = {
  cves: string[];
  count: number;
};

type ExtractUuidsOutput = {
  uuids: string[];
  count: number;
};

const cvePattern = /\bCVE-\d{4}-\d{4,}\b/gi;
const uuidPattern =
  /\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b/g;

function uniqueFirstSeen(values: string[]): string[] {
  const seen = new Set<string>();
  const unique: string[] = [];

  for (const value of values) {
    if (seen.has(value)) {
      continue;
    }

    seen.add(value);
    unique.push(value);
  }

  return unique;
}

export const extractCvesSkill: Skill<string, ExtractCvesOutput> = {
  metadata: {
    name: "extract_cves",
    version: "0.1.0",
    category: "parser",
    description: "Extract CVE identifiers from text without validating external existence.",
    execution: {
      mode: "local_only",
      network_access: "none",
      deterministic: true,
    },
    permissions: localOnlyPermissions,
  },
  run(input) {
    const cves = uniqueFirstSeen(
      Array.from(input.matchAll(cvePattern), (match) => match[0].toUpperCase()),
    );

    return {
      cves,
      count: cves.length,
    };
  },
};

export const extractUuidsSkill: Skill<string, ExtractUuidsOutput> = {
  metadata: {
    name: "extract_uuids",
    version: "0.1.0",
    category: "parser",
    description: "Extract canonical UUID values from text.",
    execution: {
      mode: "local_only",
      network_access: "none",
      deterministic: true,
    },
    permissions: localOnlyPermissions,
  },
  run(input) {
    const uuids = uniqueFirstSeen(
      Array.from(input.matchAll(uuidPattern), (match) => match[0].toLowerCase()),
    );

    return {
      uuids,
      count: uuids.length,
    };
  },
};
