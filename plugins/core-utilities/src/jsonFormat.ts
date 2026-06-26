import type { Skill } from "@security-workbench/schemas";
import { localOnlyPermissions } from "./localOnlyPermissions.js";

export interface JsonFormatOutput {
  formatted: string;
}

function parseJson(input: string): unknown {
  try {
    return JSON.parse(input) as unknown;
  } catch {
    throw new Error("json_format input must be valid JSON");
  }
}

export const jsonFormatSkill: Skill<string, JsonFormatOutput> = {
  metadata: {
    name: "json_format",
    version: "0.1.0",
    category: "transform",
    description: "Parse and pretty-print JSON using two-space indentation.",
    execution: {
      mode: "local_only",
      network_access: "none",
      deterministic: true,
    },
    permissions: localOnlyPermissions,
  },

  run(input: string) {
    if (typeof input !== "string") {
      throw new Error("json_format input must be a string");
    }

    return {
      formatted: JSON.stringify(parseJson(input), null, 2),
    };
  },
};
