import type { Skill } from "@security-workbench/schemas";
import { localOnlyPermissions } from "./localOnlyPermissions.js";

export interface JsonParseOutput {
  value: unknown;
}

function parseJson(input: string): unknown {
  try {
    return JSON.parse(input) as unknown;
  } catch {
    throw new Error("json_parse input must be valid JSON");
  }
}

export const jsonParseSkill: Skill<string, JsonParseOutput> = {
  metadata: {
    name: "json_parse",
    version: "0.1.0",
    category: "parser",
    description: "Parse JSON text into a structured JSON value.",
    execution: {
      mode: "local_only",
      network_access: "none",
      deterministic: true,
    },
    permissions: localOnlyPermissions,
  },

  run(input: string) {
    if (typeof input !== "string") {
      throw new Error("json_parse input must be a string");
    }

    return {
      value: parseJson(input),
    };
  },
};
