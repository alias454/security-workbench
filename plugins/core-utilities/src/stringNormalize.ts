import type { Skill } from "@security-workbench/schemas";
import { localOnlyPermissions } from "./localOnlyPermissions.js";

export interface StringNormalizeOutput {
  normalized: string;
  form: "NFC";
  changed: boolean;
}

export const stringNormalizeSkill: Skill<string, StringNormalizeOutput> = {
  metadata: {
    name: "string_normalize",
    version: "0.1.0",
    category: "transform",
    description: "Normalize Unicode text to NFC without trimming or case folding.",
    execution: {
      mode: "local_only",
      network_access: "none",
      deterministic: true,
    },
    permissions: localOnlyPermissions,
  },

  run(input: string) {
    if (typeof input !== "string") {
      throw new Error("string_normalize input must be a string");
    }

    const normalized = input.normalize("NFC");

    return {
      normalized,
      form: "NFC",
      changed: normalized !== input,
    };
  },
};
