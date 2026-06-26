import type { Skill } from "@security-workbench/schemas";
import { localOnlyPermissions } from "./localOnlyPermissions.js";

export interface UrlEncodeOutput {
  encoded: string;
}

export const urlEncodeSkill: Skill<string, UrlEncodeOutput> = {
  metadata: {
    name: "url_encode",
    version: "0.1.0",
    category: "transform",
    description: "Percent-encode a string using encodeURIComponent.",
    execution: {
      mode: "local_only",
      network_access: "none",
      deterministic: true,
    },
    permissions: localOnlyPermissions,
  },

  run(input: string) {
    if (typeof input !== "string") {
      throw new Error("url_encode input must be a string");
    }

    return {
      encoded: encodeURIComponent(input),
    };
  },
};
