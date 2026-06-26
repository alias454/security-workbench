import type { Skill } from "@security-workbench/schemas";
import { localOnlyPermissions } from "./localOnlyPermissions.js";

export interface UrlDecodeOutput {
  decoded: string;
}

export const urlDecodeSkill: Skill<string, UrlDecodeOutput> = {
  metadata: {
    name: "url_decode",
    version: "0.1.0",
    category: "transform",
    description: "Decode percent-encoded input using decodeURIComponent.",
    execution: {
      mode: "local_only",
      network_access: "none",
      deterministic: true,
    },
    permissions: localOnlyPermissions,
  },

  run(input: string) {
    if (typeof input !== "string") {
      throw new Error("url_decode input must be a string");
    }

    try {
      return {
        decoded: decodeURIComponent(input),
      };
    } catch {
      throw new Error("url_decode input must be valid percent-encoded text");
    }
  },
};
