import { Buffer } from "node:buffer";
import type { Skill } from "@security-workbench/schemas";
import { localOnlyPermissions } from "./localOnlyPermissions.js";

export interface Base64EncodeOutput {
  encoded: string;
}

export const base64EncodeSkill: Skill<string, Base64EncodeOutput> = {
  metadata: {
    name: "base64_encode",
    version: "0.1.0",
    category: "transform",
    description: "Encode a UTF-8 string as padded Base64.",
    execution: {
      mode: "local_only",
      network_access: "none",
      deterministic: true,
    },
    permissions: localOnlyPermissions,
  },

  run(input: string) {
    if (typeof input !== "string") {
      throw new Error("base64_encode input must be a string");
    }

    return {
      encoded: Buffer.from(input, "utf8").toString("base64"),
    };
  },
};
