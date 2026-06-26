import { Buffer } from "node:buffer";
import type { Skill } from "@security-workbench/schemas";
import { localOnlyPermissions } from "./localOnlyPermissions.js";

export interface HexEncodeOutput {
  encoded: string;
}

export const hexEncodeSkill: Skill<string, HexEncodeOutput> = {
  metadata: {
    name: "hex_encode",
    version: "0.1.0",
    category: "transform",
    description: "Encode a UTF-8 string as lowercase hexadecimal.",
    execution: {
      mode: "local_only",
      network_access: "none",
      deterministic: true,
    },
    permissions: localOnlyPermissions,
  },

  run(input: string) {
    if (typeof input !== "string") {
      throw new Error("hex_encode input must be a string");
    }

    return {
      encoded: Buffer.from(input, "utf8").toString("hex"),
    };
  },
};
