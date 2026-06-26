import { Buffer } from "node:buffer";
import type { Skill } from "@security-workbench/schemas";
import { localOnlyPermissions } from "./localOnlyPermissions.js";

export interface HexDecodeOutput {
  decoded: string;
}

function isStrictHex(input: string): boolean {
  return input.length > 0 && input.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(input);
}

export const hexDecodeSkill: Skill<string, HexDecodeOutput> = {
  metadata: {
    name: "hex_decode",
    version: "0.1.0",
    category: "transform",
    description: "Decode strict even-length hexadecimal into UTF-8 text.",
    execution: {
      mode: "local_only",
      network_access: "none",
      deterministic: true,
    },
    permissions: localOnlyPermissions,
  },

  run(input: string) {
    if (typeof input !== "string") {
      throw new Error("hex_decode input must be a string");
    }

    if (!isStrictHex(input)) {
      throw new Error("hex_decode input must be strict even-length hexadecimal");
    }

    return {
      decoded: Buffer.from(input, "hex").toString("utf8"),
    };
  },
};
