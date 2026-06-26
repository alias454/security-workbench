import { Buffer } from "node:buffer";
import type { Skill } from "@security-workbench/schemas";

export interface Base64DecodeOutput {
  decoded: string;
}

function normalizeBase64(input: string): string {
  return input.replace(/\s+/g, "");
}

function isStrictBase64(input: string): boolean {
  const normalized = normalizeBase64(input);

  if (normalized.length === 0 || normalized.length % 4 !== 0) {
    return false;
  }

  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(normalized)) {
    return false;
  }

  const firstPadding = normalized.indexOf("=");

  if (firstPadding !== -1 && !/^={1,2}$/.test(normalized.slice(firstPadding))) {
    return false;
  }

  return true;
}

export const base64DecodeSkill: Skill<string, Base64DecodeOutput> = {
  metadata: {
    name: "base64_decode",
    version: "0.1.0",
    category: "transform",
    description: "Decode a strict base64-encoded string.",
    execution: {
      mode: "local_only",
      network_access: "none",
      deterministic: true,
    },
    permissions: {
      network: "none",
      filesystem: "none",
      sends: [],
      persists: false,
      runs_external_binaries: false,
    },
  },

  run(input: string) {
    if (typeof input !== "string") {
      throw new Error("base64_decode input must be a string");
    }

    const normalized = normalizeBase64(input);

    if (!isStrictBase64(normalized)) {
      throw new Error("base64_decode input must be strict padded base64");
    }

    return {
      decoded: Buffer.from(normalized, "base64").toString("utf8"),
    };
  },
};
