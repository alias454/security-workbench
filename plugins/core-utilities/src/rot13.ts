import type { Skill } from "@security-workbench/schemas";
import { localOnlyPermissions } from "./localOnlyPermissions.js";

export interface Rot13Output {
  transformed: string;
}

function assertString(input: string): void {
  if (typeof input !== "string") {
    throw new Error("rot13 input must be a string");
  }
}

function rotateChar(char: string): string {
  const code = char.charCodeAt(0);

  if (code >= 65 && code <= 90) {
    return String.fromCharCode(((code - 65 + 13) % 26) + 65);
  }

  if (code >= 97 && code <= 122) {
    return String.fromCharCode(((code - 97 + 13) % 26) + 97);
  }

  return char;
}

export const rot13Skill: Skill<string, Rot13Output> = {
  metadata: {
    name: "rot13",
    version: "0.1.0",
    category: "transform",
    description: "Apply ROT13 substitution to ASCII letters while preserving other characters.",
    execution: {
      mode: "local_only",
      network_access: "none",
      deterministic: true,
    },
    permissions: localOnlyPermissions,
  },

  run(input: string) {
    assertString(input);

    return {
      transformed: [...input].map(rotateChar).join(""),
    };
  },
};
