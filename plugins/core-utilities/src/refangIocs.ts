import type { Skill } from "@security-workbench/schemas";

export interface RefangIocsOutput {
  refanged: string;
}

function assertString(input: string): void {
  if (typeof input !== "string") {
    throw new Error("refang_iocs input must be a string");
  }
}

export const refangIocsSkill: Skill<string, RefangIocsOutput> = {
  metadata: {
    name: "refang_iocs",
    version: "0.1.0",
    category: "transform",
    description: "Refang common defanged IOC patterns in text.",
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
    assertString(input);

    let refanged = input
      .replace(/hxxps:\/\//gi, "https://")
      .replace(/hxxp:\/\//gi, "http://");

    refanged = refanged
      .replace(/\[\.\]/g, ".")
      .replace(/\(\.\)/g, ".")
      .replace(/\{\.\}/g, ".")
      .replace(/\[dot\]/gi, ".")
      .replace(/\(dot\)/gi, ".")
      .replace(/\{dot\}/gi, ".")
      .replace(/\[@\]/g, "@")
      .replace(/\(@\)/g, "@")
      .replace(/\{@\}/g, "@")
      .replace(/\[at\]/gi, "@")
      .replace(/\(at\)/gi, "@")
      .replace(/\{at\}/gi, "@");

    return { refanged };
  },
};
