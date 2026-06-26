import type { Skill } from "@security-workbench/schemas";
import { localOnlyPermissions } from "./localOnlyPermissions.js";

export interface CalculateEntropyOutput {
  entropy: number;
  length: number;
  unique_symbols: number;
}

function shannonEntropy(input: string): CalculateEntropyOutput {
  const symbols = Array.from(input);
  const length = symbols.length;

  if (length === 0) {
    return {
      entropy: 0,
      length: 0,
      unique_symbols: 0,
    };
  }

  const counts = new Map<string, number>();

  for (const symbol of symbols) {
    counts.set(symbol, (counts.get(symbol) ?? 0) + 1);
  }

  let entropy = 0;

  for (const count of counts.values()) {
    const probability = count / length;
    entropy -= probability * Math.log2(probability);
  }

  return {
    entropy: Number(entropy.toFixed(6)),
    length,
    unique_symbols: counts.size,
  };
}

export const calculateEntropySkill: Skill<string, CalculateEntropyOutput> = {
  metadata: {
    name: "calculate_entropy",
    version: "0.1.0",
    category: "transform",
    description: "Calculate Shannon entropy over Unicode code points.",
    execution: {
      mode: "local_only",
      network_access: "none",
      deterministic: true,
    },
    permissions: localOnlyPermissions,
  },

  run(input: string) {
    if (typeof input !== "string") {
      throw new Error("calculate_entropy input must be a string");
    }

    return shannonEntropy(input);
  },
};
