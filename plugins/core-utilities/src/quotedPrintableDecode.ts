import { TextDecoder } from "node:util";
import type { Skill } from "@security-workbench/schemas";

export interface QuotedPrintableDecodeOutput {
  decoded: string;
}

const UTF8_DECODER = new TextDecoder("utf-8", { fatal: true });

function assertString(input: string): void {
  if (typeof input !== "string") {
    throw new Error("quoted_printable_decode input must be a string");
  }
}

function isHexByte(value: string): boolean {
  return /^[0-9a-fA-F]{2}$/.test(value);
}

function flushBytes(bytes: number[], output: string): string {
  if (bytes.length === 0) {
    return output;
  }

  try {
    return output + UTF8_DECODER.decode(Uint8Array.from(bytes));
  } catch {
    throw new Error("quoted_printable_decode invalid UTF-8 byte sequence");
  } finally {
    bytes.length = 0;
  }
}

function decodeQuotedPrintable(input: string): string {
  let output = "";
  const bytes: number[] = [];

  for (let i = 0; i < input.length; i += 1) {
    const char = input[i];

    if (char !== "=") {
      output = flushBytes(bytes, output);
      output += char;
      continue;
    }

    const next = input[i + 1];
    const following = input[i + 2];

    // Soft line break.
    if (next === "\r" && following === "\n") {
      i += 2;
      continue;
    }

    // Soft line break with LF-only input.
    if (next === "\n") {
      i += 1;
      continue;
    }

    const hex = input.slice(i + 1, i + 3);
    if (hex.length !== 2 || !isHexByte(hex)) {
      throw new Error("quoted_printable_decode invalid escape");
    }

    bytes.push(Number.parseInt(hex, 16));
    i += 2;
  }

  return flushBytes(bytes, output);
}

export const quotedPrintableDecodeSkill: Skill<string, QuotedPrintableDecodeOutput> = {
  metadata: {
    name: "quoted_printable_decode",
    version: "0.1.0",
    category: "transform",
    description: "Decode quoted-printable text with strict malformed escape handling.",
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

    return {
      decoded: decodeQuotedPrintable(input),
    };
  },
};
