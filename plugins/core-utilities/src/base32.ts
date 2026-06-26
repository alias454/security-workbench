import type { Skill } from "@security-workbench/schemas";
import { TextDecoder } from "node:util";
import { localOnlyPermissions } from "./localOnlyPermissions.js";

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const BASE32_LOOKUP = new Map<string, number>(
  [...BASE32_ALPHABET].map((char, index) => [char, index])
);
const VALID_PADDING_LENGTHS = new Set([0, 1, 3, 4, 6]);

export interface Base32EncodeOutput {
  encoded: string;
  alphabet: "RFC4648";
  padded: true;
}

export interface Base32DecodeOutput {
  decoded: string;
  alphabet: "RFC4648";
}

function assertString(input: string, skillName: string): void {
  if (typeof input !== "string") {
    throw new Error(`${skillName} input must be a string`);
  }
}

function encodeBase32(input: string): string {
  const bytes = Buffer.from(input, "utf8");
  let value = 0;
  let bits = 0;
  let output = "";

  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;

    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }

  if (bits > 0) {
    output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }

  while (output.length % 8 !== 0) {
    output += "=";
  }

  return output;
}

function decodeUtf8Strict(bytes: Uint8Array): string {
  const decoder = new TextDecoder("utf-8", { fatal: true });
  try {
    return decoder.decode(bytes);
  } catch {
    throw new Error("base32_decode decoded bytes are not valid UTF-8");
  }
}

function decodeBase32(input: string): string {
  if (input.length === 0) {
    return "";
  }

  const normalized = input.toUpperCase();

  if (normalized.length % 8 !== 0) {
    throw new Error("base32_decode input length must be a multiple of 8");
  }

  const firstPaddingIndex = normalized.indexOf("=");
  const dataPart = firstPaddingIndex === -1 ? normalized : normalized.slice(0, firstPaddingIndex);
  const paddingPart = firstPaddingIndex === -1 ? "" : normalized.slice(firstPaddingIndex);

  if (!/^[A-Z2-7]*$/.test(dataPart)) {
    throw new Error("base32_decode input contains invalid Base32 characters");
  }

  if (!/^=*$/.test(paddingPart)) {
    throw new Error("base32_decode padding must appear only at the end");
  }

  if (!VALID_PADDING_LENGTHS.has(paddingPart.length)) {
    throw new Error("base32_decode input has invalid RFC4648 padding length");
  }

  let value = 0;
  let bits = 0;
  const bytes: number[] = [];

  for (const char of dataPart) {
    const digit = BASE32_LOOKUP.get(char);
    if (digit === undefined) {
      throw new Error("base32_decode input contains invalid Base32 characters");
    }

    value = (value << 5) | digit;
    bits += 5;

    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }

  if (bits > 0) {
    const leftoverMask = (1 << bits) - 1;
    if ((value & leftoverMask) !== 0) {
      throw new Error("base32_decode input contains non-zero trailing padding bits");
    }
  }

  return decodeUtf8Strict(Uint8Array.from(bytes));
}

export const base32EncodeSkill: Skill<string, Base32EncodeOutput> = {
  metadata: {
    name: "base32_encode",
    version: "0.1.0",
    category: "transform",
    description: "Encode a UTF-8 string as RFC4648 padded Base32.",
    execution: {
      mode: "local_only",
      network_access: "none",
      deterministic: true,
    },
    permissions: localOnlyPermissions,
  },

  run(input: string) {
    assertString(input, "base32_encode");

    return {
      encoded: encodeBase32(input),
      alphabet: "RFC4648",
      padded: true,
    };
  },
};

export const base32DecodeSkill: Skill<string, Base32DecodeOutput> = {
  metadata: {
    name: "base32_decode",
    version: "0.1.0",
    category: "transform",
    description: "Decode strict RFC4648 padded Base32 into UTF-8 text.",
    execution: {
      mode: "local_only",
      network_access: "none",
      deterministic: true,
    },
    permissions: localOnlyPermissions,
  },

  run(input: string) {
    assertString(input, "base32_decode");

    return {
      decoded: decodeBase32(input),
      alphabet: "RFC4648",
    };
  },
};
