import { createHash } from "node:crypto";
import { type Skill } from "@security-workbench/schemas";
import { localOnlyPermissions } from "./localOnlyPermissions.js";

type HashAlgorithm = "md5" | "sha1" | "sha256" | "sha512";

type HashOutput = {
  algorithm: HashAlgorithm;
  encoding: "hex";
  hash: string;
};

type IdentifyHashCandidate = {
  algorithm: HashAlgorithm;
  encoding: "hex";
  digest_length: number;
};

type IdentifyHashOutput = {
  normalized: string;
  input_length: number;
  encoding: "hex" | "unknown";
  candidates: IdentifyHashCandidate[];
};

const execution = {
  mode: "local_only",
  network_access: "none",
  deterministic: true,
} as const;

function requireString(input: string, skillName: string): string {
  if (typeof input !== "string") {
    throw new Error(`${skillName} input must be a string`);
  }
  return input;
}

function hashUtf8(input: string, algorithm: HashAlgorithm): string {
  return createHash(algorithm).update(input, "utf8").digest("hex");
}

function createHashSkill(name: string, algorithm: HashAlgorithm, description: string): Skill<string, HashOutput> {
  return {
    metadata: {
      name,
      version: "0.1.0",
      category: "transform",
      description,
      execution,
      permissions: localOnlyPermissions,
    },
    run(input: string): HashOutput {
      const value = requireString(input, name);
      return {
        algorithm,
        encoding: "hex",
        hash: hashUtf8(value, algorithm),
      };
    },
  };
}

function identifyHexDigest(value: string): IdentifyHashCandidate[] {
  if (!/^[a-f0-9]+$/i.test(value)) {
    return [];
  }

  const candidates: IdentifyHashCandidate[] = [];

  if (value.length === 32) {
    candidates.push({ algorithm: "md5", encoding: "hex", digest_length: 32 });
  }
  if (value.length === 40) {
    candidates.push({ algorithm: "sha1", encoding: "hex", digest_length: 40 });
  }
  if (value.length === 64) {
    candidates.push({ algorithm: "sha256", encoding: "hex", digest_length: 64 });
  }
  if (value.length === 128) {
    candidates.push({ algorithm: "sha512", encoding: "hex", digest_length: 128 });
  }

  return candidates;
}

export const identifyHashSkill: Skill<string, IdentifyHashOutput> = {
  metadata: {
    name: "identify_hash",
    version: "0.1.0",
    category: "parser",
    description: "Identify likely hash algorithms from hexadecimal digest length.",
    execution,
    permissions: localOnlyPermissions,
  },
  run(input: string): IdentifyHashOutput {
    const value = requireString(input, "identify_hash").trim().toLowerCase();
    const candidates = identifyHexDigest(value);

    return {
      normalized: value,
      input_length: value.length,
      encoding: candidates.length > 0 ? "hex" : "unknown",
      candidates,
    };
  },
};

export const md5HashSkill = createHashSkill(
  "md5_hash",
  "md5",
  "Hash a UTF-8 string with MD5 and return lowercase hexadecimal.",
);

export const sha1HashSkill = createHashSkill(
  "sha1_hash",
  "sha1",
  "Hash a UTF-8 string with SHA-1 and return lowercase hexadecimal.",
);

export const sha256HashSkill = createHashSkill(
  "sha256_hash",
  "sha256",
  "Hash a UTF-8 string with SHA-256 and return lowercase hexadecimal.",
);

export const sha512HashSkill = createHashSkill(
  "sha512_hash",
  "sha512",
  "Hash a UTF-8 string with SHA-512 and return lowercase hexadecimal.",
);
