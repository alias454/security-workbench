import type { Skill } from "@security-workbench/schemas";
import { TextDecoder } from "node:util";
import { localOnlyPermissions } from "./localOnlyPermissions.js";

export interface ParseJwtOutput {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  algorithm: string | null;
  type: string | null;
  signature_present: boolean;
  signature_length: number;
  signature_verified: false;
  warnings: string[];
}

function assertString(input: string): void {
  if (typeof input !== "string") {
    throw new Error("parse_jwt input must be a string");
  }
}

function decodeBase64Url(segment: string, fieldName: string): string {
  if (!/^[A-Za-z0-9_-]*$/.test(segment)) {
    throw new Error(`parse_jwt ${fieldName} contains invalid base64url characters`);
  }

  const padded = `${segment}${"=".repeat((4 - (segment.length % 4)) % 4)}`;
  const base64 = padded.replace(/-/g, "+").replace(/_/g, "/");
  const bytes = Buffer.from(base64, "base64");
  const decoder = new TextDecoder("utf-8", { fatal: true });

  try {
    return decoder.decode(bytes);
  } catch {
    throw new Error(`parse_jwt ${fieldName} is not valid UTF-8 after base64url decode`);
  }
}

function parseJsonObject(text: string, fieldName: string): Record<string, unknown> {
  let parsed: unknown;

  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error(`parse_jwt ${fieldName} is not valid JSON`);
  }

  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error(`parse_jwt ${fieldName} must decode to a JSON object`);
  }

  return parsed as Record<string, unknown>;
}

export const parseJwtSkill: Skill<string, ParseJwtOutput> = {
  metadata: {
    name: "parse_jwt",
    version: "0.1.0",
    category: "parser",
    description: "Decode JWT header and payload without verifying the signature or exposing the raw signature.",
    execution: {
      mode: "local_only",
      network_access: "none",
      deterministic: true,
    },
    permissions: localOnlyPermissions,
  },

  run(input: string) {
    assertString(input);

    const trimmed = input.trim();
    const parts = trimmed.split(".");

    if (parts.length !== 3) {
      throw new Error("parse_jwt input must contain exactly three JWT segments");
    }

    const [headerSegment, payloadSegment, signatureSegment] = parts;

    if (!headerSegment || !payloadSegment) {
      throw new Error("parse_jwt header and payload segments must be present");
    }

    const header = parseJsonObject(decodeBase64Url(headerSegment, "header"), "header");
    const payload = parseJsonObject(decodeBase64Url(payloadSegment, "payload"), "payload");

    const algorithm = typeof header.alg === "string" ? header.alg : null;
    const type = typeof header.typ === "string" ? header.typ : null;

    return {
      header,
      payload,
      algorithm,
      type,
      signature_present: signatureSegment.length > 0,
      signature_length: signatureSegment.length,
      signature_verified: false,
      warnings: ["JWT signature is not verified by parse_jwt."],
    };
  },
};
