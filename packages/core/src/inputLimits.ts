import { Buffer } from "node:buffer";
import { PolicyRefusalError, ValidationError } from "./errors.js";

const BYTES_PER_MEGABYTE = 1024 * 1024;

export function megabytesToBytes(megabytes: number): number {
  if (!Number.isFinite(megabytes) || megabytes <= 0) {
    throw new ValidationError("max_artifact_size_mb must be a positive number");
  }

  return Math.floor(megabytes * BYTES_PER_MEGABYTE);
}

export function estimateInputBytes(input: unknown): number {
  if (typeof input === "string") {
    return Buffer.byteLength(input, "utf8");
  }

  if (Buffer.isBuffer(input)) {
    return input.byteLength;
  }

  if (input === undefined || input === null) {
    return 0;
  }

  try {
    return Buffer.byteLength(JSON.stringify(input), "utf8");
  } catch {
    throw new ValidationError("input cannot be safely measured");
  }
}

export function enforceInputSize(input: unknown, maxArtifactSizeMb: number): void {
  const maxBytes = megabytesToBytes(maxArtifactSizeMb);
  const actualBytes = estimateInputBytes(input);

  if (actualBytes > maxBytes) {
    throw new PolicyRefusalError(
      `Input refused: ${actualBytes} bytes exceeds max_artifact_size_mb=${maxArtifactSizeMb}`
    );
  }
}
