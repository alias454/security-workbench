import type { JsonObject, SourceLocation } from "./json.js";

export const parseErrorCodes = [
  "PARSE_ERROR",
  "INVALID_TYPE",
  "INVALID_JSON",
  "INVALID_FORMAT",
  "UNSUPPORTED_VERSION",
  "LIMIT_EXCEEDED",
  "EMPTY_INPUT",
  "MALFORMED_INPUT",
] as const;

export type ParseErrorCode = (typeof parseErrorCodes)[number];

export interface StructuredParseError {
  readonly code: ParseErrorCode | string;
  readonly message: string;
  readonly recoverable: boolean;
  readonly location?: SourceLocation;
  readonly details?: JsonObject;
}

export function createParseError(input: StructuredParseError): StructuredParseError {
  return input;
}

export function isParseErrorCode(value: unknown): value is ParseErrorCode {
  return typeof value === "string" && parseErrorCodes.includes(value as ParseErrorCode);
}

export function isStructuredParseError(value: unknown): value is StructuredParseError {
  if (typeof value !== "object" || value === null) {
    return false;
  }

  const candidate = value as Record<string, unknown>;
  return (
    typeof candidate.code === "string" &&
    typeof candidate.message === "string" &&
    typeof candidate.recoverable === "boolean"
  );
}
