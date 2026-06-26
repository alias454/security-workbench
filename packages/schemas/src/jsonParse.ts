import type { JsonObject, JsonValue } from "./json.js";
import { getJsonType, isJsonObject } from "./json.js";
import type { StructuredParseError } from "./parseError.js";
import { createParseError } from "./parseError.js";

export type SafeParseResult<T> =
  | {
      readonly ok: true;
      readonly value: T;
    }
  | {
      readonly ok: false;
      readonly error: StructuredParseError;
    };

export function safeJsonParse(input: unknown): SafeParseResult<JsonValue> {
  if (typeof input !== "string") {
    return {
      ok: false,
      error: createParseError({
        code: "INVALID_TYPE",
        message: "JSON input must be a string.",
        recoverable: false,
        details: {
          expected: "string",
          received: getJsonType(input),
        },
      }),
    };
  }

  try {
    return {
      ok: true,
      value: JSON.parse(input) as JsonValue,
    };
  } catch {
    return {
      ok: false,
      error: createParseError({
        code: "INVALID_JSON",
        message: "Input must be valid JSON.",
        recoverable: false,
      }),
    };
  }
}

export function safeJsonObjectParse(input: unknown): SafeParseResult<JsonObject> {
  const parsed = safeJsonParse(input);

  if (!parsed.ok) {
    return parsed;
  }

  if (!isJsonObject(parsed.value)) {
    return {
      ok: false,
      error: createParseError({
        code: "INVALID_TYPE",
        message: "Expected a JSON object.",
        recoverable: false,
        details: {
          expected: "object",
          received: getJsonType(parsed.value),
        },
      }),
    };
  }

  return {
    ok: true,
    value: parsed.value,
  };
}
