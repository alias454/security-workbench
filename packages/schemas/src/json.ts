export type JsonPrimitive = string | number | boolean | null;
export type JsonObject = { readonly [key: string]: JsonValue };
export type JsonArray = readonly JsonValue[];
export type JsonValue = JsonPrimitive | JsonObject | JsonArray;

export type JsonPath = string;

export interface SourceLocation {
  readonly line?: number;
  readonly column?: number;
  readonly offset?: number;
  readonly path?: JsonPath;
}

export const sensitivityLevels = ["low", "medium", "high", "unknown"] as const;
export type SensitivityLevel = (typeof sensitivityLevels)[number];

export function isSensitivityLevel(value: unknown): value is SensitivityLevel {
  return typeof value === "string" && sensitivityLevels.includes(value as SensitivityLevel);
}


export const jsonTypeNames = [
  "array",
  "boolean",
  "null",
  "number",
  "object",
  "string",
  "undefined",
  "unknown",
] as const;
export type JsonTypeName = (typeof jsonTypeNames)[number];

export function getJsonType(value: unknown): JsonTypeName {
  if (value === null) {
    return "null";
  }

  if (Array.isArray(value)) {
    return "array";
  }

  switch (typeof value) {
    case "boolean":
      return "boolean";
    case "number":
      return "number";
    case "object":
      return "object";
    case "string":
      return "string";
    case "undefined":
      return "undefined";
    default:
      return "unknown";
  }
}

export function isJsonObject(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function isJsonArray(value: unknown): value is JsonArray {
  return Array.isArray(value);
}
