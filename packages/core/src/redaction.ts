type JsonLike =
  | string
  | number
  | boolean
  | null
  | JsonLike[]
  | { [key: string]: JsonLike };

const REDACTED = "[REDACTED]";

const SECRET_PATTERNS: Array<[RegExp, string]> = [
  [
    /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
    "-----BEGIN REDACTED PRIVATE KEY-----\n[REDACTED]\n-----END REDACTED PRIVATE KEY-----",
  ],
  [/\bAKIA[0-9A-Z]{16}\b/g, REDACTED],
  [/\bASIA[0-9A-Z]{16}\b/g, REDACTED],
  [/\bgh[pousr]_[A-Za-z0-9_]{20,255}\b/g, REDACTED],
  [/\bgithub_pat_[A-Za-z0-9_]{20,255}\b/g, REDACTED],
  [
    /\beyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b/g,
    REDACTED,
  ],
  [/\bBearer\s+[A-Za-z0-9._~+/=-]{10,}\b/gi, "Bearer [REDACTED]"],
];

export function redactUrlCredentials(input: string): string {
  return input.replace(
    /\b([a-z][a-z0-9+.-]*:\/\/)([^/@\s:]+)(?::([^/@\s]*))?@/gi,
    "$1[REDACTED]@"
  );
}

export function redactString(input: string): string {
  let redacted = redactUrlCredentials(input);

  for (const [pattern, replacement] of SECRET_PATTERNS) {
    redacted = redacted.replace(pattern, replacement);
  }

  return redacted;
}


const SENSITIVE_REDACTION_KEYS = new Set([
  "password",
  "passwd",
  "pwd",
  "secret",
  "token",
  "accesstoken",
  "refreshtoken",
  "apikey",
  "authorization",
  "auth",
  "credential",
  "credentials",
  "privatekey",
  "clientsecret",
  "session",
  "cookie",
  "setcookie",
]);

function normalizeRedactionKey(key: string): string {
  return key.trim().replace(/[\s_-]/g, "").toLowerCase();
}

export function isSensitiveRedactionKey(key: string): boolean {
  return SENSITIVE_REDACTION_KEYS.has(normalizeRedactionKey(key));
}

const CIRCULAR_REFERENCE = "[CIRCULAR]";
const REDACTION_DEPTH_LIMIT = "[REDACTION_DEPTH_LIMIT]";
const MAX_REDACTION_DEPTH = 32;

function redactValueInternal<T>(
  value: T,
  depth: number,
  seen: WeakSet<object>
): T {
  if (typeof value === "string") {
    return redactString(value) as T;
  }

  if (value === null || typeof value !== "object") {
    return value;
  }

  if (depth >= MAX_REDACTION_DEPTH) {
    return REDACTION_DEPTH_LIMIT as T;
  }

  const objectValue = value as object;

  if (seen.has(objectValue)) {
    return CIRCULAR_REFERENCE as T;
  }

  seen.add(objectValue);

  if (Array.isArray(value)) {
    const redactedArray = value.map((item) =>
      redactValueInternal(item, depth + 1, seen)
    ) as T;
    seen.delete(objectValue);
    return redactedArray;
  }

  const redactedObject = Object.fromEntries(
    Object.entries(value as Record<string, unknown>).map(([key, nestedValue]) => [
      key,
      isSensitiveRedactionKey(key)
        ? REDACTED
        : redactValueInternal(nestedValue, depth + 1, seen),
    ]),
  ) as T;

  seen.delete(objectValue);
  return redactedObject;
}

export function redactValue<T>(value: T): T {
  return redactValueInternal(value, 0, new WeakSet<object>());
}

export function toRedactedJson(value: unknown): JsonLike {
  return redactValue(value) as JsonLike;
}
