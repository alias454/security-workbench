export type SecurityWorkbenchErrorKind =
  | "usage"
  | "validation"
  | "policy_refusal"
  | "internal";

export class SecurityWorkbenchError extends Error {
  readonly kind: SecurityWorkbenchErrorKind;
  readonly exitCode: number;

  constructor(message: string, kind: SecurityWorkbenchErrorKind, exitCode: number) {
    super(message);
    this.name = "SecurityWorkbenchError";
    this.kind = kind;
    this.exitCode = exitCode;
  }
}

export class UsageError extends SecurityWorkbenchError {
  constructor(message: string) {
    super(message, "usage", 2);
    this.name = "UsageError";
  }
}

export class ValidationError extends SecurityWorkbenchError {
  constructor(message: string) {
    super(message, "validation", 2);
    this.name = "ValidationError";
  }
}

export class PolicyRefusalError extends SecurityWorkbenchError {
  constructor(message: string) {
    super(message, "policy_refusal", 3);
    this.name = "PolicyRefusalError";
  }
}

export function isSecurityWorkbenchError(
  error: unknown
): error is SecurityWorkbenchError {
  return error instanceof SecurityWorkbenchError;
}

export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
