import type { RunPolicy, Skill } from "@security-workbench/schemas";
import { PolicyRefusalError, ValidationError } from "./errors.js";

export const defaultPolicy: RunPolicy = {
  allow_network: false,
  persist_inputs: false,
  redact_secrets: true,
  max_artifact_size_mb: 10,
  approved_sinks: [],
};

export function enforceSkillPolicy(skill: Skill, policy: RunPolicy): void {
  if (
    skill.metadata.execution.network_access === "optional" &&
    skill.metadata.execution.mode !== "network_optional"
  ) {
    throw new ValidationError(
      `Invalid skill metadata for '${skill.metadata.name}': optional network access requires network_optional mode`
    );
  }

  if (
    skill.metadata.execution.network_access === "required" &&
    skill.metadata.execution.mode !== "network_required"
  ) {
    throw new ValidationError(
      `Invalid skill metadata for '${skill.metadata.name}': required network access requires network_required mode`
    );
  }

  const permissions = skill.metadata.permissions;

  if (permissions) {
    if (
      permissions.network !== skill.metadata.execution.network_access
    ) {
      throw new ValidationError(
        `Invalid skill metadata for '${skill.metadata.name}': permissions.network must match execution.network_access`
      );
    }

    if (permissions.persists && !policy.persist_inputs) {
      throw new PolicyRefusalError(
        `Policy refused skill '${skill.metadata.name}': persistence requested but disabled`
      );
    }

    if (permissions.runs_external_binaries) {
      throw new PolicyRefusalError(
        `Policy refused skill '${skill.metadata.name}': external binaries are not allowed`
      );
    }

    if (
      permissions.filesystem === "read_write" &&
      !policy.persist_inputs
    ) {
      throw new PolicyRefusalError(
        `Policy refused skill '${skill.metadata.name}': read/write filesystem access requires persistence approval`
      );
    }
  }

  if (skill.metadata.execution.network_access !== "none" && !permissions) {
    throw new ValidationError(
      `Invalid skill metadata for '${skill.metadata.name}': network-capable skills require permissions metadata`
    );
  }

  const declaredSinks = permissions?.sends ?? [];

  if (
    declaredSinks.length > 0 &&
    skill.metadata.execution.network_access === "none"
  ) {
    throw new ValidationError(
      `Invalid skill metadata for '${skill.metadata.name}': permissions.sends requires network access declaration`
    );
  }

  if (
    skill.metadata.execution.network_access !== "none" &&
    !policy.allow_network
  ) {
    throw new PolicyRefusalError(
      `Policy refused skill '${skill.metadata.name}': network access is ${skill.metadata.execution.network_access} but disabled`
    );
  }

  if (declaredSinks.length > 0) {
    const approvedSinks = new Set(policy.approved_sinks);
    const unapprovedSinks = declaredSinks.filter((sink) => !approvedSinks.has(sink));

    if (unapprovedSinks.length > 0) {
      throw new PolicyRefusalError(
        `Policy refused skill '${skill.metadata.name}': external sinks not approved: ${unapprovedSinks.join(", ")}`
      );
    }
  }
}
