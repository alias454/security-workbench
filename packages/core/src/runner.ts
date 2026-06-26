import { randomUUID } from "node:crypto";
import type { RunPolicy, SkillRunResult } from "@security-workbench/schemas";
import { errorMessage, PolicyRefusalError } from "./errors.js";
import { enforceInputSize } from "./inputLimits.js";
import { defaultPolicy, enforceSkillPolicy } from "./policy.js";
import { redactValue } from "./redaction.js";
import { SkillRegistry } from "./registry.js";

function emptySkill(name: string): { name: string; version: string } {
  return {
    name,
    version: "unknown",
  };
}

export class SkillRunner {
  constructor(private readonly registry: SkillRegistry) {}

  async run(
    skillName: string,
    input: unknown,
    policy: Partial<RunPolicy> = {}
  ): Promise<SkillRunResult> {
    const mergedPolicy = { ...defaultPolicy, ...policy };
    const run_id = `run_${randomUUID()}`;

    let resultSkill = emptySkill(skillName);

    try {
      enforceInputSize(input, mergedPolicy.max_artifact_size_mb);

      const skill = this.registry.get(skillName);
      resultSkill = {
        name: skill.metadata.name,
        version: skill.metadata.version,
      };

      enforceSkillPolicy(skill, mergedPolicy);

      const rawOutput = await skill.run(input);
      const output = mergedPolicy.redact_secrets
        ? redactValue(rawOutput)
        : rawOutput;

      return {
        run_id,
        status: "completed",
        skill: {
          name: skill.metadata.name,
          version: skill.metadata.version,
        },
        policy: {
          allow_network: mergedPolicy.allow_network,
          network_used: skill.metadata.execution.network_access !== "none",
          external_sinks:
            skill.metadata.execution.network_access === "none"
              ? []
              : skill.metadata.permissions?.sends ?? [],
        },
        output,
        errors: [],
        warnings: [],
      };
    } catch (error) {
      const status = error instanceof PolicyRefusalError ? "refused" : "failed";
      const redactedError = mergedPolicy.redact_secrets
        ? redactValue(errorMessage(error))
        : errorMessage(error);

      return {
        run_id,
        status,
        skill: resultSkill,
        policy: {
          allow_network: mergedPolicy.allow_network,
          network_used: false,
          external_sinks: [],
        },
        errors: [redactedError],
        warnings: [],
      };
    }
  }
}
