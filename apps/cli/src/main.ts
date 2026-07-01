import {
  errorMessage,
  isSecurityWorkbenchError,
  SkillRegistry,
  SkillRunner,
  WorkflowRegistry,
  WorkflowRunner,
} from "@security-workbench/core";
import { skills as outputSkills } from "@security-workbench/core-output";
import { skills as parserSkills } from "@security-workbench/core-parsers";
import { skills as reviewerSkills } from "@security-workbench/core-reviewers";
import { skills as scoringSkills } from "@security-workbench/core-scoring";
import { skills as utilitySkills } from "@security-workbench/core-utilities";
import { parseCliArgs, readBoundedUtf8File } from "./args.js";
import { formatSkillDescription } from "./describeFormat.js";
import { formatSkillList } from "./listFormat.js";
import { formatSkillRunResult } from "./runFormat.js";
import { workflows } from "./workflows.js";
import { formatWorkflowList } from "./workflowListFormat.js";
import { formatWorkflowRunResult } from "./workflowRunFormat.js";

const DEFAULT_MAX_INPUT_FILE_BYTES = 10 * 1024 * 1024;

function usage(): string {
  return [
    "Security Workbench CLI",
    "",
    "Usage:",
    "  skills list [--category <category>] [--format table|json|tsv]",
    "  skills describe <skill_name> [--format table|json|tsv]",
    "  skills run <skill_name> --input <value> [--format json|pretty] [--unsafe]",
    "  skills run <skill_name> --input-file <path> [--format json|pretty] [--unsafe]",
    "  workflows list [--format table|json|tsv]",
    "  workflows run <workflow_name> --input <value> [--format json|pretty] [--unsafe]",
    "  workflows run <workflow_name> --input-file <path> [--format json|pretty] [--unsafe]",
  ].join("\n");
}

function buildSkillRegistry(): SkillRegistry {
  const registry = new SkillRegistry();

  for (const skill of utilitySkills) {
    registry.register(skill);
  }

  for (const skill of parserSkills) {
    registry.register(skill);
  }

  for (const skill of reviewerSkills) {
    registry.register(skill);
  }

  for (const skill of scoringSkills) {
    registry.register(skill);
  }

  for (const skill of outputSkills) {
    registry.register(skill);
  }

  return registry;
}

function buildWorkflowRegistry(skillRegistry: SkillRegistry): WorkflowRegistry {
  const registry = new WorkflowRegistry();
  const knownSkillNames = skillRegistry.list().map((skill) => skill.metadata.name);

  for (const workflow of workflows) {
    registry.register(workflow, { knownSkillNames });
  }

  return registry;
}

async function resolveInput(command: ReturnType<typeof parseCliArgs>): Promise<string> {
  if (command.kind !== "skills_run" && command.kind !== "workflows_run") {
    throw new Error("resolveInput only supports run commands");
  }

  if (command.input_source.kind === "inline") {
    return command.input_source.value;
  }

  return await readBoundedUtf8File(
    command.input_source.path,
    DEFAULT_MAX_INPUT_FILE_BYTES
  );
}

export async function main(argv = process.argv.slice(2)): Promise<number> {
  try {
    const command = parseCliArgs(argv);
    const skillRegistry = buildSkillRegistry();
    const workflowRegistry = buildWorkflowRegistry(skillRegistry);

    if (command.kind === "help") {
      console.log(usage());
      return 0;
    }

    if (command.kind === "skills_list") {
      const output = formatSkillList(skillRegistry.list(), command.options);

      if (output.length > 0) {
        console.log(output);
      }

      return 0;
    }

    if (command.kind === "skills_describe") {
      const skill = skillRegistry.get(command.skillName);
      const output = formatSkillDescription(skill, command.options);

      if (output.length > 0) {
        console.log(output);
      }

      return 0;
    }

    if (command.kind === "workflows_list") {
      const output = formatWorkflowList(workflowRegistry.list(), command.options);

      if (output.length > 0) {
        console.log(output);
      }

      return 0;
    }

    const input = await resolveInput(command);

    if (command.kind === "workflows_run") {
      const runner = new WorkflowRunner(workflowRegistry, skillRegistry);
      const result = await runner.run(command.workflowName, input);

      console.log(formatWorkflowRunResult(result, command.options));

      if (result.status === "completed") {
        return 0;
      }

      if (result.status === "refused") {
        return 3;
      }

      return 1;
    }

    const runner = new SkillRunner(skillRegistry);
    const result = await runner.run(command.skillName, input);

    console.log(formatSkillRunResult(result, command.options));

    if (result.status === "completed") {
      return 0;
    }

    if (result.status === "refused") {
      return 3;
    }

    return 1;
  } catch (error) {
    console.error(errorMessage(error));
    return isSecurityWorkbenchError(error) ? 2 : 1;
  }
}

main().then((exitCode) => {
  process.exitCode = exitCode;
});
