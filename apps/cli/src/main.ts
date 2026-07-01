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
import {
  skillCategoryValues,
  type Skill,
  type WorkflowDefinition,
} from "@security-workbench/schemas";
import { parseCliArgs, readBoundedUtf8File } from "./args.js";
import { formatSkillDescription } from "./describeFormat.js";
import { formatSkillList } from "./listFormat.js";
import { formatSkillRunResult } from "./runFormat.js";
import { workflows } from "./workflows.js";
import { formatWorkflowList } from "./workflowListFormat.js";
import { formatWorkflowRunResult } from "./workflowRunFormat.js";

const DEFAULT_MAX_INPUT_FILE_BYTES = 10 * 1024 * 1024;

function topLevelHelp(): string {
  return [
    "Security Workbench",
    "",
    "Usage:",
    "  security-workbench help",
    "  security-workbench list",
    "  security-workbench skills <command>",
    "  security-workbench workflows <command>",
    "",
    "Commands:",
    "  list        Show available skills and workflows",
    "  skills      Run or inspect skills",
    "  workflows   Run or inspect workflows",
    "",
    "Use:",
    "  security-workbench skills help",
    "  security-workbench workflows help",
  ].join("\n");
}

function skillsHelp(): string {
  return [
    "Security Workbench skills",
    "",
    "Usage:",
    "  security-workbench skills list",
    "  security-workbench skills describe <skill>",
    "  security-workbench skills run <skill> --input <text>",
    "  security-workbench skills run <skill> --input-file <path>",
  ].join("\n");
}

function workflowsHelp(): string {
  return [
    "Security Workbench workflows",
    "",
    "Usage:",
    "  security-workbench workflows list",
    "  security-workbench workflows run <workflow> --input-file <path>",
  ].join("\n");
}

function discoverySummary(
  skills: readonly Skill<unknown, unknown>[],
  workflowDefinitions: readonly WorkflowDefinition[]
): string {
  const observedCategories = new Set(
    skills.map((skill) => skill.metadata.category)
  );
  const categories = skillCategoryValues.filter((category) =>
    observedCategories.has(category)
  );

  return [
    "Security Workbench",
    "",
    "Workflows:",
    ...workflowDefinitions.map((workflow) => `  ${workflow.name}`),
    "",
    "Skill categories:",
    ...categories.map((category) => `  ${category}`),
    "",
    "Use:",
    "  security-workbench skills list",
    "  security-workbench workflows list",
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

    if (command.kind === "help") {
      console.log(topLevelHelp());
      return 0;
    }

    if (command.kind === "skills_help") {
      console.log(skillsHelp());
      return 0;
    }

    if (command.kind === "workflows_help") {
      console.log(workflowsHelp());
      return 0;
    }

    const skillRegistry = buildSkillRegistry();
    const workflowRegistry = buildWorkflowRegistry(skillRegistry);

    if (command.kind === "list") {
      console.log(discoverySummary(skillRegistry.list(), workflowRegistry.list()));
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
