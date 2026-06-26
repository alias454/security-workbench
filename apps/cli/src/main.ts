import {
  errorMessage,
  isSecurityWorkbenchError,
  SkillRegistry,
  SkillRunner,
} from "@security-workbench/core";
import { skills as parserSkills } from "@security-workbench/core-parsers";
import { skills as utilitySkills } from "@security-workbench/core-utilities";
import { parseCliArgs, readBoundedUtf8File } from "./args.js";
import { formatSkillDescription } from "./describeFormat.js";
import { formatSkillList } from "./listFormat.js";
import { formatSkillRunResult } from "./runFormat.js";

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
  ].join("\n");
}

function buildRegistry(): SkillRegistry {
  const registry = new SkillRegistry();

  for (const skill of utilitySkills) {
    registry.register(skill);
  }

  for (const skill of parserSkills) {
    registry.register(skill);
  }

  return registry;
}

async function resolveInput(command: ReturnType<typeof parseCliArgs>): Promise<string> {
  if (command.kind !== "skills_run") {
    throw new Error("resolveInput only supports skills_run commands");
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
    const registry = buildRegistry();

    if (command.kind === "help") {
      console.log(usage());
      return 0;
    }

    if (command.kind === "skills_list") {
      const output = formatSkillList(registry.list(), command.options);

      if (output.length > 0) {
        console.log(output);
      }

      return 0;
    }

    if (command.kind === "skills_describe") {
      const skill = registry.get(command.skillName);
      const output = formatSkillDescription(skill, command.options);

      if (output.length > 0) {
        console.log(output);
      }

      return 0;
    }

    const runner = new SkillRunner(registry);
    const input = await resolveInput(command);
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
