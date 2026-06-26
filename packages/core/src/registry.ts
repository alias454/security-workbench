// registry.ts
import type { Skill } from "@security-workbench/schemas";

export class SkillRegistry {
  private skills = new Map<string, Skill>();

  register(skill: Skill): void {
    if (this.skills.has(skill.metadata.name)) {
      throw new Error(`Skill already registered: ${skill.metadata.name}`);
    }

    this.skills.set(skill.metadata.name, skill);
  }

  list(): Skill[] {
    return [...this.skills.values()];
  }

  get(name: string): Skill {
    const skill = this.skills.get(name);

    if (!skill) {
      throw new Error(`Unknown skill: ${name}`);
    }

    return skill;
  }
}