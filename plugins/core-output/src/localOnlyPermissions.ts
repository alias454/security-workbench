import type { SkillPermissions } from "@security-workbench/schemas";

export const localOnlyPermissions: SkillPermissions = {
  network: "none",
  filesystem: "none",
  sends: [],
  persists: false,
  runs_external_binaries: false,
};
