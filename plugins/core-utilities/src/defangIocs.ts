import type { Skill } from "@security-workbench/schemas";
export interface DefangIocsOutput { defanged: string; }
const PRESERVED_DEFANGED_TOKENS = ["[.]", "(.)", "{.}", "[dot]", "(dot)", "{dot}", "[@]", "(@)", "{@}", "[at]", "(at)", "{at}"];
function assertString(input: string): void { if (typeof input !== "string") throw new Error("defang_iocs input must be a string"); }
function startsWithCaseInsensitive(input: string, index: number, token: string): boolean { return input.slice(index, index + token.length).toLowerCase() === token.toLowerCase(); }
export function defangText(input: string): string {
  let output = "";
  for (let index = 0; index < input.length; ) {
    if (startsWithCaseInsensitive(input, index, "https://")) { output += "hxxps://"; index += "https://".length; continue; }
    if (startsWithCaseInsensitive(input, index, "http://")) { output += "hxxp://"; index += "http://".length; continue; }
    const preservedToken = PRESERVED_DEFANGED_TOKENS.find((token) => startsWithCaseInsensitive(input, index, token));
    if (preservedToken !== undefined) { output += input.slice(index, index + preservedToken.length); index += preservedToken.length; continue; }
    const character = input[index];
    if (character === ".") { output += "[.]"; index += 1; continue; }
    if (character === "@") { output += "[@]"; index += 1; continue; }
    output += character; index += 1;
  }
  return output;
}
export const defangIocsSkill: Skill<string, DefangIocsOutput> = {
  metadata: {
    name: "defang_iocs", version: "0.1.0", category: "transform", description: "Defang common IOC patterns in text.",
    execution: { mode: "local_only", network_access: "none", deterministic: true },
    permissions: { network: "none", filesystem: "none", sends: [], persists: false, runs_external_binaries: false },
  },
  run(input: string) { assertString(input); return { defanged: defangText(input) }; },
};
