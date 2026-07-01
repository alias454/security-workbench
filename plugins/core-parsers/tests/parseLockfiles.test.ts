import { describe, expect, it } from "vitest";
import { parseLockfiles, parseLockfilesSkill } from "../src/parseLockfiles.js";
import { skills } from "../src/index.js";

const SAMPLE_PACKAGE_LOCK = `{
  "name": "fixture-app",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "fixture-app",
      "version": "1.0.0",
      "dependencies": { "left-pad": "1.3.0" },
      "devDependencies": { "vitest": "2.1.1" }
    },
    "node_modules/left-pad": {
      "version": "1.3.0",
      "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
      "integrity": "sha512-fixture"
    },
    "node_modules/vitest": {
      "version": "2.1.1",
      "dev": true,
      "dependencies": { "vite": "5.0.0" }
    }
  }
}
`;
const SAMPLE_PNPM_LOCK = `lockfileVersion: '9.0'

importers:
  .:
    dependencies:
      left-pad:
        specifier: 1.3.0
        version: 1.3.0

packages:
  /left-pad@1.3.0:
    resolution: {integrity: sha512-fixture}
  /vite@5.0.0:
    resolution: {integrity: sha512-fixture}
    dependencies:
      rollup: 4.0.0
`;
const SAMPLE_YARN_LOCK = `# yarn lockfile v1

left-pad@^1.3.0:
  version "1.3.0"
  resolved "https://registry.yarnpkg.com/left-pad/-/left-pad-1.3.0.tgz"
  integrity sha512-fixture

vite@^5.0.0:
  version "5.0.0"
  dependencies:
    rollup "4.0.0"
`;

describe("parse_lockfiles", () => {
  it("exports the parser skill with local-only permissions", () => {
    expect(skills.map((skill) => skill.metadata.name)).toContain("parse_lockfiles");
    expect(parseLockfilesSkill.metadata).toMatchObject({
      name: "parse_lockfiles",
      category: "parser",
      execution: {
        mode: "local_only",
        network_access: "none",
        deterministic: true,
      },
      permissions: {
        network: "none",
        filesystem: "none",
        sends: [],
        persists: false,
        runs_external_binaries: false,
      },
    });
  });

  it("parses npm package-lock package observations", async () => {
    const output = parseLockfiles(SAMPLE_PACKAGE_LOCK);

    expect(output.artifact).toEqual({ id: "artifact_lockfile", type: "lockfile", format: "npm_package_lock" });
    expect(output.observed.format).toBe("npm_package_lock");
    expect(output.observed.lockfile_version).toBe("3");
    expect(output.observed.package_count).toBe(2);
    expect(output.observed.package_names).toEqual(["left-pad", "vitest"]);
    expect(output.observed.package_versions).toEqual(["1.3.0", "2.1.1"]);
    expect(output.observed.root_dependency_names).toEqual(["left-pad"]);
    expect(output.observed.root_dev_dependency_names).toEqual(["vitest"]);
  });

  it("parses pnpm lock package observations", async () => {
    const output = parseLockfiles(SAMPLE_PNPM_LOCK);

    expect(output.observed.format).toBe("pnpm_lock");
    expect(output.observed.lockfile_version).toBe("9.0");
    expect(output.observed.package_manager).toBe("pnpm");
    expect(output.observed.importer_names).toEqual(["."]);
    expect(output.observed.package_names).toEqual(["left-pad", "vite"]);
    expect(output.observed.package_versions).toEqual(["1.3.0", "5.0.0"]);
  });

  it("parses yarn lock package observations", async () => {
    const output = parseLockfiles(SAMPLE_YARN_LOCK);

    expect(output.observed.format).toBe("yarn_lock");
    expect(output.observed.package_manager).toBe("yarn");
    expect(output.observed.package_names).toEqual(["left-pad", "vite"]);
    expect(output.observed.package_versions).toEqual(["1.3.0", "5.0.0"]);
  });

  it("rejects malformed and unsupported input", () => {
    expect(() => parseLockfiles("")).toThrow("parse_lockfiles input must not be empty");
    expect(() => parseLockfiles("not a lockfile")).toThrow("parse_lockfiles input must look like package-lock.json, pnpm-lock.yaml, or yarn.lock content");
    expect(() => parseLockfiles("{}")).toThrow("parse_lockfiles JSON input does not look like a package-lock or npm-shrinkwrap file");
  });
});
