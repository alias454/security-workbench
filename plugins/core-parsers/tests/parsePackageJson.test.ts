import { describe, expect, it } from "vitest";
import { parsePackageJson, parsePackageJsonSkill, skills } from "../src/index.js";

describe("parse_package_json", () => {
  it("exports the parser skill", async () => {
    expect(skills.map((skill) => skill.metadata.name)).toContain("parse_package_json");
    expect(parsePackageJsonSkill.metadata).toMatchObject({
      name: "parse_package_json",
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

  it("normalizes common package metadata", async () => {
    const result = parsePackageJson(`{
      "name": "example",
      "version": "1.0.0",
      "description": "Example package",
      "license": "MIT",
      "private": true,
      "type": "module",
      "packageManager": "pnpm@11.9.0",
      "scripts": {
        "build": "tsc -p tsconfig.json",
        "test": "vitest run"
      },
      "dependencies": {
        "left-pad": "1.3.0"
      },
      "devDependencies": {
        "typescript": "5.0.0",
        "vitest": "2.1.9"
      },
      "engines": {
        "node": ">=22"
      },
      "repository": {
        "type": "git",
        "url": "https://example.com/repo.git"
      }
    }`);

    expect(result).toEqual({
      artifact: {
        id: "artifact_package_json",
        type: "package_json",
        name: "example",
        version: "1.0.0",
      },
      observed: {
        name: "example",
        version: "1.0.0",
        description_present: true,
        license: "MIT",
        private: true,
        type: "module",
        package_manager: "pnpm@11.9.0",
        scripts: {
          present: true,
          count: 2,
          names: ["build", "test"],
        },
        dependency_sections: {
          dependencies: {
            present: true,
            count: 1,
            names: ["left-pad"],
          },
          devDependencies: {
            present: true,
            count: 2,
            names: ["typescript", "vitest"],
          },
          peerDependencies: {
            present: false,
            count: 0,
            names: [],
          },
          optionalDependencies: {
            present: false,
            count: 0,
            names: [],
          },
          bundledDependencies: {
            present: false,
            count: 0,
            names: [],
          },
          bundleDependencies: {
            present: false,
            count: 0,
            names: [],
          },
        },
        engines: {
          present: true,
          names: ["node"],
          values: {
            node: ">=22",
          },
        },
        repository: {
          present: true,
          type: "git",
          url: "https://example.com/repo.git",
        },
        bin_present: false,
        workspaces_present: false,
      },
      warnings: [],
    });
  });

  it("handles absent optional sections with stable empty summaries", async () => {
    const result = await parsePackageJsonSkill.run('{"name":"minimal","version":"0.0.1"}');

    expect(result.observed.scripts).toEqual({ present: false, count: 0, names: [] });
    expect(result.observed.dependency_sections.dependencies).toEqual({
      present: false,
      count: 0,
      names: [],
    });
    expect(result.observed.repository).toEqual({ present: false, type: null, url: null });
    expect(result.warnings).toEqual([]);
  });

  it("summarizes bundled dependency arrays", async () => {
    const result = parsePackageJson('{"bundledDependencies":["a","b",123]}');

    expect(result.observed.dependency_sections.bundledDependencies).toEqual({
      present: true,
      count: 2,
      names: ["a", "b"],
      non_string_version_count: 1,
    });
    expect(result.warnings).toContain(
      'package.json field "bundledDependencies" contains non-string entries.'
    );
  });

  it("warns on malformed optional field shapes without scoring risk", async () => {
    const result = parsePackageJson(`{
      "scripts": ["build"],
      "dependencies": ["left-pad"],
      "engines": "node",
      "repository": 123,
      "private": "yes"
    }`);

    expect(result.warnings).toHaveLength(5);
    expect(result.warnings).toEqual(
      expect.arrayContaining([
        'package.json field "private" must be a boolean when present.',
        'package.json field "scripts" must be an object when present.',
        'package.json field "dependencies" must be an object when present.',
        'package.json field "engines" must be an object when present.',
        'package.json field "repository" must be a string or object when present.',
      ]),
    );
    expect(result.observed.scripts).toEqual({ present: true, count: 0, names: [] });
  });

  it("rejects invalid JSON", async () => {
    expect(() => parsePackageJsonSkill.run("{bad json}")).toThrow(
      "parse_package_json input must be valid JSON"
    );
  });

  it("rejects arrays and null because package.json must be an object", async () => {
    expect(() => parsePackageJsonSkill.run("[]")).toThrow(
      "parse_package_json input must be a JSON object; received array"
    );
    expect(() => parsePackageJsonSkill.run("null")).toThrow(
      "parse_package_json input must be a JSON object; received null"
    );
  });
});
