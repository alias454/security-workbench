import { describe, expect, it } from "vitest";
import { reviewPackage, reviewPackageSkill } from "../src/reviewPackage.js";
import { skills } from "../src/index.js";

const parsedPackageManifest = {
  artifact: {
    id: "artifact_package_json",
    type: "package_json",
    name: "fixture-package",
    version: "1.0.0",
  },
  observed: {
    name: "fixture-package",
    version: "1.0.0",
    description_present: true,
    license: null,
    private: false,
    type: "module",
    package_manager: null,
    scripts: {
      present: true,
      count: 2,
      names: ["build", "postinstall"],
    },
    dependency_sections: {
      dependencies: {
        present: true,
        count: 1,
        names: ["left-pad"],
      },
      devDependencies: {
        present: true,
        count: 1,
        names: ["vitest"],
      },
      peerDependencies: {
        present: false,
        count: 0,
        names: [],
      },
      optionalDependencies: {
        present: true,
        count: 1,
        names: ["fsevents"],
      },
      bundledDependencies: {
        present: true,
        count: 1,
        names: ["fixture-bundled"],
      },
      bundleDependencies: {
        present: false,
        count: 0,
        names: [],
      },
    },
    engines: {
      present: false,
      names: [],
      values: {},
    },
    repository: {
      present: false,
      type: null,
      url: null,
    },
    bin_present: false,
    workspaces_present: false,
  },
  warnings: [],
} as const;

const parsedPackageLock = {
  artifact: {
    id: "artifact_lockfile",
    type: "lockfile",
    format: "npm_package_lock",
  },
  observed: {
    line_ending: "lf",
    physical_line_count: 10,
    format: "npm_package_lock",
    lockfile_version: "3",
    package_manager: null,
    package_count: 2,
    dependency_edge_count: 1,
    package_names: ["left-pad", "vite"],
    package_versions: ["1.3.0"],
    package_name_version_refs: ["left-pad@1.3.0", "vite@unknown"],
    root_dependency_names: ["left-pad"],
    root_dev_dependency_names: ["vite"],
    root_optional_dependency_names: [],
    root_peer_dependency_names: [],
    importer_names: [],
    packages: [
      {
        package_index: 0,
        name: "left-pad",
        version: "1.3.0",
        specifier: null,
        path: "node_modules/left-pad",
        dependency_count: 0,
        dev_dependency_count: 0,
        optional_dependency_count: 0,
        peer_dependency_count: 0,
      },
      {
        package_index: 1,
        name: "vite",
        version: null,
        specifier: null,
        path: "node_modules/vite",
        dependency_count: 1,
        dev_dependency_count: 0,
        optional_dependency_count: 0,
        peer_dependency_count: 0,
      },
    ],
  },
  warnings: [],
} as const;

describe("review_package", () => {
  it("exports the reviewer skill with local-only permissions", () => {
    expect(skills.map((skill) => skill.metadata.name)).toContain("review_package");
    expect(reviewPackageSkill.metadata).toMatchObject({
      name: "review_package",
      category: "reviewer",
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

  it("emits evidence-backed package manifest signals", () => {
    const output = reviewPackage(parsedPackageManifest);

    expect(output.artifact).toMatchObject({
      type: "package_review",
      source_artifact_id: "artifact_package_json",
      source_artifact_type: "package_json",
    });
    expect(output.observed.source_parser).toBe("parse_package_json");
    expect(output.observed.package_name).toBe("fixture-package");
    expect(output.observed.manifest_lifecycle_script_names).toEqual(["postinstall"]);
    expect(output.observed.optional_dependency_count).toBe(1);
    expect(output.observed.bundled_dependency_count).toBe(1);
    expect(output.signals.map((signal) => signal.type)).toEqual([
      "package.license_not_observed",
      "package.repository_not_observed",
      "package.package_manager_not_observed",
      "package.engines_not_observed",
      "package.lifecycle_scripts_observed",
      "package.optional_dependencies_observed",
      "package.bundled_dependencies_observed",
    ]);
    expect(output.signals.every((signal) => signal.evidence_refs.length > 0)).toBe(true);
    expect(output.observed.limitations).toContain(
      "Does not perform vulnerability lookup, package reputation checks, maintainer trust review, or registry enrichment.",
    );
  });

  it("emits evidence-backed lockfile signals", () => {
    const output = reviewPackage(parsedPackageLock);

    expect(output.artifact).toMatchObject({
      type: "package_review",
      source_artifact_id: "artifact_lockfile",
      source_artifact_type: "lockfile",
    });
    expect(output.observed.source_parser).toBe("parse_lockfiles");
    expect(output.observed.lockfile_format).toBe("npm_package_lock");
    expect(output.observed.lockfile_package_count).toBe(2);
    expect(output.observed.lockfile_packages_without_version_count).toBe(1);
    expect(output.signals.map((signal) => signal.type)).toEqual([
      "package.lockfile_package_version_not_observed",
      "package.lockfile_dependency_graph_observed",
      "package.root_dev_dependencies_observed",
    ]);
    expect(output.signals.every((signal) => signal.evidence_refs.length > 0)).toBe(true);
  });

  it("accepts a JSON run result from parse_lockfiles", () => {
    const runResult = {
      run_id: "run_parser",
      status: "completed",
      skill: { name: "parse_lockfiles", version: "0.1.0" },
      output: { ...parsedPackageLock, warnings: ["parser warning"] },
      errors: [],
      warnings: [],
    };

    const output = reviewPackage(JSON.stringify(runResult));

    expect(output.observed.source_parser).toBe("parse_lockfiles");
    expect(output.observed.source_warning_count).toBe(1);
    expect(output.warnings).toEqual(["Source parser emitted 1 warning(s); review output preserves source_warning_count only."]);
  });

  it("rejects objects that are not package parser output", () => {
    expect(() =>
      reviewPackage({
        artifact: { id: "artifact_sbom", type: "sbom" },
        observed: {},
        warnings: [],
      }),
    ).toThrow("review_package input artifact.type must be package_json or lockfile");
  });
});
