import type { Skill } from "@security-workbench/schemas";
import { localOnlyPermissions } from "./localOnlyPermissions.js";
import {
  detectLineEnding,
  isRecord,
  normalizeTextInput,
  parseJsonObject,
  physicalLineCount,
  recordValue,
  stringValue,
  uniqueSorted,
  type NativeJsonLineEnding,
} from "./nativeParserUtils.js";

export type LockfileFormat = "npm_package_lock" | "pnpm_lock" | "yarn_lock" | "unknown";

export interface LockfilePackageObservation {
  readonly package_index: number;
  readonly name: string | null;
  readonly version: string | null;
  readonly specifier: string | null;
  readonly path: string | null;
  readonly dependency_count: number;
  readonly dev_dependency_count: number;
  readonly optional_dependency_count: number;
  readonly peer_dependency_count: number;
}

export interface ParseLockfilesOutput {
  readonly artifact: {
    readonly id: "artifact_lockfile";
    readonly type: "lockfile";
    readonly format: LockfileFormat;
  };
  readonly observed: {
    readonly line_ending: NativeJsonLineEnding;
    readonly physical_line_count: number;
    readonly format: LockfileFormat;
    readonly lockfile_version: string | null;
    readonly package_manager: string | null;
    readonly package_count: number;
    readonly dependency_edge_count: number;
    readonly package_names: readonly string[];
    readonly package_versions: readonly string[];
    readonly package_name_version_refs: readonly string[];
    readonly root_dependency_names: readonly string[];
    readonly root_dev_dependency_names: readonly string[];
    readonly root_optional_dependency_names: readonly string[];
    readonly root_peer_dependency_names: readonly string[];
    readonly importer_names: readonly string[];
    readonly packages: readonly LockfilePackageObservation[];
  };
  readonly warnings: readonly string[];
}

function dependencyNames(value: unknown): string[] {
  return isRecord(value) ? Object.keys(value).sort() : [];
}

function packageRef(name: string | null, version: string | null): string | null {
  if (!name) {
    return null;
  }

  return `${name}@${version ?? "unknown"}`;
}

function parseNpmPackageName(path: string, record: Record<string, unknown>): string | null {
  const explicitName = stringValue(record.name);
  if (explicitName) {
    return explicitName;
  }

  if (path === "") {
    return stringValue(record.name);
  }

  const marker = "node_modules/";
  const index = path.lastIndexOf(marker);
  if (index === -1) {
    return null;
  }

  return path.slice(index + marker.length);
}

function parseNpmPackageLock(root: Record<string, unknown>, normalized: string): ParseLockfilesOutput {
  const warnings: string[] = [];
  const packagesRoot = recordValue(root, "packages");
  const rootPackage = packagesRoot ? recordValue(packagesRoot, "") : null;
  const packageEntries = packagesRoot ? Object.entries(packagesRoot).filter(([path]) => path.length > 0) : [];

  if (!packagesRoot) {
    warnings.push('package-lock field "packages" is missing or not an object; falling back to top-level dependencies.');
  }

  const packages: LockfilePackageObservation[] = packageEntries.map(([path, value], index) => {
    const record = isRecord(value) ? value : {};
    const name = parseNpmPackageName(path, record);
    return {
      package_index: index,
      name,
      version: stringValue(record.version),
      specifier: null,
      path,
      dependency_count: dependencyNames(record.dependencies).length,
      dev_dependency_count: dependencyNames(record.devDependencies).length,
      optional_dependency_count: dependencyNames(record.optionalDependencies).length,
      peer_dependency_count: dependencyNames(record.peerDependencies).length,
    };
  });

  if (packages.length === 0 && isRecord(root.dependencies)) {
    packages.push(
      ...Object.entries(root.dependencies).map(([name, value], index) => {
        const record = isRecord(value) ? value : {};
        return {
          package_index: index,
          name,
          version: stringValue(record.version),
          specifier: null,
          path: null,
          dependency_count: dependencyNames(record.requires ?? record.dependencies).length,
          dev_dependency_count: 0,
          optional_dependency_count: 0,
          peer_dependency_count: 0,
        };
      })
    );
  }

  return lockfileOutput({
    normalized,
    format: "npm_package_lock",
    lockfileVersion: stringValue(root.lockfileVersion),
    packageManager: rootPackage ? stringValue(rootPackage.packageManager) : stringValue(root.packageManager),
    packages,
    rootDependencyNames: rootPackage ? dependencyNames(rootPackage.dependencies) : dependencyNames(root.dependencies),
    rootDevDependencyNames: rootPackage ? dependencyNames(rootPackage.devDependencies) : dependencyNames(root.devDependencies),
    rootOptionalDependencyNames: rootPackage ? dependencyNames(rootPackage.optionalDependencies) : dependencyNames(root.optionalDependencies),
    rootPeerDependencyNames: rootPackage ? dependencyNames(rootPackage.peerDependencies) : dependencyNames(root.peerDependencies),
    importerNames: [],
    warnings,
  });
}

function lockfileOutput(input: {
  readonly normalized: string;
  readonly format: LockfileFormat;
  readonly lockfileVersion: string | null;
  readonly packageManager: string | null;
  readonly packages: readonly LockfilePackageObservation[];
  readonly rootDependencyNames: readonly string[];
  readonly rootDevDependencyNames: readonly string[];
  readonly rootOptionalDependencyNames: readonly string[];
  readonly rootPeerDependencyNames: readonly string[];
  readonly importerNames: readonly string[];
  readonly warnings: readonly string[];
}): ParseLockfilesOutput {
  return {
    artifact: {
      id: "artifact_lockfile",
      type: "lockfile",
      format: input.format,
    },
    observed: {
      line_ending: detectLineEnding(input.normalized),
      physical_line_count: physicalLineCount(input.normalized),
      format: input.format,
      lockfile_version: input.lockfileVersion,
      package_manager: input.packageManager,
      package_count: input.packages.length,
      dependency_edge_count: input.packages.reduce(
        (total, entry) =>
          total +
          entry.dependency_count +
          entry.dev_dependency_count +
          entry.optional_dependency_count +
          entry.peer_dependency_count,
        0
      ),
      package_names: uniqueSorted(input.packages.map((entry) => entry.name)),
      package_versions: uniqueSorted(input.packages.map((entry) => entry.version)),
      package_name_version_refs: uniqueSorted(input.packages.map((entry) => packageRef(entry.name, entry.version))),
      root_dependency_names: input.rootDependencyNames,
      root_dev_dependency_names: input.rootDevDependencyNames,
      root_optional_dependency_names: input.rootOptionalDependencyNames,
      root_peer_dependency_names: input.rootPeerDependencyNames,
      importer_names: input.importerNames,
      packages: input.packages,
    },
    warnings: input.warnings,
  };
}

function yamlSectionKeys(lines: readonly string[], sectionName: string): string[] {
  const keys: string[] = [];
  let inSection = false;

  for (const line of lines) {
    if (!inSection) {
      if (line === `${sectionName}:`) {
        inSection = true;
      }
      continue;
    }

    if (/^[^\s].*:/.test(line)) {
      break;
    }

    const match = line.match(/^\s{2}([^\s].*):\s*$/);
    if (match) {
      keys.push(match[1].replace(/^['"]|['"]$/g, ""));
    }
  }

  return keys.sort();
}

function countIndentedMapEntries(lines: readonly string[], startIndex: number): number {
  let count = 0;
  const startIndent = (lines[startIndex].match(/^\s*/) ?? [""])[0].length;

  for (let index = startIndex + 1; index < lines.length; index += 1) {
    const line = lines[index];
    if (line.trim().length === 0) {
      continue;
    }

    const indent = (line.match(/^\s*/) ?? [""])[0].length;
    if (indent <= startIndent) {
      break;
    }

    if (indent === startIndent + 2 && /^\s+[^\s].*:\s*/.test(line)) {
      count += 1;
    }
  }

  return count;
}

function parsePnpmPackageKey(key: string): { name: string | null; version: string | null } {
  const normalized = key.replace(/^['"]|['"]$/g, "");
  const peerSuffixIndex = normalized.indexOf("(");
  const withoutPeerSuffix = peerSuffixIndex === -1 ? normalized : normalized.slice(0, peerSuffixIndex);
  const slashTrimmed = withoutPeerSuffix.startsWith("/") ? withoutPeerSuffix.slice(1) : withoutPeerSuffix;
  const atIndex = slashTrimmed.lastIndexOf("@");

  if (atIndex <= 0) {
    return { name: slashTrimmed || null, version: null };
  }

  return {
    name: slashTrimmed.slice(0, atIndex),
    version: slashTrimmed.slice(atIndex + 1) || null,
  };
}

function parsePnpmLock(normalized: string): ParseLockfilesOutput {
  const warnings: string[] = [];
  const lines = normalized.replace(/\r\n/g, "\n").replace(/\r/g, "\n").split("\n");
  const packageKeys = yamlSectionKeys(lines, "packages");
  const importerNames = yamlSectionKeys(lines, "importers");
  const importersIndex = lines.findIndex((line) => line === "importers:");
  const packages = packageKeys.map((key, index) => {
    const parsed = parsePnpmPackageKey(key);
    const packageLineIndex = lines.findIndex((line) => line.trim() === `${key}:` || line.trim() === `'${key}':` || line.trim() === `"${key}":`);
    const dependencyCount = packageLineIndex === -1 ? 0 : countIndentedMapEntries(lines, packageLineIndex);
    return {
      package_index: index,
      name: parsed.name,
      version: parsed.version,
      specifier: null,
      path: key,
      dependency_count: dependencyCount,
      dev_dependency_count: 0,
      optional_dependency_count: 0,
      peer_dependency_count: 0,
    };
  });

  const lockfileVersionMatch = normalized.match(/^lockfileVersion:\s*['"]?([^'"\n]+)['"]?/m);

  if (packageKeys.length === 0) {
    warnings.push('pnpm lockfile did not contain a top-level "packages" map.');
  }

  return lockfileOutput({
    normalized,
    format: "pnpm_lock",
    lockfileVersion: lockfileVersionMatch ? lockfileVersionMatch[1].trim() : null,
    packageManager: "pnpm",
    packages,
    rootDependencyNames: importersIndex === -1 ? [] : [],
    rootDevDependencyNames: [],
    rootOptionalDependencyNames: [],
    rootPeerDependencyNames: [],
    importerNames,
    warnings,
  });
}

function yarnHeaderLines(normalized: string): string[] {
  const lines = normalized.replace(/\r\n/g, "\n").replace(/\r/g, "\n").split("\n");
  return lines.filter((line) => /^[^\s#][^:]+:\s*$/.test(line));
}

function yarnNameFromSpecifier(specifier: string): string | null {
  const first = specifier.split(/,\s*/)[0]?.replace(/^['"]|['"]$/g, "") ?? "";
  const atIndex = first.startsWith("@") ? first.indexOf("@", 1) : first.indexOf("@");
  if (atIndex <= 0) {
    return first || null;
  }

  return first.slice(0, atIndex);
}

function parseYarnLock(normalized: string): ParseLockfilesOutput {
  const headers = yarnHeaderLines(normalized);
  const lines = normalized.replace(/\r\n/g, "\n").replace(/\r/g, "\n").split("\n");
  const packages = headers.map((header, index) => {
    const specifier = header.slice(0, -1).trim();
    const lineIndex = lines.indexOf(header);
    const versionLine = lineIndex === -1
      ? undefined
      : lines.slice(lineIndex + 1).find((line) => /^\s+version\s+/.test(line) || /^\s+version:\s*/.test(line));
    const versionMatch = versionLine?.match(/version[:\s]+["']?([^"'\s]+)["']?/);
    const dependencyCount = lineIndex === -1 ? 0 : countIndentedMapEntries(lines, lineIndex);
    return {
      package_index: index,
      name: yarnNameFromSpecifier(specifier),
      version: versionMatch ? versionMatch[1] : null,
      specifier,
      path: null,
      dependency_count: dependencyCount,
      dev_dependency_count: 0,
      optional_dependency_count: 0,
      peer_dependency_count: 0,
    };
  });

  return lockfileOutput({
    normalized,
    format: "yarn_lock",
    lockfileVersion: normalized.includes("__metadata:") ? "berry" : "v1_or_compatible",
    packageManager: "yarn",
    packages,
    rootDependencyNames: [],
    rootDevDependencyNames: [],
    rootOptionalDependencyNames: [],
    rootPeerDependencyNames: [],
    importerNames: [],
    warnings: packages.length === 0 ? ['yarn lockfile did not contain package entries.'] : [],
  });
}

function detectFormat(normalized: string): LockfileFormat {
  const trimmed = normalized.trimStart();
  if (trimmed.startsWith("{")) {
    return "npm_package_lock";
  }

  if (/^lockfileVersion:/m.test(normalized) && /^importers:/m.test(normalized)) {
    return "pnpm_lock";
  }

  if (normalized.includes("yarn lockfile") || normalized.includes("__metadata:") || yarnHeaderLines(normalized).length > 0) {
    return "yarn_lock";
  }

  return "unknown";
}

export function parseLockfiles(input: string): ParseLockfilesOutput {
  const normalized = normalizeTextInput(input, "parse_lockfiles");
  const format = detectFormat(normalized);

  if (format === "npm_package_lock") {
    const root = parseJsonObject(normalized, "parse_lockfiles");
    if (root.lockfileVersion === undefined && root.packages === undefined && root.dependencies === undefined) {
      throw new Error("parse_lockfiles JSON input does not look like a package-lock or npm-shrinkwrap file");
    }
    return parseNpmPackageLock(root, normalized);
  }

  if (format === "pnpm_lock") {
    return parsePnpmLock(normalized);
  }

  if (format === "yarn_lock") {
    return parseYarnLock(normalized);
  }

  throw new Error("parse_lockfiles input must look like package-lock.json, pnpm-lock.yaml, or yarn.lock content");
}

export const parseLockfilesSkill: Skill<string, ParseLockfilesOutput> = {
  metadata: {
    name: "parse_lockfiles",
    version: "0.1.0",
    category: "parser",
    description:
      "Parse npm package-lock, pnpm-lock, or yarn.lock content into structured package and dependency observations without installing packages or scoring risk.",
    execution: {
      mode: "local_only",
      network_access: "none",
      deterministic: true,
    },
    permissions: localOnlyPermissions,
    exposure: {
      surfaces: ["cli", "api", "web", "mcp"],
      default_exposure: "enabled",
      hosted_default: "allowlist_only",
      requires_authentication: true,
      rate_limit_recommended: true,
      audit_required: true,
      max_input_mb: 10,
      risk: "medium",
      rationale: [
        "Parses attacker-controlled dependency lockfile text that may contain package names, versions, paths, and registry URLs.",
        "Does not install packages, run scripts, perform network access, persist input, or call external binaries.",
        "Parser output preserves observed dependency metadata and does not make package reputation or vulnerability claims.",
      ],
    },
  },
  run(input: string): ParseLockfilesOutput {
    return parseLockfiles(input);
  },
};
