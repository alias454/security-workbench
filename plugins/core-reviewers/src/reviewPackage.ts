import type { EvidenceRecord, JsonObject, JsonValue, SignalRecord, Skill } from "@security-workbench/schemas";
import { localOnlyPermissions } from "./localOnlyPermissions.js";

type ReviewRecord = Record<string, unknown>;
type Confidence = "confirmed" | "high" | "medium" | "low" | "unknown";
type Severity = "informational" | "low" | "medium" | "high" | "critical";
type PackageReviewSourceParser = "parse_package_json" | "parse_lockfiles";

export interface PackageReviewDependencySectionObservation {
  readonly section: string;
  readonly present: boolean;
  readonly count: number;
  readonly names: readonly string[];
  readonly non_string_version_count: number;
}

export interface PackageReviewLockfilePackageObservation {
  readonly package_index: number;
  readonly name: string | null;
  readonly version_present: boolean;
  readonly specifier_present: boolean;
  readonly path_present: boolean;
  readonly dependency_count: number;
  readonly dev_dependency_count: number;
  readonly optional_dependency_count: number;
  readonly peer_dependency_count: number;
}

export interface PackageReviewOutput {
  readonly artifact: {
    readonly id: "artifact_package_review";
    readonly type: "package_review";
    readonly source_artifact_id: string | null;
    readonly source_artifact_type: string | null;
  };
  readonly observed: {
    readonly source_parser: PackageReviewSourceParser;
    readonly source_warning_count: number;
    readonly package_name: string | null;
    readonly package_version: string | null;
    readonly package_private: boolean | null;
    readonly package_manager: string | null;
    readonly lockfile_format: string | null;
    readonly lockfile_version: string | null;
    readonly manifest_script_count: number;
    readonly manifest_lifecycle_script_count: number;
    readonly manifest_script_names: readonly string[];
    readonly manifest_lifecycle_script_names: readonly string[];
    readonly dependency_count: number;
    readonly dev_dependency_count: number;
    readonly peer_dependency_count: number;
    readonly optional_dependency_count: number;
    readonly bundled_dependency_count: number;
    readonly lockfile_package_count: number;
    readonly lockfile_packages_without_version_count: number;
    readonly lockfile_dependency_edge_count: number;
    readonly importer_count: number;
    readonly license_present: boolean | null;
    readonly repository_present: boolean | null;
    readonly engines_present: boolean | null;
    readonly bin_present: boolean | null;
    readonly workspaces_present: boolean | null;
    readonly evidence_count: number;
    readonly signal_count: number;
    readonly dependency_sections: readonly PackageReviewDependencySectionObservation[];
    readonly lockfile_packages: readonly PackageReviewLockfilePackageObservation[];
    readonly limitations: readonly string[];
  };
  readonly evidence: readonly EvidenceRecord[];
  readonly signals: readonly SignalRecord[];
  readonly warnings: readonly string[];
}

interface ParsedPackageForReview {
  readonly artifact: {
    readonly id?: string;
    readonly type?: string;
  };
  readonly observed: ReviewRecord;
  readonly sourceParser: PackageReviewSourceParser;
  readonly warnings?: readonly string[];
}

const DEPENDENCY_SECTION_NAMES = [
  "dependencies",
  "devDependencies",
  "peerDependencies",
  "optionalDependencies",
  "bundledDependencies",
  "bundleDependencies",
] as const;

const LIFECYCLE_SCRIPT_NAMES = [
  "preinstall",
  "install",
  "postinstall",
  "prepublish",
  "preprepare",
  "prepare",
  "postprepare",
  "prepack",
  "postpack",
  "prepublishOnly",
] as const;

function isRecord(value: unknown): value is ReviewRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function parseJsonString(input: string): unknown {
  try {
    return JSON.parse(input) as unknown;
  } catch {
    throw new Error("review_package input must be parse_package_json or parse_lockfiles output JSON, or a JSON run result from one of those parsers");
  }
}

function childRecord(record: ReviewRecord, key: string): ReviewRecord | undefined {
  const value = record[key];
  return isRecord(value) ? value : undefined;
}

function stringOrNull(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}

function booleanOrNull(value: unknown): boolean | null {
  return typeof value === "boolean" ? value : null;
}

function numberOrZero(value: unknown): number {
  return typeof value === "number" && Number.isFinite(value) ? value : 0;
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((entry): entry is string => typeof entry === "string") : [];
}

function recordArray(value: unknown): ReviewRecord[] {
  return Array.isArray(value) ? value.filter(isRecord) : [];
}

function uniqueSorted(values: readonly string[]): string[] {
  return [...new Set(values.filter((value) => value.length > 0))].sort((left, right) => left.localeCompare(right));
}

function evidenceValue(value: unknown): JsonValue {
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "number" ||
    typeof value === "boolean" ||
    Array.isArray(value) ||
    isRecord(value)
  ) {
    return value as JsonValue;
  }

  return String(value);
}

function unwrapInput(input: unknown): ParsedPackageForReview {
  const parsed = typeof input === "string" ? parseJsonString(input) : input;
  const candidate = isRecord(parsed) && isRecord(parsed.output) ? parsed.output : parsed;

  if (!isRecord(candidate)) {
    throw new Error("review_package input must be an object");
  }

  const artifact = childRecord(candidate, "artifact");
  const observed = childRecord(candidate, "observed");

  if (!artifact || !observed) {
    throw new Error("review_package input must be parse_package_json or parse_lockfiles output with artifact and observed fields");
  }

  if (artifact.type === "package_json") {
    return {
      artifact: {
        id: stringOrNull(artifact.id) ?? undefined,
        type: "package_json",
      },
      observed,
      sourceParser: "parse_package_json",
      warnings: stringArray(candidate.warnings),
    };
  }

  if (artifact.type === "lockfile") {
    return {
      artifact: {
        id: stringOrNull(artifact.id) ?? undefined,
        type: "lockfile",
      },
      observed,
      sourceParser: "parse_lockfiles",
      warnings: stringArray(candidate.warnings),
    };
  }

  throw new Error("review_package input artifact.type must be package_json or lockfile");
}

function dependencySectionObservations(observed: ReviewRecord): PackageReviewDependencySectionObservation[] {
  const sections = childRecord(observed, "dependency_sections");

  if (!sections) {
    return [];
  }

  return DEPENDENCY_SECTION_NAMES.map((section) => {
    const summary = childRecord(sections, section);
    return {
      section,
      present: summary?.present === true,
      count: numberOrZero(summary?.count),
      names: stringArray(summary?.names),
      non_string_version_count: numberOrZero(summary?.non_string_version_count),
    };
  });
}

function sectionCount(sections: readonly PackageReviewDependencySectionObservation[], sectionName: string): number {
  return sections.find((section) => section.section === sectionName)?.count ?? 0;
}

function bundledDependencyCount(sections: readonly PackageReviewDependencySectionObservation[]): number {
  return sectionCount(sections, "bundledDependencies") + sectionCount(sections, "bundleDependencies");
}

function scriptNames(observed: ReviewRecord): string[] {
  const scripts = childRecord(observed, "scripts");
  return uniqueSorted(stringArray(scripts?.names));
}

function lifecycleScriptNames(names: readonly string[]): string[] {
  const lifecycleSet = new Set<string>(LIFECYCLE_SCRIPT_NAMES);
  return names.filter((name) => lifecycleSet.has(name));
}

function lockfilePackageObservations(observed: ReviewRecord): PackageReviewLockfilePackageObservation[] {
  return recordArray(observed.packages).map((entry) => ({
    package_index: numberOrZero(entry.package_index),
    name: stringOrNull(entry.name),
    version_present: typeof entry.version === "string" && entry.version.length > 0,
    specifier_present: typeof entry.specifier === "string" && entry.specifier.length > 0,
    path_present: typeof entry.path === "string" && entry.path.length > 0,
    dependency_count: numberOrZero(entry.dependency_count),
    dev_dependency_count: numberOrZero(entry.dev_dependency_count),
    optional_dependency_count: numberOrZero(entry.optional_dependency_count),
    peer_dependency_count: numberOrZero(entry.peer_dependency_count),
  }));
}

function packageRef(entry: PackageReviewLockfilePackageObservation): string {
  if (entry.name) {
    return entry.version_present ? entry.name : `${entry.name}@unknown`;
  }
  return `package:${String(entry.package_index)}`;
}

function compactPackageRefs(entries: readonly PackageReviewLockfilePackageObservation[]): string[] {
  return uniqueSorted(entries.map(packageRef)).slice(0, 25);
}

function createEvidenceBuilder(sourceArtifactId: string | null) {
  const evidence: EvidenceRecord[] = [];

  function addEvidence(type: string, path: string, value: unknown, description: string): string {
    const id = `evidence_package_${String(evidence.length + 1).padStart(3, "0")}`;
    evidence.push({
      id,
      type,
      artifact_ref: sourceArtifactId ?? undefined,
      path,
      value: evidenceValue(value),
      value_kind: "metadata",
      sensitivity: "medium",
      description,
    });
    return id;
  }

  return { evidence, addEvidence };
}

function addSignal(
  signals: SignalRecord[],
  input: {
    type: string;
    summary: string;
    evidenceRefs: readonly string[];
    severity: Severity;
    confidence: Confidence;
    observed: JsonObject;
    tags?: readonly string[];
  },
): void {
  signals.push({
    id: `signal_package_${String(signals.length + 1).padStart(3, "0")}`,
    type: input.type,
    summary: input.summary,
    severity: input.severity,
    confidence: input.confidence,
    evidence_refs: input.evidenceRefs,
    observed: input.observed,
    tags: input.tags ?? ["package"],
  });
}

function addAggregateLockfileSignal(input: {
  readonly packages: readonly PackageReviewLockfilePackageObservation[];
  readonly matchingPackages: readonly PackageReviewLockfilePackageObservation[];
  readonly addEvidence: (type: string, path: string, value: unknown, description: string) => string;
  readonly signals: SignalRecord[];
  readonly evidenceType: string;
  readonly signalType: string;
  readonly summary: string;
  readonly path: string;
  readonly description: string;
  readonly severity: Severity;
  readonly tags: readonly string[];
}): void {
  if (input.matchingPackages.length === 0) {
    return;
  }

  const evidenceRef = input.addEvidence(
    input.evidenceType,
    input.path,
    {
      count: input.matchingPackages.length,
      total_packages: input.packages.length,
      package_refs: compactPackageRefs(input.matchingPackages),
    },
    input.description,
  );

  addSignal(input.signals, {
    type: input.signalType,
    summary: input.summary,
    evidenceRefs: [evidenceRef],
    severity: input.severity,
    confidence: "confirmed",
    observed: {
      count: input.matchingPackages.length,
      total_packages: input.packages.length,
    },
    tags: input.tags,
  });
}

function addManifestSignals(input: {
  readonly observed: ReviewRecord;
  readonly sections: readonly PackageReviewDependencySectionObservation[];
  readonly scriptNames: readonly string[];
  readonly lifecycleScriptNames: readonly string[];
  readonly addEvidence: (type: string, path: string, value: unknown, description: string) => string;
  readonly signals: SignalRecord[];
}): void {
  const license = stringOrNull(input.observed.license);
  const repository = childRecord(input.observed, "repository");
  const engines = childRecord(input.observed, "engines");
  const optionalDependencyCount = sectionCount(input.sections, "optionalDependencies");
  const bundledCount = bundledDependencyCount(input.sections);

  if (!license) {
    const evidenceRef = input.addEvidence(
      "package_license_not_observed",
      "observed.license",
      { license: null },
      "Parsed package manifest did not include an observed license value.",
    );
    addSignal(input.signals, {
      type: "package.license_not_observed",
      summary: "Package manifest did not include an observed license value.",
      evidenceRefs: [evidenceRef],
      severity: "informational",
      confidence: "confirmed",
      observed: { license_present: false },
      tags: ["package", "inventory-quality", "license"],
    });
  }

  if (repository && repository.present !== true) {
    const evidenceRef = input.addEvidence(
      "package_repository_not_observed",
      "observed.repository",
      repository,
      "Parsed package manifest did not include observed repository metadata.",
    );
    addSignal(input.signals, {
      type: "package.repository_not_observed",
      summary: "Package manifest did not include observed repository metadata.",
      evidenceRefs: [evidenceRef],
      severity: "informational",
      confidence: "confirmed",
      observed: { repository_present: false },
      tags: ["package", "inventory-quality", "repository"],
    });
  }

  if (!stringOrNull(input.observed.package_manager)) {
    const evidenceRef = input.addEvidence(
      "package_manager_not_observed",
      "observed.package_manager",
      { package_manager: null },
      "Parsed package manifest did not include a packageManager value.",
    );
    addSignal(input.signals, {
      type: "package.package_manager_not_observed",
      summary: "Package manifest did not include an observed packageManager value.",
      evidenceRefs: [evidenceRef],
      severity: "informational",
      confidence: "confirmed",
      observed: { package_manager_present: false },
      tags: ["package", "inventory-quality", "package-manager"],
    });
  }

  if (engines && engines.present !== true) {
    const evidenceRef = input.addEvidence(
      "package_engines_not_observed",
      "observed.engines",
      engines,
      "Parsed package manifest did not include observed runtime engine constraints.",
    );
    addSignal(input.signals, {
      type: "package.engines_not_observed",
      summary: "Package manifest did not include observed runtime engine constraints.",
      evidenceRefs: [evidenceRef],
      severity: "informational",
      confidence: "confirmed",
      observed: { engines_present: false },
      tags: ["package", "inventory-quality", "engines"],
    });
  }

  if (input.lifecycleScriptNames.length > 0) {
    const evidenceRef = input.addEvidence(
      "package_lifecycle_scripts_observed",
      "observed.scripts.names",
      { script_names: [...input.lifecycleScriptNames] },
      "Parsed package manifest included lifecycle script names that package managers may run during install or publish operations.",
    );
    addSignal(input.signals, {
      type: "package.lifecycle_scripts_observed",
      summary: `${String(input.lifecycleScriptNames.length)} package lifecycle script(s) were observed in the manifest.`,
      evidenceRefs: [evidenceRef],
      severity: "low",
      confidence: "confirmed",
      observed: { script_names: [...input.lifecycleScriptNames] },
      tags: ["package", "scripts", "install-behavior"],
    });
  }

  if (optionalDependencyCount > 0) {
    const evidenceRef = input.addEvidence(
      "package_optional_dependencies_observed",
      "observed.dependency_sections.optionalDependencies",
      { count: optionalDependencyCount },
      "Parsed package manifest included optional dependencies.",
    );
    addSignal(input.signals, {
      type: "package.optional_dependencies_observed",
      summary: `${String(optionalDependencyCount)} optional package dependenc(ies) were observed in the manifest.`,
      evidenceRefs: [evidenceRef],
      severity: "informational",
      confidence: "confirmed",
      observed: { optional_dependency_count: optionalDependencyCount },
      tags: ["package", "dependencies", "optional-dependencies"],
    });
  }

  if (bundledCount > 0) {
    const evidenceRef = input.addEvidence(
      "package_bundled_dependencies_observed",
      "observed.dependency_sections.bundledDependencies",
      { count: bundledCount },
      "Parsed package manifest included bundled dependency declarations.",
    );
    addSignal(input.signals, {
      type: "package.bundled_dependencies_observed",
      summary: `${String(bundledCount)} bundled package dependenc(ies) were observed in the manifest.`,
      evidenceRefs: [evidenceRef],
      severity: "informational",
      confidence: "confirmed",
      observed: { bundled_dependency_count: bundledCount },
      tags: ["package", "dependencies", "bundled-dependencies"],
    });
  }
}

function addLockfileSignals(input: {
  readonly observed: ReviewRecord;
  readonly packages: readonly PackageReviewLockfilePackageObservation[];
  readonly addEvidence: (type: string, path: string, value: unknown, description: string) => string;
  readonly signals: SignalRecord[];
}): void {
  const packagesWithoutVersions = input.packages.filter((entry) => !entry.version_present);
  const packagesWithEdges = input.packages.filter(
    (entry) => entry.dependency_count + entry.dev_dependency_count + entry.optional_dependency_count + entry.peer_dependency_count > 0,
  );
  const rootDevDependencyNames = stringArray(input.observed.root_dev_dependency_names);
  const rootOptionalDependencyNames = stringArray(input.observed.root_optional_dependency_names);
  const rootPeerDependencyNames = stringArray(input.observed.root_peer_dependency_names);

  if (input.packages.length === 0) {
    const evidenceRef = input.addEvidence(
      "package_lockfile_empty_inventory",
      "observed.packages",
      { package_count: 0 },
      "Parsed lockfile output did not include package observations.",
    );
    addSignal(input.signals, {
      type: "package.lockfile_empty_inventory_observed",
      summary: "Parsed lockfile output did not include package observations.",
      evidenceRefs: [evidenceRef],
      severity: "low",
      confidence: "confirmed",
      observed: { package_count: 0 },
      tags: ["package", "lockfile", "inventory-quality"],
    });
  }

  addAggregateLockfileSignal({
    packages: input.packages,
    matchingPackages: packagesWithoutVersions,
    addEvidence: input.addEvidence,
    signals: input.signals,
    evidenceType: "package_lockfile_packages_without_versions",
    signalType: "package.lockfile_package_version_not_observed",
    summary: `${String(packagesWithoutVersions.length)} lockfile package record(s) did not include observed version metadata.`,
    path: "observed.packages[*].version",
    description: "Parsed lockfile package records were missing version metadata.",
    severity: "low",
    tags: ["package", "lockfile", "inventory-quality", "version"],
  });

  if (packagesWithEdges.length > 0 || numberOrZero(input.observed.dependency_edge_count) > 0) {
    const edgeCount = numberOrZero(input.observed.dependency_edge_count);
    const evidenceRef = input.addEvidence(
      "package_lockfile_dependency_graph_observed",
      "observed.dependency_edge_count",
      {
        dependency_edge_count: edgeCount,
        packages_with_dependency_edges: packagesWithEdges.length,
      },
      "Parsed lockfile output included package dependency-edge observations.",
    );
    addSignal(input.signals, {
      type: "package.lockfile_dependency_graph_observed",
      summary: `${String(edgeCount)} lockfile dependency edge(s) were observed for package review context.`,
      evidenceRefs: [evidenceRef],
      severity: "informational",
      confidence: "confirmed",
      observed: {
        dependency_edge_count: edgeCount,
        packages_with_dependency_edges: packagesWithEdges.length,
      },
      tags: ["package", "lockfile", "dependency-graph"],
    });
  }

  if (rootDevDependencyNames.length > 0) {
    const evidenceRef = input.addEvidence(
      "package_lockfile_root_dev_dependencies_observed",
      "observed.root_dev_dependency_names",
      { names: rootDevDependencyNames },
      "Parsed lockfile output included root development dependencies.",
    );
    addSignal(input.signals, {
      type: "package.root_dev_dependencies_observed",
      summary: `${String(rootDevDependencyNames.length)} root development dependenc(ies) were observed in the lockfile.`,
      evidenceRefs: [evidenceRef],
      severity: "informational",
      confidence: "confirmed",
      observed: { root_dev_dependency_count: rootDevDependencyNames.length },
      tags: ["package", "lockfile", "dev-dependencies"],
    });
  }

  if (rootOptionalDependencyNames.length > 0) {
    const evidenceRef = input.addEvidence(
      "package_lockfile_root_optional_dependencies_observed",
      "observed.root_optional_dependency_names",
      { names: rootOptionalDependencyNames },
      "Parsed lockfile output included root optional dependencies.",
    );
    addSignal(input.signals, {
      type: "package.root_optional_dependencies_observed",
      summary: `${String(rootOptionalDependencyNames.length)} root optional dependenc(ies) were observed in the lockfile.`,
      evidenceRefs: [evidenceRef],
      severity: "informational",
      confidence: "confirmed",
      observed: { root_optional_dependency_count: rootOptionalDependencyNames.length },
      tags: ["package", "lockfile", "optional-dependencies"],
    });
  }

  if (rootPeerDependencyNames.length > 0) {
    const evidenceRef = input.addEvidence(
      "package_lockfile_root_peer_dependencies_observed",
      "observed.root_peer_dependency_names",
      { names: rootPeerDependencyNames },
      "Parsed lockfile output included root peer dependencies.",
    );
    addSignal(input.signals, {
      type: "package.root_peer_dependencies_observed",
      summary: `${String(rootPeerDependencyNames.length)} root peer dependenc(ies) were observed in the lockfile.`,
      evidenceRefs: [evidenceRef],
      severity: "informational",
      confidence: "confirmed",
      observed: { root_peer_dependency_count: rootPeerDependencyNames.length },
      tags: ["package", "lockfile", "peer-dependencies"],
    });
  }
}

export function reviewPackage(input: unknown): PackageReviewOutput {
  const parsed = unwrapInput(input);
  const observed = parsed.observed;
  const sourceArtifactId = stringOrNull(parsed.artifact.id);
  const { evidence, addEvidence } = createEvidenceBuilder(sourceArtifactId);
  const signals: SignalRecord[] = [];
  const warnings: string[] = [];
  const sections = dependencySectionObservations(observed);
  const manifestScriptNames = scriptNames(observed);
  const manifestLifecycleScriptNames = lifecycleScriptNames(manifestScriptNames);
  const lockfilePackages = lockfilePackageObservations(observed);
  const packagesWithoutVersions = lockfilePackages.filter((entry) => !entry.version_present);

  if (parsed.sourceParser === "parse_package_json") {
    addManifestSignals({
      observed,
      sections,
      scriptNames: manifestScriptNames,
      lifecycleScriptNames: manifestLifecycleScriptNames,
      addEvidence,
      signals,
    });
  } else {
    addLockfileSignals({ observed, packages: lockfilePackages, addEvidence, signals });
  }

  if ((parsed.warnings?.length ?? 0) > 0) {
    warnings.push(`Source parser emitted ${parsed.warnings?.length ?? 0} warning(s); review output preserves source_warning_count only.`);
  }

  return {
    artifact: {
      id: "artifact_package_review",
      type: "package_review",
      source_artifact_id: parsed.artifact.id ?? null,
      source_artifact_type: parsed.artifact.type ?? null,
    },
    observed: {
      source_parser: parsed.sourceParser,
      source_warning_count: parsed.warnings?.length ?? 0,
      package_name: stringOrNull(observed.name),
      package_version: stringOrNull(observed.version),
      package_private: booleanOrNull(observed.private),
      package_manager: stringOrNull(observed.package_manager),
      lockfile_format: stringOrNull(observed.format),
      lockfile_version: stringOrNull(observed.lockfile_version),
      manifest_script_count: manifestScriptNames.length,
      manifest_lifecycle_script_count: manifestLifecycleScriptNames.length,
      manifest_script_names: manifestScriptNames,
      manifest_lifecycle_script_names: manifestLifecycleScriptNames,
      dependency_count: sectionCount(sections, "dependencies"),
      dev_dependency_count: sectionCount(sections, "devDependencies"),
      peer_dependency_count: sectionCount(sections, "peerDependencies"),
      optional_dependency_count: sectionCount(sections, "optionalDependencies"),
      bundled_dependency_count: bundledDependencyCount(sections),
      lockfile_package_count: numberOrZero(observed.package_count),
      lockfile_packages_without_version_count: packagesWithoutVersions.length,
      lockfile_dependency_edge_count: numberOrZero(observed.dependency_edge_count),
      importer_count: stringArray(observed.importer_names).length,
      license_present: parsed.sourceParser === "parse_package_json" ? typeof observed.license === "string" && observed.license.length > 0 : null,
      repository_present: parsed.sourceParser === "parse_package_json" ? childRecord(observed, "repository")?.present === true : null,
      engines_present: parsed.sourceParser === "parse_package_json" ? childRecord(observed, "engines")?.present === true : null,
      bin_present: parsed.sourceParser === "parse_package_json" ? observed.bin_present === true : null,
      workspaces_present: parsed.sourceParser === "parse_package_json" ? observed.workspaces_present === true : null,
      evidence_count: evidence.length,
      signal_count: signals.length,
      dependency_sections: sections,
      lockfile_packages: lockfilePackages,
      limitations: [
        "Consumes parse_package_json or parse_lockfiles output and does not install packages.",
        "Does not execute package scripts or inspect package tarballs.",
        "Does not perform vulnerability lookup, package reputation checks, maintainer trust review, or registry enrichment.",
        "Does not infer maliciousness, exploitability, or dependency reachability.",
        "Does not score risk or generate findings.",
      ],
    },
    evidence,
    signals,
    warnings,
  };
}

export const reviewPackageSkill: Skill<unknown, PackageReviewOutput> = {
  metadata: {
    name: "review_package",
    version: "0.1.0",
    category: "reviewer",
    description: "Review parsed package manifest or lockfile metadata and emit evidence-backed package inventory and install-surface signals without vulnerability lookup.",
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
        "Reviews already parsed package manifest or lockfile metadata that may contain package names, versions, script names, and dependency metadata.",
        "Does not install packages, run scripts, perform vulnerability lookup, contact registries, score risk, or generate findings.",
        "Output preserves evidence-backed package inventory and install-surface observations with explicit limitations.",
      ],
    },
  },
  run: reviewPackage,
};
