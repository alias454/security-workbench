import type { Skill } from "@security-workbench/schemas";
import { localOnlyPermissions } from "./localOnlyPermissions.js";
import {
  detectLineEnding,
  isRecord,
  normalizeTextInput,
  parseJsonObject,
  physicalLineCount,
  recordArray,
  recordValue,
  stringArray,
  stringValue,
  uniqueSorted,
  unknownKeys,
  type NativeJsonLineEnding,
} from "./nativeParserUtils.js";

export type SbomFormat = "cyclonedx_json" | "spdx_json";

export interface SbomExternalReferenceObservation {
  readonly type: string | null;
  readonly url: string | null;
}

export interface SbomComponentObservation {
  readonly component_index: number;
  readonly source_format: SbomFormat;
  readonly id: string | null;
  readonly type: string | null;
  readonly name: string | null;
  readonly version: string | null;
  readonly supplier: string | null;
  readonly licenses: readonly string[];
  readonly purl: string | null;
  readonly cpes: readonly string[];
  readonly hash_algorithms: readonly string[];
  readonly external_references: readonly SbomExternalReferenceObservation[];
  readonly dependency_refs: readonly string[];
  readonly relationship_types: readonly string[];
  readonly download_location: string | null;
  readonly files_analyzed: boolean | null;
}

export interface ParseSbomOutput {
  readonly artifact: {
    readonly id: "artifact_sbom";
    readonly type: "sbom";
    readonly format: SbomFormat;
    readonly spec_version: string | null;
  };
  readonly observed: {
    readonly line_ending: NativeJsonLineEnding;
    readonly physical_line_count: number;
    readonly format: SbomFormat;
    readonly spec_version: string | null;
    readonly document_name: string | null;
    readonly document_namespace: string | null;
    readonly serial_number: string | null;
    readonly metadata_timestamp: string | null;
    readonly tool_names: readonly string[];
    readonly component_count: number;
    readonly package_count: number;
    readonly service_count: number;
    readonly dependency_edge_count: number;
    readonly relationship_count: number;
    readonly external_reference_count: number;
    readonly purl_count: number;
    readonly cpe_count: number;
    readonly hash_count: number;
    readonly supplier_count: number;
    readonly license_ids: readonly string[];
    readonly component_names: readonly string[];
    readonly package_names: readonly string[];
    readonly package_name_version_refs: readonly string[];
    readonly supplier_names: readonly string[];
    readonly purls: readonly string[];
    readonly cpes: readonly string[];
    readonly unknown_top_level_keys: readonly string[];
    readonly components: readonly SbomComponentObservation[];
  };
  readonly warnings: readonly string[];
}

const CYCLONEDX_ROOT_KEYS = new Set([
  "$schema",
  "bomFormat",
  "specVersion",
  "serialNumber",
  "version",
  "metadata",
  "components",
  "services",
  "dependencies",
  "vulnerabilities",
  "compositions",
  "externalReferences",
  "properties",
]);

const SPDX_ROOT_KEYS = new Set([
  "spdxVersion",
  "dataLicense",
  "SPDXID",
  "name",
  "documentNamespace",
  "creationInfo",
  "documentDescribes",
  "packages",
  "files",
  "relationships",
  "snippets",
  "annotations",
  "hasExtractedLicensingInfos",
]);

function detectSbomFormat(root: Record<string, unknown>): SbomFormat {
  if (stringValue(root.bomFormat)?.toLowerCase() === "cyclonedx" || Array.isArray(root.components)) {
    return "cyclonedx_json";
  }

  if (typeof root.spdxVersion === "string" || Array.isArray(root.packages)) {
    return "spdx_json";
  }

  throw new Error("parse_sbom input must be CycloneDX JSON or SPDX JSON");
}

function licenseString(value: unknown): string | null {
  if (typeof value === "string") {
    return value;
  }

  if (!isRecord(value)) {
    return null;
  }

  const license = recordValue(value, "license");
  const expression = stringValue(value.expression);
  if (expression) {
    return expression;
  }

  return license ? stringValue(license.id) ?? stringValue(license.name) : null;
}

function cyclonedxLicenses(component: Record<string, unknown>): string[] {
  return uniqueSorted(recordArray(component.licenses).map(licenseString));
}

function spdxLicenses(pkg: Record<string, unknown>): string[] {
  return uniqueSorted([
    stringValue(pkg.licenseConcluded),
    stringValue(pkg.licenseDeclared),
  ].filter((license) => license !== null && license !== "NOASSERTION" && license !== "NONE"));
}

function cyclonedxSupplier(component: Record<string, unknown>): string | null {
  const supplier = component.supplier;
  if (typeof supplier === "string") {
    return supplier;
  }
  if (isRecord(supplier)) {
    return stringValue(supplier.name);
  }
  return null;
}

function spdxSupplier(pkg: Record<string, unknown>): string | null {
  const supplier = stringValue(pkg.supplier);
  if (!supplier || supplier === "NOASSERTION") {
    return null;
  }
  return supplier;
}

function externalReference(value: unknown): SbomExternalReferenceObservation | null {
  if (!isRecord(value)) {
    return null;
  }

  return {
    type: stringValue(value.type) ?? stringValue(value.referenceCategory) ?? stringValue(value.referenceType),
    url: stringValue(value.url) ?? stringValue(value.referenceLocator),
  };
}

function externalReferences(value: unknown): SbomExternalReferenceObservation[] {
  return recordArray(value)
    .map(externalReference)
    .filter((entry): entry is SbomExternalReferenceObservation => entry !== null);
}

function hashAlgorithms(value: unknown): string[] {
  return uniqueSorted(recordArray(value).map((entry) => stringValue(entry.alg) ?? stringValue(entry.algorithm)));
}

function cdxCpes(component: Record<string, unknown>): string[] {
  return uniqueSorted([
    stringValue(component.cpe),
    ...stringArray(component.cpes),
  ]);
}

function packageRef(name: string | null, version: string | null): string | null {
  if (!name) {
    return null;
  }

  return `${name}@${version ?? "unknown"}`;
}

function cyclonedxDependencyMap(root: Record<string, unknown>): Map<string, string[]> {
  const map = new Map<string, string[]>();
  for (const dependency of recordArray(root.dependencies)) {
    const ref = stringValue(dependency.ref);
    if (!ref) {
      continue;
    }
    map.set(ref, stringArray(dependency.dependsOn));
  }
  return map;
}

function cyclonedxTools(metadata: Record<string, unknown> | null): string[] {
  if (!metadata) {
    return [];
  }

  const tools = metadata.tools;
  if (Array.isArray(tools)) {
    return uniqueSorted(recordArray(tools).map((tool) => stringValue(tool.name)));
  }

  const toolsRecord = isRecord(tools) ? tools : null;
  if (!toolsRecord) {
    return [];
  }

  return uniqueSorted([
    ...recordArray(toolsRecord.components).map((tool) => stringValue(tool.name)),
    ...recordArray(toolsRecord.services).map((tool) => stringValue(tool.name)),
  ]);
}

function parseCyclonedx(root: Record<string, unknown>, normalized: string): ParseSbomOutput {
  const warnings: string[] = [];
  const componentsRoot = root.components;
  const servicesRoot = root.services;
  const componentRecords = recordArray(componentsRoot);
  const serviceRecords = recordArray(servicesRoot);

  if (componentsRoot !== undefined && (!Array.isArray(componentsRoot) || componentRecords.length !== componentsRoot.length)) {
    warnings.push('CycloneDX field "components" must be an array of objects; non-object entries were ignored.');
  }

  if (servicesRoot !== undefined && (!Array.isArray(servicesRoot) || serviceRecords.length !== servicesRoot.length)) {
    warnings.push('CycloneDX field "services" must be an array of objects; non-object entries were ignored.');
  }

  const dependencyMap = cyclonedxDependencyMap(root);
  const components: SbomComponentObservation[] = [
    ...componentRecords.map((component, index) => {
      const id = stringValue(component["bom-ref"]) ?? stringValue(component.bomRef);
      return {
        component_index: index,
        source_format: "cyclonedx_json" as const,
        id,
        type: stringValue(component.type) ?? "component",
        name: stringValue(component.name),
        version: stringValue(component.version),
        supplier: cyclonedxSupplier(component),
        licenses: cyclonedxLicenses(component),
        purl: stringValue(component.purl),
        cpes: cdxCpes(component),
        hash_algorithms: hashAlgorithms(component.hashes),
        external_references: externalReferences(component.externalReferences),
        dependency_refs: id ? dependencyMap.get(id) ?? [] : [],
        relationship_types: [],
        download_location: null,
        files_analyzed: null,
      };
    }),
    ...serviceRecords.map((service, index) => {
      const id = stringValue(service["bom-ref"]) ?? stringValue(service.bomRef);
      return {
        component_index: componentRecords.length + index,
        source_format: "cyclonedx_json" as const,
        id,
        type: "service",
        name: stringValue(service.name),
        version: stringValue(service.version),
        supplier: cyclonedxSupplier(service),
        licenses: cyclonedxLicenses(service),
        purl: null,
        cpes: [],
        hash_algorithms: [],
        external_references: externalReferences(service.externalReferences),
        dependency_refs: id ? dependencyMap.get(id) ?? [] : [],
        relationship_types: [],
        download_location: null,
        files_analyzed: null,
      };
    }),
  ];

  const metadata = recordValue(root, "metadata");
  const metadataComponent = metadata ? recordValue(metadata, "component") : null;

  return sbomOutput({
    normalized,
    format: "cyclonedx_json",
    specVersion: stringValue(root.specVersion),
    documentName: metadataComponent ? stringValue(metadataComponent.name) : null,
    documentNamespace: null,
    serialNumber: stringValue(root.serialNumber),
    metadataTimestamp: metadata ? stringValue(metadata.timestamp) : null,
    toolNames: cyclonedxTools(metadata),
    components,
    serviceCount: serviceRecords.length,
    relationshipCount: 0,
    unknownTopLevelKeys: unknownKeys(root, CYCLONEDX_ROOT_KEYS),
    warnings,
  });
}

function relationshipTypesForPackage(relationships: readonly Record<string, unknown>[], spdxId: string | null): string[] {
  if (!spdxId) {
    return [];
  }

  return uniqueSorted(
    relationships
      .filter((relationship) => stringValue(relationship.spdxElementId) === spdxId)
      .map((relationship) => stringValue(relationship.relationshipType)),
  );
}

function dependencyRefsForPackage(relationships: readonly Record<string, unknown>[], spdxId: string | null): string[] {
  if (!spdxId) {
    return [];
  }

  return uniqueSorted(
    relationships
      .filter((relationship) =>
        stringValue(relationship.spdxElementId) === spdxId &&
        stringValue(relationship.relationshipType)?.includes("DEPENDS_ON") === true,
      )
      .map((relationship) => stringValue(relationship.relatedSpdxElement)),
  );
}

function spdxTools(creationInfo: Record<string, unknown> | null): string[] {
  return uniqueSorted(stringArray(creationInfo?.creators).map((creator) => creator.replace(/^Tool:\s*/i, "")));
}

function spdxExternalReferences(pkg: Record<string, unknown>): SbomExternalReferenceObservation[] {
  return externalReferences(pkg.externalRefs);
}

function parseSpdx(root: Record<string, unknown>, normalized: string): ParseSbomOutput {
  const warnings: string[] = [];
  const packagesRoot = root.packages;
  const packageRecords = recordArray(packagesRoot);
  const relationshipRecords = recordArray(root.relationships);

  if (!Array.isArray(packagesRoot)) {
    warnings.push('SPDX field "packages" is missing or not an array.');
  } else if (packageRecords.length !== packagesRoot.length) {
    warnings.push('SPDX field "packages" contains non-object entries that were ignored.');
  }

  const components = packageRecords.map((pkg, index): SbomComponentObservation => {
    const id = stringValue(pkg.SPDXID);
    const externalRefs = spdxExternalReferences(pkg);
    return {
      component_index: index,
      source_format: "spdx_json",
      id,
      type: "package",
      name: stringValue(pkg.name),
      version: stringValue(pkg.versionInfo),
      supplier: spdxSupplier(pkg),
      licenses: spdxLicenses(pkg),
      purl: externalRefs.find((entry) => entry.type === "purl")?.url ?? null,
      cpes: uniqueSorted(externalRefs.filter((entry) => entry.type === "cpe23Type").map((entry) => entry.url)),
      hash_algorithms: hashAlgorithms(pkg.checksums),
      external_references: externalRefs,
      dependency_refs: dependencyRefsForPackage(relationshipRecords, id),
      relationship_types: relationshipTypesForPackage(relationshipRecords, id),
      download_location: stringValue(pkg.downloadLocation),
      files_analyzed: typeof pkg.filesAnalyzed === "boolean" ? pkg.filesAnalyzed : null,
    };
  });

  const creationInfo = recordValue(root, "creationInfo");

  return sbomOutput({
    normalized,
    format: "spdx_json",
    specVersion: stringValue(root.spdxVersion),
    documentName: stringValue(root.name),
    documentNamespace: stringValue(root.documentNamespace),
    serialNumber: null,
    metadataTimestamp: creationInfo ? stringValue(creationInfo.created) : null,
    toolNames: spdxTools(creationInfo),
    components,
    serviceCount: 0,
    relationshipCount: relationshipRecords.length,
    unknownTopLevelKeys: unknownKeys(root, SPDX_ROOT_KEYS),
    warnings,
  });
}

function sbomOutput(input: {
  readonly normalized: string;
  readonly format: SbomFormat;
  readonly specVersion: string | null;
  readonly documentName: string | null;
  readonly documentNamespace: string | null;
  readonly serialNumber: string | null;
  readonly metadataTimestamp: string | null;
  readonly toolNames: readonly string[];
  readonly components: readonly SbomComponentObservation[];
  readonly serviceCount: number;
  readonly relationshipCount: number;
  readonly unknownTopLevelKeys: readonly string[];
  readonly warnings: readonly string[];
}): ParseSbomOutput {
  const packages = input.components.filter((component) => component.type !== "service");
  const externalReferences = input.components.flatMap((component) => component.external_references);

  return {
    artifact: {
      id: "artifact_sbom",
      type: "sbom",
      format: input.format,
      spec_version: input.specVersion,
    },
    observed: {
      line_ending: detectLineEnding(input.normalized),
      physical_line_count: physicalLineCount(input.normalized),
      format: input.format,
      spec_version: input.specVersion,
      document_name: input.documentName,
      document_namespace: input.documentNamespace,
      serial_number: input.serialNumber,
      metadata_timestamp: input.metadataTimestamp,
      tool_names: input.toolNames,
      component_count: input.components.length,
      package_count: packages.length,
      service_count: input.serviceCount,
      dependency_edge_count: input.components.reduce((total, component) => total + component.dependency_refs.length, 0),
      relationship_count: input.relationshipCount,
      external_reference_count: externalReferences.length,
      purl_count: input.components.filter((component) => component.purl !== null).length,
      cpe_count: input.components.reduce((total, component) => total + component.cpes.length, 0),
      hash_count: input.components.reduce((total, component) => total + component.hash_algorithms.length, 0),
      supplier_count: input.components.filter((component) => component.supplier !== null).length,
      license_ids: uniqueSorted(input.components.flatMap((component) => component.licenses)),
      component_names: uniqueSorted(input.components.map((component) => component.name)),
      package_names: uniqueSorted(packages.map((component) => component.name)),
      package_name_version_refs: uniqueSorted(packages.map((component) => packageRef(component.name, component.version))),
      supplier_names: uniqueSorted(input.components.map((component) => component.supplier)),
      purls: uniqueSorted(input.components.map((component) => component.purl)),
      cpes: uniqueSorted(input.components.flatMap((component) => component.cpes)),
      unknown_top_level_keys: input.unknownTopLevelKeys,
      components: input.components,
    },
    warnings: input.warnings,
  };
}

export function parseSbom(input: string): ParseSbomOutput {
  const normalized = normalizeTextInput(input, "parse_sbom");
  const root = parseJsonObject(normalized, "parse_sbom");
  const format = detectSbomFormat(root);

  if (format === "cyclonedx_json") {
    return parseCyclonedx(root, normalized);
  }

  return parseSpdx(root, normalized);
}

export const parseSbomSkill: Skill<string, ParseSbomOutput> = {
  metadata: {
    name: "parse_sbom",
    version: "0.1.0",
    category: "parser",
    description: "Parse CycloneDX or SPDX SBOM JSON into structured package, component, identifier, dependency, and metadata observations.",
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
        "Parses attacker-controlled SBOM JSON that may contain package names, versions, paths, and supplier metadata.",
        "Does not perform network access, persist input, call external services, or execute artifact content.",
        "Parser output preserves SBOM observations without vulnerability lookup, package reputation checks, scoring, or findings.",
      ],
    },
  },
  run(input: string): ParseSbomOutput {
    return parseSbom(input);
  },
};
