import type { EvidenceRecord, JsonObject, JsonValue, SignalRecord, Skill } from "@security-workbench/schemas";
import { localOnlyPermissions } from "./localOnlyPermissions.js";

type ReviewRecord = Record<string, unknown>;
type Confidence = "confirmed" | "high" | "medium" | "low" | "unknown";
type Severity = "informational" | "low" | "medium" | "high" | "critical";

export interface SbomReviewComponentObservation {
  readonly component_index: number;
  readonly source_format: string | null;
  readonly id: string | null;
  readonly type: string | null;
  readonly name: string | null;
  readonly version_present: boolean;
  readonly supplier_present: boolean;
  readonly license_count: number;
  readonly purl_present: boolean;
  readonly cpe_count: number;
  readonly external_reference_count: number;
  readonly download_location: string | null;
}

export interface SbomReviewOutput {
  readonly artifact: {
    readonly id: "artifact_sbom_review";
    readonly type: "sbom_review";
    readonly source_artifact_id: string | null;
    readonly source_artifact_type: string | null;
  };
  readonly observed: {
    readonly source_parser: "parse_sbom";
    readonly source_warning_count: number;
    readonly format: string | null;
    readonly spec_version: string | null;
    readonly reviewed_component_count: number;
    readonly package_count: number;
    readonly service_count: number;
    readonly dependency_edge_count: number;
    readonly relationship_count: number;
    readonly components_without_version_count: number;
    readonly components_without_license_count: number;
    readonly components_without_supplier_count: number;
    readonly unresolved_download_location_count: number;
    readonly purl_count: number;
    readonly cpe_count: number;
    readonly external_reference_count: number;
    readonly evidence_count: number;
    readonly signal_count: number;
    readonly component_names: readonly string[];
    readonly package_name_version_refs: readonly string[];
    readonly limitations: readonly string[];
    readonly components: readonly SbomReviewComponentObservation[];
  };
  readonly evidence: readonly EvidenceRecord[];
  readonly signals: readonly SignalRecord[];
  readonly warnings: readonly string[];
}

interface ParsedSbomForReview {
  readonly artifact: {
    readonly id?: string;
    readonly type?: string;
  };
  readonly observed: ReviewRecord;
  readonly warnings?: readonly string[];
}

function isRecord(value: unknown): value is ReviewRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function parseJsonString(input: string): unknown {
  try {
    return JSON.parse(input) as unknown;
  } catch {
    throw new Error("review_sbom input must be parse_sbom output JSON or a JSON run result from parse_sbom");
  }
}

function childRecord(record: ReviewRecord, key: string): ReviewRecord | undefined {
  const value = record[key];
  return isRecord(value) ? value : undefined;
}

function stringOrNull(value: unknown): string | null {
  return typeof value === "string" ? value : null;
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

function unwrapInput(input: unknown): ParsedSbomForReview {
  const parsed = typeof input === "string" ? parseJsonString(input) : input;
  const candidate = isRecord(parsed) && isRecord(parsed.output) ? parsed.output : parsed;

  if (!isRecord(candidate)) {
    throw new Error("review_sbom input must be an object");
  }

  const artifact = childRecord(candidate, "artifact");
  const observed = childRecord(candidate, "observed");

  if (!artifact || !observed) {
    throw new Error("review_sbom input must be parse_sbom output with artifact and observed fields");
  }

  if (artifact.type !== "sbom") {
    throw new Error("review_sbom input artifact.type must be sbom");
  }

  return {
    artifact: {
      id: stringOrNull(artifact.id) ?? undefined,
      type: stringOrNull(artifact.type) ?? undefined,
    },
    observed,
    warnings: stringArray(candidate.warnings),
  };
}

function componentObservations(observed: ReviewRecord): SbomReviewComponentObservation[] {
  return recordArray(observed.components).map((component) => {
    const licenses = stringArray(component.licenses);
    const cpes = stringArray(component.cpes);
    const externalReferences = recordArray(component.external_references);

    return {
      component_index: numberOrZero(component.component_index),
      source_format: stringOrNull(component.source_format),
      id: stringOrNull(component.id),
      type: stringOrNull(component.type),
      name: stringOrNull(component.name),
      version_present: typeof component.version === "string" && component.version.length > 0,
      supplier_present: typeof component.supplier === "string" && component.supplier.length > 0,
      license_count: licenses.length,
      purl_present: typeof component.purl === "string" && component.purl.length > 0,
      cpe_count: cpes.length,
      external_reference_count: externalReferences.length,
      download_location: stringOrNull(component.download_location),
    };
  });
}

function unresolvedDownloadLocations(components: readonly SbomReviewComponentObservation[]): SbomReviewComponentObservation[] {
  return components.filter((component) =>
    component.download_location === "NOASSERTION" || component.download_location === "NONE",
  );
}

function componentRef(component: SbomReviewComponentObservation): string {
  if (component.name) {
    return component.version_present ? component.name : `${component.name}@unknown`;
  }
  if (component.id) {
    return component.id;
  }
  return `component:${String(component.component_index)}`;
}

function compactComponentRefs(components: readonly SbomReviewComponentObservation[]): string[] {
  return uniqueSorted(components.map(componentRef)).slice(0, 25);
}

function createEvidenceBuilder(sourceArtifactId: string | null) {
  const evidence: EvidenceRecord[] = [];

  function addEvidence(type: string, path: string, value: unknown, description: string): string {
    const id = `evidence_sbom_${String(evidence.length + 1).padStart(3, "0")}`;
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
    id: `signal_sbom_${String(signals.length + 1).padStart(3, "0")}`,
    type: input.type,
    summary: input.summary,
    severity: input.severity,
    confidence: input.confidence,
    evidence_refs: input.evidenceRefs,
    observed: input.observed,
    tags: input.tags ?? ["sbom"],
  });
}

function addAggregateSignal(
  input: {
    components: readonly SbomReviewComponentObservation[];
    matchingComponents: readonly SbomReviewComponentObservation[];
    addEvidence: (type: string, path: string, value: unknown, description: string) => string;
    signals: SignalRecord[];
    evidenceType: string;
    signalType: string;
    summary: string;
    path: string;
    description: string;
    severity: Severity;
    tags: readonly string[];
  },
): void {
  if (input.matchingComponents.length === 0) {
    return;
  }

  const evidenceRef = input.addEvidence(
    input.evidenceType,
    input.path,
    {
      count: input.matchingComponents.length,
      total_components: input.components.length,
      component_refs: compactComponentRefs(input.matchingComponents),
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
      count: input.matchingComponents.length,
      total_components: input.components.length,
    },
    tags: input.tags,
  });
}

export function reviewSbom(input: unknown): SbomReviewOutput {
  const parsed = unwrapInput(input);
  const observed = parsed.observed;
  const sourceArtifactId = stringOrNull(parsed.artifact.id);
  const { evidence, addEvidence } = createEvidenceBuilder(sourceArtifactId);
  const signals: SignalRecord[] = [];
  const warnings: string[] = [];
  const components = componentObservations(observed);

  if (components.length === 0) {
    const evidenceRef = addEvidence(
      "sbom_empty_inventory",
      "observed.components",
      { component_count: 0 },
      "Parsed SBOM output did not contain component or package observations.",
    );
    addSignal(signals, {
      type: "sbom.no_components_observed",
      summary: "No components or packages were observed in the parsed SBOM inventory.",
      evidenceRefs: [evidenceRef],
      severity: "low",
      confidence: "confirmed",
      observed: { component_count: 0 },
      tags: ["sbom", "inventory-quality"],
    });
  }

  const withoutVersion = components.filter((component) => !component.version_present && component.type !== "service");
  const withoutLicense = components.filter((component) => component.license_count === 0 && component.type !== "service");
  const withoutSupplier = components.filter((component) => !component.supplier_present);
  const unresolvedDownloads = unresolvedDownloadLocations(components);
  const withExternalReferences = components.filter((component) => component.external_reference_count > 0);

  addAggregateSignal({
    components,
    matchingComponents: withoutVersion,
    addEvidence,
    signals,
    evidenceType: "sbom_components_without_versions",
    signalType: "sbom.component_version_not_observed",
    summary: `${String(withoutVersion.length)} SBOM package component(s) did not include an observed version.`,
    path: "observed.components[*].version",
    description: "Parsed SBOM component/package records were missing version metadata.",
    severity: "low",
    tags: ["sbom", "inventory-quality", "version"],
  });

  addAggregateSignal({
    components,
    matchingComponents: withoutLicense,
    addEvidence,
    signals,
    evidenceType: "sbom_components_without_licenses",
    signalType: "sbom.component_license_not_observed",
    summary: `${String(withoutLicense.length)} SBOM package component(s) did not include observed license metadata.`,
    path: "observed.components[*].licenses",
    description: "Parsed SBOM component/package records were missing license identifiers or expressions.",
    severity: "informational",
    tags: ["sbom", "inventory-quality", "license"],
  });

  addAggregateSignal({
    components,
    matchingComponents: withoutSupplier,
    addEvidence,
    signals,
    evidenceType: "sbom_components_without_suppliers",
    signalType: "sbom.component_supplier_not_observed",
    summary: `${String(withoutSupplier.length)} SBOM component(s) did not include observed supplier metadata.`,
    path: "observed.components[*].supplier",
    description: "Parsed SBOM component records were missing supplier metadata.",
    severity: "informational",
    tags: ["sbom", "inventory-quality", "supplier"],
  });

  addAggregateSignal({
    components,
    matchingComponents: unresolvedDownloads,
    addEvidence,
    signals,
    evidenceType: "sbom_unresolved_download_locations",
    signalType: "sbom.unresolved_download_location_observed",
    summary: `${String(unresolvedDownloads.length)} SPDX package component(s) used unresolved download-location markers.`,
    path: "observed.components[*].download_location",
    description: "Parsed SPDX package records used NOASSERTION or NONE for downloadLocation.",
    severity: "informational",
    tags: ["sbom", "inventory-quality", "download-location"],
  });

  if (withExternalReferences.length > 0) {
    const evidenceRef = addEvidence(
      "sbom_external_references_present",
      "observed.components[*].external_references",
      {
        count: withExternalReferences.length,
        total_components: components.length,
        component_refs: compactComponentRefs(withExternalReferences),
      },
      "Parsed SBOM component records included external references such as purl, CPE, or other URLs.",
    );
    addSignal(signals, {
      type: "sbom.external_references_observed",
      summary: `${String(withExternalReferences.length)} SBOM component(s) included external references for follow-up enrichment or review.`,
      evidenceRefs: [evidenceRef],
      severity: "informational",
      confidence: "confirmed",
      observed: {
        component_count: withExternalReferences.length,
        external_reference_count: numberOrZero(observed.external_reference_count),
      },
      tags: ["sbom", "identifiers"],
    });
  }

  if ((parsed.warnings?.length ?? 0) > 0) {
    warnings.push(`Source parser emitted ${parsed.warnings?.length ?? 0} warning(s); review output preserves source_warning_count only.`);
  }

  return {
    artifact: {
      id: "artifact_sbom_review",
      type: "sbom_review",
      source_artifact_id: parsed.artifact.id ?? null,
      source_artifact_type: parsed.artifact.type ?? null,
    },
    observed: {
      source_parser: "parse_sbom",
      source_warning_count: parsed.warnings?.length ?? 0,
      format: stringOrNull(observed.format),
      spec_version: stringOrNull(observed.spec_version),
      reviewed_component_count: components.length,
      package_count: numberOrZero(observed.package_count),
      service_count: numberOrZero(observed.service_count),
      dependency_edge_count: numberOrZero(observed.dependency_edge_count),
      relationship_count: numberOrZero(observed.relationship_count),
      components_without_version_count: withoutVersion.length,
      components_without_license_count: withoutLicense.length,
      components_without_supplier_count: withoutSupplier.length,
      unresolved_download_location_count: unresolvedDownloads.length,
      purl_count: numberOrZero(observed.purl_count),
      cpe_count: numberOrZero(observed.cpe_count),
      external_reference_count: numberOrZero(observed.external_reference_count),
      evidence_count: evidence.length,
      signal_count: signals.length,
      component_names: stringArray(observed.component_names),
      package_name_version_refs: stringArray(observed.package_name_version_refs),
      limitations: [
        "Consumes parse_sbom output and does not perform package vulnerability lookup.",
        "Does not resolve package reputation, maintainer trust, exploitability, or dependency reachability.",
        "Does not validate SBOM provenance, signer identity, or build attestation trust.",
        "Does not perform network lookups or external enrichment.",
        "Does not score risk or generate findings.",
      ],
      components,
    },
    evidence,
    signals,
    warnings,
  };
}

export const reviewSbomSkill: Skill<unknown, SbomReviewOutput> = {
  metadata: {
    name: "review_sbom",
    version: "0.1.0",
    category: "reviewer",
    description: "Review parsed SBOM inventory metadata and emit evidence-backed inventory-quality signals without vulnerability lookup.",
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
        "Reviews already parsed SBOM metadata that may contain package names, versions, suppliers, and external references.",
        "Does not perform vulnerability lookup, package reputation checks, network enrichment, scoring, or finding generation.",
        "Output preserves evidence-backed inventory-quality observations and explicit limitations.",
      ],
    },
  },
  run: reviewSbom,
};
