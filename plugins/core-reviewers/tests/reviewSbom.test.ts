import { describe, expect, it } from "vitest";
import { reviewSbom, reviewSbomSkill } from "../src/reviewSbom.js";

const parsedCyclonedxSbom = {
  artifact: {
    id: "artifact_sbom",
    type: "sbom",
    format: "cyclonedx_json",
    spec_version: "1.5",
  },
  observed: {
    format: "cyclonedx_json",
    spec_version: "1.5",
    package_count: 2,
    service_count: 1,
    dependency_edge_count: 1,
    relationship_count: 0,
    purl_count: 2,
    cpe_count: 0,
    external_reference_count: 1,
    component_names: ["example-api", "express", "lodash"],
    package_name_version_refs: ["express@4.18.2", "lodash@unknown"],
    components: [
      {
        component_index: 0,
        source_format: "cyclonedx_json",
        id: "pkg:npm/express@4.18.2",
        type: "library",
        name: "express",
        version: "4.18.2",
        supplier: "OpenJS Foundation",
        licenses: ["MIT"],
        purl: "pkg:npm/express@4.18.2",
        cpes: [],
        external_references: [{ type: "website", url: "https://expressjs.com/" }],
      },
      {
        component_index: 1,
        source_format: "cyclonedx_json",
        id: "pkg:npm/lodash",
        type: "library",
        name: "lodash",
        version: null,
        supplier: null,
        licenses: [],
        purl: "pkg:npm/lodash",
        cpes: [],
        external_references: [],
      },
      {
        component_index: 2,
        source_format: "cyclonedx_json",
        id: "service:api",
        type: "service",
        name: "example-api",
        version: "1.0.0",
        supplier: null,
        licenses: [],
        purl: null,
        cpes: [],
        external_references: [],
      },
    ],
  },
  warnings: [],
} as const;

describe("review_sbom", () => {
  it("exports the reviewer skill with local-only permissions", () => {
    expect(reviewSbomSkill.metadata.name).toBe("review_sbom");
    expect(reviewSbomSkill.metadata.category).toBe("reviewer");
    expect(reviewSbomSkill.metadata.execution).toEqual({
      mode: "local_only",
      network_access: "none",
      deterministic: true,
    });
    expect(reviewSbomSkill.metadata.permissions).toEqual({
      network: "none",
      filesystem: "none",
      sends: [],
      persists: false,
      runs_external_binaries: false,
    });
  });

  it("emits evidence-backed SBOM inventory-quality signals", () => {
    const output = reviewSbom(parsedCyclonedxSbom);

    expect(output.artifact).toMatchObject({
      type: "sbom_review",
      source_artifact_id: "artifact_sbom",
      source_artifact_type: "sbom",
    });
    expect(output.observed.source_parser).toBe("parse_sbom");
    expect(output.observed.reviewed_component_count).toBe(3);
    expect(output.observed.components_without_version_count).toBe(1);
    expect(output.observed.components_without_license_count).toBe(1);
    expect(output.observed.components_without_supplier_count).toBe(2);
    expect(output.signals.map((signal) => signal.type)).toEqual([
      "sbom.component_version_not_observed",
      "sbom.component_license_not_observed",
      "sbom.component_supplier_not_observed",
      "sbom.external_references_observed",
    ]);
    expect(output.signals.every((signal) => signal.evidence_refs.length > 0)).toBe(true);
    expect(output.observed.limitations).toContain("Does not perform network lookups or external enrichment.");
  });

  it("accepts a JSON run result from parse_sbom", () => {
    const runResult = {
      run_id: "run_parser",
      status: "completed",
      skill: { name: "parse_sbom", version: "0.1.0" },
      output: { ...parsedCyclonedxSbom, warnings: ["parser warning"] },
      errors: [],
      warnings: [],
    };

    const output = reviewSbom(JSON.stringify(runResult));

    expect(output.observed.source_parser).toBe("parse_sbom");
    expect(output.observed.source_warning_count).toBe(1);
    expect(output.warnings).toEqual(["Source parser emitted 1 warning(s); review output preserves source_warning_count only."]);
  });

  it("emits an empty-inventory signal", () => {
    const output = reviewSbom({
      artifact: { id: "artifact_sbom", type: "sbom" },
      observed: {
        format: "spdx_json",
        spec_version: "SPDX-2.3",
        package_count: 0,
        service_count: 0,
        dependency_edge_count: 0,
        relationship_count: 0,
        purl_count: 0,
        cpe_count: 0,
        external_reference_count: 0,
        component_names: [],
        package_name_version_refs: [],
        components: [],
      },
      warnings: [],
    });

    expect(output.signals.map((signal) => signal.type)).toEqual(["sbom.no_components_observed"]);
  });

  it("rejects objects that are not parse_sbom output", () => {
    expect(() =>
      reviewSbom({
        artifact: { id: "artifact_package_json", type: "package_json" },
        observed: {},
        warnings: [],
      }),
    ).toThrow("review_sbom input artifact.type must be sbom");
  });
});
