import { describe, expect, it } from "vitest";
import { parseSbom, parseSbomSkill } from "../src/parseSbom.js";
import { skills } from "../src/index.js";

function cyclonedxSbom(): string {
  return JSON.stringify({
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    serialNumber: "urn:uuid:11111111-1111-4111-8111-111111111111",
    metadata: {
      timestamp: "2026-07-01T00:00:00Z",
      tools: { components: [{ name: "syft", version: "1.0.0" }] },
      component: { type: "application", name: "example-app", version: "1.0.0" },
    },
    components: [
      {
        "bom-ref": "pkg:npm/express@4.18.2",
        type: "library",
        name: "express",
        version: "4.18.2",
        supplier: { name: "OpenJS Foundation" },
        licenses: [{ license: { id: "MIT" } }],
        purl: "pkg:npm/express@4.18.2",
        hashes: [{ alg: "SHA-256", content: "abc123" }],
        externalReferences: [{ type: "website", url: "https://expressjs.com/" }],
      },
      {
        "bom-ref": "pkg:npm/lodash",
        type: "library",
        name: "lodash",
        purl: "pkg:npm/lodash",
      },
    ],
    services: [{ "bom-ref": "service:api", name: "example-api", version: "1.0.0" }],
    dependencies: [{ ref: "pkg:npm/express@4.18.2", dependsOn: ["pkg:npm/lodash"] }],
  });
}

function spdxSbom(): string {
  return JSON.stringify({
    spdxVersion: "SPDX-2.3",
    SPDXID: "SPDXRef-DOCUMENT",
    name: "example-spdx-document",
    documentNamespace: "https://example.invalid/spdx/example-1",
    creationInfo: {
      created: "2026-07-01T00:00:00Z",
      creators: ["Tool: example-sbom-generator-1.0.0"],
    },
    packages: [
      {
        SPDXID: "SPDXRef-Package-openssl",
        name: "openssl",
        versionInfo: "3.0.13",
        downloadLocation: "NOASSERTION",
        filesAnalyzed: false,
        licenseConcluded: "Apache-2.0",
        licenseDeclared: "Apache-2.0",
        supplier: "Organization: OpenSSL Software Foundation",
        checksums: [{ algorithm: "SHA256", checksumValue: "abc123" }],
        externalRefs: [
          { referenceCategory: "PACKAGE-MANAGER", referenceType: "purl", referenceLocator: "pkg:generic/openssl@3.0.13" },
          { referenceCategory: "SECURITY", referenceType: "cpe23Type", referenceLocator: "cpe:2.3:a:openssl:openssl:3.0.13:*:*:*:*:*:*:*" },
        ],
      },
    ],
    relationships: [
      { spdxElementId: "SPDXRef-Package-openssl", relationshipType: "DEPENDS_ON", relatedSpdxElement: "SPDXRef-Package-example-lib" },
    ],
  });
}

describe("parse_sbom", () => {
  it("exports the parser skill with local-only permissions", () => {
    expect(skills.map((skill) => skill.metadata.name)).toContain("parse_sbom");
    expect(parseSbomSkill.metadata).toMatchObject({
      name: "parse_sbom",
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

  it("parses CycloneDX component, service, dependency, and identifier observations", () => {
    const output = parseSbom(cyclonedxSbom());

    expect(output.artifact).toEqual({
      id: "artifact_sbom",
      type: "sbom",
      format: "cyclonedx_json",
      spec_version: "1.5",
    });
    expect(output.observed.document_name).toBe("example-app");
    expect(output.observed.serial_number).toBe("urn:uuid:11111111-1111-4111-8111-111111111111");
    expect(output.observed.tool_names).toEqual(["syft"]);
    expect(output.observed.component_count).toBe(3);
    expect(output.observed.package_count).toBe(2);
    expect(output.observed.service_count).toBe(1);
    expect(output.observed.dependency_edge_count).toBe(1);
    expect(output.observed.purl_count).toBe(2);
    expect(output.observed.license_ids).toEqual(["MIT"]);
    expect(output.observed.package_name_version_refs).toEqual(["express@4.18.2", "lodash@unknown"]);
    expect(output.observed.components[0]).toMatchObject({
      name: "express",
      version: "4.18.2",
      supplier: "OpenJS Foundation",
      licenses: ["MIT"],
      dependency_refs: ["pkg:npm/lodash"],
    });
    expect(output.warnings).toEqual([]);
  });

  it("parses SPDX package, relationship, and external reference observations", () => {
    const output = parseSbom(spdxSbom());

    expect(output.artifact.format).toBe("spdx_json");
    expect(output.observed.spec_version).toBe("SPDX-2.3");
    expect(output.observed.document_name).toBe("example-spdx-document");
    expect(output.observed.document_namespace).toBe("https://example.invalid/spdx/example-1");
    expect(output.observed.relationship_count).toBe(1);
    expect(output.observed.dependency_edge_count).toBe(1);
    expect(output.observed.external_reference_count).toBe(2);
    expect(output.observed.purl_count).toBe(1);
    expect(output.observed.cpe_count).toBe(1);
    expect(output.observed.components[0]).toMatchObject({
      id: "SPDXRef-Package-openssl",
      source_format: "spdx_json",
      type: "package",
      name: "openssl",
      version: "3.0.13",
      supplier: "Organization: OpenSSL Software Foundation",
      licenses: ["Apache-2.0"],
      purl: "pkg:generic/openssl@3.0.13",
      dependency_refs: ["SPDXRef-Package-example-lib"],
      relationship_types: ["DEPENDS_ON"],
    });
    expect(output.warnings).toEqual([]);
  });

  it("rejects malformed and unsupported input", () => {
    expect(() => parseSbom("not json")).toThrow("parse_sbom input must be valid JSON");
    expect(() => parseSbom("[]")).toThrow("parse_sbom input must be a JSON object");
    expect(() => parseSbom('{"ok":true}')).toThrow("parse_sbom input must be CycloneDX JSON or SPDX JSON");
  });

  it("warns on malformed SPDX package arrays while preserving object entries", () => {
    const output = parseSbom(JSON.stringify({
      spdxVersion: "SPDX-2.3",
      packages: [
        { SPDXID: "SPDXRef-Package-a", name: "a" },
        "bad",
      ],
    }));

    expect(output.observed.component_count).toBe(1);
    expect(output.warnings).toContain('SPDX field "packages" contains non-object entries that were ignored.');
  });
});
