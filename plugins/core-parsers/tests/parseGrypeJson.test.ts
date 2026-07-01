import { describe, expect, it } from "vitest";
import { parseGrypeJson, parseGrypeJsonSkill } from "../src/parseGrypeJson.js";
import { skills } from "../src/index.js";

function sampleGrypeJson(): string {
  return JSON.stringify({
    schema: "https://anchore.com/syft/grype/schema/json/schema-1.2.0.json",
    descriptor: { name: "grype", version: "0.79.0" },
    source: { type: "image", target: "example/app:latest" },
    distro: { name: "alpine", version: "3.19" },
    matches: [
      {
        vulnerability: {
          id: "CVE-2024-0001",
          namespace: "alpine:distro:alpine:3.19",
          severity: "High",
          dataSource: "https://secdb.alpinelinux.org/",
          urls: ["https://security.example/CVE-2024-0001"],
          fix: { versions: ["1.2.4-r0"], state: "fixed" },
          cvss: [{ version: "3.1" }],
        },
        artifact: {
          id: "pkg-1",
          name: "openssl",
          version: "1.2.3-r0",
          type: "apk",
          language: "c",
          purl: "pkg:apk/alpine/openssl@1.2.3-r0",
          cpes: ["cpe:2.3:a:openssl:openssl:1.2.3:*:*:*:*:*:*:*"],
          locations: [{ path: "/lib/apk/db/installed" }],
          metadata: { type: "ApkMetadata", originPackage: "openssl" },
        },
        matchDetails: [
          {
            type: "exact-direct-match",
            matcher: "apk-matcher",
            searchedBy: { namespace: "alpine:distro:alpine:3.19", package: { name: "openssl", version: "1.2.3-r0" } },
            found: { versionConstraint: "< 1.2.4-r0" },
          },
        ],
      },
    ],
  });
}

describe("parse_grype_json", () => {
  it("exports the parser skill with local-only permissions", () => {
    expect(skills.map((skill) => skill.metadata.name)).toContain("parse_grype_json");
    expect(parseGrypeJsonSkill.metadata).toMatchObject({
      name: "parse_grype_json",
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

  it("parses Grype matches, vulnerabilities, packages, source, distro, and matcher details", async () => {
    const output = parseGrypeJson(sampleGrypeJson());

    expect(output.artifact).toEqual({
      id: "artifact_grype_json",
      type: "grype_json",
      schema_version: "https://anchore.com/syft/grype/schema/json/schema-1.2.0.json",
    });
    expect(output.observed.descriptor_name).toBe("grype");
    expect(output.observed.descriptor_version).toBe("0.79.0");
    expect(output.observed.source_type).toBe("image");
    expect(output.observed.source_target).toBe("example/app:latest");
    expect(output.observed.distro_name).toBe("alpine");
    expect(output.observed.match_count).toBe(1);
    expect(output.observed.vulnerability_ids).toEqual(["CVE-2024-0001"]);
    expect(output.observed.namespaces).toEqual(["alpine:distro:alpine:3.19"]);
    expect(output.observed.severities).toEqual({ High: 1 });
    expect(output.observed.fix_states).toEqual(["fixed"]);
    expect(output.observed.fixed_version_count).toBe(1);
    expect(output.observed.package_names).toEqual(["openssl"]);
    expect(output.observed.package_types).toEqual(["apk"]);
    expect(output.observed.location_paths).toEqual(["/lib/apk/db/installed"]);
    expect(output.observed.matcher_names).toEqual(["apk-matcher"]);
    expect(output.observed.match_types).toEqual(["exact-direct-match"]);
    expect(output.observed.matches[0]).toMatchObject({
      match_detail_count: 1,
      vulnerability: {
        id: "CVE-2024-0001",
        severity: "High",
        fix_state: "fixed",
        fixed_versions: ["1.2.4-r0"],
        cvss_count: 1,
      },
      artifact: {
        name: "openssl",
        version: "1.2.3-r0",
        type: "apk",
        metadata_type: "ApkMetadata",
      },
    });
    expect(output.warnings).toEqual([]);
  });

  it("rejects malformed and unsupported input", () => {
    expect(() => parseGrypeJson("not json")).toThrow("parse_grype_json input must be valid JSON");
    expect(() => parseGrypeJson("[]")).toThrow("parse_grype_json input must be a JSON object");
    expect(() => parseGrypeJson('{"descriptor":{"name":"grype"}}')).toThrow('parse_grype_json input must contain a "matches" array');
  });

  it("warns on malformed match entries while preserving object entries", () => {
    const output = parseGrypeJson(JSON.stringify({
      matches: [
        { vulnerability: { id: "CVE-1", severity: "Low" }, artifact: { name: "pkg" }, custom: true },
        "bad",
      ],
    }));

    expect(output.observed.match_count).toBe(1);
    expect(output.observed.unknown_match_keys).toEqual(["custom"]);
    expect(output.warnings).toContain('Grype field "matches" contains non-object entries that were ignored.');
  });
});
