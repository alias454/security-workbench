import { describe, expect, it } from "vitest";
import { workflows } from "../src/workflows.js";

describe("registered workflows", () => {
  it("registers review workflows for unambiguous parser-to-reviewer chains", () => {
    const byName = new Map(workflows.map((workflow) => [workflow.name, workflow]));

    expect([...byName.keys()]).toContain("certificate_review");
    expect([...byName.keys()]).toContain("jwt_review");
    expect([...byName.keys()]).toContain("sbom_review");
    expect([...byName.keys()]).toContain("package_manifest_review");
    expect([...byName.keys()]).toContain("lockfile_review");

    expect(byName.get("certificate_review")?.steps).toEqual([
      { id: "parse", skill: "parse_pem_certificate" },
      { id: "review", skill: "review_certificate", input_from: "parse" },
    ]);
    expect(byName.get("jwt_review")?.steps).toEqual([
      { id: "parse", skill: "parse_jwt" },
      { id: "review", skill: "review_jwt", input_from: "parse" },
    ]);
    expect(byName.get("sbom_review")?.steps).toEqual([
      { id: "parse", skill: "parse_sbom" },
      { id: "review", skill: "review_sbom", input_from: "parse" },
    ]);
    expect(byName.get("package_manifest_review")?.steps).toEqual([
      { id: "parse", skill: "parse_package_json" },
      { id: "review", skill: "review_package", input_from: "parse" },
    ]);
    expect(byName.get("lockfile_review")?.steps).toEqual([
      { id: "parse", skill: "parse_lockfiles" },
      { id: "review", skill: "review_package", input_from: "parse" },
    ]);
  });
});
