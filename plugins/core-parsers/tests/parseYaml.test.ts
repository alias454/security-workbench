import { describe, expect, it } from "vitest";
import { parseYamlSkill } from "../src/parseYaml.js";

async function runYaml(input: string) {
  return await parseYamlSkill.run(input);
}

describe("parse_yaml", () => {
  it("parses a simple mapping into a JSON-compatible value", async () => {
    const output = await runYaml("name: example\nenabled: true\ncount: 2\n");

    expect(output.artifact).toEqual({ id: "artifact_yaml", type: "yaml" });
    expect(output.observed.document_count).toBe(1);
    expect(output.observed.value_type).toBe("object");
    expect(output.observed.keys).toEqual(["name", "enabled", "count"]);
    expect(output.observed.value).toEqual({ name: "example", enabled: true, count: 2 });
    expect(output.observed.documents).toEqual([{ name: "example", enabled: true, count: 2 }]);
    expect(output.observed.document_summaries).toEqual([
      { document_index: 0, value_type: "object", keys: ["name", "enabled", "count"] },
    ]);
    expect(output.warnings).toEqual([]);
  });

  it("parses arrays and nested objects", async () => {
    const output = await runYaml("roles:\n  - security\n  - builder\nnested:\n  owner: brandon\n  enabled: false\n");

    expect(output.observed.value).toEqual({
      roles: ["security", "builder"],
      nested: {
        owner: "brandon",
        enabled: false,
      },
    });
  });

  it("parses null values and top-level arrays", async () => {
    const output = await runYaml("- name: first\n  value: null\n- name: second\n  value: 2\n");

    expect(output.observed.value_type).toBe("array");
    expect(output.observed.keys).toEqual([]);
    expect(output.observed.value).toEqual([
      { name: "first", value: null },
      { name: "second", value: 2 },
    ]);
  });

  it("handles multiple documents explicitly", async () => {
    const output = await runYaml("---\nname: one\n---\nname: two\n");

    expect(output.observed.document_count).toBe(2);
    expect(output.observed.value_type).toBe("multiple");
    expect(output.observed.value).toBeNull();
    expect(output.observed.documents).toEqual([{ name: "one" }, { name: "two" }]);
    expect(output.observed.document_summaries).toEqual([
      { document_index: 0, value_type: "object", keys: ["name"] },
      { document_index: 1, value_type: "object", keys: ["name"] },
    ]);
    expect(output.warnings).toContain(
      "YAML input contained multiple documents; observed.value is null and observed.documents contains parsed documents.",
    );
  });

  it("rejects malformed YAML", () => {
    expect(() => parseYamlSkill.run("name: [unterminated\n")).toThrow("parse_yaml input must be valid YAML");
  });

  it("rejects explicit custom tags", () => {
    expect(() => parseYamlSkill.run("danger: !vault secret\n")).toThrow("parse_yaml custom tags are not supported");
    expect(() => parseYamlSkill.run("danger: !!js/function 'return 1'\n")).toThrow("parse_yaml custom tags are not supported");
  });

  it("allows common standard scalar tags", async () => {
    const output = await runYaml("name: !!str 123\ncount: !!int 2\n");

    expect(output.observed.value).toEqual({ name: "123", count: 2 });
  });

  it("declares local-only permissions and hosted allowlist exposure", () => {
    expect(parseYamlSkill.metadata.category).toBe("parser");
    expect(parseYamlSkill.metadata.execution.mode).toBe("local_only");
    expect(parseYamlSkill.metadata.execution.network_access).toBe("none");
    expect(parseYamlSkill.metadata.permissions).toEqual({
      network: "none",
      filesystem: "none",
      sends: [],
      persists: false,
      runs_external_binaries: false,
    });
    expect(parseYamlSkill.metadata.exposure?.hosted_default).toBe("allowlist_only");
    expect(parseYamlSkill.metadata.exposure?.rationale.length).toBeGreaterThan(0);
  });
});
