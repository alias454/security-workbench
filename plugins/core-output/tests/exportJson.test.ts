import { describe, expect, it } from "vitest";
import { exportJson, exportJsonSkill, skills } from "../src/index.js";

describe("export_json", () => {
  it("exports the output skill with local-only permissions", () => {
    expect(skills).toContain(exportJsonSkill);
    expect(exportJsonSkill.metadata.name).toBe("export_json");
    expect(exportJsonSkill.metadata.category).toBe("output");
    expect(exportJsonSkill.metadata.execution.network_access).toBe("none");
    expect(exportJsonSkill.metadata.permissions?.network).toBe("none");
    expect(exportJsonSkill.metadata.permissions?.persists).toBe(false);
  });

  it("exports a JSON run result output as pretty JSON", () => {
    const output = exportJson(JSON.stringify({
      output: {
        artifact: { id: "artifact_source", type: "example" },
        ok: true,
      },
    }));

    expect(output.artifact.type).toBe("json_export");
    expect(output.artifact.source_artifact_id).toBe("artifact_source");
    expect(output.observed.source_kind).toBe("skill_run_result");
    expect(output.json).toContain('"ok": true');
    expect(JSON.parse(output.json)).toMatchObject({ ok: true });
  });

  it("exports plain text as a JSON string", () => {
    const output = exportJson("hello");

    expect(output.artifact.source_artifact_type).toBeNull();
    expect(output.json).toBe('"hello"');
  });
});
