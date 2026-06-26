import { describe, expect, it } from "vitest";
import { parseCsvSkill } from "../src/parseCsv.js";

async function runCsv(input: string) {
  return await parseCsvSkill.run(input);
}

describe("parse_csv", () => {
  it("returns rows, inferred records, and structural metadata", async () => {
    const output = await runCsv("name,email,active\nAlice,alice@example.com,true\nBob,bob@example.com,false\n");

    expect(output.artifact).toEqual({ id: "artifact_csv", type: "csv" });
    expect(output.observed.delimiter).toBe(",");
    expect(output.observed.quote).toBe('"');
    expect(output.observed.line_ending).toBe("lf");
    expect(output.observed.bom_present).toBe(false);
    expect(output.observed.row_count).toBe(3);
    expect(output.observed.data_row_count).toBe(2);
    expect(output.observed.column_count).toBe(3);
    expect(output.observed.has_header).toBe(true);
    expect(output.observed.header_source).toBe("inferred");
    expect(output.observed.headers).toEqual(["name", "email", "active"]);
    expect(output.observed.rows).toEqual([
      ["name", "email", "active"],
      ["Alice", "alice@example.com", "true"],
      ["Bob", "bob@example.com", "false"],
    ]);
    expect(output.observed.records).toEqual([
      { name: "Alice", email: "alice@example.com", active: "true" },
      { name: "Bob", email: "bob@example.com", active: "false" },
    ]);
    expect(output.observed.irregular_rows).toEqual([]);
    expect(output.warnings).toEqual([]);
  });

  it("handles quoted commas, escaped quotes, and CRLF", async () => {
    const output = await runCsv('name,note\r\nAlice,"hello, world"\r\nBob,"said ""hi"""\r\n');

    expect(output.observed.line_ending).toBe("crlf");
    expect(output.observed.records).toEqual([
      { name: "Alice", note: "hello, world" },
      { name: "Bob", note: 'said "hi"' },
    ]);
  });

  it("strips a UTF-8 BOM and reports that it was present", async () => {
    const output = await runCsv("\ufeffname,email\nAlice,alice@example.com\n");

    expect(output.observed.bom_present).toBe(true);
    expect(output.observed.headers).toEqual(["name", "email"]);
  });

  it("preserves rows and leaves records empty when no header is inferred", async () => {
    const output = await runCsv("1,2\n3,4\n");

    expect(output.observed.has_header).toBe(false);
    expect(output.observed.header_source).toBe("none");
    expect(output.observed.headers).toEqual([]);
    expect(output.observed.rows).toEqual([
      ["1", "2"],
      ["3", "4"],
    ]);
    expect(output.observed.records).toEqual([]);
    expect(output.warnings).toContain("CSV header row was not inferred; records view is empty and rows view should be used.");
  });

  it("warns on irregular row widths while preserving shape", async () => {
    const output = await runCsv("name,email\nAlice,alice@example.com,extra\nBob\n");

    expect(output.observed.has_header).toBe(true);
    expect(output.observed.irregular_rows).toEqual([
      { row_index: 1, expected_columns: 2, actual_columns: 3 },
      { row_index: 2, expected_columns: 2, actual_columns: 1 },
    ]);
    expect(output.warnings).toContain("CSV contains rows with inconsistent column counts.");
  });

  it("preserves values as strings and does not evaluate spreadsheet formulas", async () => {
    const output = await runCsv("name,value\nformula,=1+1\nnumber,42\nboolean,true\n");

    expect(output.observed.records).toEqual([
      { name: "formula", value: "=1+1" },
      { name: "number", value: "42" },
      { name: "boolean", value: "true" },
    ]);
  });

  it("rejects malformed quoted fields", async () => {
    expect(() => parseCsvSkill.run('name,note\nAlice,"unterminated\n')).toThrow("parse_csv input ended inside a quoted field");
    expect(() => parseCsvSkill.run('name,note\nAlice,"ok"bad\n')).toThrow("parse_csv encountered unexpected content after closing quote");
    expect(() => parseCsvSkill.run('name,note\nAl"ice,test\n')).toThrow("parse_csv quotes may only start at the beginning of a cell");
  });

  it("declares local-only permissions and hosted allowlist exposure", () => {
    expect(parseCsvSkill.metadata.category).toBe("parser");
    expect(parseCsvSkill.metadata.execution.mode).toBe("local_only");
    expect(parseCsvSkill.metadata.execution.network_access).toBe("none");
    expect(parseCsvSkill.metadata.permissions).toEqual({
      network: "none",
      filesystem: "none",
      sends: [],
      persists: false,
      runs_external_binaries: false,
    });
    expect(parseCsvSkill.metadata.exposure?.hosted_default).toBe("allowlist_only");
  });
});
