import type { Skill } from "@security-workbench/schemas";
import { localOnlyPermissions } from "./localOnlyPermissions.js";

export type CsvLineEnding = "lf" | "crlf" | "mixed" | "none";

export interface ParseCsvIrregularRow {
  row_index: number;
  expected_columns: number;
  actual_columns: number;
}

export interface ParseCsvOutput {
  artifact: {
    id: "artifact_csv";
    type: "csv";
  };
  observed: {
    delimiter: ",";
    quote: "\"";
    line_ending: CsvLineEnding;
    bom_present: boolean;
    row_count: number;
    data_row_count: number;
    column_count: number | null;
    has_header: boolean;
    header_source: "inferred" | "none";
    headers: string[];
    rows: string[][];
    records: Array<Record<string, string>>;
    irregular_rows: ParseCsvIrregularRow[];
  };
  warnings: string[];
}

interface ParsedCsv {
  rows: string[][];
  lineEnding: CsvLineEnding;
  bomPresent: boolean;
}

const MAX_ROWS_RETURNED = 1_000;
const MAX_RECORDS_RETURNED = 1_000;
const MAX_COLUMNS = 500;
const MAX_CELL_CHARS = 100_000;

function normalizeInput(input: string): { text: string; bomPresent: boolean } {
  if (typeof input !== "string") {
    throw new Error("parse_csv input must be a string");
  }

  if (input.length === 0) {
    throw new Error("parse_csv input must not be empty");
  }

  const bomPresent = input.charCodeAt(0) === 0xfeff;
  return {
    text: bomPresent ? input.slice(1) : input,
    bomPresent,
  };
}

function detectLineEnding(text: string): CsvLineEnding {
  const crlfCount = (text.match(/\r\n/g) ?? []).length;
  const withoutCrLf = text.replace(/\r\n/g, "");
  const lfCount = (withoutCrLf.match(/\n/g) ?? []).length;
  const crCount = (withoutCrLf.match(/\r/g) ?? []).length;

  if (crlfCount === 0 && lfCount === 0 && crCount === 0) {
    return "none";
  }

  if (crlfCount > 0 && lfCount === 0 && crCount === 0) {
    return "crlf";
  }

  if (crlfCount === 0 && lfCount > 0 && crCount === 0) {
    return "lf";
  }

  return "mixed";
}

function parseCsvText(input: string): ParsedCsv {
  const { text, bomPresent } = normalizeInput(input);
  const lineEnding = detectLineEnding(text);
  const rows: string[][] = [];
  let row: string[] = [];
  let cell = "";
  let inQuotes = false;
  let justClosedQuote = false;
  let sawAnyCharacter = false;

  const pushCell = () => {
    row.push(cell);
    if (row.length > MAX_COLUMNS) {
      throw new Error(`parse_csv supports at most ${MAX_COLUMNS} columns`);
    }
    cell = "";
    justClosedQuote = false;
  };

  const pushRow = () => {
    pushCell();
    rows.push(row);
    row = [];
  };

  for (let index = 0; index < text.length; index += 1) {
    const char = text[index];
    sawAnyCharacter = true;

    if (cell.length > MAX_CELL_CHARS) {
      throw new Error(`parse_csv cell exceeds ${MAX_CELL_CHARS} characters`);
    }

    if (inQuotes) {
      if (char === "\"") {
        const next = text[index + 1];
        if (next === "\"") {
          cell += "\"";
          index += 1;
        } else {
          inQuotes = false;
          justClosedQuote = true;
        }
      } else {
        cell += char;
      }
      continue;
    }

    if (justClosedQuote) {
      if (char === ",") {
        pushCell();
        continue;
      }

      if (char === "\r") {
        if (text[index + 1] === "\n") {
          index += 1;
        }
        pushRow();
        continue;
      }

      if (char === "\n") {
        pushRow();
        continue;
      }

      throw new Error("parse_csv encountered unexpected content after closing quote");
    }

    if (char === "\"") {
      if (cell.length !== 0) {
        throw new Error("parse_csv quotes may only start at the beginning of a cell");
      }
      inQuotes = true;
      continue;
    }

    if (char === ",") {
      pushCell();
      continue;
    }

    if (char === "\r") {
      if (text[index + 1] === "\n") {
        index += 1;
      }
      pushRow();
      continue;
    }

    if (char === "\n") {
      pushRow();
      continue;
    }

    cell += char;
  }

  if (inQuotes) {
    throw new Error("parse_csv input ended inside a quoted field");
  }

  if (justClosedQuote || cell.length > 0 || row.length > 0 || !sawAnyCharacter) {
    pushRow();
  }

  // Drop a final empty row caused by a trailing newline. Internal empty rows are preserved.
  if (rows.length > 0) {
    const last = rows[rows.length - 1];
    if (last.length === 1 && last[0] === "" && /(?:\r\n|\n|\r)$/.test(text)) {
      rows.pop();
    }
  }

  return { rows, lineEnding, bomPresent };
}

function hasDuplicate(values: string[]): boolean {
  const seen = new Set<string>();
  for (const value of values) {
    if (seen.has(value)) {
      return true;
    }
    seen.add(value);
  }
  return false;
}

function looksLikeHeader(row: string[], dataRows: string[][]): boolean {
  if (row.length === 0) {
    return false;
  }

  if (row.some((cell) => cell.trim().length === 0)) {
    return false;
  }

  if (hasDuplicate(row)) {
    return false;
  }

  const headerishCells = row.filter((cell) => /^[A-Za-z_][A-Za-z0-9_ .:/-]*$/.test(cell));
  if (headerishCells.length !== row.length) {
    return false;
  }

  if (dataRows.length === 0) {
    return true;
  }

  const comparableRows = dataRows.slice(0, 10).filter((dataRow) => dataRow.length === row.length);
  if (comparableRows.length === 0) {
    return true;
  }

  const dataHasDifferentShape = comparableRows.some((dataRow) =>
    dataRow.some((cell, index) => {
      const header = row[index];
      if (cell === header) {
        return false;
      }
      return /^[-+]?\d+(?:\.\d+)?$/.test(cell) || cell.includes("@") || cell.includes("://") || cell.length !== header.length;
    }),
  );

  return dataHasDifferentShape;
}

function computeIrregularRows(rows: string[][], expectedColumns: number | null): ParseCsvIrregularRow[] {
  if (expectedColumns === null) {
    return [];
  }

  return rows.flatMap((row, index) => {
    if (row.length === expectedColumns) {
      return [];
    }

    return [
      {
        row_index: index,
        expected_columns: expectedColumns,
        actual_columns: row.length,
      },
    ];
  });
}

function createRecords(headers: string[], dataRows: string[][]): Array<Record<string, string>> {
  return dataRows.slice(0, MAX_RECORDS_RETURNED).map((row) => {
    const record: Record<string, string> = {};
    for (const [index, header] of headers.entries()) {
      record[header] = row[index] ?? "";
    }
    return record;
  });
}

function parseCsv(input: string): ParseCsvOutput {
  const { rows, lineEnding, bomPresent } = parseCsvText(input);
  const warnings: string[] = [];

  if (rows.length === 0) {
    throw new Error("parse_csv input did not contain any rows");
  }

  const firstRow = rows[0] ?? [];
  const expectedColumns = firstRow.length > 0 ? firstRow.length : null;
  const irregularRows = computeIrregularRows(rows, expectedColumns);
  const hasHeader = looksLikeHeader(firstRow, rows.slice(1));
  const headers = hasHeader ? firstRow : [];
  const dataRows = hasHeader ? rows.slice(1) : rows;
  const records = hasHeader ? createRecords(headers, dataRows) : [];
  const returnedRows = rows.slice(0, MAX_ROWS_RETURNED);

  if (irregularRows.length > 0) {
    warnings.push("CSV contains rows with inconsistent column counts.");
  }

  if (!hasHeader) {
    warnings.push("CSV header row was not inferred; records view is empty and rows view should be used.");
  }

  if (rows.length > MAX_ROWS_RETURNED) {
    warnings.push(`CSV row output was truncated to ${MAX_ROWS_RETURNED} rows.`);
  }

  if (hasHeader && dataRows.length > MAX_RECORDS_RETURNED) {
    warnings.push(`CSV records output was truncated to ${MAX_RECORDS_RETURNED} records.`);
  }

  if (lineEnding === "mixed") {
    warnings.push("CSV contains mixed line endings.");
  }

  return {
    artifact: {
      id: "artifact_csv",
      type: "csv",
    },
    observed: {
      delimiter: ",",
      quote: "\"",
      line_ending: lineEnding,
      bom_present: bomPresent,
      row_count: rows.length,
      data_row_count: dataRows.length,
      column_count: expectedColumns,
      has_header: hasHeader,
      header_source: hasHeader ? "inferred" : "none",
      headers,
      rows: returnedRows,
      records,
      irregular_rows: irregularRows,
    },
    warnings,
  };
}

export const parseCsvSkill: Skill<string, ParseCsvOutput> = {
  metadata: {
    name: "parse_csv",
    version: "0.1.0",
    category: "parser",
    description: "Parse CSV text into table rows, inferred records, and structural metadata without type coercion or formula evaluation.",
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
      max_input_mb: 1,
      risk: "low",
      rationale: [
        "CSV parsing is local-only and does not interpret spreadsheet formulas, retrieve remote content, persist input, or invoke OS commands.",
        "Hosted exposure remains allowlist-only because CSV inputs may contain sensitive tabular data and should be gated before API, web, or MCP exposure.",
      ],
    },
  },
  run(input: string): ParseCsvOutput {
    return parseCsv(input);
  },
};
