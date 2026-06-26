import type { Skill } from "@security-workbench/schemas";

interface LineSplit {
  lines: string[];
  trailing_newline: boolean;
}

interface TextLineOutput {
  text: string;
  original_line_count: number;
}

export interface TrimLinesOutput extends TextLineOutput {
  changed_line_count: number;
}

export interface RemoveEmptyLinesOutput extends TextLineOutput {
  kept_line_count: number;
  removed_line_count: number;
  removes_whitespace_only_lines: true;
}

export interface DedupeLinesOutput extends TextLineOutput {
  unique_line_count: number;
  removed_line_count: number;
  case_sensitive: true;
}

export interface SortLinesOutput extends TextLineOutput {
  sorted_line_count: number;
  order: "ascending";
  case_sensitive: true;
}

export interface CountLinesOutput {
  line_count: number;
  non_empty_line_count: number;
  empty_line_count: number;
  trailing_newline: boolean;
}

function assertString(input: string, skillName: string): void {
  if (typeof input !== "string") {
    throw new Error(`${skillName} input must be a string`);
  }
}

function splitLines(input: string): LineSplit {
  if (input.length === 0) {
    return { lines: [], trailing_newline: false };
  }

  const normalized = input.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
  const trailing_newline = normalized.endsWith("\n");
  const lines = normalized.split("\n");

  if (trailing_newline) {
    lines.pop();
  }

  return { lines, trailing_newline };
}

function joinLines(lines: string[], trailingNewline: boolean): string {
  if (lines.length === 0) {
    return "";
  }

  return `${lines.join("\n")}${trailingNewline ? "\n" : ""}`;
}

function commonPermissions() {
  return {
    network: "none" as const,
    filesystem: "none" as const,
    sends: [],
    persists: false,
    runs_external_binaries: false,
  };
}

export const trimLinesSkill: Skill<string, TrimLinesOutput> = {
  metadata: {
    name: "trim_lines",
    version: "0.1.0",
    category: "transform",
    description: "Trim leading and trailing whitespace from each line.",
    execution: {
      mode: "local_only",
      network_access: "none",
      deterministic: true,
    },
    permissions: commonPermissions(),
  },

  run(input: string) {
    assertString(input, "trim_lines");

    const { lines, trailing_newline } = splitLines(input);
    const trimmedLines = lines.map((line) => line.trim());
    const changed_line_count = lines.filter(
      (line, index) => line !== trimmedLines[index]
    ).length;

    return {
      text: joinLines(trimmedLines, trailing_newline),
      original_line_count: lines.length,
      changed_line_count,
    };
  },
};

export const removeEmptyLinesSkill: Skill<string, RemoveEmptyLinesOutput> = {
  metadata: {
    name: "remove_empty_lines",
    version: "0.1.0",
    category: "transform",
    description: "Remove empty and whitespace-only lines from multiline text.",
    execution: {
      mode: "local_only",
      network_access: "none",
      deterministic: true,
    },
    permissions: commonPermissions(),
  },

  run(input: string) {
    assertString(input, "remove_empty_lines");

    const { lines, trailing_newline } = splitLines(input);
    const keptLines = lines.filter((line) => line.trim().length > 0);

    return {
      text: joinLines(keptLines, trailing_newline && keptLines.length > 0),
      original_line_count: lines.length,
      kept_line_count: keptLines.length,
      removed_line_count: lines.length - keptLines.length,
      removes_whitespace_only_lines: true,
    };
  },
};

export const dedupeLinesSkill: Skill<string, DedupeLinesOutput> = {
  metadata: {
    name: "dedupe_lines",
    version: "0.1.0",
    category: "transform",
    description: "Remove duplicate lines while preserving first-seen order.",
    execution: {
      mode: "local_only",
      network_access: "none",
      deterministic: true,
    },
    permissions: commonPermissions(),
  },

  run(input: string) {
    assertString(input, "dedupe_lines");

    const { lines, trailing_newline } = splitLines(input);
    const seen = new Set<string>();
    const uniqueLines: string[] = [];

    for (const line of lines) {
      if (seen.has(line)) {
        continue;
      }

      seen.add(line);
      uniqueLines.push(line);
    }

    return {
      text: joinLines(uniqueLines, trailing_newline && uniqueLines.length > 0),
      original_line_count: lines.length,
      unique_line_count: uniqueLines.length,
      removed_line_count: lines.length - uniqueLines.length,
      case_sensitive: true,
    };
  },
};

export const sortLinesSkill: Skill<string, SortLinesOutput> = {
  metadata: {
    name: "sort_lines",
    version: "0.1.0",
    category: "transform",
    description: "Sort lines in deterministic ascending code-unit order.",
    execution: {
      mode: "local_only",
      network_access: "none",
      deterministic: true,
    },
    permissions: commonPermissions(),
  },

  run(input: string) {
    assertString(input, "sort_lines");

    const { lines, trailing_newline } = splitLines(input);
    const sortedLines = [...lines].sort((a, b) => {
      if (a === b) {
        return 0;
      }

      return a < b ? -1 : 1;
    });

    return {
      text: joinLines(sortedLines, trailing_newline && sortedLines.length > 0),
      original_line_count: lines.length,
      sorted_line_count: sortedLines.length,
      order: "ascending",
      case_sensitive: true,
    };
  },
};

export const countLinesSkill: Skill<string, CountLinesOutput> = {
  metadata: {
    name: "count_lines",
    version: "0.1.0",
    category: "transform",
    description: "Count total, empty, and non-empty logical lines.",
    execution: {
      mode: "local_only",
      network_access: "none",
      deterministic: true,
    },
    permissions: commonPermissions(),
  },

  run(input: string) {
    assertString(input, "count_lines");

    const { lines, trailing_newline } = splitLines(input);
    const non_empty_line_count = lines.filter((line) => line.trim().length > 0).length;

    return {
      line_count: lines.length,
      non_empty_line_count,
      empty_line_count: lines.length - non_empty_line_count,
      trailing_newline,
    };
  },
};
