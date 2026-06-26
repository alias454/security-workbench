import type { Skill } from "@security-workbench/schemas";

export interface UnicodeEscapeDecodeOutput {
  decoded: string;
}

function assertString(input: string): void {
  if (typeof input !== "string") {
    throw new Error("unicode_escape_decode input must be a string");
  }
}

function isHex(value: string): boolean {
  return /^[0-9a-fA-F]+$/.test(value);
}

function codePointFromHex(value: string): string {
  if (value.length === 0 || !isHex(value)) {
    throw new Error("unicode_escape_decode invalid Unicode escape");
  }

  const codePoint = Number.parseInt(value, 16);

  if (!Number.isSafeInteger(codePoint) || codePoint < 0 || codePoint > 0x10ffff) {
    throw new Error("unicode_escape_decode invalid Unicode escape");
  }

  return String.fromCodePoint(codePoint);
}

function decodeUnicodeEscapes(input: string): string {
  let output = "";

  for (let i = 0; i < input.length; i += 1) {
    const char = input[i];

    if (char !== "\\") {
      output += char;
      continue;
    }

    if (i + 1 >= input.length) {
      output += char;
      continue;
    }

    const next = input[i + 1];

    switch (next) {
      case "n":
        output += "\n";
        i += 1;
        break;
      case "r":
        output += "\r";
        i += 1;
        break;
      case "t":
        output += "\t";
        i += 1;
        break;
      case "b":
        output += "\b";
        i += 1;
        break;
      case "f":
        output += "\f";
        i += 1;
        break;
      case "v":
        output += "\v";
        i += 1;
        break;
      case "0":
        output += "\0";
        i += 1;
        break;
      case "\\":
        output += "\\";
        i += 1;
        break;
      case '"':
        output += '"';
        i += 1;
        break;
      case "'":
        output += "'";
        i += 1;
        break;
      case "x": {
        const value = input.slice(i + 2, i + 4);
        if (value.length !== 2 || !isHex(value)) {
          throw new Error("unicode_escape_decode invalid hex escape");
        }
        output += String.fromCharCode(Number.parseInt(value, 16));
        i += 3;
        break;
      }
      case "u": {
        if (input[i + 2] === "{") {
          const end = input.indexOf("}", i + 3);
          if (end === -1) {
            throw new Error("unicode_escape_decode invalid Unicode escape");
          }

          const value = input.slice(i + 3, end);
          output += codePointFromHex(value);
          i = end;
          break;
        }

        const value = input.slice(i + 2, i + 6);
        if (value.length !== 4 || !isHex(value)) {
          throw new Error("unicode_escape_decode invalid Unicode escape");
        }

        output += String.fromCharCode(Number.parseInt(value, 16));
        i += 5;
        break;
      }
      default:
        // Unknown backslash escapes are preserved to avoid changing unrelated text.
        output += char + next;
        i += 1;
        break;
    }
  }

  return output;
}

export const unicodeEscapeDecodeSkill: Skill<string, UnicodeEscapeDecodeOutput> = {
  metadata: {
    name: "unicode_escape_decode",
    version: "0.1.0",
    category: "transform",
    description: "Decode common JavaScript-style Unicode and character escapes without eval.",
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
  },

  run(input: string) {
    assertString(input);

    return {
      decoded: decodeUnicodeEscapes(input),
    };
  },
};
