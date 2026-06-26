import type { Skill } from "@security-workbench/schemas";

export interface HtmlEntityDecodeOutput {
  decoded: string;
}

const NAMED_ENTITIES: Record<string, string> = {
  amp: "&",
  lt: "<",
  gt: ">",
  quot: '"',
  apos: "'",
  nbsp: "\u00a0",
};

function assertString(input: string): void {
  if (typeof input !== "string") {
    throw new Error("html_entity_decode input must be a string");
  }
}

function decodeNumericEntity(entityBody: string): string | undefined {
  const lower = entityBody.toLowerCase();
  const valueText = lower.startsWith("#x")
    ? entityBody.slice(2)
    : lower.startsWith("#")
      ? entityBody.slice(1)
      : "";

  if (valueText.length === 0) {
    return undefined;
  }

  const radix = lower.startsWith("#x") ? 16 : 10;
  const pattern = radix === 16 ? /^[0-9a-fA-F]+$/ : /^[0-9]+$/;

  if (!pattern.test(valueText)) {
    return undefined;
  }

  const codePoint = Number.parseInt(valueText, radix);

  if (!Number.isSafeInteger(codePoint) || codePoint < 0 || codePoint > 0x10ffff) {
    return undefined;
  }

  // Reject surrogate scalar values in numeric character references.
  if (codePoint >= 0xd800 && codePoint <= 0xdfff) {
    return undefined;
  }

  return String.fromCodePoint(codePoint);
}

function decodeHtmlEntities(input: string): string {
  return input.replace(/&(#x[0-9a-fA-F]+|#[0-9]+|[a-zA-Z][a-zA-Z0-9]+);/g, (match, body: string) => {
    if (body.startsWith("#")) {
      return decodeNumericEntity(body) ?? match;
    }

    return NAMED_ENTITIES[body] ?? match;
  });
}

export const htmlEntityDecodeSkill: Skill<string, HtmlEntityDecodeOutput> = {
  metadata: {
    name: "html_entity_decode",
    version: "0.1.0",
    category: "transform",
    description: "Decode common HTML named and numeric character entities.",
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
      decoded: decodeHtmlEntities(input),
    };
  },
};
