import { describe, expect, it } from "vitest";
import { jsonFormatSkill } from "../src/jsonFormat.js";
import { jsonParseSkill } from "../src/jsonParse.js";

describe("json_parse", () => {
  it("is categorized as a parser", () => {
    expect(jsonParseSkill.metadata.category).toBe("parser");
  });

  it("parses JSON text", async () => {
    const result = await jsonParseSkill.run('{"x":1,"items":[true,null]}');

    expect(result).toEqual({
      value: {
        x: 1,
        items: [true, null],
      },
    });
  });

  it("rejects non-string input", async () => {
    await expect(
      async () => await jsonParseSkill.run(123 as unknown as string)
    ).rejects.toThrow("json_parse input must be a string");
  });

  it("rejects invalid JSON", async () => {
    await expect(async () => await jsonParseSkill.run("{bad json}")).rejects.toThrow(
      "json_parse input must be valid JSON"
    );
  });
});

describe("json_format", () => {
  it("is categorized as a transform", () => {
    expect(jsonFormatSkill.metadata.category).toBe("transform");
  });

  it("formats JSON text with two-space indentation", async () => {
    const result = await jsonFormatSkill.run('{"x":1,"items":[true,null]}');

    expect(result).toEqual({
      formatted: '{\n  "x": 1,\n  "items": [\n    true,\n    null\n  ]\n}',
    });
  });

  it("rejects non-string input", async () => {
    await expect(
      async () => await jsonFormatSkill.run(123 as unknown as string)
    ).rejects.toThrow("json_format input must be a string");
  });

  it("rejects invalid JSON", async () => {
    await expect(async () => await jsonFormatSkill.run("{bad json}")).rejects.toThrow(
      "json_format input must be valid JSON"
    );
  });
});
