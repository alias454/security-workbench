import { describe, expect, it } from "vitest";
import { htmlEntityDecodeSkill } from "../src/htmlEntityDecode.js";

describe("html_entity_decode", () => {
  it("decodes common named HTML entities", async () => {
    const result = await htmlEntityDecodeSkill.run("Tom &amp; Jerry &lt;tag&gt; &quot;x&quot; &apos;y&apos;");

    expect(result).toEqual({
      decoded: "Tom & Jerry <tag> \"x\" 'y'",
    });
  });

  it("decodes decimal and hexadecimal numeric entities", async () => {
    const result = await htmlEntityDecodeSkill.run("&#65;&#x41;&#x1F600;");

    expect(result).toEqual({
      decoded: "AA😀",
    });
  });

  it("preserves unknown and invalid entities", async () => {
    const result = await htmlEntityDecodeSkill.run("&unknown; &#xD800; &notclosed");

    expect(result).toEqual({
      decoded: "&unknown; &#xD800; &notclosed",
    });
  });

  it("rejects non-string input", async () => {
    await expect(
      async () => await htmlEntityDecodeSkill.run(123 as unknown as string)
    ).rejects.toThrow("html_entity_decode input must be a string");
  });
});
