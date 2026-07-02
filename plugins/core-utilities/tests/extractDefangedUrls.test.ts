import { describe, expect, it } from "vitest";
import { extractDefangedUrlsSkill } from "../src/extractDefangedUrls.js";
import { normalizeIndicatorsSkill } from "../src/normalizeIndicators.js";

describe("extract_defanged_urls", () => {
  it("extracts normalized URL candidates from raw defanged text", async () => {
    const result = await extractDefangedUrlsSkill.run(`
See hxxps://evil[.]example/login?u=1#frag
Mirror: hxxp://downloads<dot>example(.)net:8080/file.
`);

    expect(result.artifact).toEqual({
      id: "artifact_defanged_url_extraction",
      type: "defanged_url_extraction",
    });
    expect(result.observed.input_source_type).toBe("raw_text");
    expect(result.urls).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          original_value: "hxxps://evil[.]example/login?u=1#frag",
          normalized_url: "https://evil.example/login?u=1#frag",
          scheme: "https",
          hostname: "evil.example",
          path_present: true,
          query_present: true,
          fragment_present: true,
          transformations: expect.arrayContaining(["hxxps_to_https", "defanged_dot"]),
        }),
        expect.objectContaining({
          normalized_url: "http://downloads.example.net:8080/file",
          scheme: "http",
          hostname: "downloads.example.net",
          port: "8080",
          transformations: expect.arrayContaining(["hxxp_to_http", "defanged_dot"]),
        }),
      ])
    );
  });

  it("deduplicates normalized URL candidates", async () => {
    const result = await extractDefangedUrlsSkill.run(
      "hxxps://same[.]example/path https://same.example/path hxxps://same[dot]example/path"
    );

    expect(result.urls).toHaveLength(1);
    expect(result.urls[0]).toMatchObject({
      normalized_url: "https://same.example/path",
      occurrence_count: 3,
    });
    expect(result.observed.duplicate_count).toBe(2);
  });

  it("accepts normalize_indicators output and preserves source type", async () => {
    const normalized = await normalizeIndicatorsSkill.run("hxxps://evil[.]example/login user<at>evil<dot>example");
    const result = await extractDefangedUrlsSkill.run(JSON.stringify(normalized));

    expect(result.observed.input_source_type).toBe("indicator_normalization");
    expect(result.urls).toEqual([
      expect.objectContaining({
        normalized_url: "https://evil.example/login",
        source: "indicator_normalization",
      }),
    ]);
  });

  it("accepts JSON skill run result output wrappers", async () => {
    const normalized = await normalizeIndicatorsSkill.run("hxxp://wrapped[.]example/a");
    const result = await extractDefangedUrlsSkill.run(JSON.stringify({ output: normalized }));

    expect(result.observed.input_source_type).toBe("indicator_normalization");
    expect(result.urls[0]?.normalized_url).toBe("http://wrapped.example/a");
  });

  it("redacts credential values while tracking credential presence", async () => {
    const result = await extractDefangedUrlsSkill.run("hxxps://user:pass@login[.]example/path");

    expect(result.urls[0]).toMatchObject({
      normalized_url: "https://%5BREDACTED%5D:%5BREDACTED%5D@login.example/path",
      username_present: true,
      password_present: true,
    });
    expect(result.observed.credentialed_url_count).toBe(1);
  });

  it("returns a warning when no URL candidates are observed", async () => {
    const result = await extractDefangedUrlsSkill.run("admin<at>example<dot>com example[.]com");

    expect(result.urls).toEqual([]);
    expect(result.warnings).toContain("No defanged or HTTP/HTTPS URL candidates observed.");
  });

  it("rejects non-string input", async () => {
    await expect(async () => await extractDefangedUrlsSkill.run(123 as unknown as string)).rejects.toThrow(
      "extract_defanged_urls input must be a string"
    );
  });
});
