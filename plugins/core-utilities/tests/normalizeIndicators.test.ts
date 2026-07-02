import { describe, expect, it } from "vitest";
import { normalizeIndicatorsSkill } from "../src/normalizeIndicators.js";

describe("normalize_indicators", () => {
  it("normalizes mixed defanged candidate indicators without IOC verdicts", async () => {
    const result = await normalizeIndicatorsSkill.run(`
hxxps://evil[.]example/login
evil[.]example
192[.]0[.]2[.]44
user<at>evil<dot>example
SHA256: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
`);

    expect(result.artifact).toEqual({
      id: "artifact_indicator_normalization",
      type: "indicator_normalization",
    });
    expect(result.indicators).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          normalized_value: "https://evil.example/login",
          indicator_type: "url",
          transformations: expect.arrayContaining(["hxxps_to_https", "defanged_dot"]),
        }),
        expect.objectContaining({
          normalized_value: "evil.example",
          indicator_type: "domain",
          transformations: ["defanged_dot"],
        }),
        expect.objectContaining({
          normalized_value: "192.0.2.44",
          indicator_type: "ipv4",
          transformations: ["defanged_dot"],
        }),
        expect.objectContaining({
          normalized_value: "user@evil.example",
          indicator_type: "email_address",
          transformations: expect.arrayContaining(["defanged_at", "defanged_dot"]),
        }),
        expect.objectContaining({
          normalized_value: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
          indicator_type: "sha256",
        }),
      ])
    );
    expect(result.limitations.join(" ")).toContain("does not confirm IOC status");
  });

  it("handles angle and word email defanging forms", async () => {
    const result = await normalizeIndicatorsSkill.run(
      "support<at>paypa1<dot>example billing at secure-payments dot example"
    );

    expect(result.indicators).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          normalized_value: "support@paypa1.example",
          indicator_type: "email_address",
          transformations: expect.arrayContaining(["defanged_at", "defanged_dot"]),
        }),
        expect.objectContaining({
          normalized_value: "billing@secure-payments.example",
          indicator_type: "email_address",
          transformations: expect.arrayContaining(["word_at", "word_dot"]),
        }),
      ])
    );
  });

  it("deduplicates normalized candidates while preserving occurrence counts", async () => {
    const result = await normalizeIndicatorsSkill.run(
      "foo[.]bar foo.bar hxxp://foo[.]bar/path hxxp://foo.bar/path"
    );

    const domain = result.indicators.find(
      (indicator) => indicator.indicator_type === "domain" && indicator.normalized_value === "foo.bar"
    );
    const url = result.indicators.find(
      (indicator) => indicator.indicator_type === "url" && indicator.normalized_value === "http://foo.bar/path"
    );

    expect(domain?.occurrence_count).toBeGreaterThanOrEqual(2);
    expect(url?.occurrence_count).toBe(2);
    expect(result.observed.duplicate_count).toBeGreaterThanOrEqual(2);
  });

  it("normalizes host and port candidates", async () => {
    const result = await normalizeIndicatorsSkill.run("C2 bad-domain[.]test:8443 and 192[.]0[.]2[.]44:443");

    expect(result.indicators).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ normalized_value: "bad-domain.test:8443", indicator_type: "host_port" }),
        expect.objectContaining({ normalized_value: "192.0.2.44:443", indicator_type: "ipv4_port" }),
      ])
    );
  });

  it("rejects non-string input", async () => {
    await expect(async () => await normalizeIndicatorsSkill.run(123 as unknown as string)).rejects.toThrow(
      "normalize_indicators input must be a string"
    );
  });
});
