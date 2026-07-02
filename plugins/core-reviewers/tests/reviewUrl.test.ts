import { describe, expect, it } from "vitest";
import { reviewUrl, reviewUrlSkill } from "../src/reviewUrl.js";
import { skills } from "../src/index.js";

const extractedUrls = {
  artifact: {
    id: "artifact_defanged_url_extraction",
    type: "defanged_url_extraction",
  },
  observed: {
    input_source_type: "raw_text",
    candidate_count: 4,
    url_count: 4,
    duplicate_count: 0,
    credentialed_url_count: 1,
    transformation_counts: {
      hxxp_to_http: 1,
      hxxps_to_https: 3,
      defanged_dot: 4,
    },
  },
  urls: [
    {
      original_value: "hxxp://192[.]0[.]2[.]10:8080/drop.exe?next=hxxps://example[.]org#frag",
      normalized_url: "http://192.0.2.10:8080/drop.exe?next=https://example.org#frag",
      scheme: "http",
      hostname: "192.0.2.10",
      port: "8080",
      path_present: true,
      query_present: true,
      fragment_present: true,
      username_present: false,
      password_present: false,
      transformations: ["hxxp_to_http", "defanged_dot"],
      source: "raw_text",
      first_seen_line: 2,
      occurrence_count: 1,
    },
    {
      original_value: "hxxps://user:pass@login[.]example/path",
      normalized_url: "https://%5BREDACTED%5D:%5BREDACTED%5D@login.example/path",
      scheme: "https",
      hostname: "login.example",
      port: null,
      path_present: true,
      query_present: false,
      fragment_present: false,
      username_present: true,
      password_present: true,
      transformations: ["hxxps_to_https", "defanged_dot"],
      source: "raw_text",
      first_seen_line: 3,
      occurrence_count: 1,
    },
    {
      original_value: "hxxps://xn--pple-43d[.]example/login",
      normalized_url: "https://xn--pple-43d.example/login",
      scheme: "https",
      hostname: "xn--pple-43d.example",
      port: null,
      path_present: true,
      query_present: false,
      fragment_present: false,
      username_present: false,
      password_present: false,
      transformations: ["hxxps_to_https", "defanged_dot"],
      source: "raw_text",
      first_seen_line: 4,
      occurrence_count: 1,
    },
    {
      original_value: "hxxps://a.b.c.d.e.example/path",
      normalized_url: "https://a.b.c.d.e.example/path",
      scheme: "https",
      hostname: "a.b.c.d.e.example",
      port: null,
      path_present: true,
      query_present: false,
      fragment_present: false,
      username_present: false,
      password_present: false,
      transformations: ["hxxps_to_https"],
      source: "indicator_normalization",
      first_seen_line: 5,
      occurrence_count: 1,
    },
  ],
  limitations: [],
  warnings: [],
} as const;

describe("review_url", () => {
  it("exports the reviewer skill with local-only permissions", () => {
    expect(skills.map((skill) => skill.metadata.name)).toContain("review_url");
    expect(reviewUrlSkill.metadata).toMatchObject({
      name: "review_url",
      category: "reviewer",
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
    });
  });

  it("emits evidence-backed URL structure signals", () => {
    const output = reviewUrl(extractedUrls);

    expect(output.artifact).toMatchObject({
      id: "artifact_url_review",
      type: "url_review",
      source_artifact_id: "artifact_defanged_url_extraction",
      source_artifact_type: "defanged_url_extraction",
    });
    expect(output.observed.source_parser).toBe("extract_defanged_urls");
    expect(output.observed.reviewed_url_count).toBe(4);
    expect(output.observed.plain_http_count).toBe(1);
    expect(output.observed.userinfo_url_count).toBe(1);
    expect(output.observed.ip_literal_host_count).toBe(1);
    expect(output.observed.non_default_port_count).toBe(1);
    expect(output.observed.punycode_host_count).toBe(1);
    expect(output.observed.many_subdomains_count).toBe(1);
    expect(output.observed.redirect_parameter_url_count).toBe(1);
    expect(output.observed.suspicious_file_extension_count).toBe(1);
    expect(output.signals.map((signal) => signal.type)).toEqual([
      "url.plain_http_observed",
      "url.ip_literal_host_observed",
      "url.non_default_port_observed",
      "url.query_parameters_observed",
      "url.fragment_observed",
      "url.redirect_parameter_name_observed",
      "url.suspicious_file_extension_observed",
      "url.userinfo_observed",
      "url.punycode_host_observed",
      "url.many_subdomains_observed",
    ]);
    expect(output.signals.every((signal) => signal.evidence_refs.length > 0)).toBe(true);
    expect(output.observed.urls[0]).toMatchObject({
      normalized_url: "http://192.0.2.10:8080/drop.exe?next=https://example.org#frag",
      query_parameter_count: 1,
      redirect_parameter_names: ["next"],
      file_extension: "exe",
    });
    expect(output.observed.limitations).toContain(
      "Does not perform DNS lookup, URL fetching, redirect following, reputation checks, browser rendering, or content inspection.",
    );
  });

  it("accepts a JSON run result from extract_defanged_urls", () => {
    const runResult = {
      run_id: "run_parser",
      status: "completed",
      skill: { name: "extract_defanged_urls", version: "0.1.0" },
      output: { ...extractedUrls, warnings: ["source warning"] },
      errors: [],
      warnings: [],
    };

    const output = reviewUrl(JSON.stringify(runResult));

    expect(output.observed.source_parser).toBe("extract_defanged_urls");
    expect(output.observed.source_warning_count).toBe(1);
    expect(output.warnings).toEqual(["Source parser emitted 1 warning(s); review output preserves source_warning_count only."]);
  });

  it("emits an informational signal when no URL observations are present", () => {
    const output = reviewUrl({
      artifact: { id: "artifact_defanged_url_extraction", type: "defanged_url_extraction" },
      urls: [],
      warnings: ["No defanged or HTTP/HTTPS URL candidates observed."],
    });

    expect(output.observed.reviewed_url_count).toBe(0);
    expect(output.signals.map((signal) => signal.type)).toEqual(["url.no_urls_observed"]);
  });

  it("rejects objects that are not extract_defanged_urls output", () => {
    expect(() =>
      reviewUrl({
        artifact: { id: "artifact_indicator_normalization", type: "indicator_normalization" },
        indicators: [],
      }),
    ).toThrow("review_url input must be extract_defanged_urls output with artifact.type defanged_url_extraction");
  });
});
