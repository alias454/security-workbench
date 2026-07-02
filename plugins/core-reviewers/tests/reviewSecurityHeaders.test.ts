import { describe, expect, it } from "vitest";
import { reviewSecurityHeaders, reviewSecurityHeadersSkill } from "../src/reviewSecurityHeaders.js";
import { skills } from "../src/index.js";

const parsedWeakHeaders = {
  artifact: {
    id: "artifact_http_headers",
    type: "http_headers",
  },
  observed: {
    status_line_present: true,
    http_version: "1.1",
    status_code: 200,
    reason_phrase: "OK",
    line_ending: "lf",
    header_count: 4,
    unique_header_name_count: 4,
    duplicate_header_names: [],
    malformed_line_count: 0,
    folded_line_count: 0,
    headers: [
      {
        original_name: "Content-Security-Policy",
        lower_name: "content-security-policy",
        value: "default-src *; script-src 'unsafe-inline'",
      },
      {
        original_name: "Strict-Transport-Security",
        lower_name: "strict-transport-security",
        value: "max-age=300",
      },
      {
        original_name: "Set-Cookie",
        lower_name: "set-cookie",
        value: "session=redacted; Path=/",
      },
      {
        original_name: "Location",
        lower_name: "location",
        value: "/next",
      },
    ],
    header_names: ["content-security-policy", "location", "set-cookie", "strict-transport-security"],
    content_security_policy_present: true,
    strict_transport_security_present: true,
    x_frame_options_present: false,
    x_content_type_options_present: false,
    referrer_policy_present: false,
    permissions_policy_present: false,
    set_cookie_count: 1,
    location_present: true,
  },
  warnings: [],
} as const;

const parsedStrongHeaders = {
  artifact: {
    id: "artifact_http_headers",
    type: "http_headers",
  },
  observed: {
    status_line_present: true,
    http_version: "2",
    status_code: 200,
    reason_phrase: "OK",
    line_ending: "lf",
    header_count: 7,
    unique_header_name_count: 7,
    duplicate_header_names: [],
    malformed_line_count: 0,
    folded_line_count: 0,
    headers: [
      {
        original_name: "Content-Security-Policy",
        lower_name: "content-security-policy",
        value: "default-src 'self'; frame-ancestors 'none'",
      },
      {
        original_name: "Strict-Transport-Security",
        lower_name: "strict-transport-security",
        value: "max-age=31536000; includeSubDomains",
      },
      {
        original_name: "X-Content-Type-Options",
        lower_name: "x-content-type-options",
        value: "nosniff",
      },
      {
        original_name: "Referrer-Policy",
        lower_name: "referrer-policy",
        value: "no-referrer",
      },
      {
        original_name: "Permissions-Policy",
        lower_name: "permissions-policy",
        value: "geolocation=()",
      },
      {
        original_name: "Set-Cookie",
        lower_name: "set-cookie",
        value: "session=redacted; Secure; HttpOnly; SameSite=Lax",
      },
      {
        original_name: "Cache-Control",
        lower_name: "cache-control",
        value: "no-store",
      },
    ],
    header_names: [
      "cache-control",
      "content-security-policy",
      "permissions-policy",
      "referrer-policy",
      "set-cookie",
      "strict-transport-security",
      "x-content-type-options",
    ],
    content_security_policy_present: true,
    strict_transport_security_present: true,
    x_frame_options_present: false,
    x_content_type_options_present: true,
    referrer_policy_present: true,
    permissions_policy_present: true,
    set_cookie_count: 1,
    location_present: false,
  },
  warnings: [],
} as const;

describe("review_security_headers", () => {
  it("exports the reviewer skill with local-only permissions", () => {
    expect(skills.map((skill) => skill.metadata.name)).toContain("review_security_headers");
    expect(reviewSecurityHeadersSkill.metadata).toMatchObject({
      name: "review_security_headers",
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

  it("emits evidence-backed security header signals", () => {
    const output = reviewSecurityHeaders(parsedWeakHeaders);

    expect(output.artifact).toMatchObject({
      type: "security_headers_review",
      source_artifact_id: "artifact_http_headers",
      source_artifact_type: "http_headers",
    });
    expect(output.observed.source_parser).toBe("parse_http_headers");
    expect(output.observed.content_security_policy_has_unsafe_inline).toBe(true);
    expect(output.observed.content_security_policy_has_wildcard_source).toBe(true);
    expect(output.observed.strict_transport_security_max_age).toBe(300);
    expect(output.observed.set_cookie_without_secure_count).toBe(1);
    expect(output.observed.set_cookie_without_http_only_count).toBe(1);
    expect(output.observed.set_cookie_without_same_site_count).toBe(1);
    expect(output.signals.map((signal) => signal.type)).toEqual([
      "security_headers.csp_unsafe_inline_observed",
      "security_headers.csp_wildcard_source_observed",
      "security_headers.hsts_short_max_age_observed",
      "security_headers.hsts_include_subdomains_not_observed",
      "security_headers.frame_protection_not_observed",
      "security_headers.x_content_type_options_not_observed",
      "security_headers.referrer_policy_not_observed",
      "security_headers.permissions_policy_not_observed",
      "security_headers.cookie_secure_attribute_not_observed",
      "security_headers.cookie_http_only_attribute_not_observed",
      "security_headers.cookie_same_site_attribute_not_observed",
    ]);
    expect(output.signals.every((signal) => signal.evidence_refs.length > 0)).toBe(true);
    expect(output.observed.limitations).toContain(
      "Does not perform HTTP requests, browser policy validation, TLS validation, DNS lookup, redirect following, or live endpoint checks.",
    );
  });

  it("emits no signals for a header set with common observed controls", () => {
    const output = reviewSecurityHeaders(parsedStrongHeaders);

    expect(output.signals).toEqual([]);
    expect(output.observed.content_security_policy_has_frame_ancestors).toBe(true);
    expect(output.observed.frame_protection_observed).toBe(true);
    expect(output.observed.strict_transport_security_include_subdomains_present).toBe(true);
    expect(output.observed.set_cookie_without_secure_count).toBe(0);
    expect(output.observed.set_cookie_without_http_only_count).toBe(0);
    expect(output.observed.set_cookie_without_same_site_count).toBe(0);
  });

  it("accepts a JSON run result from parse_http_headers", () => {
    const runResult = {
      run_id: "run_parser",
      status: "completed",
      skill: { name: "parse_http_headers", version: "0.1.0" },
      output: { ...parsedWeakHeaders, warnings: ["parser warning"] },
      errors: [],
      warnings: [],
    };

    const output = reviewSecurityHeaders(JSON.stringify(runResult));

    expect(output.observed.source_parser).toBe("parse_http_headers");
    expect(output.observed.source_warning_count).toBe(1);
    expect(output.warnings).toEqual(["Source parser emitted 1 warning(s); review output preserves source_warning_count only."]);
  });

  it("rejects objects that are not parse_http_headers output", () => {
    expect(() =>
      reviewSecurityHeaders({
        artifact: { id: "artifact_email_headers", type: "email_headers" },
        observed: {},
        warnings: [],
      }),
    ).toThrow("review_security_headers input must be parse_http_headers output with artifact.type http_headers and observed fields");
  });
});
