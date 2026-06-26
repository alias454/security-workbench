import { describe, expect, it } from "vitest";
import { parseHttpHeaders, parseHttpHeadersSkill } from "../src/parseHttpHeaders.js";
import { skills } from "../src/index.js";

async function runHttpHeaders(input: string) {
  return await parseHttpHeadersSkill.run(input);
}

describe("parse_http_headers", () => {
  it("exports the parser skill with local-only permissions", () => {
    expect(skills.map((skill) => skill.metadata.name)).toContain("parse_http_headers");
    expect(parseHttpHeadersSkill.metadata).toMatchObject({
      name: "parse_http_headers",
      category: "parser",
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
      exposure: {
        hosted_default: "allowlist_only",
        requires_authentication: true,
        rate_limit_recommended: true,
        audit_required: true,
      },
    });
  });

  it("parses an HTTP response header preamble and observed header presence", async () => {
    const output = await runHttpHeaders([
      "HTTP/1.1 200 OK",
      "Content-Type: text/html; charset=utf-8",
      "Content-Security-Policy: default-src 'self'",
      "Strict-Transport-Security: max-age=31536000",
      "X-Frame-Options: DENY",
      "X-Content-Type-Options: nosniff",
      "Referrer-Policy: no-referrer",
      "Permissions-Policy: geolocation=()",
      "Set-Cookie: session=example; HttpOnly",
      "Location: https://example.com/next",
      "",
      "body is ignored",
    ].join("\r\n"));

    expect(output.artifact).toEqual({ id: "artifact_http_headers", type: "http_headers" });
    expect(output.observed.status_line_present).toBe(true);
    expect(output.observed.http_version).toBe("1.1");
    expect(output.observed.status_code).toBe(200);
    expect(output.observed.reason_phrase).toBe("OK");
    expect(output.observed.line_ending).toBe("crlf");
    expect(output.observed.header_count).toBe(9);
    expect(output.observed.unique_header_name_count).toBe(9);
    expect(output.observed.duplicate_header_names).toEqual([]);
    expect(output.observed.content_security_policy_present).toBe(true);
    expect(output.observed.strict_transport_security_present).toBe(true);
    expect(output.observed.x_frame_options_present).toBe(true);
    expect(output.observed.x_content_type_options_present).toBe(true);
    expect(output.observed.referrer_policy_present).toBe(true);
    expect(output.observed.permissions_policy_present).toBe(true);
    expect(output.observed.set_cookie_count).toBe(1);
    expect(output.observed.location_present).toBe(true);
    expect(output.warnings).toEqual([]);
  });

  it("normalizes duplicate header names case-insensitively", async () => {
    const output = await runHttpHeaders([
      "HTTP/2 302 Found",
      "Set-Cookie: one=1",
      "set-cookie: two=2",
      "Cache-Control: no-store",
      "CACHE-CONTROL: max-age=0",
    ].join("\n"));

    expect(output.observed.http_version).toBe("2");
    expect(output.observed.status_code).toBe(302);
    expect(output.observed.duplicate_header_names).toEqual(["cache-control", "set-cookie"]);
    expect(output.observed.set_cookie_count).toBe(2);
    expect(output.observed.headers.map((header) => header.lower_name)).toEqual([
      "set-cookie",
      "set-cookie",
      "cache-control",
      "cache-control",
    ]);
  });

  it("preserves header values as strings without interpreting them", async () => {
    const output = parseHttpHeaders("X-Formula: =1+1\nX-Json: {\"enabled\":true}\n");

    expect(output.observed.status_line_present).toBe(false);
    expect(output.observed.headers).toEqual([
      { original_name: "X-Formula", lower_name: "x-formula", value: "=1+1" },
      { original_name: "X-Json", lower_name: "x-json", value: '{"enabled":true}' },
    ]);
  });

  it("warns about malformed lines while preserving valid header fields", async () => {
    const output = await runHttpHeaders([
      "HTTP/1.1 204 No Content",
      "not a header",
      "Bad Name: ignored",
      "X-Valid: yes",
      " folded continuation",
    ].join("\n"));

    expect(output.observed.header_count).toBe(1);
    expect(output.observed.malformed_line_count).toBe(2);
    expect(output.observed.folded_line_count).toBe(1);
    expect(output.observed.headers).toEqual([
      { original_name: "X-Valid", lower_name: "x-valid", value: "yes folded continuation" },
    ]);
    expect(output.warnings).toEqual([
      "HTTP header line 2 is missing a valid name/value separator.",
      "HTTP header line 3 has an invalid header name.",
      "HTTP header line 5 is a folded continuation line.",
    ]);
  });

  it("warns about mixed line endings", async () => {
    const output = await runHttpHeaders("X-One: 1\r\nX-Two: 2\n");

    expect(output.observed.line_ending).toBe("mixed");
    expect(output.warnings).toContain("HTTP header input contains mixed line endings.");
  });

  it("rejects empty input and inputs without valid header fields", () => {
    expect(() => parseHttpHeadersSkill.run("\n\t\n")).toThrow(
      "parse_http_headers input must not be empty"
    );
    expect(() => parseHttpHeadersSkill.run("HTTP/1.1 200 OK\nnot a header\n")).toThrow(
      "parse_http_headers input did not contain any valid header fields"
    );
  });

  it("rejects non-string input", () => {
    expect(() => parseHttpHeadersSkill.run(123 as unknown as string)).toThrow(
      "parse_http_headers input must be a string"
    );
  });
});
