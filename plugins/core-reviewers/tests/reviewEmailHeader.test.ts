import { describe, expect, it } from "vitest";
import { reviewEmailHeader, reviewEmailHeaderSkill } from "../src/reviewEmailHeader.js";

const parsedEmailHeaders = {
  headers: [
    { name: "From", name_lower: "from", value: "Security Alerts <alerts@example.com>" },
    { name: "Reply-To", name_lower: "reply-to", value: "Help Desk <helpdesk.example.net@example.net>" },
    { name: "Return-Path", name_lower: "return-path", value: "<bounce@example.net>" },
    { name: "To", name_lower: "to", value: "Analyst <analyst@example.org>" },
    { name: "Subject", name_lower: "subject", value: "Suspicious login" },
    { name: "Authentication-Results", name_lower: "authentication-results", value: "mx.example.org; spf=fail smtp.mailfrom=example.net; dkim=pass header.d=example.com; dmarc=fail header.from=example.com" },
    { name: "X-Test", name_lower: "x-test", value: "one" },
    { name: "X-Test", name_lower: "x-test", value: "two" },
  ],
  header_count: 8,
  duplicate_header_names: ["x-test"],
  observed: {
    from: "Security Alerts <alerts@example.com>",
    to: "Analyst <analyst@example.org>",
    cc: null,
    subject: "Suspicious login",
    date: null,
    message_id: null,
    received_count: 0,
    authentication_results: [
      "mx.example.org; spf=fail smtp.mailfrom=example.net; dkim=pass header.d=example.com; dmarc=fail header.from=example.com",
    ],
  },
  warnings: [],
} as const;

describe("review_email_header", () => {
  it("exports the reviewer skill with local-only permissions", () => {
    expect(reviewEmailHeaderSkill.metadata.name).toBe("review_email_header");
    expect(reviewEmailHeaderSkill.metadata.category).toBe("reviewer");
    expect(reviewEmailHeaderSkill.metadata.execution).toEqual({
      mode: "local_only",
      network_access: "none",
      deterministic: true,
    });
    expect(reviewEmailHeaderSkill.metadata.permissions).toEqual({
      network: "none",
      filesystem: "none",
      sends: [],
      persists: false,
      runs_external_binaries: false,
    });
  });

  it("emits evidence-backed header review signals without copying full header values", () => {
    const output = reviewEmailHeader(parsedEmailHeaders);

    expect(output.artifact).toEqual({
      id: "artifact_email_header_review",
      type: "email_header_review",
      source_artifact_id: null,
      source_artifact_type: null,
    });
    expect(output.observed.source_parser).toBe("parse_email_headers");
    expect(output.observed.header_count).toBe(8);
    expect(output.observed.from_domain).toBe("example.com");
    expect(output.observed.reply_to_domain).toBe("example.net");
    expect(output.observed.authentication_result_mechanisms).toEqual(["dkim", "dmarc", "spf"]);
    expect(output.observed.authentication_result_failures).toEqual([
      { mechanism: "dmarc", result: "fail" },
      { mechanism: "spf", result: "fail" },
    ]);
    expect(output.signals.map((signal) => signal.type)).toEqual([
      "email_header.duplicate_header_name_observed",
      "email_header.authentication_result_failure_observed",
      "email_header.received_chain_not_observed",
      "email_header.message_id_not_observed",
      "email_header.date_not_observed",
      "email_header.reply_to_from_domain_mismatch_observed",
      "email_header.return_path_from_domain_mismatch_observed",
    ]);
    expect(output.signals.every((signal) => signal.evidence_refs.length > 0)).toBe(true);
    expect(JSON.stringify(output)).not.toContain("Suspicious login");
    expect(JSON.stringify(output)).not.toContain("Security Alerts");
  });

  it("accepts a JSON run result from parse_email_headers", () => {
    const runResult = {
      run_id: "run_parser",
      status: "completed",
      skill: { name: "parse_email_headers", version: "0.1.0" },
      output: {
        ...parsedEmailHeaders,
        warnings: ["No headers parsed."],
      },
      errors: [],
      warnings: [],
    };

    const output = reviewEmailHeader(JSON.stringify(runResult));

    expect(output.observed.source_parser).toBe("parse_email_headers");
    expect(output.observed.source_warning_count).toBe(1);
    expect(output.warnings).toEqual(["Source parser emitted 1 warning(s); review output preserves source_warning_count only."]);
  });

  it("emits a missing Authentication-Results signal when none was observed", () => {
    const output = reviewEmailHeader({
      headers: [
        { name: "From", name_lower: "from", value: "alerts@example.com" },
        { name: "To", name_lower: "to", value: "analyst@example.org" },
      ],
      header_count: 2,
      duplicate_header_names: [],
      observed: {
        from: "alerts@example.com",
        to: "analyst@example.org",
        cc: null,
        subject: null,
        date: null,
        message_id: null,
        received_count: 0,
        authentication_results: [],
      },
      warnings: [],
    });

    expect(output.signals.map((signal) => signal.type)).toContain("email_header.authentication_results_not_observed");
    expect(output.signals.map((signal) => signal.type)).toContain("email_header.message_id_not_observed");
  });

  it("rejects objects that are not parse_email_headers output", () => {
    expect(() => reviewEmailHeader({ headers: [], warnings: [] })).toThrow(
      "review_email_header input must be parse_email_headers output with headers and observed fields",
    );
  });
});
