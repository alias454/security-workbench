import { describe, expect, it } from "vitest";
import { parseEmailHeadersSkill } from "../src/parseEmailHeaders.js";

describe("parse_email_headers", () => {
  it("parses headers, continuations, duplicates, and observed fields", async () => {
    const input = [
      "From: Alice <alice@example.com>",
      "To: bob@example.com",
      "Subject: Test subject",
      "Message-ID: <abc@example.com>",
      "Received: by mx1.example.com",
      "Authentication-Results: mx.example.com;",
      " spf=pass smtp.mailfrom=example.com",
      "X-Test: one",
      "X-Test: two",
      "",
      "Body starts here",
    ].join("\n");

    const result = await parseEmailHeadersSkill.run(input);

    expect(result.header_count).toBe(8);
    expect(result.duplicate_header_names).toEqual(["x-test"]);
    expect(result.observed).toEqual({
      from: "Alice <alice@example.com>",
      to: "bob@example.com",
      cc: null,
      subject: "Test subject",
      date: null,
      message_id: "<abc@example.com>",
      received_count: 1,
      authentication_results: ["mx.example.com; spf=pass smtp.mailfrom=example.com"],
    });
    expect(result.headers.at(-1)).toEqual({
      name: "X-Test",
      name_lower: "x-test",
      value: "two",
    });
  });

  it("rejects malformed header lines", async () => {
    await expect(async () => await parseEmailHeadersSkill.run("Bad header")).rejects.toThrow(
      "parse_email_headers encountered malformed header line without field name and colon"
    );
  });

  it("rejects continuation before first header", async () => {
    await expect(async () => await parseEmailHeadersSkill.run(" folded")) .rejects.toThrow(
      "parse_email_headers continuation line encountered before any header"
    );
  });

  it("rejects non-string input", async () => {
    await expect(
      async () => await parseEmailHeadersSkill.run(123 as unknown as string)
    ).rejects.toThrow("parse_email_headers input must be a string");
  });
});
