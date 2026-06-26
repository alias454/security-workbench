import { describe, expect, it } from "vitest";

import { redactValue } from "../src/redaction.js";

describe("redactValue sensitive key handling", () => {
  it("redacts values by sensitive snake_case and lowercase keys", () => {
    expect(redactValue({ password: "hunter2" })).toEqual({
      password: "[REDACTED]",
    });

    expect(redactValue({ api_key: "abc123" })).toEqual({
      api_key: "[REDACTED]",
    });

    expect(redactValue({ authorization: "Basic abc123" })).toEqual({
      authorization: "[REDACTED]",
    });
  });

  it("redacts values by sensitive camelCase keys", () => {
    expect(redactValue({ apiKey: "abc123" })).toEqual({
      apiKey: "[REDACTED]",
    });

    expect(
      redactValue({ privateKey: "-----BEGIN PRIVATE KEY-----example" }),
    ).toEqual({
      privateKey: "[REDACTED]",
    });
  });

  it("redacts nested sensitive keys while preserving object shape", () => {
    expect(
      redactValue({
        nested: {
          client_secret: "plain-short-value",
        },
      }),
    ).toEqual({
      nested: {
        client_secret: "[REDACTED]",
      },
    });
  });

  it("redacts sensitive keys in arrays without redacting safe keys", () => {
    expect(
      redactValue([
        { token: "abc" },
        { name: "safe-value" },
      ]),
    ).toEqual([
      { token: "[REDACTED]" },
      { name: "safe-value" },
    ]);
  });

  it("does not mutate caller-owned objects", () => {
    const input = {
      nested: {
        password: "hunter2",
        name: "safe-value",
      },
    };

    const output = redactValue(input);

    expect(output).toEqual({
      nested: {
        password: "[REDACTED]",
        name: "safe-value",
      },
    });
    expect(input).toEqual({
      nested: {
        password: "hunter2",
        name: "safe-value",
      },
    });
  });
});
