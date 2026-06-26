import { describe, expect, it } from "vitest";
import { parseUrlSkill } from "../src/parseUrl.js";

describe("parse_url", () => {
  it("parses URL components", async () => {
    const result = await parseUrlSkill.run("https://example.com/path?x=1&x=2#frag");

    expect(result).toMatchObject({
      href: "https://example.com/path?x=1&x=2#frag",
      protocol: "https:",
      hostname: "example.com",
      port: "",
      pathname: "/path",
      search: "?x=1&x=2",
      hash: "#frag",
      username_present: false,
      password_present: false,
      query_params: {
        x: ["1", "2"],
      },
    });
  });

  it("tracks username and password presence without exposing credentials in href", async () => {
    const result = await parseUrlSkill.run("https://user:pass@example.com/path");

    expect(result.username_present).toBe(true);
    expect(result.password_present).toBe(true);
    expect(result.href).toBe("https://%5BREDACTED%5D:%5BREDACTED%5D@example.com/path");
  });

  it("rejects non-string input", async () => {
    await expect(
      async () => await parseUrlSkill.run(123 as unknown as string)
    ).rejects.toThrow("parse_url input must be a string");
  });

  it("rejects invalid URLs", async () => {
    await expect(
      async () => await parseUrlSkill.run("not a url")
    ).rejects.toThrow();
  });
});
