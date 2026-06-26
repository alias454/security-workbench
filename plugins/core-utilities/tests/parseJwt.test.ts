import { describe, expect, it } from "vitest";
import { parseJwtSkill } from "../src/parseJwt.js";

function base64urlJson(value: unknown): string {
  return Buffer.from(JSON.stringify(value), "utf8")
    .toString("base64url");
}

describe("parse_jwt", () => {
  it("decodes JWT header and payload without exposing signature", async () => {
    const header = { alg: "HS256", typ: "JWT" };
    const payload = { sub: "123", name: "Alice", admin: true };
    const signature = Buffer.from("signature", "utf8").toString("base64url");
    const token = `${base64urlJson(header)}.${base64urlJson(payload)}.${signature}`;

    const result = await parseJwtSkill.run(token);

    expect(result).toEqual({
      header,
      payload,
      algorithm: "HS256",
      type: "JWT",
      signature_present: true,
      signature_length: signature.length,
      signature_verified: false,
      warnings: ["JWT signature is not verified by parse_jwt."],
    });
  });

  it("rejects tokens without three segments", async () => {
    await expect(async () => await parseJwtSkill.run("a.b")).rejects.toThrow(
      "parse_jwt input must contain exactly three JWT segments"
    );
  });

  it("rejects non-object header JSON", async () => {
    const token = `${Buffer.from("[]", "utf8").toString("base64url")}.${base64urlJson({ sub: "123" })}.sig`;

    await expect(async () => await parseJwtSkill.run(token)).rejects.toThrow(
      "parse_jwt header must decode to a JSON object"
    );
  });

  it("rejects non-string input", async () => {
    await expect(async () => await parseJwtSkill.run(123 as unknown as string)).rejects.toThrow(
      "parse_jwt input must be a string"
    );
  });
});
