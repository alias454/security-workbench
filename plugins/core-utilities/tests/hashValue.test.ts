import { describe, expect, it } from "vitest";
import { identifyHashSkill, md5HashSkill, sha1HashSkill, sha256HashSkill, sha512HashSkill } from "../src/hashValue.js";

describe("hash skills", () => {
  it("computes MD5", () => {
    expect(md5HashSkill.run("hello")).toEqual({
      algorithm: "md5",
      encoding: "hex",
      hash: "5d41402abc4b2a76b9719d911017c592",
    });
  });

  it("computes SHA-1", () => {
    expect(sha1HashSkill.run("hello")).toEqual({
      algorithm: "sha1",
      encoding: "hex",
      hash: "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",
    });
  });

  it("computes SHA-256", () => {
    expect(sha256HashSkill.run("hello")).toEqual({
      algorithm: "sha256",
      encoding: "hex",
      hash: "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
    });
  });

  it("computes SHA-512", () => {
    expect(sha512HashSkill.run("hello")).toEqual({
      algorithm: "sha512",
      encoding: "hex",
      hash: "9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043",
    });
  });

  it("identifies likely hash algorithms by hexadecimal digest length", () => {
    expect(identifyHashSkill.run("5D41402ABC4B2A76B9719D911017C592")).toEqual({
      normalized: "5d41402abc4b2a76b9719d911017c592",
      input_length: 32,
      encoding: "hex",
      candidates: [{ algorithm: "md5", encoding: "hex", digest_length: 32 }],
    });
  });

  it("returns no candidates for non-hex input", () => {
    expect(identifyHashSkill.run("not-a-hash")).toEqual({
      normalized: "not-a-hash",
      input_length: 10,
      encoding: "unknown",
      candidates: [],
    });
  });

  it("categorizes hash identification as parser and explicit hashing as transforms", () => {
    expect(identifyHashSkill.metadata.category).toBe("parser");
    expect(md5HashSkill.metadata.category).toBe("transform");
    expect(sha1HashSkill.metadata.category).toBe("transform");
    expect(sha256HashSkill.metadata.category).toBe("transform");
    expect(sha512HashSkill.metadata.category).toBe("transform");
  });

  it("declares local-only permissions", () => {
    for (const skill of [identifyHashSkill, md5HashSkill, sha1HashSkill, sha256HashSkill, sha512HashSkill]) {
      const permissions = skill.metadata.permissions;

      expect(skill.metadata.execution.network_access).toBe("none");
      expect(permissions).toBeDefined();
      expect(permissions?.network).toBe("none");
      expect(permissions?.filesystem).toBe("none");
      expect(permissions?.persists).toBe(false);
      expect(permissions?.runs_external_binaries).toBe(false);
    }
  });
});
