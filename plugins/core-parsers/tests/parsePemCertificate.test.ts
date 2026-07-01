import { describe, expect, it } from "vitest";
import { parsePemCertificate, parsePemCertificateSkill } from "../src/parsePemCertificate.js";
import { skills } from "../src/index.js";

const SAMPLE_CERTIFICATE = `-----BEGIN CERTIFICATE-----
MIIDnDCCAoSgAwIBAgIUO121tT+neM8qfAME0u0xT6J3l9UwDQYJKoZIhvcNAQEL
BQAwRTEUMBIGA1UEAwwLZXhhbXBsZS5jb20xIDAeBgNVBAoMF1NlY3VyaXR5IFdv
cmtiZW5jaCBUZXN0MQswCQYDVQQGEwJVUzAeFw0yNjA3MDEyMTU2MzZaFw0yNzA3
MDEyMTU2MzZaMEUxFDASBgNVBAMMC2V4YW1wbGUuY29tMSAwHgYDVQQKDBdTZWN1
cml0eSBXb3JrYmVuY2ggVGVzdDELMAkGA1UEBhMCVVMwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQCZtUv+JlzkFcB0R2wVt674GrFDcme5m+L5ot9po+sM
zzCyxx3Oz5ZNlda41JVcNGoM/6AGwEd3YVDnPun1YxAIduVdlVwr01ALemBs3tsu
L5KAreK5nKcQm/mi2jC0O1LmDQZBvjn7xEL8hEpAR0Ihh2SQo/RLLA7Md5QNIHlQ
gza4ATpx+rxYgXxKAVwOqErlyzTPf/4+YO0sYfno/O15h0rMNdBKkTmJQ7hKXFqq
/FK4pnJ8eDqquITnG5SsoLQ2UuGSXZaZWtGJH+7LYQBqJsN6NOxAG8EylKqUdFLk
50cGhkRIcN+vgCmzIxJGBB2g0PIDrOYZqVjDFxc7QXIJAgMBAAGjgYMwgYAwHQYD
VR0OBBYEFENs3fM4uL/LhFU+t465NFRtOnp4MB8GA1UdIwQYMBaAFENs3fM4uL/L
hFU+t465NFRtOnp4MA8GA1UdEwEB/wQFMAMBAf8wLQYDVR0RBCYwJIILZXhhbXBs
ZS5jb22CD3d3dy5leGFtcGxlLmNvbYcEwAACCjANBgkqhkiG9w0BAQsFAAOCAQEA
flKyDYwtzfnEDO/dVRuW6g8icIV7R6y+R1AXsU4Z/mXX8o9hW5p/A8NUSlM/57em
PctrcNmLNYuT0BTs1aFI6QznS9GI7yfxhv2OGRP/N/UJHtT+XxBjc7QD46rmM71u
0/NPLTO+zT+2HswH8KKDLdKHqB6vseIHsDnCETMapF75i58NDbuJzz6TutbSs/7/
6RSNPW5qOd0bumdVr7+ffNTPull7ZTToTs0nPxOFj6xAbPzm9vKRx5L9lyw7fiAG
/IZzNGHJVL3bTORl3RaVY7TZWQAkHlZk1KmEmMwGtvKxCayHs1TFi+cJtntsngLX
onT1PpM2M5v9D3M2HZpoUw==
-----END CERTIFICATE-----
`;

describe("parse_pem_certificate", () => {
  it("exports the parser skill with local-only permissions", () => {
    expect(skills.map((skill) => skill.metadata.name)).toContain("parse_pem_certificate");
    expect(parsePemCertificateSkill.metadata).toMatchObject({
      name: "parse_pem_certificate",
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
    });
  });

  it("parses PEM certificate blocks into X.509 observations", async () => {
    const output = parsePemCertificate(SAMPLE_CERTIFICATE);

    expect(output.artifact).toEqual({ id: "artifact_pem_certificate", type: "pem_certificate" });
    expect(output.observed.pem_certificate_block_count).toBe(1);
    expect(output.observed.valid_certificate_count).toBe(1);
    expect(output.observed.invalid_certificate_block_count).toBe(0);
    expect(output.observed.subjects[0]).toContain("CN=example.com");
    expect(output.observed.issuers[0]).toContain("CN=example.com");
    expect(output.observed.subject_alt_name_values).toEqual(["192.0.2.10", "example.com", "www.example.com"]);
    expect(output.observed.public_key_types).toEqual(["rsa"]);
    expect(output.observed.certificates[0]).toMatchObject({
      certificate_index: 0,
      subject_alt_name_present: true,
      ca: true,
      public_key_type: "rsa",
      public_key_size_bits: 2048,
    });
    expect(output.observed.certificates[0]?.fingerprint_sha256).toMatch(/^[A-F0-9:]+$/);
    expect(output.warnings).toEqual([]);
  });

  it("rejects input without valid PEM certificate blocks", () => {
    expect(() => parsePemCertificate("not a certificate")).toThrow("parse_pem_certificate input must contain at least one PEM CERTIFICATE block");
    expect(() => parsePemCertificate("-----BEGIN CERTIFICATE-----\nnot-base64\n-----END CERTIFICATE-----")).toThrow("parse_pem_certificate input did not contain any valid PEM certificates");
  });
});
