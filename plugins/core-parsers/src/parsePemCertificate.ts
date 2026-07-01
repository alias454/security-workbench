import { X509Certificate } from "node:crypto";
import type { Skill } from "@security-workbench/schemas";
import { localOnlyPermissions } from "./localOnlyPermissions.js";
import {
  detectLineEnding,
  normalizeTextInput,
  physicalLineCount,
  uniqueSorted,
  type NativeJsonLineEnding,
} from "./nativeParserUtils.js";

export interface PemCertificateSubjectAltNameObservation {
  readonly type: string;
  readonly value: string;
}

export interface PemCertificateObservation {
  readonly certificate_index: number;
  readonly subject: string;
  readonly issuer: string;
  readonly serial_number: string;
  readonly valid_from: string;
  readonly valid_to: string;
  readonly valid_from_iso: string | null;
  readonly valid_to_iso: string | null;
  readonly fingerprint_sha256: string;
  readonly fingerprint_sha1: string;
  readonly subject_alt_names: readonly PemCertificateSubjectAltNameObservation[];
  readonly subject_alt_name_present: boolean;
  readonly info_access_present: boolean;
  readonly ca: boolean;
  readonly public_key_type: string | null;
  readonly public_key_size_bits: number | null;
  readonly raw_length_bytes: number;
}

export interface InvalidPemCertificateBlockObservation {
  readonly block_index: number;
  readonly reason: string;
}

export interface ParsePemCertificateOutput {
  readonly artifact: {
    readonly id: "artifact_pem_certificate";
    readonly type: "pem_certificate";
  };
  readonly observed: {
    readonly line_ending: NativeJsonLineEnding;
    readonly physical_line_count: number;
    readonly pem_certificate_block_count: number;
    readonly valid_certificate_count: number;
    readonly invalid_certificate_block_count: number;
    readonly subjects: readonly string[];
    readonly issuers: readonly string[];
    readonly serial_numbers: readonly string[];
    readonly subject_alt_name_values: readonly string[];
    readonly ca_certificate_count: number;
    readonly public_key_types: readonly string[];
    readonly certificates: readonly PemCertificateObservation[];
    readonly invalid_blocks: readonly InvalidPemCertificateBlockObservation[];
  };
  readonly warnings: readonly string[];
}

const CERTIFICATE_BLOCK_PATTERN = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;

function isoDate(value: string): string | null {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return null;
  }

  return date.toISOString();
}

function parseSubjectAltName(value: string | undefined): PemCertificateSubjectAltNameObservation[] {
  if (!value || value.trim().length === 0) {
    return [];
  }

  return value
    .split(/,\s*/)
    .map((entry) => {
      const separatorIndex = entry.indexOf(":");
      if (separatorIndex === -1) {
        return { type: "unknown", value: entry.trim() };
      }

      return {
        type: entry.slice(0, separatorIndex).trim(),
        value: entry.slice(separatorIndex + 1).trim(),
      };
    })
    .filter((entry) => entry.value.length > 0);
}

function publicKeySizeBits(certificate: X509Certificate): number | null {
  const details = certificate.publicKey.asymmetricKeyDetails;
  if (!details) {
    return null;
  }

  if (typeof details.modulusLength === "number") {
    return details.modulusLength;
  }

  if (typeof details.namedCurve === "string") {
    const match = details.namedCurve.match(/(\d+)/);
    return match ? Number(match[1]) : null;
  }

  return null;
}

function certificateObservation(block: string, certificateIndex: number): PemCertificateObservation {
  const certificate = new X509Certificate(block);
  const subjectAltNames = parseSubjectAltName(certificate.subjectAltName);

  return {
    certificate_index: certificateIndex,
    subject: certificate.subject,
    issuer: certificate.issuer,
    serial_number: certificate.serialNumber,
    valid_from: certificate.validFrom,
    valid_to: certificate.validTo,
    valid_from_iso: isoDate(certificate.validFrom),
    valid_to_iso: isoDate(certificate.validTo),
    fingerprint_sha256: certificate.fingerprint256,
    fingerprint_sha1: certificate.fingerprint,
    subject_alt_names: subjectAltNames,
    subject_alt_name_present: subjectAltNames.length > 0,
    info_access_present: typeof certificate.infoAccess === "string" && certificate.infoAccess.length > 0,
    ca: certificate.ca,
    public_key_type: certificate.publicKey.asymmetricKeyType ?? null,
    public_key_size_bits: publicKeySizeBits(certificate),
    raw_length_bytes: certificate.raw.length,
  };
}

export function parsePemCertificate(input: string): ParsePemCertificateOutput {
  const normalized = normalizeTextInput(input, "parse_pem_certificate");
  const warnings: string[] = [];
  const blocks = normalized.match(CERTIFICATE_BLOCK_PATTERN) ?? [];

  if (blocks.length === 0) {
    throw new Error("parse_pem_certificate input must contain at least one PEM CERTIFICATE block");
  }

  const certificates: PemCertificateObservation[] = [];
  const invalidBlocks: InvalidPemCertificateBlockObservation[] = [];

  for (const [index, block] of blocks.entries()) {
    try {
      certificates.push(certificateObservation(block, index));
    } catch (error) {
      invalidBlocks.push({
        block_index: index,
        reason: error instanceof Error ? error.message : "invalid certificate block",
      });
    }
  }

  if (certificates.length === 0) {
    throw new Error("parse_pem_certificate input did not contain any valid PEM certificates");
  }

  if (invalidBlocks.length > 0) {
    warnings.push(`${String(invalidBlocks.length)} PEM CERTIFICATE block(s) could not be parsed.`);
  }

  return {
    artifact: {
      id: "artifact_pem_certificate",
      type: "pem_certificate",
    },
    observed: {
      line_ending: detectLineEnding(normalized),
      physical_line_count: physicalLineCount(normalized),
      pem_certificate_block_count: blocks.length,
      valid_certificate_count: certificates.length,
      invalid_certificate_block_count: invalidBlocks.length,
      subjects: uniqueSorted(certificates.map((certificate) => certificate.subject)),
      issuers: uniqueSorted(certificates.map((certificate) => certificate.issuer)),
      serial_numbers: uniqueSorted(certificates.map((certificate) => certificate.serial_number)),
      subject_alt_name_values: uniqueSorted(certificates.flatMap((certificate) => certificate.subject_alt_names.map((entry) => entry.value))),
      ca_certificate_count: certificates.filter((certificate) => certificate.ca).length,
      public_key_types: uniqueSorted(certificates.map((certificate) => certificate.public_key_type)),
      certificates,
      invalid_blocks: invalidBlocks,
    },
    warnings,
  };
}

export const parsePemCertificateSkill: Skill<string, ParsePemCertificateOutput> = {
  metadata: {
    name: "parse_pem_certificate",
    version: "0.1.0",
    category: "parser",
    description:
      "Parse PEM CERTIFICATE blocks into structured X.509 metadata without chain validation, revocation checks, network access, or risk scoring.",
    execution: {
      mode: "local_only",
      network_access: "none",
      deterministic: true,
    },
    permissions: localOnlyPermissions,
    exposure: {
      surfaces: ["cli", "api", "web", "mcp"],
      default_exposure: "enabled",
      hosted_default: "allowlist_only",
      requires_authentication: true,
      rate_limit_recommended: true,
      audit_required: true,
      max_input_mb: 1,
      risk: "low",
      rationale: [
        "Parses attacker-controlled PEM text using Node.js X509Certificate without invoking external binaries.",
        "Does not perform certificate chain validation, revocation checks, network access, persistence, or scoring.",
        "Output preserves observed certificate metadata and does not claim trustworthiness or validity beyond parseability and encoded dates.",
      ],
    },
  },
  run(input: string): ParsePemCertificateOutput {
    return parsePemCertificate(input);
  },
};
