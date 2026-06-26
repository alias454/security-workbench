import type { Skill } from "@security-workbench/schemas";
import { localOnlyPermissions } from "./localOnlyPermissions.js";
import { refangText, trimTrailingPunctuation, uniqueSorted } from "./iocText.js";

export interface ExtractIocsOutput {
  urls: string[];
  domains: string[];
  ipv4_addresses: string[];
  email_addresses: string[];
  sha256_hashes: string[];
}

const URL_PATTERN = /\bhttps?:\/\/[^\s<>"'`]+/gi;
const EMAIL_PATTERN = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63}\b/gi;
const IPV4_PATTERN = /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/g;
const SHA256_PATTERN = /\b[a-fA-F0-9]{64}\b/g;
const DOMAIN_PATTERN = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b/gi;

function extractUrls(input: string): string[] {
  return uniqueSorted(
    [...input.matchAll(URL_PATTERN)].map((match) =>
      trimTrailingPunctuation(match[0])
    )
  );
}

function extractEmails(input: string): string[] {
  return uniqueSorted(
    [...input.matchAll(EMAIL_PATTERN)].map((match) =>
      trimTrailingPunctuation(match[0]).toLowerCase()
    )
  );
}

function extractIpv4Addresses(input: string): string[] {
  return uniqueSorted([...input.matchAll(IPV4_PATTERN)].map((match) => match[0]));
}

function extractSha256Hashes(input: string): string[] {
  return uniqueSorted(
    [...input.matchAll(SHA256_PATTERN)].map((match) => match[0].toLowerCase())
  );
}

function isIpv4Like(value: string): boolean {
  return /^\d+(?:\.\d+){3}$/.test(value);
}

function extractDomains(input: string, urls: string[], emails: string[]): string[] {
  const domains: string[] = [];

  for (const url of urls) {
    try {
      domains.push(new URL(url).hostname.toLowerCase());
    } catch {
      // URL_PATTERN is intentionally simple. Ignore anything URL cannot normalize.
    }
  }

  for (const email of emails) {
    const atIndex = email.lastIndexOf("@");
    if (atIndex !== -1) {
      domains.push(email.slice(atIndex + 1).toLowerCase());
    }
  }

  for (const match of input.matchAll(DOMAIN_PATTERN)) {
    const candidate = trimTrailingPunctuation(match[0]).toLowerCase();
    if (!isIpv4Like(candidate)) {
      domains.push(candidate);
    }
  }

  return uniqueSorted(domains);
}

export const extractIocsSkill: Skill<string, ExtractIocsOutput> = {
  metadata: {
    name: "extract_iocs",
    version: "0.1.0",
    category: "parser",
    description: "Extract simple URL, domain, IPv4, email, and SHA-256 indicators from text.",
    execution: {
      mode: "local_only",
      network_access: "none",
      deterministic: true,
    },
    permissions: localOnlyPermissions,
  },

  run(input: string) {
    if (typeof input !== "string") {
      throw new Error("extract_iocs input must be a string");
    }

    const normalized = refangText(input);
    const urls = extractUrls(normalized);
    const email_addresses = extractEmails(normalized);
    const ipv4_addresses = extractIpv4Addresses(normalized);
    const sha256_hashes = extractSha256Hashes(normalized);
    const domains = extractDomains(normalized, urls, email_addresses);

    return {
      urls,
      domains,
      ipv4_addresses,
      email_addresses,
      sha256_hashes,
    };
  },
};
