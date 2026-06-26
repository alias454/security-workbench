import type { Skill } from "@security-workbench/schemas";
import { localOnlyPermissions } from "./localOnlyPermissions.js";

export interface ExtractUrlsOutput {
  urls: string[];
  count: number;
}

export interface ExtractDomainsOutput {
  domains: string[];
  count: number;
}

export interface ExtractEmailsOutput {
  email_addresses: string[];
  count: number;
}

export interface ExtractIpv4Output {
  ipv4_addresses: string[];
  count: number;
}

export interface ExtractHashesOutput {
  md5_hashes: string[];
  sha1_hashes: string[];
  sha256_hashes: string[];
  sha512_hashes: string[];
  total_count: number;
}

const URL_PATTERN = /\bhttps?:\/\/[^\s<>"'`]+/gi;
const EMAIL_PATTERN = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63}\b/gi;
const IPV4_PATTERN = /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/g;
const DOMAIN_PATTERN = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b/gi;
const MD5_PATTERN = /\b[a-fA-F0-9]{32}\b/g;
const SHA1_PATTERN = /\b[a-fA-F0-9]{40}\b/g;
const SHA256_PATTERN = /\b[a-fA-F0-9]{64}\b/g;
const SHA512_PATTERN = /\b[a-fA-F0-9]{128}\b/g;

function assertString(input: string, skillName: string): void {
  if (typeof input !== "string") {
    throw new Error(`${skillName} input must be a string`);
  }
}

function normalizeDefangedText(input: string): string {
  return input
    .replace(/hxxps:\/\//gi, "https://")
    .replace(/hxxp:\/\//gi, "http://")
    .replace(/\[\.\]/g, ".")
    .replace(/\(\.\)/g, ".")
    .replace(/\{\.\}/g, ".")
    .replace(/\[dot\]/gi, ".")
    .replace(/\(dot\)/gi, ".")
    .replace(/\{dot\}/gi, ".")
    .replace(/\[@\]/g, "@")
    .replace(/\(@\)/g, "@")
    .replace(/\{@\}/g, "@")
    .replace(/\[at\]/gi, "@")
    .replace(/\(at\)/gi, "@")
    .replace(/\{at\}/gi, "@");
}

function trimTrailingPunctuation(value: string): string {
  return value.replace(/[),.;:!?]+$/g, "");
}

function uniqueSorted(values: string[]): string[] {
  return [...new Set(values)].sort((a, b) => a.localeCompare(b));
}

function extractUrlsFromText(input: string): string[] {
  return uniqueSorted(
    [...input.matchAll(URL_PATTERN)].map((match) => trimTrailingPunctuation(match[0]))
  );
}

function extractEmailsFromText(input: string): string[] {
  return uniqueSorted(
    [...input.matchAll(EMAIL_PATTERN)].map((match) =>
      trimTrailingPunctuation(match[0]).toLowerCase()
    )
  );
}

function extractIpv4FromText(input: string): string[] {
  return uniqueSorted([...input.matchAll(IPV4_PATTERN)].map((match) => match[0]));
}

function isIpv4Like(value: string): boolean {
  return /^\d+(?:\.\d+){3}$/.test(value);
}

function extractDomainsFromText(input: string): string[] {
  const urls = extractUrlsFromText(input);
  const emails = extractEmailsFromText(input);
  const domains: string[] = [];

  for (const url of urls) {
    try {
      domains.push(new URL(url).hostname.toLowerCase());
    } catch {
      // The URL pattern is intentionally broad. Ignore values URL cannot normalize.
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

function extractHashesFromText(input: string): Omit<ExtractHashesOutput, "total_count"> {
  return {
    md5_hashes: uniqueSorted([...input.matchAll(MD5_PATTERN)].map((match) => match[0].toLowerCase())),
    sha1_hashes: uniqueSorted([...input.matchAll(SHA1_PATTERN)].map((match) => match[0].toLowerCase())),
    sha256_hashes: uniqueSorted([...input.matchAll(SHA256_PATTERN)].map((match) => match[0].toLowerCase())),
    sha512_hashes: uniqueSorted([...input.matchAll(SHA512_PATTERN)].map((match) => match[0].toLowerCase())),
  };
}

export const extractUrlsSkill: Skill<string, ExtractUrlsOutput> = {
  metadata: {
    name: "extract_urls",
    version: "0.1.0",
    category: "parser",
    description: "Extract simple HTTP and HTTPS URLs from text.",
    execution: { mode: "local_only", network_access: "none", deterministic: true },
    permissions: localOnlyPermissions,
  },

  run(input: string) {
    assertString(input, "extract_urls");
    const urls = extractUrlsFromText(normalizeDefangedText(input));
    return { urls, count: urls.length };
  },
};

export const extractDomainsSkill: Skill<string, ExtractDomainsOutput> = {
  metadata: {
    name: "extract_domains",
    version: "0.1.0",
    category: "parser",
    description: "Extract simple domain names from text, URLs, and email addresses.",
    execution: { mode: "local_only", network_access: "none", deterministic: true },
    permissions: localOnlyPermissions,
  },

  run(input: string) {
    assertString(input, "extract_domains");
    const domains = extractDomainsFromText(normalizeDefangedText(input));
    return { domains, count: domains.length };
  },
};

export const extractEmailsSkill: Skill<string, ExtractEmailsOutput> = {
  metadata: {
    name: "extract_emails",
    version: "0.1.0",
    category: "parser",
    description: "Extract email addresses from text.",
    execution: { mode: "local_only", network_access: "none", deterministic: true },
    permissions: localOnlyPermissions,
  },

  run(input: string) {
    assertString(input, "extract_emails");
    const email_addresses = extractEmailsFromText(normalizeDefangedText(input));
    return { email_addresses, count: email_addresses.length };
  },
};

export const extractIpv4Skill: Skill<string, ExtractIpv4Output> = {
  metadata: {
    name: "extract_ipv4",
    version: "0.1.0",
    category: "parser",
    description: "Extract valid IPv4 addresses from text.",
    execution: { mode: "local_only", network_access: "none", deterministic: true },
    permissions: localOnlyPermissions,
  },

  run(input: string) {
    assertString(input, "extract_ipv4");
    const ipv4_addresses = extractIpv4FromText(normalizeDefangedText(input));
    return { ipv4_addresses, count: ipv4_addresses.length };
  },
};

export const extractHashesSkill: Skill<string, ExtractHashesOutput> = {
  metadata: {
    name: "extract_hashes",
    version: "0.1.0",
    category: "parser",
    description: "Extract MD5, SHA-1, SHA-256, and SHA-512 hex hashes from text.",
    execution: { mode: "local_only", network_access: "none", deterministic: true },
    permissions: localOnlyPermissions,
  },

  run(input: string) {
    assertString(input, "extract_hashes");
    const hashes = extractHashesFromText(input);
    return {
      ...hashes,
      total_count:
        hashes.md5_hashes.length +
        hashes.sha1_hashes.length +
        hashes.sha256_hashes.length +
        hashes.sha512_hashes.length,
    };
  },
};
