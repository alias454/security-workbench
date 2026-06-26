import type { Skill } from "@security-workbench/schemas";

export interface ParsedUrl {
  href: string;
  protocol: string;
  hostname: string;
  port: string;
  pathname: string;
  search: string;
  hash: string;
  username_present: boolean;
  password_present: boolean;
  query_params: Record<string, string[]>;
}

function safeHref(url: URL): string {
  const clone = new URL(url.href);

  if (clone.username.length > 0) {
    clone.username = "[REDACTED]";
  }

  if (clone.password.length > 0) {
    clone.password = "[REDACTED]";
  }

  return clone.href;
}

export const parseUrlSkill: Skill<string, ParsedUrl> = {
  metadata: {
    name: "parse_url",
    version: "0.1.0",
    category: "parser",
    description: "Parse a URL into structured components without exposing credentials.",
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
  },

  run(input: string) {
    if (typeof input !== "string") {
      throw new Error("parse_url input must be a string");
    }

    const url = new URL(input);
    const query_params: Record<string, string[]> = {};

    for (const [key, value] of url.searchParams.entries()) {
      query_params[key] ??= [];
      query_params[key].push(value);
    }

    return {
      href: safeHref(url),
      protocol: url.protocol,
      hostname: url.hostname,
      port: url.port,
      pathname: url.pathname,
      search: url.search,
      hash: url.hash,
      username_present: url.username.length > 0,
      password_present: url.password.length > 0,
      query_params,
    };
  },
};
