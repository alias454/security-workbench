import type { CliRunFormat } from "./args.js";

export interface SkillRunFormatOptions {
  format: CliRunFormat;
  unsafe?: boolean;
}

export interface FormattableSkillRunResult {
  run_id: string;
  status: string;
  skill: {
    name: string;
    version: string;
  };
  policy: {
    allow_network: boolean;
    network_used: boolean;
    external_sinks: readonly string[];
  };
  output?: unknown;
  errors: readonly string[];
  warnings: readonly string[];
}

interface DisplayOptions {
  unsafe: boolean;
}

const EMAIL_PATTERN = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi;
const IPV4_PATTERN = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
const DOMAIN_PATTERN = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b/gi;

function formatJson(result: FormattableSkillRunResult): string {
  return JSON.stringify(result, null, 2);
}

function replaceDots(value: string): string {
  return value.replace(/\./g, "[.]");
}

function defangIocLikeText(value: string): string {
  let output = value
    .replace(/\bhttps:\/\//gi, "hxxps://")
    .replace(/\bhttp:\/\//gi, "hxxp://");

  output = output.replace(EMAIL_PATTERN, (match) => replaceDots(match.replace("@", "[@]")));
  output = output.replace(IPV4_PATTERN, (match) => replaceDots(match));
  output = output.replace(DOMAIN_PATTERN, (match) => replaceDots(match));

  return output;
}

function displayString(value: string, options: DisplayOptions): string {
  return options.unsafe ? value : defangIocLikeText(value);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function sanitizedForDisplay(
  value: unknown,
  options: DisplayOptions,
  seen = new WeakSet<object>()
): unknown {
  if (typeof value === "string") {
    return displayString(value, options);
  }

  if (Array.isArray(value)) {
    if (seen.has(value)) {
      return "[CIRCULAR]";
    }

    seen.add(value);
    return value.map((entry) => sanitizedForDisplay(entry, options, seen));
  }

  if (isRecord(value)) {
    if (seen.has(value)) {
      return "[CIRCULAR]";
    }

    seen.add(value);
    return Object.fromEntries(
      Object.entries(value).map(([key, entry]) => [key, sanitizedForDisplay(entry, options, seen)])
    );
  }

  return value;
}

function formatList(values: readonly string[], options: DisplayOptions): string {
  if (values.length === 0) {
    return "[]";
  }

  return values.map((value) => displayString(value, options)).join(", ");
}

function formatOutput(value: unknown, options: DisplayOptions): string {
  if (value === undefined) {
    return "(none)";
  }

  if (typeof value === "string") {
    return displayString(value, options);
  }

  return JSON.stringify(sanitizedForDisplay(value, options), null, 2);
}

function section(title: string, body: readonly string[]): string[] {
  return [title, "-".repeat(title.length), ...body];
}

function outputRecord(result: FormattableSkillRunResult): Record<string, unknown> | undefined {
  return isRecord(result.output) ? result.output : undefined;
}

function recordValue(record: Record<string, unknown>, key: string): Record<string, unknown> | undefined {
  const value = record[key];
  return isRecord(value) ? value : undefined;
}

function stringArray(record: Record<string, unknown>, key: string): readonly string[] {
  const value = record[key];

  if (!Array.isArray(value)) {
    return [];
  }

  return value.filter((entry): entry is string => typeof entry === "string");
}

function numberValue(record: Record<string, unknown>, key: string): number | undefined {
  const value = record[key];
  return typeof value === "number" ? value : undefined;
}

function recordArray(record: Record<string, unknown>, key: string): readonly Record<string, unknown>[] {
  const value = record[key];

  if (!Array.isArray(value)) {
    return [];
  }

  return value.filter((entry): entry is Record<string, unknown> => isRecord(entry));
}

function booleanText(value: unknown): string {
  return value === true ? "yes" : value === false ? "no" : "unknown";
}

function bulletList(values: readonly string[], options: DisplayOptions): string[] {
  if (values.length === 0) {
    return ["- none"];
  }

  return values.map((value) => `- ${displayString(value, options)}`);
}

function namedList(title: string, values: readonly string[], options: DisplayOptions): string[] {
  return ["", `${title} (${values.length})`, ...bulletList(values, options)];
}

function renderExtractIocs(record: Record<string, unknown>, options: DisplayOptions): string[] {
  return [
    ...section("IOC Extraction", [
      ...namedList("URLs", stringArray(record, "urls"), options),
      ...namedList("Domains", stringArray(record, "domains"), options),
      ...namedList("IPv4 addresses", stringArray(record, "ipv4_addresses"), options),
      ...namedList("Email addresses", stringArray(record, "email_addresses"), options),
      ...namedList("SHA-256 hashes", stringArray(record, "sha256_hashes"), options),
    ]),
  ];
}

function renderSimpleArray(
  title: string,
  record: Record<string, unknown>,
  key: string,
  options: DisplayOptions
): string[] {
  const values = stringArray(record, key);
  return section(title, [`Count: ${numberValue(record, "count") ?? values.length}`, "", ...bulletList(values, options)]);
}

function renderExtractHashes(record: Record<string, unknown>, options: DisplayOptions): string[] {
  return section("Hash Extraction", [
    `Total count: ${numberValue(record, "total_count") ?? "unknown"}`,
    ...namedList("MD5", stringArray(record, "md5_hashes"), options),
    ...namedList("SHA-1", stringArray(record, "sha1_hashes"), options),
    ...namedList("SHA-256", stringArray(record, "sha256_hashes"), options),
    ...namedList("SHA-512", stringArray(record, "sha512_hashes"), options),
  ]);
}

function renderCsv(record: Record<string, unknown>, options: DisplayOptions): string[] | undefined {
  const observed = recordValue(record, "observed");
  if (!observed) {
    return undefined;
  }

  const headers = stringArray(observed, "headers");
  const irregularRows = Array.isArray(observed.irregular_rows) ? observed.irregular_rows : [];

  const lines = section("CSV", [
    `Rows: ${numberValue(observed, "row_count") ?? "unknown"}`,
    `Data rows: ${numberValue(observed, "data_row_count") ?? "unknown"}`,
    `Columns: ${numberValue(observed, "column_count") ?? "unknown"}`,
    `Header: ${booleanText(observed.has_header)}${typeof observed.header_source === "string" ? ` (${observed.header_source})` : ""}`,
    `Delimiter: ${typeof observed.delimiter === "string" ? observed.delimiter : "unknown"}`,
    `Line ending: ${typeof observed.line_ending === "string" ? observed.line_ending : "unknown"}`,
    ...namedList("Headers", headers, options),
  ]);

  if (irregularRows.length > 0) {
    lines.push("", `Irregular rows (${irregularRows.length})`);
    for (const row of irregularRows) {
      if (isRecord(row)) {
        lines.push(
          `- row ${String(row.row_index)}: expected ${String(row.expected_columns)}, actual ${String(row.actual_columns)}`
        );
      }
    }
  }

  return lines;
}

function renderYaml(record: Record<string, unknown>, options: DisplayOptions): string[] | undefined {
  const observed = recordValue(record, "observed");
  if (!observed) {
    return undefined;
  }

  return section("YAML", [
    `Documents: ${numberValue(observed, "document_count") ?? "unknown"}`,
    `Value type: ${typeof observed.value_type === "string" ? observed.value_type : "unknown"}`,
    ...namedList("Top-level keys", stringArray(observed, "keys"), options),
  ]);
}

function renderPackageJson(record: Record<string, unknown>, options: DisplayOptions): string[] | undefined {
  const artifact = recordValue(record, "artifact");
  const observed = recordValue(record, "observed");
  if (!observed) {
    return undefined;
  }

  const scripts = recordValue(observed, "scripts");
  const dependencySections = recordValue(observed, "dependency_sections");
  const dependencies = dependencySections ? recordValue(dependencySections, "dependencies") : undefined;
  const devDependencies = dependencySections ? recordValue(dependencySections, "devDependencies") : undefined;

  return section("package.json", [
    `Name: ${displayString(String(observed.name ?? artifact?.name ?? "unknown"), options)}`,
    `Version: ${String(observed.version ?? artifact?.version ?? "unknown")}`,
    `Private: ${booleanText(observed.private)}`,
    `License: ${String(observed.license ?? "none")}`,
    `Scripts: ${scripts ? numberValue(scripts, "count") ?? 0 : 0}`,
    `Dependencies: ${dependencies ? numberValue(dependencies, "count") ?? 0 : 0}`,
    `Dev dependencies: ${devDependencies ? numberValue(devDependencies, "count") ?? 0 : 0}`,
    ...namedList("Script names", scripts ? stringArray(scripts, "names") : [], options),
    ...namedList("Dependency names", dependencies ? stringArray(dependencies, "names") : [], options),
  ]);
}



function renderIpPrefixList(record: Record<string, unknown>, options: DisplayOptions): string[] | undefined {
  const observed = recordValue(record, "observed");
  if (!observed) {
    return undefined;
  }

  const entries = recordArray(observed, "entries");
  const invalidLines = recordArray(observed, "invalid_lines");
  const duplicateEntries = recordArray(observed, "duplicate_entries");
  const prefixLengths = recordValue(observed, "prefix_lengths");
  const prefixLengthLines = prefixLengths
    ? Object.entries(prefixLengths)
        .filter(([, value]) => typeof value === "number")
        .sort(([left], [right]) => Number(left) - Number(right))
        .map(([length, count]) => `/${length}: ${String(count)}`)
    : [];
  const entryLines = entries.slice(0, 20).map((entry) => {
    const line = String(entry.line ?? "?");
    const normalizedValue = String(entry.normalized_value ?? entry.value ?? "unknown");
    const kind = String(entry.kind ?? "unknown");
    const version = String(entry.ip_version ?? "unknown");
    return `line ${line}: ${displayString(normalizedValue, options)} (${version} ${kind})`;
  });
  const invalidLineSummaries = invalidLines.slice(0, 20).map((entry) => {
    const line = String(entry.line ?? "?");
    const value = String(entry.value ?? "unknown");
    const reason = String(entry.reason ?? "invalid");
    return `line ${line}: ${displayString(value, options)} - ${reason}`;
  });
  const duplicateLineSummaries = duplicateEntries.slice(0, 20).map((entry) => {
    const value = String(entry.normalized_value ?? "unknown");
    return `${displayString(value, options)} first_line=${String(entry.first_line ?? "?")} duplicate_line=${String(entry.duplicate_line ?? "?")} occurrences=${String(entry.occurrences ?? "?")}`;
  });

  return section("IP Prefix List", [
    `Physical lines: ${numberValue(observed, "physical_line_count") ?? "unknown"}`,
    `Line ending: ${typeof observed.line_ending === "string" ? observed.line_ending : "unknown"}`,
    `Valid entries: ${numberValue(observed, "valid_entry_count") ?? entries.length}`,
    `Host addresses: ${numberValue(observed, "host_address_count") ?? "unknown"}`,
    `CIDR prefixes: ${numberValue(observed, "cidr_prefix_count") ?? "unknown"}`,
    `IPv4 entries: ${numberValue(observed, "ipv4_entry_count") ?? "unknown"}`,
    `IPv6 entries: ${numberValue(observed, "ipv6_entry_count") ?? "unknown"}`,
    `Malformed lines: ${numberValue(observed, "malformed_line_count") ?? invalidLines.length}`,
    `Duplicate entries: ${numberValue(observed, "duplicate_entry_count") ?? duplicateEntries.length}`,
    `Blank/comment/inline-comment lines: ${String(numberValue(observed, "blank_line_count") ?? "unknown")}/${String(numberValue(observed, "comment_line_count") ?? "unknown")}/${String(numberValue(observed, "inline_comment_count") ?? "unknown")}`,
    ...namedList("Prefix lengths", prefixLengthLines, options),
    ...namedList("Entries", entryLines, options),
    ...namedList("Duplicates", duplicateLineSummaries, options),
    ...namedList("Invalid lines", invalidLineSummaries, options),
  ]);
}

function renderAsnList(record: Record<string, unknown>, options: DisplayOptions): string[] | undefined {
  const observed = recordValue(record, "observed");
  if (!observed) {
    return undefined;
  }

  const entries = recordArray(observed, "entries");
  const invalidLines = recordArray(observed, "invalid_lines");
  const duplicateEntries = recordArray(observed, "duplicate_entries");
  const entryLines = entries.slice(0, 20).map((entry) => {
    const line = String(entry.line ?? "?");
    const normalizedAsn = String(entry.normalized_asn ?? "unknown");
    const note = typeof entry.note === "string" && entry.note.length > 0 ? ` note=${displayString(entry.note, options)}` : "";
    return `line ${line}: ${displayString(normalizedAsn, options)}${note}`;
  });
  const invalidLineSummaries = invalidLines.slice(0, 20).map((entry) => {
    const line = String(entry.line ?? "?");
    const value = String(entry.value ?? "unknown");
    const reason = String(entry.reason ?? "invalid");
    return `line ${line}: ${displayString(value, options)} - ${reason}`;
  });
  const duplicateLineSummaries = duplicateEntries.slice(0, 20).map((entry) => {
    const value = String(entry.normalized_asn ?? "unknown");
    return `${displayString(value, options)} first_line=${String(entry.first_line ?? "?")} duplicate_line=${String(entry.duplicate_line ?? "?")} occurrences=${String(entry.occurrences ?? "?")}`;
  });

  return section("ASN List", [
    `Physical lines: ${numberValue(observed, "physical_line_count") ?? "unknown"}`,
    `Line ending: ${typeof observed.line_ending === "string" ? observed.line_ending : "unknown"}`,
    `Valid entries: ${numberValue(observed, "valid_entry_count") ?? entries.length}`,
    `Unique ASNs: ${numberValue(observed, "unique_asn_count") ?? "unknown"}`,
    `Malformed lines: ${numberValue(observed, "malformed_line_count") ?? invalidLines.length}`,
    `Duplicate entries: ${numberValue(observed, "duplicate_entry_count") ?? duplicateEntries.length}`,
    `Blank/comment/inline-comment lines: ${String(numberValue(observed, "blank_line_count") ?? "unknown")}/${String(numberValue(observed, "comment_line_count") ?? "unknown")}/${String(numberValue(observed, "inline_comment_count") ?? "unknown")}`,
    ...namedList("ASNs", stringArray(observed, "normalized_asns"), options),
    ...namedList("Entries", entryLines, options),
    ...namedList("Duplicates", duplicateLineSummaries, options),
    ...namedList("Invalid lines", invalidLineSummaries, options),
  ]);
}

function renderAsnAllowDenyList(record: Record<string, unknown>, options: DisplayOptions): string[] | undefined {
  const observed = recordValue(record, "observed");
  if (!observed) {
    return undefined;
  }

  const entries = recordArray(observed, "entries");
  const invalidLines = recordArray(observed, "invalid_lines");
  const duplicateEntries = recordArray(observed, "duplicate_entries");
  const conflictingEntries = recordArray(observed, "conflicting_entries");
  const entryLines = entries.slice(0, 20).map((entry) => {
    const line = String(entry.line ?? "?");
    const action = String(entry.action ?? "unknown");
    const normalizedAsn = String(entry.normalized_asn ?? "unknown");
    const reason = typeof entry.reason === "string" && entry.reason.length > 0 ? ` reason=${displayString(entry.reason, options)}` : "";
    return `line ${line}: ${action} ${displayString(normalizedAsn, options)}${reason}`;
  });
  const invalidLineSummaries = invalidLines.slice(0, 20).map((entry) => {
    const line = String(entry.line ?? "?");
    const value = String(entry.value ?? "unknown");
    const reason = String(entry.reason ?? "invalid");
    return `line ${line}: ${displayString(value, options)} - ${reason}`;
  });
  const duplicateLineSummaries = duplicateEntries.slice(0, 20).map((entry) => {
    const action = String(entry.action ?? "unknown");
    const value = String(entry.normalized_asn ?? "unknown");
    return `${action} ${displayString(value, options)} first_line=${String(entry.first_line ?? "?")} duplicate_line=${String(entry.duplicate_line ?? "?")} occurrences=${String(entry.occurrences ?? "?")}`;
  });
  const conflictLineSummaries = conflictingEntries.slice(0, 20).map((entry) => {
    const value = String(entry.normalized_asn ?? "unknown");
    const allowLines = Array.isArray(entry.allow_lines) ? entry.allow_lines.join(",") : "?";
    const denyLines = Array.isArray(entry.deny_lines) ? entry.deny_lines.join(",") : "?";
    return `${displayString(value, options)} allow_lines=${allowLines} deny_lines=${denyLines}`;
  });

  return section("ASN Allow/Deny List", [
    `Physical lines: ${numberValue(observed, "physical_line_count") ?? "unknown"}`,
    `Line ending: ${typeof observed.line_ending === "string" ? observed.line_ending : "unknown"}`,
    `Valid entries: ${numberValue(observed, "valid_entry_count") ?? entries.length}`,
    `Allow entries: ${numberValue(observed, "allow_entry_count") ?? "unknown"}`,
    `Deny entries: ${numberValue(observed, "deny_entry_count") ?? "unknown"}`,
    `Unique ASNs: ${numberValue(observed, "unique_asn_count") ?? "unknown"}`,
    `Malformed lines: ${numberValue(observed, "malformed_line_count") ?? invalidLines.length}`,
    `Duplicate entries: ${numberValue(observed, "duplicate_entry_count") ?? duplicateEntries.length}`,
    `Conflicting entries: ${numberValue(observed, "conflict_entry_count") ?? conflictingEntries.length}`,
    `Blank/comment/inline-comment lines: ${String(numberValue(observed, "blank_line_count") ?? "unknown")}/${String(numberValue(observed, "comment_line_count") ?? "unknown")}/${String(numberValue(observed, "inline_comment_count") ?? "unknown")}`,
    ...namedList("Entries", entryLines, options),
    ...namedList("Duplicates", duplicateLineSummaries, options),
    ...namedList("Conflicts", conflictLineSummaries, options),
    ...namedList("Invalid lines", invalidLineSummaries, options),
  ]);
}

function renderAsnObservations(record: Record<string, unknown>, options: DisplayOptions): string[] | undefined {
  const observed = recordValue(record, "observed");
  if (!observed) {
    return undefined;
  }

  const entries = recordArray(observed, "entries");
  const repeatedAsns = recordArray(observed, "repeated_asns");
  const invalidLines = recordArray(observed, "invalid_lines");
  const entryLines = entries.slice(0, 20).map((entry) => {
    const line = String(entry.line ?? "?");
    const normalizedAsn = String(entry.normalized_asn ?? "unknown");
    const indicator = typeof entry.indicator === "string" ? ` indicator=${displayString(entry.indicator, options)}` : "";
    const source = typeof entry.source === "string" ? ` source=${displayString(entry.source, options)}` : "";
    return `line ${line}: ${displayString(normalizedAsn, options)}${indicator}${source}`;
  });
  const repeatedAsnLines = repeatedAsns.slice(0, 20).map((entry) => {
    const normalizedAsn = String(entry.normalized_asn ?? "unknown");
    const lines = Array.isArray(entry.lines) ? entry.lines.join(",") : "?";
    return `${displayString(normalizedAsn, options)} count=${String(entry.count ?? "?")} lines=${lines}`;
  });
  const invalidLineSummaries = invalidLines.slice(0, 20).map((entry) => {
    const line = String(entry.line ?? "?");
    const value = String(entry.value ?? "unknown");
    const reason = String(entry.reason ?? "invalid");
    return `line ${line}: ${displayString(value, options)} - ${reason}`;
  });

  return section("ASN Observations", [
    `Physical lines: ${numberValue(observed, "physical_line_count") ?? "unknown"}`,
    `Line ending: ${typeof observed.line_ending === "string" ? observed.line_ending : "unknown"}`,
    `Valid observations: ${numberValue(observed, "valid_observation_count") ?? entries.length}`,
    `Unique ASNs: ${numberValue(observed, "unique_asn_count") ?? "unknown"}`,
    `Repeated ASNs: ${numberValue(observed, "repeated_asn_count") ?? repeatedAsns.length}`,
    `With indicator/source/timestamp: ${String(numberValue(observed, "observations_with_indicator_count") ?? "unknown")}/${String(numberValue(observed, "observations_with_source_count") ?? "unknown")}/${String(numberValue(observed, "observations_with_timestamp_count") ?? "unknown")}`,
    `Malformed lines: ${numberValue(observed, "malformed_line_count") ?? invalidLines.length}`,
    `Blank/comment/inline-comment lines: ${String(numberValue(observed, "blank_line_count") ?? "unknown")}/${String(numberValue(observed, "comment_line_count") ?? "unknown")}/${String(numberValue(observed, "inline_comment_count") ?? "unknown")}`,
    ...namedList("Observations", entryLines, options),
    ...namedList("Repeated ASNs", repeatedAsnLines, options),
    ...namedList("Invalid lines", invalidLineSummaries, options),
  ]);
}

function renderBgpPrefixTable(record: Record<string, unknown>, options: DisplayOptions): string[] | undefined {
  const observed = recordValue(record, "observed");
  if (!observed) {
    return undefined;
  }

  const entries = recordArray(observed, "entries");
  const invalidLines = recordArray(observed, "invalid_lines");
  const duplicateEntries = recordArray(observed, "duplicate_entries");
  const conflictingPrefixes = recordArray(observed, "conflicting_prefixes");
  const prefixLengths = recordValue(observed, "prefix_lengths");
  const prefixLengthLines = prefixLengths
    ? Object.entries(prefixLengths)
        .filter(([, value]) => typeof value === "number")
        .sort(([left], [right]) => Number(left) - Number(right))
        .map(([length, count]) => `/${length}: ${String(count)}`)
    : [];
  const entryLines = entries.slice(0, 20).map((entry) => {
    const line = String(entry.line ?? "?");
    const prefix = String(entry.normalized_prefix ?? entry.prefix ?? "unknown");
    const originAsn = String(entry.origin_asn ?? "unknown");
    const version = String(entry.ip_version ?? "unknown");
    return `line ${line}: ${displayString(prefix, options)} origin=${displayString(originAsn, options)} (${version})`;
  });
  const duplicateLineSummaries = duplicateEntries.slice(0, 20).map((entry) => {
    const prefix = String(entry.normalized_prefix ?? "unknown");
    const originAsn = String(entry.origin_asn ?? "unknown");
    return `${displayString(prefix, options)} origin=${displayString(originAsn, options)} first_line=${String(entry.first_line ?? "?")} duplicate_line=${String(entry.duplicate_line ?? "?")} occurrences=${String(entry.occurrences ?? "?")}`;
  });
  const conflictLineSummaries = conflictingPrefixes.slice(0, 20).map((entry) => {
    const prefix = String(entry.normalized_prefix ?? "unknown");
    const originAsns = Array.isArray(entry.origin_asns) ? entry.origin_asns.join(",") : "?";
    const lines = Array.isArray(entry.lines) ? entry.lines.join(",") : "?";
    return `${displayString(prefix, options)} origin_asns=${originAsns} lines=${lines}`;
  });
  const invalidLineSummaries = invalidLines.slice(0, 20).map((entry) => {
    const line = String(entry.line ?? "?");
    const value = String(entry.value ?? "unknown");
    const reason = String(entry.reason ?? "invalid");
    return `line ${line}: ${displayString(value, options)} - ${reason}`;
  });

  return section("BGP Prefix Table", [
    `Physical lines: ${numberValue(observed, "physical_line_count") ?? "unknown"}`,
    `Line ending: ${typeof observed.line_ending === "string" ? observed.line_ending : "unknown"}`,
    `Valid entries: ${numberValue(observed, "valid_entry_count") ?? entries.length}`,
    `IPv4 prefixes: ${numberValue(observed, "ipv4_prefix_count") ?? "unknown"}`,
    `IPv6 prefixes: ${numberValue(observed, "ipv6_prefix_count") ?? "unknown"}`,
    `Unique prefixes: ${numberValue(observed, "unique_prefix_count") ?? "unknown"}`,
    `Unique origin ASNs: ${numberValue(observed, "unique_origin_asn_count") ?? "unknown"}`,
    `Duplicate entries: ${numberValue(observed, "duplicate_entry_count") ?? duplicateEntries.length}`,
    `Conflicting prefixes: ${numberValue(observed, "conflicting_prefix_count") ?? conflictingPrefixes.length}`,
    `Malformed lines: ${numberValue(observed, "malformed_line_count") ?? invalidLines.length}`,
    ...namedList("Prefix lengths", prefixLengthLines, options),
    ...namedList("Entries", entryLines, options),
    ...namedList("Duplicates", duplicateLineSummaries, options),
    ...namedList("Conflicting prefixes", conflictLineSummaries, options),
    ...namedList("Invalid lines", invalidLineSummaries, options),
  ]);
}

function renderBrowserExtensionPermissionReview(
  record: Record<string, unknown>,
  options: DisplayOptions
): string[] | undefined {
  const artifact = recordValue(record, "artifact");
  const observed = recordValue(record, "observed");
  if (!observed) {
    return undefined;
  }

  const signals = recordArray(record, "signals");
  const evidence = recordArray(record, "evidence");
  const signalLines = signals.slice(0, 20).map((signal) => {
    const type = String(signal.type ?? "unknown");
    const summary = String(signal.summary ?? "");
    const refs = Array.isArray(signal.evidence_refs) ? signal.evidence_refs.length : 0;
    return `${type}: ${summary} evidence_refs=${refs}`;
  });

  return section("Browser Extension Permission Review", [
    `Name: ${displayString(String(artifact?.name ?? "unknown"), options)}`,
    `Version: ${String(artifact?.version ?? "unknown")}`,
    `Manifest version: ${String(artifact?.manifest_version ?? "unknown")}`,
    `Manifest generation: ${String(observed.manifest_generation ?? "unknown")}`,
    `Signals: ${numberValue(observed, "signal_count") ?? signals.length}`,
    `Evidence records: ${numberValue(observed, "evidence_count") ?? evidence.length}`,
    `Source warnings: ${numberValue(observed, "source_warning_count") ?? 0}`,
    ...namedList("Broad host permissions", stringArray(observed, "broad_host_permissions"), options),
    ...namedList("Broad optional host permissions", stringArray(observed, "broad_optional_host_permissions"), options),
    ...namedList("Wildcard host permissions", stringArray(observed, "wildcard_host_permissions"), options),
    ...namedList("Notable API permissions", stringArray(observed, "notable_api_permissions"), options),
    ...namedList("Notable optional API permissions", stringArray(observed, "notable_optional_api_permissions"), options),
    ...namedList("Broad content script matches", stringArray(observed, "broad_content_script_matches"), options),
    "",
    "Surfaces",
    `- background present: ${booleanText(observed.background_present)}`,
    `- background type: ${String(observed.background_type ?? "unknown")}`,
    `- externally_connectable present: ${booleanText(observed.externally_connectable_present)}`,
    `- web accessible resources present: ${booleanText(observed.web_accessible_resources_present)}`,
    `- web accessible resource count: ${numberValue(observed, "web_accessible_resource_count") ?? 0}`,
    `- update_url present: ${booleanText(observed.update_url_present)}`,
    `- oauth2 present: ${booleanText(observed.oauth2_present)}`,
    `- content_security_policy present: ${booleanText(observed.content_security_policy_present)}`,
    ...namedList("Externally connectable matches", stringArray(observed, "externally_connectable_matches"), options),
    ...namedList("Web accessible resource matches", stringArray(observed, "web_accessible_resource_matches"), options),
    ...namedList("Signals", signalLines, options),
  ]);
}

function renderBrowserExtensionRiskScore(
  record: Record<string, unknown>,
  options: DisplayOptions
): string[] | undefined {
  const artifact = recordValue(record, "artifact");
  const observed = recordValue(record, "observed");
  const risk = recordValue(record, "risk");
  if (!observed) {
    return undefined;
  }

  const categoryScores = recordValue(observed, "category_scores");
  const categoryLines = categoryScores
    ? Object.entries(categoryScores)
        .filter(([, value]) => typeof value === "number")
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, value]) => `- ${key}: ${String(value)}`)
    : ["- none"];

  const contributions = recordArray(record, "contributions");
  const contributionLines = contributions.slice(0, 20).map((contribution) => {
    const points = typeof contribution.points === "number" ? contribution.points : "unknown";
    const signalType = String(contribution.signal_type ?? "unknown");
    const category = String(contribution.category ?? "unknown");
    const evidenceRefs = Array.isArray(contribution.evidence_refs) ? contribution.evidence_refs.length : 0;
    return `${signalType}: +${String(points)} (${category}) evidence_refs=${evidenceRefs}`;
  });

  return section("Browser Extension Risk Score", [
    `Name: ${displayString(String(artifact?.name ?? "unknown"), options)}`,
    `Version: ${String(artifact?.version ?? "unknown")}`,
    `Manifest version: ${String(artifact?.manifest_version ?? "unknown")}`,
    `Score: ${String(observed.score ?? "unknown")}/${String(observed.max_score ?? "unknown")}`,
    `Raw score: ${String(observed.raw_score ?? "unknown")}`,
    `Capped: ${booleanText(observed.capped)}`,
    `Review attention: ${String(observed.review_attention_level ?? "unknown")}`,
    `Risk level: ${String(observed.risk_level ?? risk?.level ?? "unknown")}`,
    `Confidence: ${String(observed.confidence ?? risk?.confidence ?? "unknown")}`,
    `Score model: ${String(observed.score_model ?? "unknown")}`,
    `Review signals: ${numberValue(observed, "review_signal_count") ?? "unknown"}`,
    `Contributing signals: ${numberValue(observed, "contributing_signal_count") ?? contributions.length}`,
    `Source warnings: ${numberValue(observed, "source_warning_count") ?? 0}`,
    "",
    "Category scores",
    ...categoryLines,
    ...namedList("Contributing signal types", stringArray(observed, "contributing_signal_types"), options),
    ...namedList("Unmatched signal types", stringArray(observed, "unmatched_signal_types"), options),
    ...namedList("Contributions", contributionLines, options),
    ...namedList("Limitations", stringArray(record, "limitations"), options),
  ]);
}


function renderBrowserExtensionFinding(
  record: Record<string, unknown>,
  options: DisplayOptions
): string[] | undefined {
  const artifact = recordValue(record, "artifact");
  const observed = recordValue(record, "observed");
  const finding = recordValue(record, "finding");
  if (!observed || !finding) {
    return undefined;
  }

  const markdown = typeof record.markdown === "string" ? record.markdown : "";
  const observedBehavior = stringArray(finding, "observed_behavior");
  const inferredRisk = stringArray(finding, "inferred_risk");
  const mitigations = stringArray(finding, "mitigations");
  const openQuestions = stringArray(finding, "open_questions");

  return section("Browser Extension Finding", [
    `Name: ${displayString(String(artifact?.name ?? "unknown"), options)}`,
    `Version: ${String(artifact?.version ?? "unknown")}`,
    `Manifest version: ${String(artifact?.manifest_version ?? "unknown")}`,
    `Finding ID: ${String(finding.id ?? "unknown")}`,
    `Status: ${String(finding.status ?? "unknown")}`,
    `Score: ${String(observed.score ?? "unknown")}/${String(observed.max_score ?? "unknown")}`,
    `Review attention: ${String(observed.review_attention_level ?? "unknown")}`,
    `Risk level: ${String(observed.risk_level ?? "unknown")}`,
    `Confidence: ${String(observed.confidence ?? "unknown")}`,
    `Finding template: ${String(observed.finding_template ?? "unknown")}`,
    `Evidence refs: ${numberValue(observed, "evidence_ref_count") ?? 0}`,
    `Signal refs: ${numberValue(observed, "signal_ref_count") ?? 0}`,
    `Markdown lines: ${numberValue(observed, "markdown_line_count") ?? (markdown.length > 0 ? markdown.split("\n").length : 0)}`,
    "",
    "Summary",
    displayString(String(finding.summary ?? ""), options),
    ...namedList("Observed behavior", observedBehavior, options),
    ...namedList("Inferred risk", inferredRisk, options),
    ...namedList("Recommended review actions", mitigations, options),
    ...namedList("Open questions", openQuestions, options),
  ]);
}

function renderBrowserExtensionManifest(
  record: Record<string, unknown>,
  options: DisplayOptions
): string[] | undefined {
  const artifact = recordValue(record, "artifact");
  const observed = recordValue(record, "observed");
  if (!observed) {
    return undefined;
  }

  const contentScripts = recordValue(observed, "content_scripts");
  const background = recordValue(observed, "background");
  const webAccessibleResources = recordValue(observed, "web_accessible_resources");

  return section("Browser Extension Manifest", [
    `Name: ${displayString(String(observed.name ?? artifact?.name ?? "unknown"), options)}`,
    `Version: ${String(observed.version ?? artifact?.version ?? "unknown")}`,
    `Manifest version: ${String(observed.manifest_version ?? artifact?.manifest_version ?? "unknown")}`,
    "",
    "Compatibility",
    `- detected generation: ${typeof observed.detected_manifest_generation === "string" ? observed.detected_manifest_generation : "unknown"}`,
    `- likely browser families: ${stringArray(observed, "likely_browser_families").length > 0 ? stringArray(observed, "likely_browser_families").join(", ") : "unknown"}`,
    `- MV2 fields present: ${booleanText(observed.mv2_fields_present)}`,
    `- MV3 fields present: ${booleanText(observed.mv3_fields_present)}`,
    `- browser-specific settings: ${recordValue(observed, "browser_specific_settings")?.present === true ? "yes" : "no"}`,
    `- legacy applications: ${recordValue(observed, "legacy_applications")?.present === true ? "yes" : "no"}`,
    `- browser-specific keys: ${stringArray(observed, "browser_specific_keys").length > 0 ? stringArray(observed, "browser_specific_keys").join(", ") : "none"}`,
    `- legacy browser-specific keys: ${stringArray(observed, "legacy_browser_specific_keys").length > 0 ? stringArray(observed, "legacy_browser_specific_keys").join(", ") : "none"}`,
    `- unknown top-level keys: ${stringArray(observed, "unknown_top_level_keys").length > 0 ? stringArray(observed, "unknown_top_level_keys").join(", ") : "none"}`,
    `- unmodeled top-level keys: ${stringArray(observed, "unsupported_or_unmodeled_keys").length > 0 ? stringArray(observed, "unsupported_or_unmodeled_keys").join(", ") : "none"}`,
    ...namedList("Permissions", stringArray(observed, "permissions"), options),
    ...namedList("Optional permissions", stringArray(observed, "optional_permissions"), options),
    ...namedList("Host permissions", stringArray(observed, "host_permissions"), options),
    ...namedList("Optional host permissions", stringArray(observed, "optional_host_permissions"), options),
    "",
    "Content scripts",
    `- count: ${contentScripts ? numberValue(contentScripts, "count") ?? 0 : 0}`,
    `- JS files: ${contentScripts ? numberValue(contentScripts, "js_count") ?? 0 : 0}`,
    `- CSS files: ${contentScripts ? numberValue(contentScripts, "css_count") ?? 0 : 0}`,
    ...namedList("Content script matches", contentScripts ? stringArray(contentScripts, "matches") : [], options),
    "",
    "Background",
    `- present: ${background ? booleanText(background.present) : "unknown"}`,
    `- type: ${background && typeof background.type === "string" ? background.type : "unknown"}`,
    `- service worker: ${background && typeof background.service_worker === "string" ? displayString(background.service_worker, options) : "none"}`,
    "",
    "Other observations",
    `- CSP present: ${booleanText(observed.content_security_policy_present)}`,
    `- OAuth2 present: ${booleanText(observed.oauth2_present)}`,
    `- update_url present: ${booleanText(observed.update_url_present)}`,
    `- icons present: ${booleanText(observed.icons_present)}`,
    `- action present: ${booleanText(observed.action_present)}`,
    `- web accessible resources: ${webAccessibleResources ? numberValue(webAccessibleResources, "count") ?? 0 : 0}`,
  ]);
}

function renderHttpHeaders(record: Record<string, unknown>, options: DisplayOptions): string[] | undefined {
  const observed = recordValue(record, "observed");
  if (!observed) {
    return undefined;
  }

  const headerNames = stringArray(observed, "header_names");
  const duplicateNames = stringArray(observed, "duplicate_header_names");

  return section("HTTP Headers", [
    `Status line: ${booleanText(observed.status_line_present)}`,
    `HTTP version: ${String(observed.http_version ?? "unknown")}`,
    `Status code: ${String(observed.status_code ?? "unknown")}`,
    `Reason phrase: ${displayString(String(observed.reason_phrase ?? "unknown"), options)}`,
    `Line ending: ${typeof observed.line_ending === "string" ? observed.line_ending : "unknown"}`,
    `Headers: ${numberValue(observed, "header_count") ?? "unknown"}`,
    `Unique header names: ${numberValue(observed, "unique_header_name_count") ?? "unknown"}`,
    `Malformed lines: ${numberValue(observed, "malformed_line_count") ?? 0}`,
    `Folded lines: ${numberValue(observed, "folded_line_count") ?? 0}`,
    `Set-Cookie headers: ${numberValue(observed, "set_cookie_count") ?? 0}`,
    "",
    "Observed header fields",
    `- content-security-policy: ${booleanText(observed.content_security_policy_present)}`,
    `- strict-transport-security: ${booleanText(observed.strict_transport_security_present)}`,
    `- x-frame-options: ${booleanText(observed.x_frame_options_present)}`,
    `- x-content-type-options: ${booleanText(observed.x_content_type_options_present)}`,
    `- referrer-policy: ${booleanText(observed.referrer_policy_present)}`,
    `- permissions-policy: ${booleanText(observed.permissions_policy_present)}`,
    `- location: ${booleanText(observed.location_present)}`,
    ...namedList("Header names", headerNames, options),
    ...namedList("Duplicate header names", duplicateNames, options),
  ]);
}




function renderTrufflehogNdjson(record: Record<string, unknown>, options: DisplayOptions): string[] | undefined {
  const observed = recordValue(record, "observed");
  if (!observed) {
    return undefined;
  }

  const resultRecords = recordArray(observed, "result_records");
  const resultLines = resultRecords.slice(0, 20).map((entry) => {
    const detector = String(entry.detector_name ?? "unknown");
    const status = String(entry.verification_status ?? "unknown");
    const source = recordValue(entry, "source");
    const file = source && typeof source.file === "string" ? source.file : "unknown";
    const line = source && typeof source.line === "number" ? `:${source.line}` : "";
    return `line ${String(entry.line_number ?? "?")}: ${detector} status=${status} source=${file}${line}`;
  });

  return section("TruffleHog NDJSON", [
    `Line ending: ${typeof observed.line_ending === "string" ? observed.line_ending : "unknown"}`,
    `Physical lines: ${numberValue(observed, "physical_line_count") ?? "unknown"}`,
    `NDJSON lines: ${numberValue(observed, "ndjson_line_count") ?? "unknown"}`,
    `Blank lines: ${numberValue(observed, "blank_line_count") ?? 0}`,
    `Valid records: ${numberValue(observed, "valid_record_count") ?? "unknown"}`,
    `Malformed lines: ${numberValue(observed, "malformed_line_count") ?? 0}`,
    `Non-object lines: ${numberValue(observed, "non_object_line_count") ?? 0}`,
    `Verified records: ${numberValue(observed, "verified_count") ?? 0}`,
    `Unverified records: ${numberValue(observed, "unverified_count") ?? 0}`,
    `Unknown verification records: ${numberValue(observed, "unknown_verification_count") ?? 0}`,
    `Raw secret values present: ${numberValue(observed, "raw_secret_present_count") ?? 0}`,
    `RawV2 secret values present: ${numberValue(observed, "raw_v2_secret_present_count") ?? 0}`,
    `Scanner-redacted secret values present: ${numberValue(observed, "redacted_secret_present_count") ?? 0}`,
    ...namedList("Detector names", stringArray(observed, "detector_names"), options),
    ...namedList("Decoder names", stringArray(observed, "decoder_names"), options),
    ...namedList("Source names", stringArray(observed, "source_names"), options),
    ...namedList("Repositories", stringArray(observed, "repositories"), options),
    ...namedList("Files", stringArray(observed, "files"), options),
    ...namedList("File line refs", stringArray(observed, "file_line_refs"), options),
    ...namedList("Extra data keys", stringArray(observed, "extra_data_keys"), options),
    ...namedList("Structured data keys", stringArray(observed, "structured_data_keys"), options),
    ...namedList("Unknown top-level keys", stringArray(observed, "unknown_top_level_keys"), options),
    ...namedList("Result records", resultLines, options),
  ]);
}

function renderGithubActionsWorkflow(record: Record<string, unknown>, options: DisplayOptions): string[] | undefined {
  const artifact = recordValue(record, "artifact");
  const observed = recordValue(record, "observed");
  if (!observed) {
    return undefined;
  }

  const triggers = recordValue(observed, "triggers");
  const topLevelPermissions = recordValue(observed, "top_level_permissions");
  const permissionEntries = topLevelPermissions ? recordArray(topLevelPermissions, "entries") : [];
  const permissionLines = permissionEntries.map((entry) => `${String(entry.scope ?? "unknown")}: ${String(entry.value ?? "unknown")}`);
  const jobs = recordArray(observed, "jobs");
  const jobLines = jobs.map((job) => {
    const id = String(job.id ?? "unknown");
    const steps = String(job.step_count ?? "unknown");
    const runsOn = Array.isArray(job.runs_on) ? job.runs_on.map((entry) => String(entry)).join(", ") : "none";
    const reusable = typeof job.reusable_workflow_ref === "string" ? ` reusable=${job.reusable_workflow_ref}` : "";
    return `${id}: steps=${steps} runs-on=${runsOn}${reusable}`;
  });
  const checkoutSteps = recordArray(observed, "checkout_steps");
  const checkoutLines = checkoutSteps.map((step) => {
    const persist = String(step.persist_credentials ?? "unknown");
    const depth = String(step.fetch_depth ?? "unknown");
    const depthLabel = ["f", "etch-depth"].join("");
    return `${String(step.path ?? "unknown")}: ${String(step.uses ?? "unknown")} persist-credentials=${persist} ${depthLabel}=${depth}`;
  });

  return section("GitHub Actions Workflow", [
    `Name: ${displayString(String(observed.name ?? artifact?.name ?? "unknown"), options)}`,
    `Line ending: ${typeof observed.line_ending === "string" ? observed.line_ending : "unknown"}`,
    `Physical lines: ${numberValue(observed, "physical_line_count") ?? "unknown"}`,
    `Run name present: ${booleanText(observed.run_name_present)}`,
    `Jobs: ${numberValue(observed, "job_count") ?? "unknown"}`,
    `Steps: ${numberValue(observed, "total_step_count") ?? "unknown"}`,
    `Uses steps: ${numberValue(observed, "uses_step_count") ?? 0}`,
    `Run steps: ${numberValue(observed, "run_step_count") ?? 0}`,
    `Job-level uses: ${numberValue(observed, "job_level_uses_count") ?? 0}`,
    `Checkout steps: ${numberValue(observed, "checkout_step_count") ?? 0}`,
    "",
    "Triggers",
    `- configured: ${triggers ? booleanText(triggers.configured) : "unknown"}`,
    `- value kind: ${triggers && typeof triggers.value_kind === "string" ? triggers.value_kind : "unknown"}`,
    `- schedule cron entries: ${triggers ? numberValue(triggers, "schedule_cron_count") ?? 0 : 0}`,
    ...namedList("Trigger events", triggers ? stringArray(triggers, "event_names") : [], options),
    ...namedList("Top-level keys", stringArray(observed, "top_level_keys"), options),
    ...namedList("Unknown top-level keys", stringArray(observed, "unknown_top_level_keys"), options),
    ...namedList("Top-level env keys", stringArray(observed, "top_level_env_keys"), options),
    ...namedList("Top-level permission entries", permissionLines, options),
    ...namedList("Jobs", jobLines, options),
    ...namedList("Unique action uses", stringArray(observed, "unique_action_uses"), options),
    ...namedList("Checkout observations", checkoutLines, options),
    ...namedList("Referenced contexts", stringArray(observed, "referenced_contexts"), options),
    ...namedList("Referenced secret names", stringArray(observed, "referenced_secret_names"), options),
  ]);
}

function renderDockerfile(record: Record<string, unknown>, options: DisplayOptions): string[] | undefined {
  const observed = recordValue(record, "observed");
  if (!observed) {
    return undefined;
  }

  const stages = recordArray(observed, "stages");
  const baseImages = stages.map((stage) => {
    const baseImage = String(stage.base_image ?? "unknown");
    const alias = typeof stage.alias === "string" ? ` AS ${stage.alias}` : "";
    return `line ${String(stage.line ?? "?")}: ${baseImage}${alias}`;
  });
  const instructionCounts = recordValue(observed, "instruction_counts");
  const instructionCountLines = instructionCounts
    ? Object.entries(instructionCounts)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([name, count]) => `${name}: ${String(count)}`)
    : [];
  const commandForms = recordValue(observed, "command_forms");
  const runForms = commandForms ? recordValue(commandForms, "run") : undefined;
  const cmdForms = commandForms ? recordValue(commandForms, "cmd") : undefined;
  const entrypointForms = commandForms ? recordValue(commandForms, "entrypoint") : undefined;
  const addedPaths = recordArray(observed, "added_paths");
  const copiedPaths = recordArray(observed, "copied_paths");
  const addUrlLikeSources = stringArray(observed, "add_url_like_sources");

  return section("Dockerfile", [
    `Physical lines: ${numberValue(observed, "physical_line_count") ?? "unknown"}`,
    `Logical instructions: ${numberValue(observed, "logical_instruction_count") ?? "unknown"}`,
    `Line ending: ${typeof observed.line_ending === "string" ? observed.line_ending : "unknown"}`,
    `Stages: ${numberValue(observed, "stage_count") ?? "unknown"}`,
    `Final stage index: ${String(observed.final_stage_index ?? "none")}`,
    `Healthcheck present: ${booleanText(observed.healthcheck_present)}`,
    `Healthcheck disabled: ${booleanText(observed.healthcheck_disabled)}`,
    `Entrypoint present: ${booleanText(observed.entrypoint_present)}`,
    `CMD present: ${booleanText(observed.cmd_present)}`,
    `SHELL instruction present: ${booleanText(observed.shell_instruction_present)}`,
    "",
    "Command forms",
    `- RUN shell/json-array: ${runForms ? numberValue(runForms, "shell_form_count") ?? 0 : 0}/${runForms ? numberValue(runForms, "json_array_form_count") ?? 0 : 0}`,
    `- CMD shell/json-array: ${cmdForms ? numberValue(cmdForms, "shell_form_count") ?? 0 : 0}/${cmdForms ? numberValue(cmdForms, "json_array_form_count") ?? 0 : 0}`,
    `- ENTRYPOINT shell/json-array: ${entrypointForms ? numberValue(entrypointForms, "shell_form_count") ?? 0 : 0}/${entrypointForms ? numberValue(entrypointForms, "json_array_form_count") ?? 0 : 0}`,
    ...namedList("Base images", baseImages, options),
    ...namedList("Instruction counts", instructionCountLines, options),
    ...namedList("Exposed ports", stringArray(observed, "exposed_ports"), options),
    ...namedList("Declared users", stringArray(observed, "declared_users"), options),
    ...namedList("Workdirs", stringArray(observed, "workdirs"), options),
    ...namedList("ENV keys", stringArray(observed, "env_keys"), options),
    ...namedList("ARG keys", stringArray(observed, "arg_keys"), options),
    ...namedList(
      "COPY destinations",
      copiedPaths.map((entry) => String(entry.destination ?? "unknown")),
      options
    ),
    ...namedList(
      "ADD destinations",
      addedPaths.map((entry) => String(entry.destination ?? "unknown")),
      options
    ),
    ...namedList("ADD URL-like sources", addUrlLikeSources, options),
    ...namedList("Unknown instructions", recordArray(observed, "unknown_instructions").map((entry) => String(entry.instruction ?? "unknown")), options),
  ]);
}


function renderSarif(record: Record<string, unknown>, options: DisplayOptions): string[] | undefined {
  const artifact = recordValue(record, "artifact");
  const observed = recordValue(record, "observed");
  if (!observed) {
    return undefined;
  }

  const levels = recordValue(observed, "result_levels");
  const levelLines = levels
    ? Object.entries(levels)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([level, count]) => `${level}: ${String(count)}`)
    : [];
  const runs = recordArray(observed, "runs");
  const runLines = runs.map((run) => {
    const tool = String(run.tool_driver_name ?? "unknown");
    const version = typeof run.tool_driver_version === "string" ? `@${run.tool_driver_version}` : "";
    return `run ${String(run.run_index ?? "?")}: ${tool}${version} rules=${String(run.rule_count ?? "unknown")} results=${String(run.result_count ?? "unknown")}`;
  });
  const results = recordArray(observed, "results");
  const resultLines = results.slice(0, 20).map((result) => {
    const rule = String(result.rule_id ?? "unknown");
    const level = String(result.level ?? "unknown");
    const locations = recordArray(result, "locations");
    const firstLocation = locations[0];
    const uri = firstLocation && typeof firstLocation.uri === "string" ? firstLocation.uri : "unknown";
    const startLine = firstLocation && typeof firstLocation.region_start_line === "number" ? `:${String(firstLocation.region_start_line)}` : "";
    return `run ${String(result.run_index ?? "?")} result ${String(result.result_index ?? "?")}: ${rule} level=${level} location=${uri}${startLine}`;
  });

  return section("SARIF", [
    `Version: ${String(observed.version ?? artifact?.version ?? "unknown")}`,
    `Schema present: ${booleanText(observed.schema_present)}`,
    `Line ending: ${typeof observed.line_ending === "string" ? observed.line_ending : "unknown"}`,
    `Physical lines: ${numberValue(observed, "physical_line_count") ?? "unknown"}`,
    `Runs: ${numberValue(observed, "run_count") ?? "unknown"}`,
    `Rules: ${numberValue(observed, "rule_count") ?? "unknown"}`,
    `Results: ${numberValue(observed, "result_count") ?? "unknown"}`,
    `Artifacts: ${numberValue(observed, "artifact_count") ?? 0}`,
    `Invocations: ${numberValue(observed, "invocation_count") ?? 0}`,
    `Taxa: ${numberValue(observed, "taxon_count") ?? 0}`,
    `Suppressions: ${numberValue(observed, "suppression_count") ?? 0}`,
    `Results with fixes: ${numberValue(observed, "fixes_present_count") ?? 0}`,
    `Fingerprint key count: ${numberValue(observed, "fingerprint_key_count") ?? 0}`,
    `Partial fingerprint key count: ${numberValue(observed, "partial_fingerprint_key_count") ?? 0}`,
    ...namedList("Tool drivers", stringArray(observed, "tool_driver_names"), options),
    ...namedList("Tool extensions", stringArray(observed, "tool_extension_names"), options),
    ...namedList("Result levels", levelLines, options),
    ...namedList("Rule IDs", stringArray(observed, "rule_ids"), options),
    ...namedList("Result rule IDs", stringArray(observed, "result_rule_ids"), options),
    ...namedList("Result location refs", stringArray(observed, "result_location_refs"), options),
    ...namedList("Tags", stringArray(observed, "tags"), options),
    ...namedList("Taxa IDs", stringArray(observed, "taxa_ids"), options),
    ...namedList("Fingerprint keys", stringArray(observed, "fingerprint_keys"), options),
    ...namedList("Partial fingerprint keys", stringArray(observed, "partial_fingerprint_keys"), options),
    ...namedList("Unknown top-level keys", stringArray(observed, "unknown_top_level_keys"), options),
    ...namedList("Runs", runLines, options),
    ...namedList("Results", resultLines, options),
  ]);
}

function renderSkillAwareOutput(
  result: FormattableSkillRunResult,
  options: DisplayOptions
): string[] | undefined {
  const record = outputRecord(result);
  if (!record) {
    return undefined;
  }

  switch (result.skill.name) {
    case "extract_iocs":
      return renderExtractIocs(record, options);
    case "extract_urls":
      return renderSimpleArray("URL Extraction", record, "urls", options);
    case "extract_domains":
      return renderSimpleArray("Domain Extraction", record, "domains", options);
    case "extract_emails":
      return renderSimpleArray("Email Extraction", record, "email_addresses", options);
    case "extract_ipv4":
      return renderSimpleArray("IPv4 Extraction", record, "ipv4_addresses", options);
    case "extract_cves":
      return renderSimpleArray("CVE Extraction", record, "cves", options);
    case "extract_uuids":
      return renderSimpleArray("UUID Extraction", record, "uuids", options);
    case "extract_hashes":
      return renderExtractHashes(record, options);
    case "parse_csv":
      return renderCsv(record, options);
    case "parse_yaml":
      return renderYaml(record, options);
    case "parse_package_json":
      return renderPackageJson(record, options);
    case "parse_browser_extension_manifest":
      return renderBrowserExtensionManifest(record, options);
    case "review_browser_extension_permissions":
      return renderBrowserExtensionPermissionReview(record, options);
    case "score_browser_extension_risk":
      return renderBrowserExtensionRiskScore(record, options);
    case "generate_browser_extension_finding":
      return renderBrowserExtensionFinding(record, options);
    case "parse_dockerfile":
      return renderDockerfile(record, options);
    case "parse_github_actions_workflow":
      return renderGithubActionsWorkflow(record, options);
    case "parse_trufflehog_ndjson":
      return renderTrufflehogNdjson(record, options);
    case "parse_sarif":
      return renderSarif(record, options);
    case "parse_ip_prefix_list":
      return renderIpPrefixList(record, options);
    case "parse_asn_list":
      return renderAsnList(record, options);
    case "parse_asn_allow_deny_list":
      return renderAsnAllowDenyList(record, options);
    case "parse_asn_observations":
      return renderAsnObservations(record, options);
    case "parse_bgp_prefix_table":
      return renderBgpPrefixTable(record, options);
    case "parse_http_headers":
      return renderHttpHeaders(record, options);
    default:
      return undefined;
  }
}

function formatPretty(result: FormattableSkillRunResult, options: DisplayOptions): string {
  const lines: string[] = [];

  lines.push(
    ...section("Run", [
      `Status: ${result.status}`,
      `Run ID: ${result.run_id}`,
      `Skill: ${result.skill.name}@${result.skill.version}`,
      `Allow network: ${result.policy.allow_network}`,
      `Network used: ${result.policy.network_used}`,
      `External sinks: ${formatList(result.policy.external_sinks, options)}`,
      `Display safety: ${options.unsafe ? "unsafe" : "safe"}`,
    ])
  );

  const renderedOutput = renderSkillAwareOutput(result, options);
  lines.push(
    "",
    ...(renderedOutput
      ? section("Output", renderedOutput)
      : section("Output", [formatOutput(result.output, options)]))
  );

  if (result.warnings.length > 0) {
    lines.push("", ...section("Warnings", result.warnings.map((warning) => `- ${displayString(warning, options)}`)));
  }

  if (result.errors.length > 0) {
    lines.push("", ...section("Errors", result.errors.map((error) => `- ${displayString(error, options)}`)));
  }

  return lines.join("\n");
}

export function formatSkillRunResult(
  result: FormattableSkillRunResult,
  options: SkillRunFormatOptions
): string {
  if (options.format === "pretty") {
    return formatPretty(result, { unsafe: options.unsafe === true });
  }

  return formatJson(result);
}
