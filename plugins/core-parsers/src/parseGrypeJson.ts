import type { Skill } from "@security-workbench/schemas";
import { localOnlyPermissions } from "./localOnlyPermissions.js";
import {
  countBy,
  detectLineEnding,
  isRecord,
  normalizeTextInput,
  parseJsonObject,
  physicalLineCount,
  recordArray,
  recordValue,
  stringArray,
  stringValue,
  uniqueSorted,
  unknownKeys,
  type NativeJsonLineEnding,
} from "./nativeParserUtils.js";

export interface GrypeArtifactObservation {
  readonly id: string | null;
  readonly name: string | null;
  readonly version: string | null;
  readonly type: string | null;
  readonly language: string | null;
  readonly purl: string | null;
  readonly cpes: readonly string[];
  readonly location_paths: readonly string[];
  readonly metadata_type: string | null;
  readonly metadata_keys: readonly string[];
}

export interface GrypeVulnerabilityObservation {
  readonly id: string | null;
  readonly namespace: string | null;
  readonly severity: string | null;
  readonly fix_state: string | null;
  readonly fixed_versions: readonly string[];
  readonly cvss_count: number;
  readonly related_vulnerability_ids: readonly string[];
  readonly data_source: string | null;
  readonly urls: readonly string[];
}

export interface GrypeMatchObservation {
  readonly match_index: number;
  readonly vulnerability: GrypeVulnerabilityObservation;
  readonly artifact: GrypeArtifactObservation;
  readonly match_detail_count: number;
  readonly matcher_names: readonly string[];
  readonly match_types: readonly string[];
  readonly searched_by_keys: readonly string[];
  readonly found_keys: readonly string[];
  readonly unknown_top_level_keys: readonly string[];
}

export interface ParseGrypeJsonOutput {
  readonly artifact: {
    readonly id: "artifact_grype_json";
    readonly type: "grype_json";
    readonly schema_version: string | null;
  };
  readonly observed: {
    readonly line_ending: NativeJsonLineEnding;
    readonly physical_line_count: number;
    readonly schema_version: string | null;
    readonly descriptor_name: string | null;
    readonly descriptor_version: string | null;
    readonly source_type: string | null;
    readonly source_target: string | null;
    readonly distro_name: string | null;
    readonly distro_version: string | null;
    readonly match_count: number;
    readonly vulnerability_ids: readonly string[];
    readonly namespaces: readonly string[];
    readonly severities: Readonly<Record<string, number>>;
    readonly fix_states: readonly string[];
    readonly fixed_version_count: number;
    readonly package_names: readonly string[];
    readonly package_types: readonly string[];
    readonly package_languages: readonly string[];
    readonly purls: readonly string[];
    readonly cpes: readonly string[];
    readonly location_paths: readonly string[];
    readonly matcher_names: readonly string[];
    readonly match_types: readonly string[];
    readonly unknown_top_level_keys: readonly string[];
    readonly unknown_match_keys: readonly string[];
    readonly matches: readonly GrypeMatchObservation[];
  };
  readonly warnings: readonly string[];
}

const KNOWN_ROOT_KEYS = new Set([
  "matches",
  "ignoredMatches",
  "source",
  "distro",
  "descriptor",
  "schema",
]);
const KNOWN_MATCH_KEYS = new Set(["vulnerability", "artifact", "matchDetails", "relatedVulnerabilities"]);

function grypeArtifact(value: unknown): GrypeArtifactObservation {
  const record = isRecord(value) ? value : {};
  const metadata = recordValue(record, "metadata");
  const locations = recordArray(record.locations);

  return {
    id: stringValue(record.id),
    name: stringValue(record.name),
    version: stringValue(record.version),
    type: stringValue(record.type),
    language: stringValue(record.language),
    purl: stringValue(record.purl),
    cpes: stringArray(record.cpes),
    location_paths: uniqueSorted(locations.map((location) => stringValue(location.path))),
    metadata_type: metadata ? stringValue(metadata.type) : null,
    metadata_keys: metadata ? Object.keys(metadata).sort() : [],
  };
}

function fixedVersions(fix: unknown): string[] {
  const record = isRecord(fix) ? fix : null;
  if (!record) {
    return [];
  }

  return stringArray(record.versions);
}

function relatedIds(vulnerability: Record<string, unknown>, match: Record<string, unknown>): string[] {
  const fromVulnerability = recordArray(vulnerability.relatedVulnerabilities).map((entry) => stringValue(entry.id));
  const fromMatch = recordArray(match.relatedVulnerabilities).map((entry) => stringValue(entry.id));
  return uniqueSorted([...fromVulnerability, ...fromMatch]);
}

function urls(vulnerability: Record<string, unknown>): string[] {
  return uniqueSorted([
    ...stringArray(vulnerability.urls),
    stringValue(vulnerability.dataSource),
  ]);
}

function grypeVulnerability(match: Record<string, unknown>): GrypeVulnerabilityObservation {
  const vulnerability = recordValue(match, "vulnerability") ?? {};
  const cvss = Array.isArray(vulnerability.cvss) ? vulnerability.cvss : [];
  const fix = recordValue(vulnerability, "fix");

  return {
    id: stringValue(vulnerability.id),
    namespace: stringValue(vulnerability.namespace),
    severity: stringValue(vulnerability.severity),
    fix_state: fix ? stringValue(fix.state) : null,
    fixed_versions: fixedVersions(fix),
    cvss_count: cvss.length,
    related_vulnerability_ids: relatedIds(vulnerability, match),
    data_source: stringValue(vulnerability.dataSource),
    urls: urls(vulnerability),
  };
}

function matchDetails(value: unknown): Record<string, unknown>[] {
  return recordArray(value);
}

function detailString(detail: Record<string, unknown>, key: string): string | null {
  const direct = stringValue(detail[key]);
  if (direct !== null) {
    return direct;
  }

  const searchedBy = recordValue(detail, "searchedBy");
  const found = recordValue(detail, "found");
  return stringValue(searchedBy?.[key]) ?? stringValue(found?.[key]);
}

function detailKeys(detail: Record<string, unknown>, key: "searchedBy" | "found"): string[] {
  const record = recordValue(detail, key);
  return record ? Object.keys(record).sort() : [];
}

function grypeMatch(match: Record<string, unknown>, matchIndex: number): GrypeMatchObservation {
  const details = matchDetails(match.matchDetails);

  return {
    match_index: matchIndex,
    vulnerability: grypeVulnerability(match),
    artifact: grypeArtifact(match.artifact),
    match_detail_count: details.length,
    matcher_names: uniqueSorted(details.map((detail) => detailString(detail, "matcher"))),
    match_types: uniqueSorted(details.map((detail) => detailString(detail, "type"))),
    searched_by_keys: uniqueSorted(details.flatMap((detail) => detailKeys(detail, "searchedBy"))),
    found_keys: uniqueSorted(details.flatMap((detail) => detailKeys(detail, "found"))),
    unknown_top_level_keys: unknownKeys(match, KNOWN_MATCH_KEYS),
  };
}

export function parseGrypeJson(input: string): ParseGrypeJsonOutput {
  const normalized = normalizeTextInput(input, "parse_grype_json");
  const root = parseJsonObject(normalized, "parse_grype_json");
  const warnings: string[] = [];

  if (!Array.isArray(root.matches)) {
    throw new Error('parse_grype_json input must contain a "matches" array');
  }

  const matchRecords = recordArray(root.matches);
  if (matchRecords.length !== root.matches.length) {
    warnings.push('Grype field "matches" contains non-object entries that were ignored.');
  }

  const matches = matchRecords.map((match, index) => grypeMatch(match, index));
  const descriptor = recordValue(root, "descriptor");
  const source = recordValue(root, "source");
  const distro = recordValue(root, "distro");

  return {
    artifact: {
      id: "artifact_grype_json",
      type: "grype_json",
      schema_version: stringValue(root.schema),
    },
    observed: {
      line_ending: detectLineEnding(normalized),
      physical_line_count: physicalLineCount(normalized),
      schema_version: stringValue(root.schema),
      descriptor_name: descriptor ? stringValue(descriptor.name) : null,
      descriptor_version: descriptor ? stringValue(descriptor.version) : null,
      source_type: source ? stringValue(source.type) : null,
      source_target: source ? stringValue(source.target) : null,
      distro_name: distro ? stringValue(distro.name) : null,
      distro_version: distro ? stringValue(distro.version) : null,
      match_count: matches.length,
      vulnerability_ids: uniqueSorted(matches.map((match) => match.vulnerability.id)),
      namespaces: uniqueSorted(matches.map((match) => match.vulnerability.namespace)),
      severities: countBy(matches.map((match) => match.vulnerability.severity ?? "unknown")),
      fix_states: uniqueSorted(matches.map((match) => match.vulnerability.fix_state)),
      fixed_version_count: matches.reduce((total, match) => total + match.vulnerability.fixed_versions.length, 0),
      package_names: uniqueSorted(matches.map((match) => match.artifact.name)),
      package_types: uniqueSorted(matches.map((match) => match.artifact.type)),
      package_languages: uniqueSorted(matches.map((match) => match.artifact.language)),
      purls: uniqueSorted(matches.map((match) => match.artifact.purl)),
      cpes: uniqueSorted(matches.flatMap((match) => match.artifact.cpes)),
      location_paths: uniqueSorted(matches.flatMap((match) => match.artifact.location_paths)),
      matcher_names: uniqueSorted(matches.flatMap((match) => match.matcher_names)),
      match_types: uniqueSorted(matches.flatMap((match) => match.match_types)),
      unknown_top_level_keys: unknownKeys(root, KNOWN_ROOT_KEYS),
      unknown_match_keys: uniqueSorted(matches.flatMap((match) => match.unknown_top_level_keys)),
      matches,
    },
    warnings,
  };
}

export const parseGrypeJsonSkill: Skill<string, ParseGrypeJsonOutput> = {
  metadata: {
    name: "parse_grype_json",
    version: "0.1.0",
    category: "parser",
    description:
      "Parse Grype native JSON into structured vulnerability-match, package, source, distro, and matcher observations without scoring risk.",
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
      max_input_mb: 10,
      risk: "medium",
      rationale: [
        "Parses attacker-controlled scanner output that may contain package metadata, image metadata, and vulnerability descriptions.",
        "Does not perform network access, persist input, call external services, or execute artifact content.",
        "Parser output preserves native Grype observations without normalizing across scanners or assigning exploitability.",
      ],
    },
  },
  run(input: string): ParseGrypeJsonOutput {
    return parseGrypeJson(input);
  },
};
