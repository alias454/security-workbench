import type { Skill } from "@security-workbench/schemas";
import { localOnlyPermissions } from "./localOnlyPermissions.js";

export type SarifLineEnding = "lf" | "crlf" | "mixed" | "none";
export type SarifValueKind = "string" | "array" | "object" | "boolean" | "number" | "null" | "unknown";

export interface SarifRuleObservation {
  readonly run_index: number;
  readonly path: string;
  readonly id: string | null;
  readonly name: string | null;
  readonly short_description_text: string | null;
  readonly full_description_text: string | null;
  readonly help_uri: string | null;
  readonly default_level: string | null;
  readonly tags: readonly string[];
  readonly properties_keys: readonly string[];
  readonly unknown_keys: readonly string[];
}

export interface SarifLocationObservation {
  readonly result_index: number;
  readonly location_index: number;
  readonly uri: string | null;
  readonly uri_base_id: string | null;
  readonly region_start_line: number | null;
  readonly region_start_column: number | null;
  readonly region_end_line: number | null;
  readonly region_end_column: number | null;
  readonly logical_location_names: readonly string[];
}

export interface SarifResultObservation {
  readonly run_index: number;
  readonly result_index: number;
  readonly rule_id: string | null;
  readonly rule_index: number | null;
  readonly kind: string | null;
  readonly level: string | null;
  readonly baseline_state: string | null;
  readonly message_text: string | null;
  readonly message_markdown_present: boolean;
  readonly location_count: number;
  readonly locations: readonly SarifLocationObservation[];
  readonly related_location_count: number;
  readonly fingerprint_keys: readonly string[];
  readonly partial_fingerprint_keys: readonly string[];
  readonly suppression_count: number;
  readonly suppression_kinds: readonly string[];
  readonly fix_count: number;
  readonly fixes_present: boolean;
  readonly taxa_ids: readonly string[];
  readonly properties_keys: readonly string[];
  readonly unknown_keys: readonly string[];
}

export interface SarifRunObservation {
  readonly run_index: number;
  readonly tool_driver_name: string | null;
  readonly tool_driver_version: string | null;
  readonly tool_driver_information_uri: string | null;
  readonly tool_extension_names: readonly string[];
  readonly automation_id: string | null;
  readonly invocation_count: number;
  readonly original_uri_base_ids: readonly string[];
  readonly artifact_count: number;
  readonly rule_count: number;
  readonly result_count: number;
  readonly taxon_count: number;
  readonly properties_keys: readonly string[];
  readonly unknown_keys: readonly string[];
}

export interface ParseSarifOutput {
  readonly artifact: {
    readonly id: "artifact_sarif";
    readonly type: "sarif";
    readonly version: string | null;
  };
  readonly observed: {
    readonly line_ending: SarifLineEnding;
    readonly physical_line_count: number;
    readonly version: string | null;
    readonly schema_present: boolean;
    readonly run_count: number;
    readonly tool_driver_names: readonly string[];
    readonly tool_driver_versions: readonly string[];
    readonly tool_extension_names: readonly string[];
    readonly automation_ids: readonly string[];
    readonly invocation_count: number;
    readonly artifact_count: number;
    readonly rule_count: number;
    readonly result_count: number;
    readonly taxon_count: number;
    readonly artifact_uris: readonly string[];
    readonly result_location_uris: readonly string[];
    readonly result_location_refs: readonly string[];
    readonly rule_ids: readonly string[];
    readonly result_rule_ids: readonly string[];
    readonly result_levels: Readonly<Record<string, number>>;
    readonly result_kinds: readonly string[];
    readonly baseline_states: readonly string[];
    readonly suppression_count: number;
    readonly suppression_kinds: readonly string[];
    readonly fixes_present_count: number;
    readonly fingerprint_key_count: number;
    readonly partial_fingerprint_key_count: number;
    readonly fingerprint_keys: readonly string[];
    readonly partial_fingerprint_keys: readonly string[];
    readonly taxa_ids: readonly string[];
    readonly tags: readonly string[];
    readonly property_keys: readonly string[];
    readonly unknown_top_level_keys: readonly string[];
    readonly unknown_run_keys: readonly string[];
    readonly unknown_rule_keys: readonly string[];
    readonly unknown_result_keys: readonly string[];
    readonly runs: readonly SarifRunObservation[];
    readonly rules: readonly SarifRuleObservation[];
    readonly results: readonly SarifResultObservation[];
  };
  readonly warnings: readonly string[];
}

type JsonRecord = Record<string, unknown>;

const KNOWN_TOP_LEVEL_KEYS = new Set(["version", "$schema", "runs", "inlineExternalProperties", "properties"]);
const KNOWN_RUN_KEYS = new Set([
  "tool",
  "invocations",
  "conversion",
  "language",
  "versionControlProvenance",
  "originalUriBaseIds",
  "artifacts",
  "logicalLocations",
  "graphs",
  "results",
  "automationDetails",
  "runAggregates",
  "baselineGuid",
  "redactionTokens",
  "defaultEncoding",
  "defaultSourceLanguage",
  "newlineSequences",
  "columnKind",
  "externalPropertyFileReferences",
  "threadFlowLocations",
  "taxonomies",
  "addresses",
  "translations",
  "policies",
  "webRequests",
  "webResponses",
  "specialLocations",
  "properties",
]);
const KNOWN_RULE_KEYS = new Set([
  "id",
  "name",
  "shortDescription",
  "fullDescription",
  "messageStrings",
  "defaultConfiguration",
  "helpUri",
  "help",
  "relationships",
  "deprecatedIds",
  "deprecatedGuids",
  "deprecatedNames",
  "guid",
  "properties",
]);
const KNOWN_RESULT_KEYS = new Set([
  "ruleId",
  "ruleIndex",
  "rule",
  "kind",
  "level",
  "message",
  "analysisTarget",
  "locations",
  "stacks",
  "codeFlows",
  "graphs",
  "graphTraversals",
  "relatedLocations",
  "suppressions",
  "baselineState",
  "rank",
  "attachments",
  "hostedViewerUri",
  "workItemUris",
  "fingerprints",
  "partialFingerprints",
  "provenance",
  "fixes",
  "taxa",
  "webRequest",
  "webResponse",
  "properties",
]);

function normalizeInput(input: string): string {
  if (typeof input !== "string") {
    throw new Error("parse_sarif input must be a string");
  }

  if (input.length === 0 || input.trim().length === 0) {
    throw new Error("parse_sarif input must not be empty");
  }

  return input.charCodeAt(0) === 0xfeff ? input.slice(1) : input;
}

function detectLineEnding(text: string): SarifLineEnding {
  const crlfCount = (text.match(/\r\n/g) ?? []).length;
  const withoutCrLf = text.replace(/\r\n/g, "");
  const lfCount = (withoutCrLf.match(/\n/g) ?? []).length;
  const crCount = (withoutCrLf.match(/\r/g) ?? []).length;

  if (crlfCount === 0 && lfCount === 0 && crCount === 0) {
    return "none";
  }

  if (crlfCount > 0 && lfCount === 0 && crCount === 0) {
    return "crlf";
  }

  if (crlfCount === 0 && lfCount > 0 && crCount === 0) {
    return "lf";
  }

  return "mixed";
}

function physicalLineCount(text: string): number {
  return text.replace(/\r\n/g, "\n").replace(/\r/g, "\n").split("\n").length;
}

function isRecord(value: unknown): value is JsonRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function valueKind(value: unknown): SarifValueKind {
  if (value === null) {
    return "null";
  }
  if (Array.isArray(value)) {
    return "array";
  }
  if (isRecord(value)) {
    return "object";
  }
  const type = typeof value;
  if (type === "string" || type === "boolean" || type === "number") {
    return type;
  }
  return "unknown";
}

function stringValue(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}

function numberValue(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function asRecord(value: unknown): JsonRecord | null {
  return isRecord(value) ? value : null;
}

function asArray(value: unknown): unknown[] | null {
  return Array.isArray(value) ? value : null;
}

function keysOfRecord(value: unknown): string[] {
  return isRecord(value) ? Object.keys(value).sort() : [];
}

function unknownKeys(record: JsonRecord, knownKeys: ReadonlySet<string>): string[] {
  return Object.keys(record).filter((key) => !knownKeys.has(key)).sort();
}

function uniqueSorted(values: Iterable<string>): string[] {
  return [...new Set(values)].filter((value) => value.length > 0).sort();
}

function countBy(values: Iterable<string>): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const value of values) {
    if (value.length === 0) {
      continue;
    }
    counts[value] = (counts[value] ?? 0) + 1;
  }
  return Object.fromEntries(Object.entries(counts).sort(([left], [right]) => left.localeCompare(right)));
}

function textFromMessage(value: unknown): string | null {
  const message = asRecord(value);
  if (!message) {
    return null;
  }

  return stringValue(message.text) ?? stringValue(message.markdown) ?? null;
}

function markdownPresent(value: unknown): boolean {
  const message = asRecord(value);
  return message ? typeof message.markdown === "string" : false;
}

function descriptorText(value: unknown): string | null {
  const record = asRecord(value);
  return record ? stringValue(record.text) : null;
}

function sarifLocationRef(location: SarifLocationObservation): string | null {
  if (!location.uri) {
    return null;
  }

  if (location.region_start_line !== null) {
    return `${location.uri}:${location.region_start_line}`;
  }

  return location.uri;
}

function parseRule(runIndex: number, ruleIndex: number, value: unknown, warnings: string[]): SarifRuleObservation | null {
  const rule = asRecord(value);
  const path = `runs[${runIndex}].tool.driver.rules[${ruleIndex}]`;
  if (!rule) {
    warnings.push(`${path} is ${valueKind(value)}, not an object.`);
    return null;
  }

  const properties = asRecord(rule.properties);
  const tags = asArray(properties?.tags)
    ?.filter((entry): entry is string => typeof entry === "string") ?? [];
  const defaultConfiguration = asRecord(rule.defaultConfiguration);

  return {
    run_index: runIndex,
    path,
    id: stringValue(rule.id),
    name: stringValue(rule.name),
    short_description_text: descriptorText(rule.shortDescription),
    full_description_text: descriptorText(rule.fullDescription),
    help_uri: stringValue(rule.helpUri),
    default_level: stringValue(defaultConfiguration?.level),
    tags: uniqueSorted(tags),
    properties_keys: keysOfRecord(rule.properties),
    unknown_keys: unknownKeys(rule, KNOWN_RULE_KEYS),
  };
}

function logicalLocationNames(locationsValue: unknown): string[] {
  const locations = asArray(locationsValue) ?? [];
  const names: string[] = [];

  for (const location of locations) {
    const record = asRecord(location);
    if (!record) {
      continue;
    }
    const name = stringValue(record.fullyQualifiedName) ?? stringValue(record.name);
    if (name) {
      names.push(name);
    }
  }

  return uniqueSorted(names);
}

function parseLocation(resultIndex: number, locationIndex: number, value: unknown, warnings: string[]): SarifLocationObservation | null {
  const location = asRecord(value);
  const path = `results[${resultIndex}].locations[${locationIndex}]`;
  if (!location) {
    warnings.push(`${path} is ${valueKind(value)}, not an object.`);
    return null;
  }

  const physicalLocation = asRecord(location.physicalLocation);
  const artifactLocation = asRecord(physicalLocation?.artifactLocation);
  const region = asRecord(physicalLocation?.region);

  return {
    result_index: resultIndex,
    location_index: locationIndex,
    uri: stringValue(artifactLocation?.uri),
    uri_base_id: stringValue(artifactLocation?.uriBaseId),
    region_start_line: numberValue(region?.startLine),
    region_start_column: numberValue(region?.startColumn),
    region_end_line: numberValue(region?.endLine),
    region_end_column: numberValue(region?.endColumn),
    logical_location_names: logicalLocationNames(location.logicalLocations),
  };
}

function parseTaxa(value: unknown, warnings: string[], path: string): string[] {
  const taxa = asArray(value) ?? [];
  const ids: string[] = [];

  taxa.forEach((entry, index) => {
    const record = asRecord(entry);
    if (!record) {
      warnings.push(`${path}[${index}] is ${valueKind(entry)}, not an object.`);
      return;
    }

    const id = stringValue(record.id);
    if (id) {
      ids.push(id);
    }
  });

  return uniqueSorted(ids);
}

function parseSuppressions(value: unknown, warnings: string[], path: string): string[] {
  const suppressions = asArray(value) ?? [];
  const kinds: string[] = [];

  suppressions.forEach((entry, index) => {
    const record = asRecord(entry);
    if (!record) {
      warnings.push(`${path}[${index}] is ${valueKind(entry)}, not an object.`);
      return;
    }

    const kind = stringValue(record.kind);
    if (kind) {
      kinds.push(kind);
    }
  });

  return uniqueSorted(kinds);
}

function parseResult(runIndex: number, resultIndex: number, value: unknown, warnings: string[]): SarifResultObservation | null {
  const result = asRecord(value);
  const path = `runs[${runIndex}].results[${resultIndex}]`;
  if (!result) {
    warnings.push(`${path} is ${valueKind(value)}, not an object.`);
    return null;
  }

  const locationsValue = asArray(result.locations);
  if (result.locations !== undefined && !locationsValue) {
    warnings.push(`${path}.locations is ${valueKind(result.locations)}, not an array.`);
  }

  const locations = (locationsValue ?? [])
    .map((location, locationIndex) => parseLocation(resultIndex, locationIndex, location, warnings))
    .filter((location): location is SarifLocationObservation => location !== null);
  const relatedLocations = asArray(result.relatedLocations);
  if (result.relatedLocations !== undefined && !relatedLocations) {
    warnings.push(`${path}.relatedLocations is ${valueKind(result.relatedLocations)}, not an array.`);
  }
  const suppressions = asArray(result.suppressions);
  if (result.suppressions !== undefined && !suppressions) {
    warnings.push(`${path}.suppressions is ${valueKind(result.suppressions)}, not an array.`);
  }
  const fixes = asArray(result.fixes);
  if (result.fixes !== undefined && !fixes) {
    warnings.push(`${path}.fixes is ${valueKind(result.fixes)}, not an array.`);
  }

  return {
    run_index: runIndex,
    result_index: resultIndex,
    rule_id: stringValue(result.ruleId),
    rule_index: numberValue(result.ruleIndex),
    kind: stringValue(result.kind),
    level: stringValue(result.level),
    baseline_state: stringValue(result.baselineState),
    message_text: textFromMessage(result.message),
    message_markdown_present: markdownPresent(result.message),
    location_count: locations.length,
    locations,
    related_location_count: relatedLocations?.length ?? 0,
    fingerprint_keys: keysOfRecord(result.fingerprints),
    partial_fingerprint_keys: keysOfRecord(result.partialFingerprints),
    suppression_count: suppressions?.length ?? 0,
    suppression_kinds: parseSuppressions(result.suppressions, warnings, `${path}.suppressions`),
    fix_count: fixes?.length ?? 0,
    fixes_present: (fixes?.length ?? 0) > 0,
    taxa_ids: parseTaxa(result.taxa, warnings, `${path}.taxa`),
    properties_keys: keysOfRecord(result.properties),
    unknown_keys: unknownKeys(result, KNOWN_RESULT_KEYS),
  };
}

function artifactUris(run: JsonRecord): string[] {
  const artifacts = asArray(run.artifacts) ?? [];
  const uris: string[] = [];

  for (const artifact of artifacts) {
    const artifactRecord = asRecord(artifact);
    const location = asRecord(artifactRecord?.location);
    const uri = stringValue(location?.uri);
    if (uri) {
      uris.push(uri);
    }
  }

  return uniqueSorted(uris);
}

function originalUriBaseIds(run: JsonRecord): string[] {
  const bases = asRecord(run.originalUriBaseIds);
  return bases ? Object.keys(bases).sort() : [];
}

function parseRun(runIndex: number, value: unknown, warnings: string[]): {
  readonly run: SarifRunObservation | null;
  readonly rules: readonly SarifRuleObservation[];
  readonly results: readonly SarifResultObservation[];
  readonly artifacts: readonly string[];
  readonly taxaIds: readonly string[];
} {
  const run = asRecord(value);
  const path = `runs[${runIndex}]`;
  if (!run) {
    warnings.push(`${path} is ${valueKind(value)}, not an object.`);
    return { run: null, rules: [], results: [], artifacts: [], taxaIds: [] };
  }

  const tool = asRecord(run.tool);
  const driver = asRecord(tool?.driver);
  const extensions = asArray(tool?.extensions) ?? [];
  const extensionNames = extensions
    .map((extension) => stringValue(asRecord(extension)?.name) ?? "")
    .filter((name) => name.length > 0);
  const rulesValue = asArray(driver?.rules);
  if (driver?.rules !== undefined && !rulesValue) {
    warnings.push(`${path}.tool.driver.rules is ${valueKind(driver.rules)}, not an array.`);
  }
  const rules = (rulesValue ?? [])
    .map((rule, ruleIndex) => parseRule(runIndex, ruleIndex, rule, warnings))
    .filter((rule): rule is SarifRuleObservation => rule !== null);
  const resultsValue = asArray(run.results);
  if (run.results !== undefined && !resultsValue) {
    warnings.push(`${path}.results is ${valueKind(run.results)}, not an array.`);
  }
  const results = (resultsValue ?? [])
    .map((result, resultIndex) => parseResult(runIndex, resultIndex, result, warnings))
    .filter((result): result is SarifResultObservation => result !== null);
  const taxonomies = asArray(run.taxonomies) ?? [];
  const taxonomyTaxaIds: string[] = [];
  taxonomies.forEach((taxonomy, taxonomyIndex) => {
    const taxonomyRecord = asRecord(taxonomy);
    if (!taxonomyRecord) {
      warnings.push(`${path}.taxonomies[${taxonomyIndex}] is ${valueKind(taxonomy)}, not an object.`);
      return;
    }
    taxonomyTaxaIds.push(...parseTaxa(taxonomyRecord.taxa, warnings, `${path}.taxonomies[${taxonomyIndex}].taxa`));
  });
  const automationDetails = asRecord(run.automationDetails);
  const invocations = asArray(run.invocations);
  if (run.invocations !== undefined && !invocations) {
    warnings.push(`${path}.invocations is ${valueKind(run.invocations)}, not an array.`);
  }
  const artifacts = artifactUris(run);
  const runObservation: SarifRunObservation = {
    run_index: runIndex,
    tool_driver_name: stringValue(driver?.name),
    tool_driver_version: stringValue(driver?.version) ?? stringValue(driver?.semanticVersion),
    tool_driver_information_uri: stringValue(driver?.informationUri),
    tool_extension_names: uniqueSorted(extensionNames),
    automation_id: stringValue(automationDetails?.id),
    invocation_count: invocations?.length ?? 0,
    original_uri_base_ids: originalUriBaseIds(run),
    artifact_count: artifacts.length,
    rule_count: rules.length,
    result_count: results.length,
    taxon_count: taxonomyTaxaIds.length,
    properties_keys: keysOfRecord(run.properties),
    unknown_keys: unknownKeys(run, KNOWN_RUN_KEYS),
  };

  return {
    run: runObservation,
    rules,
    results,
    artifacts,
    taxaIds: uniqueSorted(taxonomyTaxaIds),
  };
}

export function parseSarif(input: string): ParseSarifOutput {
  const normalized = normalizeInput(input);
  const lineEnding = detectLineEnding(normalized);
  const warnings: string[] = [];

  if (lineEnding === "mixed") {
    warnings.push("SARIF input contains mixed line endings.");
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(normalized);
  } catch {
    throw new Error("parse_sarif input must be valid JSON");
  }

  const root = asRecord(parsed);
  if (!root) {
    throw new Error(`parse_sarif input must be a JSON object; received ${valueKind(parsed)}`);
  }

  const runsValue = asArray(root.runs);
  if (!runsValue || runsValue.length === 0) {
    throw new Error("parse_sarif input must contain a non-empty runs array");
  }

  const runObservations: SarifRunObservation[] = [];
  const ruleObservations: SarifRuleObservation[] = [];
  const resultObservations: SarifResultObservation[] = [];
  const artifactUriObservations: string[] = [];
  const taxonomyTaxaIds: string[] = [];

  runsValue.forEach((run, runIndex) => {
    const parsedRun = parseRun(runIndex, run, warnings);
    if (parsedRun.run) {
      runObservations.push(parsedRun.run);
    }
    ruleObservations.push(...parsedRun.rules);
    resultObservations.push(...parsedRun.results);
    artifactUriObservations.push(...parsedRun.artifacts);
    taxonomyTaxaIds.push(...parsedRun.taxaIds);
  });

  if (runObservations.length === 0) {
    throw new Error("parse_sarif input did not contain any valid SARIF runs");
  }

  const locationUris = uniqueSorted(resultObservations.flatMap((result) => result.locations.map((location) => location.uri ?? "")));
  const locationRefs = uniqueSorted(
    resultObservations.flatMap((result) => result.locations.map((location) => sarifLocationRef(location) ?? ""))
  );
  const resultRuleIds = uniqueSorted(resultObservations.map((result) => result.rule_id ?? ""));
  const ruleIds = uniqueSorted(ruleObservations.map((rule) => rule.id ?? ""));
  const fingerprintKeys = uniqueSorted(resultObservations.flatMap((result) => result.fingerprint_keys));
  const partialFingerprintKeys = uniqueSorted(resultObservations.flatMap((result) => result.partial_fingerprint_keys));
  const resultTaxaIds = uniqueSorted(resultObservations.flatMap((result) => result.taxa_ids));
  const tags = uniqueSorted(ruleObservations.flatMap((rule) => rule.tags));
  const propertyKeys = uniqueSorted([
    ...ruleObservations.flatMap((rule) => rule.properties_keys.map((key) => `rule.${key}`)),
    ...resultObservations.flatMap((result) => result.properties_keys.map((key) => `result.${key}`)),
    ...runObservations.flatMap((run) => run.properties_keys.map((key) => `run.${key}`)),
  ]);

  return {
    artifact: {
      id: "artifact_sarif",
      type: "sarif",
      version: stringValue(root.version),
    },
    observed: {
      line_ending: lineEnding,
      physical_line_count: physicalLineCount(normalized),
      version: stringValue(root.version),
      schema_present: typeof root.$schema === "string",
      run_count: runObservations.length,
      tool_driver_names: uniqueSorted(runObservations.map((run) => run.tool_driver_name ?? "")),
      tool_driver_versions: uniqueSorted(runObservations.map((run) => run.tool_driver_version ?? "")),
      tool_extension_names: uniqueSorted(runObservations.flatMap((run) => run.tool_extension_names)),
      automation_ids: uniqueSorted(runObservations.map((run) => run.automation_id ?? "")),
      invocation_count: runObservations.reduce((total, run) => total + run.invocation_count, 0),
      artifact_count: artifactUriObservations.length,
      rule_count: ruleObservations.length,
      result_count: resultObservations.length,
      taxon_count: uniqueSorted([...taxonomyTaxaIds, ...resultTaxaIds]).length,
      artifact_uris: uniqueSorted(artifactUriObservations),
      result_location_uris: locationUris,
      result_location_refs: locationRefs,
      rule_ids: ruleIds,
      result_rule_ids: resultRuleIds,
      result_levels: countBy(resultObservations.map((result) => result.level ?? "unknown")),
      result_kinds: uniqueSorted(resultObservations.map((result) => result.kind ?? "")),
      baseline_states: uniqueSorted(resultObservations.map((result) => result.baseline_state ?? "")),
      suppression_count: resultObservations.reduce((total, result) => total + result.suppression_count, 0),
      suppression_kinds: uniqueSorted(resultObservations.flatMap((result) => result.suppression_kinds)),
      fixes_present_count: resultObservations.filter((result) => result.fixes_present).length,
      fingerprint_key_count: fingerprintKeys.length,
      partial_fingerprint_key_count: partialFingerprintKeys.length,
      fingerprint_keys: fingerprintKeys,
      partial_fingerprint_keys: partialFingerprintKeys,
      taxa_ids: uniqueSorted([...taxonomyTaxaIds, ...resultTaxaIds]),
      tags,
      property_keys: propertyKeys,
      unknown_top_level_keys: unknownKeys(root, KNOWN_TOP_LEVEL_KEYS),
      unknown_run_keys: uniqueSorted(runObservations.flatMap((run) => run.unknown_keys)),
      unknown_rule_keys: uniqueSorted(ruleObservations.flatMap((rule) => rule.unknown_keys)),
      unknown_result_keys: uniqueSorted(resultObservations.flatMap((result) => result.unknown_keys)),
      runs: runObservations,
      rules: ruleObservations,
      results: resultObservations,
    },
    warnings,
  };
}

export const parseSarifSkill: Skill<string, ParseSarifOutput> = {
  metadata: {
    name: "parse_sarif",
    version: "0.1.0",
    category: "parser",
    description:
      "Parse SARIF JSON into structured static-analysis run, rule, result, location, and fingerprint observations without scoring risk.",
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
        "Parses attacker-controlled scanner output that may contain source paths, code context, repository metadata, and finding messages.",
        "Does not perform network access, persist input, call external services, or execute artifact content.",
        "Parser output preserves observed scanner structure without deciding whether results are true positives or assigning risk.",
        "Hosted exposure remains allowlist-only because SARIF artifacts can contain sensitive repository and source metadata.",
      ],
    },
  },
  run(input: string): ParseSarifOutput {
    return parseSarif(input);
  },
};
