import type { Skill } from "@security-workbench/schemas";

type JsonObject = Record<string, unknown>;

type ManifestGeneration = "mv2" | "mv3" | "unknown";
type BrowserFamily = "chromium" | "firefox" | "safari";
type BackgroundType = "service_worker" | "scripts" | "page" | "unknown" | null;
type WebAccessibleResourcesFormat = "none" | "mv2_legacy" | "mv3_objects" | "mixed";
type ContentSecurityPolicyFormat = "none" | "string" | "object" | "invalid";

type BrowserExtensionManifestOutput = {
  artifact: {
    id: "artifact_browser_extension_manifest";
    type: "browser_extension_manifest";
    name: string | null;
    version: string | null;
    manifest_version: number | null;
  };
  observed: {
    manifest_version: number | null;
    detected_manifest_generation: ManifestGeneration;
    likely_browser_families: BrowserFamily[];
    name: string | null;
    version: string | null;
    description_present: boolean;
    permissions: string[];
    api_permissions: string[];
    optional_permissions: string[];
    optional_api_permissions: string[];
    host_permissions: string[];
    explicit_host_permissions: string[];
    host_permissions_from_permissions: string[];
    optional_host_permissions: string[];
    explicit_optional_host_permissions: string[];
    optional_host_permissions_from_optional_permissions: string[];
    content_scripts: {
      count: number;
      matches: string[];
      js_count: number;
      css_count: number;
    };
    background: {
      present: boolean;
      type: BackgroundType;
      service_worker: string | null;
      scripts: string[];
      page: string | null;
      persistent: boolean | null;
    };
    actions: {
      action_present: boolean;
      browser_action_present: boolean;
      page_action_present: boolean;
      sidebar_action_present: boolean;
      any_action_present: boolean;
    };
    externally_connectable: {
      present: boolean;
      matches: string[];
      ids: string[];
    };
    web_accessible_resources: {
      present: boolean;
      format: WebAccessibleResourcesFormat;
      count: number;
      resources: string[];
      matches: string[];
      extension_ids: string[];
      use_dynamic_url_present: boolean;
    };
    content_security_policy_present: boolean;
    content_security_policy_format: ContentSecurityPolicyFormat;
    oauth2_present: boolean;
    update_url_present: boolean;
    icons_present: boolean;
    action_present: boolean;
    browser_specific_settings: {
      present: boolean;
      gecko_present: boolean;
      gecko_id: string | null;
      gecko_strict_min_version: string | null;
      gecko_strict_max_version: string | null;
    };
    legacy_applications: {
      present: boolean;
      gecko_present: boolean;
      gecko_id: string | null;
    };
    chromium: {
      minimum_chrome_version: string | null;
      offline_enabled_present: boolean;
      oauth2_present: boolean;
      update_url_present: boolean;
      declarative_net_request_present: boolean;
      declarative_net_request_rule_resources_count: number;
    };
    commands: {
      present: boolean;
      count: number;
      names: string[];
    };
    mv2_fields_present: boolean;
    mv3_fields_present: boolean;
    browser_specific_keys: string[];
    legacy_browser_specific_keys: string[];
    unknown_top_level_keys: string[];
    unsupported_or_unmodeled_keys: string[];
  };
  warnings: string[];
};

const knownTopLevelKeys = new Set([
  "action",
  "applications",
  "author",
  "automation",
  "background",
  "browser_action",
  "browser_specific_settings",
  "chrome_settings_overrides",
  "chrome_url_overrides",
  "commands",
  "content_capabilities",
  "content_scripts",
  "content_security_policy",
  "declarative_net_request",
  "default_locale",
  "description",
  "devtools_page",
  "differential_fingerprint",
  "externally_connectable",
  "homepage_url",
  "host_permissions",
  "icons",
  "import",
  "incognito",
  "key",
  "manifest_version",
  "minimum_chrome_version",
  "name",
  "oauth2",
  "offline_enabled",
  "omnibox",
  "optional_host_permissions",
  "optional_permissions",
  "options_page",
  "options_ui",
  "page_action",
  "permissions",
  "protocol_handlers",
  "requirements",
  "sandbox",
  "short_name",
  "sidebar_action",
  "storage",
  "theme",
  "trial_tokens",
  "tts_engine",
  "update_url",
  "version",
  "version_name",
  "web_accessible_resources",
]);

function isPlainObject(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function valueType(value: unknown): string {
  if (value === null) return "null";
  if (Array.isArray(value)) return "array";
  return typeof value;
}

function optionalString(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}

function optionalBoolean(value: unknown): boolean | null {
  return typeof value === "boolean" ? value : null;
}

function unique(values: string[]): string[] {
  return [...new Set(values)];
}

function readStringArray(value: unknown, path: string, warnings: string[]): string[] {
  if (value === undefined) return [];

  if (!Array.isArray(value)) {
    warnings.push(`${path} should be an array of strings; ignored ${valueType(value)} value.`);
    return [];
  }

  const result: string[] = [];
  let ignored = false;

  for (const item of value) {
    if (typeof item === "string") {
      result.push(item);
    } else {
      ignored = true;
    }
  }

  if (ignored) {
    warnings.push(`${path} contained non-string entries that were ignored.`);
  }

  return result;
}

function isHostPermissionPattern(value: string): boolean {
  const trimmed = value.trim();
  return trimmed === "<all_urls>" || trimmed.includes("://");
}

function apiPermissionsOnly(values: string[]): string[] {
  return values.filter((value) => !isHostPermissionPattern(value));
}

function hostPermissionPatternsOnly(values: string[]): string[] {
  return values.filter(isHostPermissionPattern);
}

function parseManifestVersion(value: unknown, warnings: string[]): number | null {
  if (value === undefined) {
    warnings.push("manifest_version is required for browser extension manifests.");
    return null;
  }

  if (typeof value !== "number" || !Number.isInteger(value)) {
    warnings.push(`manifest_version should be an integer; observed ${valueType(value)} value.`);
    return null;
  }

  if (value !== 2 && value !== 3) {
    warnings.push(`Unsupported manifest_version ${value}; parser returned observed fields without compatibility claims.`);
  }

  return value;
}

function detectManifestGeneration(manifestVersion: number | null): ManifestGeneration {
  if (manifestVersion === 2) return "mv2";
  if (manifestVersion === 3) return "mv3";
  return "unknown";
}

function parseContentScripts(value: unknown, warnings: string[]): BrowserExtensionManifestOutput["observed"]["content_scripts"] {
  const result = {
    count: 0,
    matches: [] as string[],
    js_count: 0,
    css_count: 0,
  };

  if (value === undefined) return result;

  if (!Array.isArray(value)) {
    warnings.push(`content_scripts should be an array; ignored ${valueType(value)} value.`);
    return result;
  }

  result.count = value.length;

  for (const [index, entry] of value.entries()) {
    if (!isPlainObject(entry)) {
      warnings.push(`content_scripts[${index}] should be an object; ignored ${valueType(entry)} value.`);
      continue;
    }

    result.matches.push(...readStringArray(entry.matches, `content_scripts[${index}].matches`, warnings));
    result.js_count += readStringArray(entry.js, `content_scripts[${index}].js`, warnings).length;
    result.css_count += readStringArray(entry.css, `content_scripts[${index}].css`, warnings).length;
  }

  result.matches = unique(result.matches);
  return result;
}

function parseBackground(value: unknown, warnings: string[]): BrowserExtensionManifestOutput["observed"]["background"] {
  const result = {
    present: value !== undefined,
    type: null as BackgroundType,
    service_worker: null as string | null,
    scripts: [] as string[],
    page: null as string | null,
    persistent: null as boolean | null,
  };

  if (value === undefined) return result;

  if (!isPlainObject(value)) {
    result.type = "unknown";
    warnings.push(`background should be an object; ignored ${valueType(value)} value.`);
    return result;
  }

  result.service_worker = optionalString(value.service_worker);
  result.scripts = readStringArray(value.scripts, "background.scripts", warnings);
  result.page = optionalString(value.page);
  result.persistent = optionalBoolean(value.persistent);

  if (value.persistent !== undefined && result.persistent === null) {
    warnings.push(`background.persistent should be a boolean; ignored ${valueType(value.persistent)} value.`);
  }

  if (result.service_worker !== null) {
    result.type = "service_worker";
  } else if (result.scripts.length > 0) {
    result.type = "scripts";
  } else if (result.page !== null) {
    result.type = "page";
  } else {
    result.type = "unknown";
    warnings.push("background was present but no recognized background entry was observed.");
  }

  return result;
}

function parseActions(parsed: JsonObject): BrowserExtensionManifestOutput["observed"]["actions"] {
  const actionPresent = isPlainObject(parsed.action);
  const browserActionPresent = isPlainObject(parsed.browser_action);
  const pageActionPresent = isPlainObject(parsed.page_action);
  const sidebarActionPresent = isPlainObject(parsed.sidebar_action);

  return {
    action_present: actionPresent,
    browser_action_present: browserActionPresent,
    page_action_present: pageActionPresent,
    sidebar_action_present: sidebarActionPresent,
    any_action_present: actionPresent || browserActionPresent || pageActionPresent || sidebarActionPresent,
  };
}

function parseExternallyConnectable(value: unknown, warnings: string[]): BrowserExtensionManifestOutput["observed"]["externally_connectable"] {
  const result = {
    present: value !== undefined,
    matches: [] as string[],
    ids: [] as string[],
  };

  if (value === undefined) return result;

  if (!isPlainObject(value)) {
    warnings.push(`externally_connectable should be an object; ignored ${valueType(value)} value.`);
    return result;
  }

  result.matches = unique(readStringArray(value.matches, "externally_connectable.matches", warnings));
  result.ids = unique(readStringArray(value.ids, "externally_connectable.ids", warnings));
  return result;
}

function parseWebAccessibleResources(value: unknown, warnings: string[]): BrowserExtensionManifestOutput["observed"]["web_accessible_resources"] {
  const result = {
    present: value !== undefined,
    format: "none" as WebAccessibleResourcesFormat,
    count: 0,
    resources: [] as string[],
    matches: [] as string[],
    extension_ids: [] as string[],
    use_dynamic_url_present: false,
  };

  if (value === undefined) return result;

  if (!Array.isArray(value)) {
    warnings.push(`web_accessible_resources should be an array; ignored ${valueType(value)} value.`);
    return result;
  }

  let legacyEntryObserved = false;
  let objectEntryObserved = false;

  for (const [index, entry] of value.entries()) {
    if (typeof entry === "string") {
      legacyEntryObserved = true;
      result.resources.push(entry);
      continue;
    }

    if (!isPlainObject(entry)) {
      warnings.push(`web_accessible_resources[${index}] should be a string or object; ignored ${valueType(entry)} value.`);
      continue;
    }

    objectEntryObserved = true;
    result.resources.push(...readStringArray(entry.resources, `web_accessible_resources[${index}].resources`, warnings));
    result.matches.push(...readStringArray(entry.matches, `web_accessible_resources[${index}].matches`, warnings));
    result.extension_ids.push(...readStringArray(entry.extension_ids, `web_accessible_resources[${index}].extension_ids`, warnings));
    if (entry.use_dynamic_url !== undefined) {
      result.use_dynamic_url_present = true;
      if (typeof entry.use_dynamic_url !== "boolean") {
        warnings.push(`web_accessible_resources[${index}].use_dynamic_url should be a boolean; observed ${valueType(entry.use_dynamic_url)} value.`);
      }
    }
  }

  if (legacyEntryObserved && objectEntryObserved) {
    result.format = "mixed";
  } else if (objectEntryObserved) {
    result.format = "mv3_objects";
  } else if (legacyEntryObserved) {
    result.format = "mv2_legacy";
  }

  result.resources = unique(result.resources);
  result.matches = unique(result.matches);
  result.extension_ids = unique(result.extension_ids);
  result.count = result.resources.length;
  return result;
}

function parseContentSecurityPolicyFormat(value: unknown): ContentSecurityPolicyFormat {
  if (value === undefined) return "none";
  if (typeof value === "string") return "string";
  if (isPlainObject(value)) return "object";
  return "invalid";
}

function readGeckoSettings(value: unknown): { gecko_present: boolean; gecko_id: string | null; gecko_strict_min_version: string | null; gecko_strict_max_version: string | null } {
  if (!isPlainObject(value) || !isPlainObject(value.gecko)) {
    return {
      gecko_present: false,
      gecko_id: null,
      gecko_strict_min_version: null,
      gecko_strict_max_version: null,
    };
  }

  return {
    gecko_present: true,
    gecko_id: optionalString(value.gecko.id),
    gecko_strict_min_version: optionalString(value.gecko.strict_min_version),
    gecko_strict_max_version: optionalString(value.gecko.strict_max_version),
  };
}

function parseCommands(value: unknown): BrowserExtensionManifestOutput["observed"]["commands"] {
  if (!isPlainObject(value)) {
    return {
      present: value !== undefined,
      count: 0,
      names: [],
    };
  }

  const names = Object.keys(value).sort();
  return {
    present: true,
    count: names.length,
    names,
  };
}

function parseDeclarativeNetRequestRuleResources(value: unknown): number {
  if (!isPlainObject(value) || !Array.isArray(value.rule_resources)) {
    return 0;
  }

  return value.rule_resources.filter(isPlainObject).length;
}

function collectPresentKeys(parsed: JsonObject, keys: string[]): string[] {
  return keys.filter((key) => parsed[key] !== undefined);
}

function detectBrowserFamilies(parsed: JsonObject, manifestGeneration: ManifestGeneration): BrowserFamily[] {
  const families = new Set<BrowserFamily>();

  const hasFirefoxSpecific =
    parsed.browser_specific_settings !== undefined ||
    parsed.applications !== undefined ||
    parsed.sidebar_action !== undefined ||
    parsed.chrome_settings_overrides !== undefined;

  const hasChromiumSpecific =
    parsed.minimum_chrome_version !== undefined ||
    parsed.oauth2 !== undefined ||
    parsed.update_url !== undefined ||
    parsed.offline_enabled !== undefined ||
    parsed.externally_connectable !== undefined ||
    parsed.declarative_net_request !== undefined;

  if (hasFirefoxSpecific) {
    families.add("firefox");
  }

  if (hasChromiumSpecific) {
    families.add("chromium");
  }

  if (families.size === 0 && (manifestGeneration === "mv2" || manifestGeneration === "mv3")) {
    families.add("chromium");
    families.add("firefox");
    families.add("safari");
  }

  return ["chromium", "firefox", "safari"].filter((family) => families.has(family as BrowserFamily)) as BrowserFamily[];
}

function parseBrowserExtensionManifestInput(input: string): BrowserExtensionManifestOutput {
  if (typeof input !== "string") {
    throw new Error("parse_browser_extension_manifest input must be a string");
  }

  if (input.trim().length === 0) {
    throw new Error("parse_browser_extension_manifest input must not be empty");
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(input);
  } catch {
    throw new Error("parse_browser_extension_manifest input must be valid JSON");
  }

  if (!isPlainObject(parsed)) {
    throw new Error(`parse_browser_extension_manifest input must be a JSON object; received ${valueType(parsed)}`);
  }

  const warnings: string[] = [];
  const manifestVersion = parseManifestVersion(parsed.manifest_version, warnings);
  const manifestGeneration = detectManifestGeneration(manifestVersion);
  const name = optionalString(parsed.name);
  const version = optionalString(parsed.version);
  const permissions = unique(readStringArray(parsed.permissions, "permissions", warnings));
  const optionalPermissions = unique(readStringArray(parsed.optional_permissions, "optional_permissions", warnings));
  const explicitHostPermissions = unique(readStringArray(parsed.host_permissions, "host_permissions", warnings));
  const explicitOptionalHostPermissions = unique(readStringArray(parsed.optional_host_permissions, "optional_host_permissions", warnings));
  const hostPermissionsFromPermissions = unique(hostPermissionPatternsOnly(permissions));
  const optionalHostPermissionsFromOptionalPermissions = unique(hostPermissionPatternsOnly(optionalPermissions));
  const contentScripts = parseContentScripts(parsed.content_scripts, warnings);
  const background = parseBackground(parsed.background, warnings);
  const actions = parseActions(parsed);
  const externallyConnectable = parseExternallyConnectable(parsed.externally_connectable, warnings);
  const webAccessibleResources = parseWebAccessibleResources(parsed.web_accessible_resources, warnings);
  const cspFormat = parseContentSecurityPolicyFormat(parsed.content_security_policy);
  const browserSpecific = readGeckoSettings(parsed.browser_specific_settings);
  const legacyApplications = readGeckoSettings(parsed.applications);
  const commands = parseCommands(parsed.commands);
  const chromiumDnrRuleResourceCount = parseDeclarativeNetRequestRuleResources(parsed.declarative_net_request);
  const browserSpecificKeys = collectPresentKeys(parsed, [
    "applications",
    "browser_specific_settings",
    "chrome_settings_overrides",
    "chrome_url_overrides",
    "declarative_net_request",
    "externally_connectable",
    "minimum_chrome_version",
    "oauth2",
    "offline_enabled",
    "sidebar_action",
    "update_url",
  ]);
  const legacyBrowserSpecificKeys = collectPresentKeys(parsed, ["applications"]);
  const unknownTopLevelKeys = Object.keys(parsed).filter((key) => !knownTopLevelKeys.has(key)).sort();

  if (parsed.name !== undefined && name === null) {
    warnings.push(`name should be a string; observed ${valueType(parsed.name)} value.`);
  }

  if (parsed.version !== undefined && version === null) {
    warnings.push(`version should be a string; observed ${valueType(parsed.version)} value.`);
  }

  if (parsed.content_security_policy !== undefined && cspFormat === "invalid") {
    warnings.push(`content_security_policy should be a string or object; observed ${valueType(parsed.content_security_policy)} value.`);
  }

  const mv2FieldsPresent =
    background.scripts.length > 0 ||
    background.page !== null ||
    background.persistent !== null ||
    actions.browser_action_present ||
    actions.page_action_present ||
    hostPermissionsFromPermissions.length > 0 ||
    webAccessibleResources.format === "mv2_legacy" ||
    webAccessibleResources.format === "mixed" ||
    parsed.applications !== undefined;

  const mv3FieldsPresent =
    background.service_worker !== null ||
    explicitHostPermissions.length > 0 ||
    explicitOptionalHostPermissions.length > 0 ||
    actions.action_present ||
    webAccessibleResources.format === "mv3_objects" ||
    webAccessibleResources.format === "mixed" ||
    parsed.declarative_net_request !== undefined;

  return {
    artifact: {
      id: "artifact_browser_extension_manifest",
      type: "browser_extension_manifest",
      name,
      version,
      manifest_version: manifestVersion,
    },
    observed: {
      manifest_version: manifestVersion,
      detected_manifest_generation: manifestGeneration,
      likely_browser_families: detectBrowserFamilies(parsed, manifestGeneration),
      name,
      version,
      description_present: typeof parsed.description === "string" && parsed.description.length > 0,
      permissions,
      api_permissions: unique(apiPermissionsOnly(permissions)),
      optional_permissions: optionalPermissions,
      optional_api_permissions: unique(apiPermissionsOnly(optionalPermissions)),
      host_permissions: unique([...explicitHostPermissions, ...hostPermissionsFromPermissions]),
      explicit_host_permissions: explicitHostPermissions,
      host_permissions_from_permissions: hostPermissionsFromPermissions,
      optional_host_permissions: unique([...explicitOptionalHostPermissions, ...optionalHostPermissionsFromOptionalPermissions]),
      explicit_optional_host_permissions: explicitOptionalHostPermissions,
      optional_host_permissions_from_optional_permissions: optionalHostPermissionsFromOptionalPermissions,
      content_scripts: contentScripts,
      background,
      actions,
      externally_connectable: externallyConnectable,
      web_accessible_resources: webAccessibleResources,
      content_security_policy_present: parsed.content_security_policy !== undefined,
      content_security_policy_format: cspFormat,
      oauth2_present: isPlainObject(parsed.oauth2),
      update_url_present: typeof parsed.update_url === "string" && parsed.update_url.length > 0,
      icons_present: isPlainObject(parsed.icons),
      action_present: actions.any_action_present,
      browser_specific_settings: {
        present: parsed.browser_specific_settings !== undefined,
        ...browserSpecific,
      },
      legacy_applications: {
        present: parsed.applications !== undefined,
        gecko_present: legacyApplications.gecko_present,
        gecko_id: legacyApplications.gecko_id,
      },
      chromium: {
        minimum_chrome_version: optionalString(parsed.minimum_chrome_version),
        offline_enabled_present: parsed.offline_enabled !== undefined,
        oauth2_present: isPlainObject(parsed.oauth2),
        update_url_present: typeof parsed.update_url === "string" && parsed.update_url.length > 0,
        declarative_net_request_present: isPlainObject(parsed.declarative_net_request),
        declarative_net_request_rule_resources_count: chromiumDnrRuleResourceCount,
      },
      commands,
      mv2_fields_present: mv2FieldsPresent,
      mv3_fields_present: mv3FieldsPresent,
      browser_specific_keys: browserSpecificKeys,
      legacy_browser_specific_keys: legacyBrowserSpecificKeys,
      unknown_top_level_keys: unknownTopLevelKeys,
      unsupported_or_unmodeled_keys: unknownTopLevelKeys,
    },
    warnings,
  };
}

export const parseBrowserExtensionManifest: Skill<string, BrowserExtensionManifestOutput> = {
  metadata: {
    name: "parse_browser_extension_manifest",
    version: "0.1.0",
    category: "parser",
    description: "Parse common WebExtensions-style browser extension manifests across Manifest V2 and V3 without scoring risk.",
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
        "Parses attacker-controlled browser extension manifest metadata.",
        "Does not install extension packages, run extension code, or perform network lookups.",
        "Output may contain attacker-controlled strings and should be escaped by renderers and agents.",
      ],
    },
  },
  run: parseBrowserExtensionManifestInput,
};
