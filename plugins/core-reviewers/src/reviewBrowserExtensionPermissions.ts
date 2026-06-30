import type { EvidenceRecord, JsonObject, JsonValue, SignalRecord, Skill } from "@security-workbench/schemas";
import { localOnlyPermissions } from "./localOnlyPermissions.js";

type ReviewRecord = Record<string, unknown>;
type Confidence = "confirmed" | "high" | "medium" | "low" | "unknown";

export type ParsedBrowserExtensionManifestForReview = {
  artifact: {
    id?: string;
    type?: string;
    name?: string | null;
    version?: string | null;
    manifest_version?: number | null;
  };
  observed: ReviewRecord;
  warnings?: readonly string[];
};

export type BrowserExtensionPermissionReviewEvidence = EvidenceRecord;
export type BrowserExtensionPermissionReviewSignal = SignalRecord;

export type BrowserExtensionPermissionReviewOutput = {
  artifact: {
    id: "artifact_browser_extension_permission_review";
    type: "browser_extension_permission_review";
    source_artifact_id: string | null;
    source_artifact_type: string | null;
    name: string | null;
    version: string | null;
    manifest_version: number | null;
  };
  observed: {
    source_parser: "parse_browser_extension_manifest";
    source_warning_count: number;
    manifest_generation: string | null;
    reviewed_surfaces: string[];
    evidence_count: number;
    signal_count: number;
    broad_host_permissions: string[];
    broad_optional_host_permissions: string[];
    wildcard_host_permissions: string[];
    wildcard_optional_host_permissions: string[];
    api_permissions: string[];
    optional_api_permissions: string[];
    notable_api_permissions: string[];
    notable_optional_api_permissions: string[];
    content_script_matches: string[];
    broad_content_script_matches: string[];
    externally_connectable_present: boolean;
    externally_connectable_matches: string[];
    externally_connectable_ids: string[];
    web_accessible_resources_present: boolean;
    web_accessible_resource_count: number;
    web_accessible_resource_matches: string[];
    background_present: boolean;
    background_type: string | null;
    update_url_present: boolean;
    oauth2_present: boolean;
    content_security_policy_present: boolean;
  };
  evidence: BrowserExtensionPermissionReviewEvidence[];
  signals: BrowserExtensionPermissionReviewSignal[];
  warnings: string[];
};

const notableApiPermissions = new Set([
  "bookmarks",
  "clipboardRead",
  "clipboardWrite",
  "cookies",
  "debugger",
  "declarativeNetRequest",
  "declarativeNetRequestWithHostAccess",
  "downloads",
  "history",
  "identity",
  "management",
  "nativeMessaging",
  "privacy",
  "proxy",
  "scripting",
  "tabs",
  "webRequest",
  "webRequestBlocking",
]);

function isRecord(value: unknown): value is ReviewRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function stringOrNull(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}

function numberOrNull(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function stringArray(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return [];
  }

  return value.filter((entry): entry is string => typeof entry === "string");
}

function uniqueSorted(values: readonly string[]): string[] {
  return [...new Set(values)].sort((left, right) => left.localeCompare(right));
}

function childRecord(record: ReviewRecord, key: string): ReviewRecord | undefined {
  const value = record[key];
  return isRecord(value) ? value : undefined;
}

function parseJsonString(input: string): unknown {
  try {
    return JSON.parse(input) as unknown;
  } catch {
    throw new Error("review_browser_extension_permissions input must be parsed manifest JSON or a JSON run result from parse_browser_extension_manifest");
  }
}

function unwrapInput(input: unknown): ParsedBrowserExtensionManifestForReview {
  const parsed = typeof input === "string" ? parseJsonString(input) : input;
  const candidate = isRecord(parsed) && isRecord(parsed.output) ? parsed.output : parsed;

  if (!isRecord(candidate)) {
    throw new Error("review_browser_extension_permissions input must be an object");
  }

  const artifact = childRecord(candidate, "artifact");
  const observed = childRecord(candidate, "observed");

  if (!artifact || !observed) {
    throw new Error("review_browser_extension_permissions input must be parse_browser_extension_manifest output with artifact and observed fields");
  }

  if (artifact.type !== "browser_extension_manifest") {
    throw new Error("review_browser_extension_permissions input artifact.type must be browser_extension_manifest");
  }

  return {
    artifact: {
      id: stringOrNull(artifact.id) ?? undefined,
      type: stringOrNull(artifact.type) ?? undefined,
      name: stringOrNull(artifact.name),
      version: stringOrNull(artifact.version),
      manifest_version: numberOrNull(artifact.manifest_version),
    },
    observed,
    warnings: Array.isArray(candidate.warnings) ? candidate.warnings.filter((entry): entry is string => typeof entry === "string") : [],
  };
}

function isAllUrlsPattern(value: string): boolean {
  return value.trim().toLowerCase() === "<all_urls>";
}

function isBroadHostPattern(value: string): boolean {
  const normalized = value.trim().toLowerCase();
  return (
    normalized === "<all_urls>" ||
    normalized === "*://*/*" ||
    normalized === "http://*/*" ||
    normalized === "https://*/*" ||
    normalized === "ftp://*/*"
  );
}

function isWildcardHostPattern(value: string): boolean {
  const normalized = value.trim().toLowerCase();
  return isBroadHostPattern(normalized) || normalized.startsWith("*://") || normalized.includes("://*.");
}

function notablePermissions(values: readonly string[]): string[] {
  return uniqueSorted(values.filter((value) => notableApiPermissions.has(value)));
}

function evidenceValue(value: unknown): JsonValue {
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "number" ||
    typeof value === "boolean" ||
    Array.isArray(value) ||
    isRecord(value)
  ) {
    return value as JsonValue;
  }

  return String(value);
}

function createEvidenceBuilder(sourceArtifactId: string | null) {
  const evidence: EvidenceRecord[] = [];

  function addEvidence(type: string, path: string, value: unknown, description: string): string {
    const id = `evidence_browser_extension_${String(evidence.length + 1).padStart(3, "0")}`;
    evidence.push({
      id,
      type,
      artifact_ref: sourceArtifactId ?? undefined,
      path,
      value: evidenceValue(value),
      value_kind: "metadata",
      sensitivity: "low",
      description,
    });
    return id;
  }

  return { evidence, addEvidence };
}

function addSignal(
  signals: SignalRecord[],
  input: {
    type: string;
    summary: string;
    evidenceRefs: readonly string[];
    observed: JsonObject;
    confidence?: Confidence;
    tags?: readonly string[];
  }
): void {
  signals.push({
    id: `signal_browser_extension_${String(signals.length + 1).padStart(3, "0")}`,
    type: input.type,
    summary: input.summary,
    confidence: input.confidence ?? "confirmed",
    evidence_refs: input.evidenceRefs,
    observed: input.observed,
    tags: input.tags ?? ["browser-extension", "permissions"],
  });
}

function addArraySignal(
  signals: SignalRecord[],
  addEvidence: (type: string, path: string, value: unknown, description: string) => string,
  values: readonly string[],
  input: {
    evidenceType: string;
    evidencePath: string;
    evidenceDescription: string;
    signalType: string;
    summary: string;
    observedKey: string;
    tags?: readonly string[];
  }
): void {
  if (values.length === 0) {
    return;
  }

  const evidenceRef = addEvidence(input.evidenceType, input.evidencePath, values, input.evidenceDescription);
  addSignal(signals, {
    type: input.signalType,
    summary: input.summary,
    evidenceRefs: [evidenceRef],
    observed: {
      [input.observedKey]: values,
      count: values.length,
    },
    tags: input.tags,
  });
}

export function reviewBrowserExtensionPermissions(input: unknown): BrowserExtensionPermissionReviewOutput {
  const parsed = unwrapInput(input);
  const observed = parsed.observed;
  const sourceArtifactId = stringOrNull(parsed.artifact.id);
  const { evidence, addEvidence } = createEvidenceBuilder(sourceArtifactId);
  const signals: SignalRecord[] = [];
  const warnings: string[] = [];

  const permissions = stringArray(observed.permissions);
  const optionalPermissions = stringArray(observed.optional_permissions);
  const apiPermissions = uniqueSorted(stringArray(observed.api_permissions));
  const optionalApiPermissions = uniqueSorted(stringArray(observed.optional_api_permissions));
  const hostPermissions = uniqueSorted(stringArray(observed.host_permissions));
  const optionalHostPermissions = uniqueSorted(stringArray(observed.optional_host_permissions));
  const broadHostPermissions = uniqueSorted(hostPermissions.filter(isBroadHostPattern));
  const broadOptionalHostPermissions = uniqueSorted(optionalHostPermissions.filter(isBroadHostPattern));
  const wildcardHostPermissions = uniqueSorted(hostPermissions.filter(isWildcardHostPattern));
  const wildcardOptionalHostPermissions = uniqueSorted(optionalHostPermissions.filter(isWildcardHostPattern));
  const allUrlsPermissions = uniqueSorted([...hostPermissions, ...optionalHostPermissions].filter(isAllUrlsPattern));
  const reviewedNotablePermissions = notablePermissions(apiPermissions);
  const reviewedNotableOptionalPermissions = notablePermissions(optionalApiPermissions);

  const contentScripts = childRecord(observed, "content_scripts");
  const contentScriptMatches = contentScripts ? uniqueSorted(stringArray(contentScripts.matches)) : [];
  const broadContentScriptMatches = uniqueSorted(contentScriptMatches.filter(isBroadHostPattern));

  const externallyConnectable = childRecord(observed, "externally_connectable");
  const externallyConnectablePresent = externallyConnectable?.present === true;
  const externallyConnectableMatches = externallyConnectable ? uniqueSorted(stringArray(externallyConnectable.matches)) : [];
  const externallyConnectableIds = externallyConnectable ? uniqueSorted(stringArray(externallyConnectable.ids)) : [];

  const webAccessibleResources = childRecord(observed, "web_accessible_resources");
  const webAccessibleResourcesPresent = webAccessibleResources?.present === true;
  const webAccessibleResourceCount = typeof webAccessibleResources?.count === "number" ? webAccessibleResources.count : 0;
  const webAccessibleResourceMatches = webAccessibleResources ? uniqueSorted(stringArray(webAccessibleResources.matches)) : [];

  const background = childRecord(observed, "background");
  const backgroundPresent = background?.present === true;
  const backgroundType = stringOrNull(background?.type);
  const updateUrlPresent = observed.update_url_present === true;
  const oauth2Present = observed.oauth2_present === true;
  const contentSecurityPolicyPresent = observed.content_security_policy_present === true;

  addArraySignal(signals, addEvidence, allUrlsPermissions, {
    evidenceType: "browser_extension_all_urls_permission",
    evidencePath: "observed.host_permissions / observed.optional_host_permissions",
    evidenceDescription: "The parsed manifest includes <all_urls> in required or optional host permissions.",
    signalType: "browser_extension.all_urls_permission_present",
    summary: "Browser extension manifest declares <all_urls> host access.",
    observedKey: "patterns",
    tags: ["browser-extension", "host-permissions"],
  });

  addArraySignal(signals, addEvidence, broadHostPermissions, {
    evidenceType: "browser_extension_broad_host_permissions",
    evidencePath: "observed.host_permissions",
    evidenceDescription: "The parsed manifest includes broad required host permission patterns.",
    signalType: "browser_extension.broad_host_permissions_present",
    summary: "Browser extension manifest declares broad required host permissions.",
    observedKey: "patterns",
    tags: ["browser-extension", "host-permissions"],
  });

  addArraySignal(signals, addEvidence, broadOptionalHostPermissions, {
    evidenceType: "browser_extension_broad_optional_host_permissions",
    evidencePath: "observed.optional_host_permissions",
    evidenceDescription: "The parsed manifest includes broad optional host permission patterns.",
    signalType: "browser_extension.broad_optional_host_permissions_present",
    summary: "Browser extension manifest declares broad optional host permissions.",
    observedKey: "patterns",
    tags: ["browser-extension", "host-permissions"],
  });

  addArraySignal(signals, addEvidence, reviewedNotablePermissions, {
    evidenceType: "browser_extension_notable_api_permissions",
    evidencePath: "observed.api_permissions",
    evidenceDescription: "The parsed manifest includes API permissions that commonly warrant review.",
    signalType: "browser_extension.notable_api_permissions_present",
    summary: "Browser extension manifest declares API permissions that commonly warrant review.",
    observedKey: "permissions",
    tags: ["browser-extension", "api-permissions"],
  });

  addArraySignal(signals, addEvidence, reviewedNotableOptionalPermissions, {
    evidenceType: "browser_extension_notable_optional_api_permissions",
    evidencePath: "observed.optional_api_permissions",
    evidenceDescription: "The parsed manifest includes optional API permissions that commonly warrant review.",
    signalType: "browser_extension.notable_optional_api_permissions_present",
    summary: "Browser extension manifest declares optional API permissions that commonly warrant review.",
    observedKey: "permissions",
    tags: ["browser-extension", "api-permissions"],
  });

  addArraySignal(signals, addEvidence, broadContentScriptMatches, {
    evidenceType: "browser_extension_broad_content_script_matches",
    evidencePath: "observed.content_scripts.matches",
    evidenceDescription: "The parsed manifest includes content script matches on broad host patterns.",
    signalType: "browser_extension.broad_content_script_matches_present",
    summary: "Browser extension content scripts are declared for broad host patterns.",
    observedKey: "matches",
    tags: ["browser-extension", "content-scripts"],
  });

  if (backgroundPresent) {
    const evidenceRef = addEvidence(
      "browser_extension_background_context",
      "observed.background",
      { present: backgroundPresent, type: backgroundType },
      "The parsed manifest declares a background context."
    );
    addSignal(signals, {
      type: "browser_extension.background_context_present",
      summary: "Browser extension manifest declares a background context.",
      evidenceRefs: [evidenceRef],
      observed: { present: backgroundPresent, type: backgroundType ?? "unknown" },
      tags: ["browser-extension", "background"],
    });
  }

  if (externallyConnectablePresent && (externallyConnectableMatches.length > 0 || externallyConnectableIds.length > 0)) {
    const evidenceRef = addEvidence(
      "browser_extension_externally_connectable",
      "observed.externally_connectable",
      { matches: externallyConnectableMatches, ids: externallyConnectableIds },
      "The parsed manifest declares externally_connectable matches or extension IDs."
    );
    addSignal(signals, {
      type: "browser_extension.externally_connectable_present",
      summary: "Browser extension manifest declares externally_connectable entries.",
      evidenceRefs: [evidenceRef],
      observed: { matches: externallyConnectableMatches, ids: externallyConnectableIds },
      tags: ["browser-extension", "externally-connectable"],
    });
  }

  if (webAccessibleResourcesPresent && (webAccessibleResourceCount > 0 || webAccessibleResourceMatches.length > 0)) {
    const evidenceRef = addEvidence(
      "browser_extension_web_accessible_resources",
      "observed.web_accessible_resources",
      { count: webAccessibleResourceCount, matches: webAccessibleResourceMatches },
      "The parsed manifest declares web accessible resources."
    );
    addSignal(signals, {
      type: "browser_extension.web_accessible_resources_present",
      summary: "Browser extension manifest declares web accessible resources.",
      evidenceRefs: [evidenceRef],
      observed: { count: webAccessibleResourceCount, matches: webAccessibleResourceMatches },
      tags: ["browser-extension", "web-accessible-resources"],
    });
  }

  if (updateUrlPresent) {
    const evidenceRef = addEvidence(
      "browser_extension_update_url_present",
      "observed.update_url_present",
      true,
      "The parsed manifest reports update_url presence."
    );
    addSignal(signals, {
      type: "browser_extension.update_url_present",
      summary: "Browser extension manifest declares update_url presence.",
      evidenceRefs: [evidenceRef],
      observed: { update_url_present: true },
      tags: ["browser-extension", "update-url"],
    });
  }

  if (oauth2Present) {
    const evidenceRef = addEvidence(
      "browser_extension_oauth2_present",
      "observed.oauth2_present",
      true,
      "The parsed manifest reports oauth2 presence."
    );
    addSignal(signals, {
      type: "browser_extension.oauth2_present",
      summary: "Browser extension manifest declares oauth2 configuration presence.",
      evidenceRefs: [evidenceRef],
      observed: { oauth2_present: true },
      tags: ["browser-extension", "oauth2"],
    });
  }

  if (!contentSecurityPolicyPresent) {
    const evidenceRef = addEvidence(
      "browser_extension_csp_not_observed",
      "observed.content_security_policy_present",
      false,
      "The parsed manifest did not report an explicit content_security_policy entry."
    );
    addSignal(signals, {
      type: "browser_extension.content_security_policy_not_observed",
      summary: "Browser extension manifest did not include an explicit content_security_policy entry.",
      evidenceRefs: [evidenceRef],
      observed: { content_security_policy_present: false },
      tags: ["browser-extension", "content-security-policy"],
    });
  }

  if (parsed.warnings && parsed.warnings.length > 0) {
    warnings.push(`Source parser emitted ${parsed.warnings.length} warning(s); review output preserves source_warning_count only.`);
  }

  return {
    artifact: {
      id: "artifact_browser_extension_permission_review",
      type: "browser_extension_permission_review",
      source_artifact_id: sourceArtifactId,
      source_artifact_type: stringOrNull(parsed.artifact.type),
      name: parsed.artifact.name ?? null,
      version: parsed.artifact.version ?? null,
      manifest_version: parsed.artifact.manifest_version ?? null,
    },
    observed: {
      source_parser: "parse_browser_extension_manifest",
      source_warning_count: parsed.warnings?.length ?? 0,
      manifest_generation: stringOrNull(observed.detected_manifest_generation),
      reviewed_surfaces: [
        "permissions",
        "host_permissions",
        "optional_permissions",
        "content_scripts",
        "background",
        "externally_connectable",
        "web_accessible_resources",
        "update_url",
        "oauth2",
        "content_security_policy",
      ],
      evidence_count: evidence.length,
      signal_count: signals.length,
      broad_host_permissions: broadHostPermissions,
      broad_optional_host_permissions: broadOptionalHostPermissions,
      wildcard_host_permissions: wildcardHostPermissions,
      wildcard_optional_host_permissions: wildcardOptionalHostPermissions,
      api_permissions: apiPermissions,
      optional_api_permissions: optionalApiPermissions,
      notable_api_permissions: reviewedNotablePermissions,
      notable_optional_api_permissions: reviewedNotableOptionalPermissions,
      content_script_matches: contentScriptMatches,
      broad_content_script_matches: broadContentScriptMatches,
      externally_connectable_present: externallyConnectablePresent,
      externally_connectable_matches: externallyConnectableMatches,
      externally_connectable_ids: externallyConnectableIds,
      web_accessible_resources_present: webAccessibleResourcesPresent,
      web_accessible_resource_count: webAccessibleResourceCount,
      web_accessible_resource_matches: webAccessibleResourceMatches,
      background_present: backgroundPresent,
      background_type: backgroundType,
      update_url_present: updateUrlPresent,
      oauth2_present: oauth2Present,
      content_security_policy_present: contentSecurityPolicyPresent,
    },
    evidence,
    signals,
    warnings,
  };
}

export const reviewBrowserExtensionPermissionsSkill: Skill<unknown, BrowserExtensionPermissionReviewOutput> = {
  metadata: {
    name: "review_browser_extension_permissions",
    version: "0.1.0",
    category: "reviewer",
    description: "Review parsed browser extension manifest permission surfaces and emit evidence-backed local signals without scoring risk.",
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
        "Reviews already parsed browser extension manifest observations.",
        "Does not install extensions, execute extension code, contact browser stores, or perform network lookups.",
        "Output may include attacker-controlled manifest strings and should be escaped by renderers and agents.",
      ],
    },
  },
  run: reviewBrowserExtensionPermissions,
};
