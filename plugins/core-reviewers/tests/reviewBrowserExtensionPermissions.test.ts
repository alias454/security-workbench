import { describe, expect, it } from "vitest";
import {
  reviewBrowserExtensionPermissions,
  reviewBrowserExtensionPermissionsSkill,
} from "../src/reviewBrowserExtensionPermissions.js";

const parsedManifestOutput = {
  artifact: {
    id: "artifact_browser_extension_manifest",
    type: "browser_extension_manifest",
    name: "Fixture Extension",
    version: "1.0.0",
    manifest_version: 3,
  },
  observed: {
    detected_manifest_generation: "mv3",
    permissions: ["tabs", "storage"],
    api_permissions: ["tabs", "storage"],
    optional_permissions: ["cookies"],
    optional_api_permissions: ["cookies"],
    host_permissions: ["<all_urls>", "https://*.example.com/*"],
    optional_host_permissions: ["*://*/*"],
    content_scripts: {
      count: 1,
      matches: ["<all_urls>", "https://app.example.com/*"],
      js_count: 1,
      css_count: 0,
    },
    background: {
      present: true,
      type: "service_worker",
      service_worker: "background.js",
      scripts: [],
      page: null,
      persistent: null,
    },
    externally_connectable: {
      present: true,
      matches: ["https://app.example.com/*"],
      ids: ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
    },
    web_accessible_resources: {
      present: true,
      format: "mv3_objects",
      count: 2,
      resources: ["panel.html", "assets/*.js"],
      matches: ["https://app.example.com/*"],
      extension_ids: [],
      use_dynamic_url_present: true,
    },
    content_security_policy_present: false,
    oauth2_present: true,
    update_url_present: true,
  },
  warnings: [],
} as const;

describe("review_browser_extension_permissions", () => {
  it("exports the reviewer skill with local-only permissions", () => {
    expect(reviewBrowserExtensionPermissionsSkill.metadata.name).toBe("review_browser_extension_permissions");
    expect(reviewBrowserExtensionPermissionsSkill.metadata.category).toBe("reviewer");
    expect(reviewBrowserExtensionPermissionsSkill.metadata.execution).toEqual({
      mode: "local_only",
      network_access: "none",
      deterministic: true,
    });
    expect(reviewBrowserExtensionPermissionsSkill.metadata.permissions).toEqual({
      network: "none",
      filesystem: "none",
      sends: [],
      persists: false,
      runs_external_binaries: false,
    });
  });

  it("emits evidence-backed signals for browser extension permission review surfaces", () => {
    const output = reviewBrowserExtensionPermissions(parsedManifestOutput);

    expect(output.artifact).toMatchObject({
      type: "browser_extension_permission_review",
      source_artifact_id: "artifact_browser_extension_manifest",
      source_artifact_type: "browser_extension_manifest",
      name: "Fixture Extension",
      version: "1.0.0",
      manifest_version: 3,
    });

    expect(output.observed.broad_host_permissions).toEqual(["<all_urls>"]);
    expect(output.observed.broad_optional_host_permissions).toEqual(["*://*/*"]);
    expect(output.observed.notable_api_permissions).toEqual(["tabs"]);
    expect(output.observed.notable_optional_api_permissions).toEqual(["cookies"]);
    expect(output.observed.broad_content_script_matches).toEqual(["<all_urls>"]);
    expect(output.observed.background_present).toBe(true);
    expect(output.observed.externally_connectable_present).toBe(true);
    expect(output.observed.web_accessible_resources_present).toBe(true);
    expect(output.observed.update_url_present).toBe(true);
    expect(output.observed.oauth2_present).toBe(true);
    expect(output.observed.content_security_policy_present).toBe(false);

    expect(output.evidence.length).toBeGreaterThan(0);
    expect(output.signals.length).toBe(output.observed.signal_count);
    expect(output.evidence.length).toBe(output.observed.evidence_count);
    expect(output.signals.map((signal) => signal.type)).toEqual([
      "browser_extension.all_urls_permission_present",
      "browser_extension.broad_host_permissions_present",
      "browser_extension.broad_optional_host_permissions_present",
      "browser_extension.notable_api_permissions_present",
      "browser_extension.notable_optional_api_permissions_present",
      "browser_extension.broad_content_script_matches_present",
      "browser_extension.background_context_present",
      "browser_extension.externally_connectable_present",
      "browser_extension.web_accessible_resources_present",
      "browser_extension.update_url_present",
      "browser_extension.oauth2_present",
      "browser_extension.content_security_policy_not_observed",
    ]);
    expect(output.signals.every((signal) => signal.evidence_refs.length > 0)).toBe(true);
  });

  it("accepts a JSON run result from parse_browser_extension_manifest", () => {
    const runResult = {
      run_id: "run_parser",
      status: "completed",
      skill: { name: "parse_browser_extension_manifest", version: "0.1.0" },
      output: parsedManifestOutput,
      errors: [],
      warnings: [],
    };

    const output = reviewBrowserExtensionPermissions(JSON.stringify(runResult));

    expect(output.observed.source_parser).toBe("parse_browser_extension_manifest");
    expect(output.observed.broad_host_permissions).toEqual(["<all_urls>"]);
  });

  it("preserves source parser warning count without copying all source warnings", () => {
    const output = reviewBrowserExtensionPermissions({
      ...parsedManifestOutput,
      warnings: ["source parser warning"],
    });

    expect(output.observed.source_warning_count).toBe(1);
    expect(output.warnings).toEqual([
      "Source parser emitted 1 warning(s); review output preserves source_warning_count only.",
    ]);
  });

  it("returns an empty signal set for a minimal low-surface parsed manifest", () => {
    const output = reviewBrowserExtensionPermissions({
      artifact: {
        id: "artifact_browser_extension_manifest",
        type: "browser_extension_manifest",
        name: "Minimal",
        version: "1.0.0",
        manifest_version: 3,
      },
      observed: {
        detected_manifest_generation: "mv3",
        permissions: [],
        api_permissions: [],
        optional_permissions: [],
        optional_api_permissions: [],
        host_permissions: [],
        optional_host_permissions: [],
        content_scripts: { count: 0, matches: [], js_count: 0, css_count: 0 },
        background: { present: false, type: null },
        externally_connectable: { present: false, matches: [], ids: [] },
        web_accessible_resources: { present: false, count: 0, matches: [] },
        content_security_policy_present: true,
        oauth2_present: false,
        update_url_present: false,
      },
      warnings: [],
    });

    expect(output.signals).toEqual([]);
    expect(output.evidence).toEqual([]);
    expect(output.observed.signal_count).toBe(0);
  });

  it("rejects raw manifest JSON that has not been parsed by parse_browser_extension_manifest", () => {
    expect(() => reviewBrowserExtensionPermissions('{"manifest_version":3,"name":"Raw"}')).toThrow(
      "review_browser_extension_permissions input must be parse_browser_extension_manifest output with artifact and observed fields"
    );
  });

  it("rejects invalid JSON strings", () => {
    expect(() => reviewBrowserExtensionPermissions("{bad json}")).toThrow(
      "review_browser_extension_permissions input must be parsed manifest JSON or a JSON run result from parse_browser_extension_manifest"
    );
  });

  it("rejects non-browser-extension parser output", () => {
    expect(() =>
      reviewBrowserExtensionPermissions({
        artifact: { id: "artifact_package_json", type: "package_json" },
        observed: {},
        warnings: [],
      })
    ).toThrow("review_browser_extension_permissions input artifact.type must be browser_extension_manifest");
  });
});
