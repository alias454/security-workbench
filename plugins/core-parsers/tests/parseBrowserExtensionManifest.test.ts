import { describe, expect, it } from "vitest";

import { parseBrowserExtensionManifest } from "../src/parseBrowserExtensionManifest.js";

const manifestV3 = JSON.stringify({
  manifest_version: 3,
  name: "Fixture Extension",
  version: "1.2.3",
  description: "Example extension manifest for parser tests.",
  permissions: ["storage", "tabs", "scripting"],
  optional_permissions: ["notifications"],
  host_permissions: ["https://*.example.com/*"],
  optional_host_permissions: ["https://api.example.net/*"],
  background: {
    service_worker: "background.js",
  },
  content_scripts: [
    {
      matches: ["https://*.example.com/*"],
      js: ["content.js"],
      css: ["content.css"],
    },
  ],
  externally_connectable: {
    matches: ["https://portal.example.com/*"],
  },
  web_accessible_resources: [
    {
      resources: ["assets/icon.png", "assets/panel.html"],
      matches: ["https://*.example.com/*"],
    },
  ],
  content_security_policy: {
    extension_pages: "script-src 'self'; object-src 'self'",
  },
  oauth2: {
    client_id: "fixture-client-id",
    scopes: ["profile"],
  },
  action: {
    default_title: "Fixture",
  },
  icons: {
    "128": "icon.png",
  },
});

describe("parse_browser_extension_manifest", () => {
  it("parses manifest v3 metadata and extension surfaces", async () => {
    const output = await parseBrowserExtensionManifest.run(manifestV3);

    expect(output.artifact).toEqual({
      id: "artifact_browser_extension_manifest",
      type: "browser_extension_manifest",
      name: "Fixture Extension",
      version: "1.2.3",
      manifest_version: 3,
    });
    expect(output.observed.detected_manifest_generation).toBe("mv3");
    expect(output.observed.likely_browser_families).toEqual(["chromium"]);
    expect(output.observed.permissions).toEqual(["storage", "tabs", "scripting"]);
    expect(output.observed.api_permissions).toEqual(["storage", "tabs", "scripting"]);
    expect(output.observed.host_permissions).toEqual(["https://*.example.com/*"]);
    expect(output.observed.explicit_host_permissions).toEqual(["https://*.example.com/*"]);
    expect(output.observed.host_permissions_from_permissions).toEqual([]);
    expect(output.observed.background).toEqual({
      present: true,
      type: "service_worker",
      service_worker: "background.js",
      scripts: [],
      page: null,
      persistent: null,
    });
    expect(output.observed.actions).toEqual({
      action_present: true,
      browser_action_present: false,
      page_action_present: false,
      sidebar_action_present: false,
      any_action_present: true,
    });
    expect(output.observed.content_scripts).toEqual({
      count: 1,
      matches: ["https://*.example.com/*"],
      js_count: 1,
      css_count: 1,
    });
    expect(output.observed.web_accessible_resources).toEqual({
      present: true,
      format: "mv3_objects",
      count: 2,
      resources: ["assets/icon.png", "assets/panel.html"],
      matches: ["https://*.example.com/*"],
      extension_ids: [],
      use_dynamic_url_present: false,
    });
    expect(output.observed.content_security_policy_format).toBe("object");
    expect(output.observed.oauth2_present).toBe(true);
    expect(output.observed.action_present).toBe(true);
    expect(output.observed.mv2_fields_present).toBe(false);
    expect(output.observed.mv3_fields_present).toBe(true);
    expect(output.warnings).toEqual([]);
  });

  it("parses manifest v2 background scripts, persistent background pages, and host patterns inside permissions", async () => {
    const output = await parseBrowserExtensionManifest.run(
      JSON.stringify({
        manifest_version: 2,
        name: "Legacy Fixture Extension",
        version: "2.0.0",
        permissions: ["storage", "tabs", "https://*.example.org/*", "<all_urls>"],
        optional_permissions: ["notifications", "https://api.example.net/*"],
        background: {
          scripts: ["background-a.js", "background-b.js"],
          persistent: false,
        },
        browser_action: {
          default_title: "Legacy Fixture",
        },
        page_action: {
          default_title: "Page Fixture",
        },
        web_accessible_resources: ["panel.html", "icon.png"],
        content_security_policy: "script-src 'self'; object-src 'self'",
      }),
    );

    expect(output.observed.detected_manifest_generation).toBe("mv2");
    expect(output.observed.api_permissions).toEqual(["storage", "tabs"]);
    expect(output.observed.host_permissions_from_permissions).toEqual(["https://*.example.org/*", "<all_urls>"]);
    expect(output.observed.host_permissions).toEqual(["https://*.example.org/*", "<all_urls>"]);
    expect(output.observed.optional_api_permissions).toEqual(["notifications"]);
    expect(output.observed.optional_host_permissions_from_optional_permissions).toEqual(["https://api.example.net/*"]);
    expect(output.observed.background.type).toBe("scripts");
    expect(output.observed.background.scripts).toEqual(["background-a.js", "background-b.js"]);
    expect(output.observed.background.persistent).toBe(false);
    expect(output.observed.actions.browser_action_present).toBe(true);
    expect(output.observed.actions.page_action_present).toBe(true);
    expect(output.observed.web_accessible_resources.format).toBe("mv2_legacy");
    expect(output.observed.content_security_policy_format).toBe("string");
    expect(output.observed.mv2_fields_present).toBe(true);
    expect(output.observed.mv3_fields_present).toBe(false);
  });

  it("parses Firefox browser_specific_settings and legacy applications.gecko", async () => {
    const output = await parseBrowserExtensionManifest.run(
      JSON.stringify({
        manifest_version: 2,
        name: "Firefox Fixture",
        version: "1.0.0",
        browser_specific_settings: {
          gecko: {
            id: "fixture@example.com",
            strict_min_version: "109.0",
            strict_max_version: "120.*",
          },
        },
        applications: {
          gecko: {
            id: "legacy@example.com",
          },
        },
        sidebar_action: {
          default_panel: "sidebar.html",
        },
        chrome_settings_overrides: {
          homepage: "https://example.com/",
        },
      }),
    );

    expect(output.observed.browser_specific_settings).toEqual({
      present: true,
      gecko_present: true,
      gecko_id: "fixture@example.com",
      gecko_strict_min_version: "109.0",
      gecko_strict_max_version: "120.*",
    });
    expect(output.observed.legacy_applications).toEqual({
      present: true,
      gecko_present: true,
      gecko_id: "legacy@example.com",
    });
    expect(output.observed.actions.sidebar_action_present).toBe(true);
    expect(output.observed.browser_specific_keys).toEqual([
      "applications",
      "browser_specific_settings",
      "chrome_settings_overrides",
      "sidebar_action",
    ]);
    expect(output.observed.legacy_browser_specific_keys).toEqual(["applications"]);
    expect(output.observed.likely_browser_families).toEqual(["firefox"]);
  });

  it("parses Chromium MV3-specific observations without scoring risk", async () => {
    const output = await parseBrowserExtensionManifest.run(
      JSON.stringify({
        manifest_version: 3,
        name: "Chromium Fixture",
        version: "3.0.0",
        minimum_chrome_version: "120",
        offline_enabled: true,
        update_url: "https://clients2.google.com/service/update2/crx",
        permissions: ["declarativeNetRequest", "storage"],
        declarative_net_request: {
          rule_resources: [
            {
              id: "ruleset_1",
              enabled: true,
              path: "rules/ruleset_1.json",
            },
          ],
        },
        commands: {
          toggle: {
            suggested_key: {
              default: "Ctrl+Shift+Y",
            },
          },
        },
      }),
    );

    expect(output.observed.chromium).toEqual({
      minimum_chrome_version: "120",
      offline_enabled_present: true,
      oauth2_present: false,
      update_url_present: true,
      declarative_net_request_present: true,
      declarative_net_request_rule_resources_count: 1,
    });
    expect(output.observed.commands).toEqual({
      present: true,
      count: 1,
      names: ["toggle"],
    });
    expect(output.observed.browser_specific_keys).toEqual([
      "declarative_net_request",
      "minimum_chrome_version",
      "offline_enabled",
      "update_url",
    ]);
    expect(output.observed.mv3_fields_present).toBe(true);
  });

  it("preserves unknown top-level keys as observations", async () => {
    const output = await parseBrowserExtensionManifest.run(
      JSON.stringify({
        manifest_version: 3,
        name: "Unknown Key Fixture",
        version: "1.0.0",
        x_vendor_specific: true,
        experimental_extension_surface: {
          enabled: true,
        },
      }),
    );

    expect(output.observed.unknown_top_level_keys).toEqual(["experimental_extension_surface", "x_vendor_specific"]);
    expect(output.observed.unsupported_or_unmodeled_keys).toEqual(["experimental_extension_surface", "x_vendor_specific"]);
  });

  it("rejects invalid JSON", () => {
    expect(() => parseBrowserExtensionManifest.run("{bad json}")).toThrow(
      "parse_browser_extension_manifest input must be valid JSON",
    );
  });

  it("rejects non-object JSON", () => {
    expect(() => parseBrowserExtensionManifest.run("[]")).toThrow(
      "parse_browser_extension_manifest input must be a JSON object; received array",
    );
  });

  it("warns on malformed optional fields without scoring risk", async () => {
    const output = await parseBrowserExtensionManifest.run(
      JSON.stringify({
        manifest_version: 99,
        name: 123,
        version: false,
        permissions: "storage",
        content_scripts: [{ matches: ["https://*.example.com/*", 42], js: "content.js" }, null],
        background: {
          persistent: "sometimes",
        },
        externally_connectable: "bad",
        web_accessible_resources: [{ resources: ["panel.html", 7], matches: "bad", use_dynamic_url: "yes" }],
        content_security_policy: 7,
      }),
    );

    expect(output.observed.manifest_version).toBe(99);
    expect(output.observed.detected_manifest_generation).toBe("unknown");
    expect(output.observed.name).toBeNull();
    expect(output.observed.version).toBeNull();
    expect(output.warnings).toEqual(
      expect.arrayContaining([
        "Unsupported manifest_version 99; parser returned observed fields without compatibility claims.",
        "name should be a string; observed number value.",
        "version should be a string; observed boolean value.",
        "permissions should be an array of strings; ignored string value.",
        "background.persistent should be a boolean; ignored string value.",
        "background was present but no recognized background entry was observed.",
        "externally_connectable should be an object; ignored string value.",
        "content_security_policy should be a string or object; observed number value.",
      ]),
    );
  });

  it("declares local-only execution permissions and reviewed exposure", () => {
    expect(parseBrowserExtensionManifest.metadata.name).toBe("parse_browser_extension_manifest");
    expect(parseBrowserExtensionManifest.metadata.category).toBe("parser");
    expect(parseBrowserExtensionManifest.metadata.execution.mode).toBe("local_only");
    expect(parseBrowserExtensionManifest.metadata.execution.network_access).toBe("none");
    expect(parseBrowserExtensionManifest.metadata.permissions).toEqual({
      network: "none",
      filesystem: "none",
      sends: [],
      persists: false,
      runs_external_binaries: false,
    });
    expect(parseBrowserExtensionManifest.metadata.exposure?.hosted_default).toBe("allowlist_only");
    expect(parseBrowserExtensionManifest.metadata.exposure?.rationale.length).toBeGreaterThan(0);
  });
});
