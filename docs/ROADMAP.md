# Roadmap

This file tracks engineering work only. Avoid product-spec sprawl here.

Current baseline:

```text
CLI MVP
core runtime
core utilities
core parsers
safe input-file handling
exposure metadata contracts
fixture-backed smoke script
```

Verified gate:

```bash
pnpm build
pnpm test
pnpm typecheck:test
./security-workbench-full-smoke.sh
```

## Current skill baseline

Core parsers:

```text
parse_http_headers
parse_dockerfile
parse_github_actions_workflow
parse_trufflehog_ndjson
parse_sarif
parse_package_json
parse_csv
parse_yaml
parse_browser_extension_manifest
parse_ip_prefix_list
parse_asn_list
parse_asn_allow_deny_list
parse_asn_observations
parse_bgp_prefix_table
```

Core utility parser-category skills:

```text
identify_hash
json_parse
extract_iocs
extract_urls
extract_domains
extract_emails
extract_ipv4
extract_hashes
extract_cves
extract_uuids
parse_url
parse_jwt
parse_email_headers
```

## Current reviewer baseline

Core reviewers:

```text
review_browser_extension_permissions
```

## Current scoring baseline

Core scoring:

```text
score_browser_extension_risk
```

## Current output baseline

Core output:

```text
generate_browser_extension_finding
```

## Current browser extension chain

Completed through PR 7C:

```text
parse_browser_extension_manifest
→ review_browser_extension_permissions
→ score_browser_extension_risk
→ generate_browser_extension_finding
```

## Next work

Recommended next infrastructure parser:

```text
parse_rir_whois_text
```

Generic output/export candidates remain future work:

```text
export_markdown
export_json
generate_finding
```

## Near-term parser backlog

General parser candidates:

```text
parse_pem_certificate
parse_package_lock
parse_pnpm_lock
parse_yarn_lock
parse_requirements_txt
parse_cyclonedx_sbom
parse_spdx_sbom
parse_csp
parse_set_cookie_headers
parse_semgrep_json
parse_checkov_json
parse_grype_json
parse_npm_audit_json
```

Infrastructure artifact parser lane:

```text
parse_asn_list
parse_asn_allow_deny_list
parse_asn_observations
parse_bgp_prefix_table
parse_rir_whois_text
parse_mac_address_list
parse_oui_registry
```

Boundary:

```text
Parsers normalize local artifacts only. `parse_ip_prefix_list`, `parse_asn_list`, `parse_asn_allow_deny_list`, `parse_asn_observations`, and `parse_bgp_prefix_table` are implemented infrastructure parsers. `parse_rir_whois_text` remains future work.
No live ASN/BGP/RIR/RDAP/DNS/MAC vendor lookups in parsers.
No reputation claims.
No malicious/benign ASN conclusions.
```

## Future plugin lanes

### plugin-local-registries

Purpose: offline/control-owned registry parsing and lookup.

Candidate skills:

```text
parse_oui_registry
lookup_mac_vendor_local
lookup_ip_prefix_membership_local
lookup_asn_membership_local
lookup_oui_registry_local
normalize_registry_snapshot
```

Data sources should be bundled, cached, or user-supplied. Network update commands come later and require explicit policy.

### plugin-infrastructure-intel

Purpose: explicit opt-in network/provider infrastructure enrichment.

Candidate skills:

```text
enrich_ip_to_asn
enrich_domain_to_asn
enrich_asn_prefixes
enrich_asn_neighbors
enrich_prefix_rpki_status
```

### plugin-browser-extension

Purpose: browser extension review workflow.

Candidate skills:

```text
review_content_scripts
review_externally_connectable
review_web_accessible_resources
```

### plugin-scanner-normalize

Purpose: scanner-specific normalization and summary workflows.

Candidate skills:

```text
parse_semgrep_json
parse_checkov_json
parse_grype_json
normalize_scanner_results
dedupe_scanner_results
summarize_scanner_results
```

`parse_sarif` and `parse_trufflehog_ndjson` are already implemented as core parser primitives.

### Other plugin candidates

```text
plugin-url-triage
plugin-email
plugin-certificates
plugin-packages
plugin-cloudformation
plugin-kubernetes
plugin-terraform
plugin-iam-policy
plugin-vulnerability-intake
plugin-ai-agent
plugin-notion
```

## Future workflow candidates

```text
browser_extension_review
ioc_cleanup
extract_defang_urls
jwt_review
email_header_review
package_review
scanner_summary
merge_scanner_results
asn_cluster_iocs
asn_denylist_review
local_mac_vendor_lookup
prefix_membership_review
vuln_feed_infra_cluster
notion_export_markdown
```

## Deferred platform work

```text
CircleCI or other CI runner
plugin manifest schema
plugin install/search/update commands
workflow runner
profiles
REST API
web UI
MCP server
network/provider enrichment foundation
local persistence/run history
third-party plugin execution
```

CI note:

```text
Prefer CircleCI or explicit container image when added.
Gate: pnpm install --frozen-lockfile, pnpm build, pnpm test, pnpm typecheck:test, full smoke.
Avoid self-hosted CI for public PRs unless runner isolation is reviewed.
```

## Release blockers before API/MCP/plugin loading

Before REST API, MCP, hosted mode, plugin manifest loading, third-party plugins, or network-capable enrichment, satisfy:

```text
docs/SECURITY_MODEL.md
```
