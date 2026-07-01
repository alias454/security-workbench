# Plugins and Skills

Plugins ship skills. Skills are small typed capabilities executed by the runtime.

Current implementation:

```text
packages/core
packages/schemas
plugins/core-utilities
plugins/core-parsers
plugins/core-reviewers
plugins/core-scoring
plugins/core-output
apps/cli
```

Current interface:

```text
CLI only
```

Current registered skills:

```text
69 total
39 core-utilities
21 core-parsers
2 core-reviewers
2 core-scoring
5 core-output
transform, parser, reviewer, scoring, and output categories
```

## Implemented plugin packages

| Package | Skills | Role |
|---|---:|---|
| `plugins/core-utilities` | 39 | deterministic transforms and lightweight parser-category utilities |
| `plugins/core-parsers` | 21 | richer local artifact/document parsers and scanner normalization transforms |
| `plugins/core-reviewers` | 2 | deterministic local evidence-backed reviewer skills |
| `plugins/core-scoring` | 2 | deterministic local evidence-linked prioritization skills |
| `plugins/core-output` | 5 | deterministic local finding and export output skills |

## core-utilities inventory

```text
base64_decode
base64_encode
base32_encode
base32_decode
url_encode
url_decode
hex_encode
hex_decode
identify_hash
md5_hash
sha1_hash
sha256_hash
sha512_hash
rot13
json_parse
json_format
calculate_entropy
string_normalize
html_entity_decode
unicode_escape_decode
quoted_printable_decode
defang_iocs
refang_iocs
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
trim_lines
remove_empty_lines
dedupe_lines
sort_lines
count_lines
```

## core-parsers inventory

```text
parse_http_headers
parse_dockerfile
parse_github_actions_workflow
parse_trufflehog_ndjson
parse_sarif
parse_semgrep_json
parse_checkov_json
parse_grype_json
normalize_scanner_results
dedupe_scanner_results
parse_pem_certificate
parse_lockfiles
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

## core-reviewers inventory

```text
review_browser_extension_permissions
review_static_analysis_results
```

## core-scoring inventory

```text
score_browser_extension_risk
score_static_analysis_attention
```

## core-output inventory

```text
generate_browser_extension_finding
generate_static_analysis_triage_summary
generate_finding
export_markdown
export_json
```


## Current registered workflows

Registered workflows are runtime definitions that chain existing skills. Workflow behavior is documented in recipes and the owning plugin docs.

| Workflow | Steps | Purpose |
|---|---|---|
| `browser_extension_review` | `parse_browser_extension_manifest` → `review_browser_extension_permissions` → `score_browser_extension_risk` → `generate_browser_extension_finding` | Review a browser extension manifest and generate a draft permission finding. |
| `static_analysis_triage` | `parse_sarif` → `review_static_analysis_results` → `score_static_analysis_attention` → `generate_static_analysis_triage_summary` | Review SARIF scanner output and generate a draft triage summary. |

## Ownership rules

```text
core-utilities: small primitives
core-parsers: richer local parsers
reviewer plugins: evidence-backed interpretation
enrichment plugins: external/provider or local registry context
scoring plugins: prioritization
output plugins: findings and exports
```

## Planned plugin families

```text
plugin-browser-extension
plugin-local-registries
plugin-infrastructure-intel
plugin-scanner-normalize
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

## Adding/changing a skill

```text
pick owning plugin
keep scope small
declare permissions
declare future exposure intent when relevant
add input/output schema coverage when the skill is stable
add tests, including malformed input
add fixtures if useful
update plugin docs and this inventory
run full gate
```

Future third-party plugins must also document privacy behavior, network/provider sends, persistence, examples, and license compatibility before they are considered for reviewed or stable quality labels.

## Adding/changing a pipeline

```text
define expected input artifact type
list skill steps in execution order
preserve evidence references between steps
state risk and confidence assumptions
add fixture input and golden output coverage
document network behavior and external disclosure
```

Full gate:

```bash
pnpm build
pnpm test
pnpm typecheck:test
./security-workbench-full-smoke.sh
```
