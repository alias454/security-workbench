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
52 total
39 core-utilities
10 core-parsers
1 core-reviewers
1 core-scoring
1 core-output
transform, parser, reviewer, scoring, and output categories
```

## Implemented plugin packages

| Package | Skills | Role |
|---|---:|---|
| `plugins/core-utilities` | 39 | deterministic transforms and lightweight parser-category utilities |
| `plugins/core-parsers` | 10 | richer local artifact/document parsers |
| `plugins/core-reviewers` | 1 | deterministic local evidence-backed reviewer skills |
| `plugins/core-scoring` | 1 | deterministic local evidence-linked prioritization skills |
| `plugins/core-output` | 1 | deterministic local finding and export output skills |

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
parse_package_json
parse_csv
parse_yaml
parse_browser_extension_manifest
parse_ip_prefix_list
```

## core-reviewers inventory

```text
review_browser_extension_permissions
```

## core-scoring inventory

```text
score_browser_extension_risk
```

## core-output inventory

```text
generate_browser_extension_finding
```

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
add tests, including malformed input
add fixtures if useful
update plugin docs and this inventory
run full gate
```

Full gate:

```bash
pnpm build
pnpm test
pnpm typecheck:test
./security-workbench-full-smoke.sh
```
