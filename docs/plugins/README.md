# Security Workbench — Plugins and Skills

## Purpose

Plugins are the primary extension mechanism for Security Workbench. Skills are the executable capabilities shipped by plugins.

Security Workbench is an analyst workbench for repeatable security artifact tasks: parse, transform, enrich, review, and export.

The relationship is:

```text
Analyst task → Workflow / Pipeline → Skill → Plugin implementation → Runtime execution
```

- A **skill** is one small typed capability, such as `parse_jwt`, `parse_csv`, `extract_iocs`, or `review_extension_permissions`.
- A **plugin** owns and ships skills, tests, fixtures, documentation, permission metadata, and optionally workflows or schemas.
- A **workflow/pipeline** composes registered skills into repeatable analyst jobs.
- A **profile** is a curated bundle of plugins for a common user type.

## Current implementation status

Implemented today:

```text
packages/core
packages/schemas
plugins/core-utilities
plugins/core-parsers
apps/cli
```

Current interface:

```text
CLI only
```

Current registered skills:

```text
48 total registered skills
39 core-utilities skills
9 core-parsers skills
transform-category and parser-category skills only
```

Current plugin loading model:

```text
official plugins are wired directly by the CLI
plugin manifest loader is not implemented yet
third-party/community plugin execution is not enabled yet
plugin install command is not implemented yet
```

Not implemented yet:

```text
plugin manifest loader
plugin install/search/update commands
profiles
pipeline runner
workflow packs
REST API
web UI
MCP server
network-capable plugins
provider enrichment
finding/export generation
```

## Implemented plugin packages

| Package | NPM name | Skills | Status | Docs |
|---|---|---:|---|---|
| `plugins/core-utilities` | `@security-workbench/core-utilities` | 39 | implemented baseline utility primitives | `docs/plugins/core-utilities.md` |
| `plugins/core-parsers` | `@security-workbench/core-parsers` | 9 | implemented artifact parsers | `docs/plugins/core-parsers.md` |

## Core versus domain plugins

### Core plugins

Core plugins are always useful and broadly reusable.

```text
core-utilities
core-parsers
core-output later
```

Core should provide primitives such as:

```text
JSON/YAML/CSV parsing and formatting
encoding and decoding
hashing
URL parsing
IOC extraction
line cleanup
defang/refang
lightweight token/header parsing
safe output helpers
```

### Domain plugins

Domain plugins add depth for specific analyst jobs.

Planned or candidate domain plugins:

| Plugin | Purpose |
|---|---|
| `plugin-url-triage` | Shortlink expansion, redirect chains, URL/domain/IP lookup workflows. |
| `plugin-email` | Email header analysis, authentication-results parsing, phishing extraction. |
| `plugin-certificates` | PEM/X.509 parsing, SAN extraction, expiry review, CT lookup later. |
| `plugin-packages` | Package manifests, lockfiles, script/dependency review, package enrichment later. |
| `plugin-browser-extension` | Browser extension manifest review, permissions, host access, content scripts. |
| `plugin-scanner-normalize` | SARIF, Semgrep, Checkov, TruffleHog, Grype, npm audit normalization. |
| `plugin-cloudformation` | CloudFormation validation, intrinsic references, security review. |
| `plugin-kubernetes` | Kubernetes manifest parsing, workload/RBAC review. |
| `plugin-terraform` | Terraform plan/config parsing and review. |
| `plugin-iam-policy` | IAM/SCP/cloud policy parsing and review. |
| `plugin-vulnerability-intake` | CVE/advisory parsing and external vulnerability enrichment. |
| `plugin-ai-agent` | MCP/tool schema, agent config, and prompt/tool exposure review. |

## Skill contract summary

Every skill should be:

```text
typed
testable
deterministic where practical
policy-aware
small and focused
composable
clear about malformed input
clear about side effects
```

Every implemented skill currently declares:

```text
name
version
category
description
execution mode
network behavior
determinism
permission metadata
run implementation
unit tests
```

Future reviewable skills should also include:

```text
input schema
output schema
fixtures or testdata where useful
golden output tests for non-trivial behavior
examples
exposure policy when reviewed for API/web/MCP surfaces
known limitations
```

## Skill categories

Current and planned skill categories:

```text
transform
parser
reviewer
enrichment
scoring
output
```

Current implemented skills are only transform and parser skills.

## Permission baseline

Current local skill permission shape:

```ts
permissions: {
  network: "none",
  filesystem: "none",
  sends: [],
  persists: false,
  runs_external_binaries: false,
}
```

`--input-file` is adapter input acquisition. It does not grant plugin filesystem permissions. Skills receive bounded string input from the runtime.

## Capability labels

Future plugins and skills should declare capability labels:

| Label | Meaning |
|---|---|
| `local` | No network, no persistence, no external binaries. |
| `network-direct` | Direct DNS/HTTP/TLS/RDAP/WHOIS/etc. calls. |
| `provider` | Calls a third-party API or intelligence corpus. |
| `active` | Touches target infrastructure in a visible way. |
| `explicit-opt-in` | Requires policy/user approval. |

These labels should be visible in `skills describe`, `plugin info`, future API metadata, and future MCP tool descriptions.

## Exposure metadata

Exposure metadata is separate from execution permissions.

```text
permissions = what a skill may do at runtime
exposure    = where a skill should be reachable: CLI, API, web, MCP
```

Hosted API, hosted web, and MCP adapters are not implemented. When they exist, they must not blindly expose every registered skill. Missing exposure metadata should fail closed or require explicit allowlist behavior in shared/hosted contexts.

## Plugin install direction

Future user-facing commands may include:

```bash
sw plugin list
sw plugin search kubernetes
sw plugin info @security-workbench/plugin-kubernetes
sw plugin install @security-workbench/plugin-kubernetes
sw plugin install ./plugin.tgz
sw plugin install https://example.com/plugin.tgz
sw plugin remove @security-workbench/plugin-kubernetes
sw plugin enable @security-workbench/plugin-kubernetes
sw plugin disable @security-workbench/plugin-kubernetes
```

Arbitrary URL installs should come after local/official plugin loading because plugins are code and must be treated as trust-bearing dependencies.

A plugin install flow must validate the manifest, resolve dependencies, enforce declared permissions, display network/filesystem/persistence behavior, and fail closed on unsafe or invalid metadata.

Canonical design details live in `docs/PLUGIN_SYSTEM.md`.

## Profiles

Profiles are curated bundles of plugins. They should reduce install noise without bypassing trust or permission checks.

Candidate profiles:

```text
minimal       core utilities and parsers only
analyst       IOC, URL triage, email, certificates
appsec        packages, browser extension, scanner normalization, SBOM/SARIF
cloud         CloudFormation, Kubernetes, Terraform, IAM policy
cti           URL/domain enrichment, passive DNS/provider plugins, vuln intake
ai-security   MCP/tool schema, agent workflow, prompt/tool exposure review
```

## Skill ownership inventory

### `core-utilities`

Local utility primitives, including transforms, text utilities, IOC utilities, line utilities, structured extraction, and lightweight parser-category skills.

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

### `core-parsers`

Local artifact parser primitives.

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
```

## Adding or changing a skill

When adding a skill:

```text
choose the owning plugin
keep the skill small and focused
declare permissions
add unit tests
add malformed-input tests
add fixtures or testdata if behavior is non-trivial
update the owning plugin doc
update this index only if the public inventory changes
run the full gate
```

Full gate:

```bash
pnpm build
pnpm test
pnpm typecheck:test
./security-workbench-full-smoke.sh
```

## Related docs

```text
docs/PLUGIN_SYSTEM.md
docs/ANALYST_WORKFLOWS.md
docs/ROADMAP.md
docs/ARCHITECTURE.md
docs/THREAT_MODEL.md
docs/PRIVACY_MODEL.md
docs/EXPOSURE_POLICY.md
docs/FIXTURES.md
docs/plugins/core-utilities.md
docs/plugins/core-parsers.md
```
