# Security Workbench Roadmap

**Version:** 0.2.0  
**Status:** CLI MVP with core utilities, core parsers, safe file input, exposure contracts, fixtures, and full smoke coverage  
**Project:** Security Workbench  
**Update policy:** Keep this file synchronized when milestones complete or implementation priority changes.

## Purpose

This roadmap defines the implementation path for Security Workbench.

Security Workbench is an analyst workbench for repeatable security artifact tasks: parse, transform, enrich, review, and export.

The near-term strategy is to turn the current deterministic skill base into a coherent workbench with installable plugin families, reusable workflows, and curated profiles.

## Current baseline

Implemented packages:

```text
packages/schemas
packages/core
plugins/core-utilities
plugins/core-parsers
apps/cli
```

Implemented capability areas:

```text
skill registry
skill runner
runtime policy enforcement
input size limits
redaction helpers
structured errors
strict CLI argument parsing
safe CLI --input-file support
CLI skill list/describe/run workflows
CLI output formatting
schema/result contracts
safe JSON helpers
exposure policy contracts
plugin docs
fixture-backed CLI examples
source-audited full smoke script
```

Skill inventories live in:

```text
docs/plugins/README.md
docs/plugins/core-utilities.md
docs/plugins/core-parsers.md
```

Current parser package skills:

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

Parser candidates after the core parser foundation sprint:

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
parse_kubernetes_manifest
parse_terraform_plan_json
parse_cloudformation_template
parse_iam_policy
parse_cvss_vector
parse_osv_record
parse_ghsa_advisory
parse_mcp_config
parse_agent_tool_schema
```

Parser-category skills currently implemented in `core-utilities`:

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

Verified gates:

```bash
pnpm build
pnpm test
pnpm typecheck:test
./security-workbench-full-smoke.sh
```

## Not implemented yet

```text
plugin manifest loader
plugin install/search/update commands
runtime JSON schema validation for skill input/output
pipeline runner
workflow CLI commands
profiles
REST API
web UI
MCP server
SQLite/local store
external enrichment
finding/export generation
batch input modes such as lines or records
network-capable plugins
third-party plugin execution
```

## Roadmap principles

### 1. Repeatable artifact tasks are the product

Prioritize capabilities that help analysts and security engineers parse, transform, enrich, review, and export artifacts they handle repeatedly.

### 2. Core stays boring

Core primitives should remain stable, broadly useful, deterministic, and low-risk.

### 3. Domain depth belongs in plugins

Optional plugin families should add specialized validators, parsers, enrichers, reviewers, workflows, and exporters.

### 4. Workflows turn primitives into value

Do not keep adding primitives forever without forming recognizable workflows. A useful workbench needs both small tools and saved analyst recipes.

### 5. Plugins are trust-bearing dependencies

Plugin installation must include manifest validation, permission review, dependency checks, and fail-closed behavior.

### 6. Preserve evidence before conclusions

Parsers report observations. Reviewers and scorers make labeled inferences. Findings cite evidence.

### 7. One execution path for humans and agents

CLI, future REST API, Web UI, and MCP must share the same runtime, policy model, schemas, and plugin registry.

## Completed milestones

### Milestone 0 — Hardened baseline runtime

Status: implemented.

```text
workspace setup
core runtime
schemas package
core-utilities plugin
CLI app
skill registry
skill runner
default policy
input size enforcement
policy refusal
redaction helpers
strict encoder/decoder behavior
URL credential redaction
unit tests and test typechecking
```

### Milestone 1 — Core utility expansion

Status: implemented.

The transform/plugin primitive base is implemented in `plugins/core-utilities`. See `docs/plugins/core-utilities.md` for the canonical skill list.

### Milestone 2 — Safe file input

Status: implemented.

```text
--input <value>
--input-file <path>
bounded valid UTF-8 file reads
no globbing
no recursive reads
no archive parsing
input-file tests
```

### Milestone 2.5 — CLI discovery and formatting

Status: implemented.

```text
skills list
skills list --format table|json|tsv
skills list --category parser|transform
skills describe <skill_name>
skills describe --format table|json|tsv
skills run --format json|pretty
```

### Milestone 3 — Schema contracts and safe JSON helpers

Status: implemented.

```text
ArtifactSummary
EvidenceRecord
SignalRecord
RiskAssessment
FindingRecord
StructuredParseError
AnalysisResult
safeJsonParse
safeJsonObjectParse
isJsonObject
isJsonArray
getJsonType
```

### Milestone 3.5 — Exposure policy contracts

Status: implemented as schema/metadata contracts only.

Adapter enforcement is not implemented yet.

### Milestone 5 — Core parsers

Status: implemented for the core parser foundation sprint.

Implemented in `core-parsers`:

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

The parser foundation sprint intentionally stops at evidence-ready observation. Risk review, prioritization, finding generation, and export belong to reviewer, scoring, and output milestones.

### Milestone 5.1 — Fixtures and runnable examples

Status: implemented.

Top-level fake fixtures live under `fixtures/` and are documented in `docs/FIXTURES.md`.

## Immediate next work

### Product/docs alignment

Status: implemented for the current CLI/parser foundation; keep synchronized as milestones complete.

```text
docs/PRODUCT_POSITIONING.md
docs/ANALYST_WORKFLOWS.md
docs/PLUGIN_SYSTEM.md
docs/plugins/README.md
docs/pipelines/README.md
```

### First workflow-shaped vertical slice

Goal:

```text
Prove the workbench model with one plugin-shaped workflow that uses existing primitives and produces structured output.
```

Best candidates:

```text
url-triage: extract URLs, identify shortlinks, expand redirects later, defang/export
browser-extension: parse manifest, review permissions, export notes
packages: parse package.json, review scripts/dependencies, export notes
```

Recommended first pick:

```text
browser-extension for security-review demo clarity
```

The first reviewer path should start with `review_browser_extension_permissions`, using `parse_browser_extension_manifest` output as evidence input. URL-triage remains a strong daily-utility workflow after the first reviewer vertical slice exists.

## Next planned milestones

### Milestone 6 — Lightweight deterministic reviewers

Initial reviewers:

```text
review_browser_extension_permissions
review_jwt_security
inspect_url
analyze_email_headers
review_package_scripts
detect_secrets
```

Reviewers must separate observed facts from inferred risk.

### Milestone 7 — Output and export primitives

Planned:

```text
generate_finding
export_json
export_markdown
export_csv
export_ioc_table
mitigation or remediation note generation
```

### Milestone 8 — Workflow runner and workflow pack

Initial transform recipes:

```text
ioc_cleanup
extract_defang_urls
json_validate_format
url_decode_extract
```

Initial review pipelines:

```text
url_review
jwt_review
email_header_review
package_review
browser_extension_review
```

### Milestone 9 — Plugin manifest schema for official plugins

Goal:

```text
Add a manifest contract before enabling external/community plugin loading.
```

Work:

```text
security-workbench.plugin.json schema
manifest validation tests
capability declarations
permission declarations
dependency declarations
exposure declarations
plugin diagnostics
fail-closed loader behavior for official plugins
```

### Milestone 10 — Plugin install MVP, local source only

Goal:

```text
Install plugin packages from local path or tarball with strict manifest validation.
```

Commands:

```bash
sw plugin list
sw plugin info <name>
sw plugin install ./plugin.tgz
sw plugin remove <name>
sw plugin enable <name>
sw plugin disable <name>
```

Arbitrary URL install remains deferred.

### Milestone 11 — Profiles

Goal:

```text
Curated plugin bundles without forcing every user to install every domain.
```

Candidate profiles:

```text
minimal
analyst
appsec
cloud
cti
ai-security
```

### Milestone 12 — Network and provider enrichment foundation

Goal:

```text
Enable explicit network/provider enrichment without hidden disclosure.
```

Required first:

```text
sends/sinks declarations
approved_sinks enforcement
network policy tests
source labeling in output
API key handling model
rate-limit/error handling
```

Initial enrichers:

```text
dns_lookup
rdap_lookup
tls_certificate_fetch
expand_shortlink
urlscan_lookup
osv_lookup
```

### Later milestones

```text
official plugin registry
arbitrary URL plugin install with explicit warnings and integrity pins
REST API and local Web UI
MCP and agent interface
local persistence / run history
community plugin review process
release hardening
```

## Plugin roadmap

### First wave

```text
plugin-url-triage
plugin-browser-extension
plugin-packages
plugin-email
plugin-certificates
```

### Second wave

```text
plugin-scanner-normalize
plugin-cloudformation
plugin-kubernetes
plugin-vulnerability-intake
plugin-iam-policy
```

### Later wave

```text
plugin-terraform
plugin-ai-agent
plugin-saas-export-review
plugin-detection-rule-helper
plugin-static-script-triage
```

## Intentionally deferred

```text
archive extraction
compressed artifact parsing
generic XML parser
hosted/API/MCP surfaces
third-party plugin loading
arbitrary URL plugin install
raw input persistence
full CyberChef parity
full SaaS integrations
live cluster/cloud account querying
```

Reason: these require additional resource controls, parser-hardening, output escaping, audit, allowlists, dependency review, or external disclosure handling.

## Release blockers before API/MCP/plugin loading

Before REST API, MCP, hosted mode, plugin manifest loading, third-party/community plugins, or network-capable enrichment plugins are enabled, the project must satisfy:

```text
docs/security/pre-api-mcp-plugin-gate.md
```

No exception should be made without documented rationale and compensating controls.

## Success definition

The project is successful when analysts and security engineers can use one workbench for recurring artifact tasks while the platform remains:

```text
useful for small daily jobs
plugin-driven
workflow-capable
evidence-centered
human-usable
agent-usable later
community-extensible
explicit about external disclosure
secure by default
clear about limitations
```
