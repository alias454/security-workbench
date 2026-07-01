# Roadmap

This file tracks open engineering work and sequencing. Completed capability behavior belongs in `README.md`, `docs/plugins/README.md`, and the owning `docs/plugins/*.md` file. When work lands, update those docs and reshape this roadmap around the remaining work.

Current baseline:

```text
CLI skill and workflow runners
local-only runtime policy and safe input handling
core transform/parser/reviewer/scoring/output plugins
registered browser-extension and static-analysis triage workflows
stable workflow definition validation
full smoke, source audit, and Semgrep validation
```

Detailed implemented capability is documented in:

```text
README.md
docs/plugins/README.md
docs/plugins/core-*.md
docs/SECURITY_MODEL.md
```

Verified gate:

```bash
pnpm build
pnpm test
pnpm typecheck:test
./security-workbench-full-smoke.sh
```

## Active sequence

```text
1. Add scanner-native JSON parsers for Semgrep, Checkov, and Grype.
2. Normalize and dedupe scanner results.
3. Expand static-analysis triage beyond SARIF.
```

Sequence rule:

```text
recipes explain workflows
registered workflows before arbitrary DAGs
workflow CLI before REST/web/MCP adapters
local-only workflows before network enrichment
```

## Workflow runner lite

The current runner supports narrow registered workflows, not general pipeline execution.

Current registered workflows:

```text
browser_extension_review
static_analysis_triage
```

Later pipeline support should add broader skill input/output schema validation and more fixture-backed golden-output coverage.

## Near-term candidates

These are candidates for the next small PR stack after the active sequence starts.

```text
parse_semgrep_json
parse_checkov_json
parse_grype_json
parse_pem_certificate
parse_lockfiles
parse_sbom
```

## Workflow backlog

```text
url_review
phishing_review
email_header_review
jwt_review
certificate_review
browser_extension_review
package_review
sbom_review
ai_workflow_review
domain_security_review
security_headers_review
typosquat_review
vulnerability_prioritization
scanner_summary
merge_scanner_results
ioc_cleanup
extract_defang_urls
asn_cluster_iocs
asn_denylist_review
local_mac_vendor_lookup
prefix_membership_review
vuln_feed_infra_cluster
notion_export_markdown
```

## Scanner/static-analysis lane

Purpose: normalize scanner output into deduplicated, evidence-backed triage summaries.

Candidate work:

```text
parse scanner-native JSON outputs
normalize scanner results
dedupe scanner results
expand static-analysis triage across scanner-native formats
```

Keep tool-specific parsing separate from prioritization and finding generation.

## Infrastructure and local registry lane

Purpose: normalize local infrastructure artifacts and support offline/control-owned registry lookups.

Candidate work:

```text
parse RIR WHOIS text
parse MAC address lists
parse OUI registry snapshots
lookup MAC vendor from local registry
lookup IP prefix membership from local registry
lookup ASN membership from local registry
normalize local registry snapshots
```

Boundary:

```text
Parsers normalize local artifacts only.
No live ASN/BGP/RIR/RDAP/DNS/MAC vendor lookups in parsers.
No reputation claims.
No malicious/benign ASN conclusions.
```

## Network enrichment lane

Network/provider enrichment is deferred until disclosure, policy, audit, and adapter labeling are ready.

Candidate work:

```text
DNS lookup
RDAP lookup
certificate transparency lookup
URLhaus lookup
CVE lookup
OSV lookup
GHSA lookup
EPSS lookup
CISA KEV lookup
MITRE ATT&CK lookup
package registry lookup
GitHub repository metadata lookup
IP/domain/ASN enrichment
RPKI status enrichment
```

## Future plugin lanes

```text
plugin-browser-extension
plugin-scanner-normalize
plugin-local-registries
plugin-infrastructure-intel
plugin-url-triage
plugin-email
plugin-certificates
plugin-packages
plugin-sbom
plugin-cloudformation
plugin-kubernetes
plugin-terraform
plugin-iam-policy
plugin-vulnerability-intake
plugin-ai-agent
plugin-notion
```

## Deferred platform capabilities

Runtime and plugin system:

```text
plugin manifest schema and loader
plugin install/search/update commands
third-party plugin execution
plugin quality labels
profiles
full input/output schema validation
structured local audit/run metadata
```

REST API:

```text
shared-runtime API adapter
health and discovery endpoints
skill run endpoint
workflow run endpoint
```

Local web UI:

```text
workflow selection
artifact paste/upload
structured result viewer
evidence and signal drill-down
risk and finding preview
Markdown/JSON export
run history
network/disclosure indicators
```

MCP and agent safety:

```text
MCP server over stable workflows
tool allowlist
network lookup approval model
artifact size limits
explicit persistence flags
safe logging and redaction defaults
structured refusal/error responses
agent-triggered run audit metadata
no destructive actions in initial MCP release
```

Community and release hardening:

```text
plugin contribution guide
skill and pipeline templates
enrichment/scoring/exporter templates
fixture and golden-output guidance
issue and pull request templates
release automation
Docker image and local Docker Compose
signed/checksummed release artifacts where practical
example plugin repository/template
documentation site or expanded docs index
screenshots/demo data
```

Persistence and audit:

```text
SQLite-backed local store
artifacts
runs
findings
saved pipelines
enrichment cache
audit log
```

CI note:

```text
Prefer CircleCI or explicit container image when added.
Gate: pnpm install --frozen-lockfile, pnpm build, pnpm test, pnpm typecheck:test, full smoke.
Avoid self-hosted CI for public PRs unless runner isolation is reviewed.
```

## Release blockers before API/MCP/plugin loading

Before REST API, MCP, hosted mode, plugin manifest loading, third-party plugins, persistence, or network-capable enrichment, satisfy:

```text
shared runtime path for all adapters
fail-closed exposure metadata behavior
policy enforcement for network, filesystem, persistence, and external binaries
broader skill and workflow input/output schema validation
redaction-safe logs and outputs
bounded artifact handling per adapter
audit metadata for runs
clear external disclosure model
updated docs/SECURITY_MODEL.md
```
