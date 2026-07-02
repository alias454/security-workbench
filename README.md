# Security Workbench

Security Workbench is a CLI workbench for repeatable security artifact tasks: parse, transform, normalize, review, and export.

Security Workbench is intended to grow from a CLI workbench into a shared runtime for evidence-backed skills and registered workflows. Future adapters such as REST API, local web UI, and MCP should reuse that runtime path rather than becoming separate analysis engines.

The current build is intentionally local and deterministic. Routine artifacts such as encoded blobs, URLs, headers, JSON, CSV, YAML, Dockerfiles, GitHub Actions workflows, scanner outputs, JWTs, and manifests should be parsed and normalized before deciding whether AI or external enrichment is needed.

```text
artifact or text blob
  → parse / transform
  → extract useful structure
  → review supported signals
  → score review attention
  → generate draft finding output
```

## Current status

Implemented:

```text
TypeScript monorepo
pnpm workspace
packages/schemas
packages/core
plugins/core-utilities
plugins/core-parsers
plugins/core-reviewers
plugins/core-scoring
plugins/core-output
apps/cli
single-skill registry and runner
registered workflow registry and runner
workflow definition validation
CLI workflows list / run
runtime policy enforcement
safe bounded --input-file handling
runtime redaction helpers
fixture-backed smoke script
```

Current interface:

```text
CLI only
```

Not implemented yet:

```text
plugin manifest loader
plugin install commands
external enrichment
REST API
web UI
MCP server
local persistence
```

## Install

```bash
pnpm install
```

## Common commands

Discovery:

```bash
pnpm --filter @security-workbench/cli start help
pnpm --filter @security-workbench/cli start list
pnpm --filter @security-workbench/cli start skills help
pnpm --filter @security-workbench/cli start workflows help
```

Skills and workflows:

```bash
pnpm --filter @security-workbench/cli start skills list
pnpm --filter @security-workbench/cli start skills describe parse_sarif
pnpm --filter @security-workbench/cli start skills run json_parse --input '{"ok":true}'
pnpm --filter @security-workbench/cli start workflows list --format table
pnpm --filter @security-workbench/cli start workflows run browser_extension_review --input-file "$PWD/fixtures/browser-extension/manifest-v2-broad-hosts.json" --format pretty
pnpm --filter @security-workbench/cli start workflows run static_analysis_triage --input-file "$PWD/fixtures/sarif/codeql-results.sarif" --format pretty
pnpm --filter @security-workbench/cli start workflows run certificate_review --input-file "$PWD/fixtures/certificates/example-cert.pem" --format pretty
pnpm --filter @security-workbench/cli start workflows run jwt_review --input-file "$PWD/fixtures/jwt/alg-none.jwt" --format pretty
pnpm --filter @security-workbench/cli start workflows run sbom_review --input-file "$PWD/fixtures/sbom/cyclonedx.json" --format pretty
pnpm --filter @security-workbench/cli start workflows run package_manifest_review --input-file "$PWD/fixtures/package-json/basic-package.json" --format pretty
pnpm --filter @security-workbench/cli start workflows run lockfile_review --input-file "$PWD/fixtures/lockfiles/package-lock.json" --format pretty
```

Fixture examples use `$PWD` from the repo root:

```bash
pnpm --filter @security-workbench/cli start skills run parse_sarif --input-file "$PWD/fixtures/sarif/codeql-results.sarif" --format pretty
pnpm --filter @security-workbench/cli start skills run parse_trufflehog_ndjson --input-file "$PWD/fixtures/trufflehog/git-results.ndjson" --format pretty
pnpm --filter @security-workbench/cli start skills run parse_semgrep_json --input-file "$PWD/fixtures/scanners/semgrep-results.json" --format pretty
pnpm --filter @security-workbench/cli start skills run parse_checkov_json --input-file "$PWD/fixtures/scanners/checkov-results.json" --format pretty
pnpm --filter @security-workbench/cli start skills run parse_grype_json --input-file "$PWD/fixtures/scanners/grype-results.json" --format pretty
pnpm --filter @security-workbench/cli start skills run parse_semgrep_json --input-file "$PWD/fixtures/scanners/semgrep-results.json" > /tmp/semgrep.parsed.json
pnpm --filter @security-workbench/cli start skills run normalize_scanner_results --input-file /tmp/semgrep.parsed.json --format pretty
pnpm --filter @security-workbench/cli start skills run normalize_scanner_results --input-file /tmp/semgrep.parsed.json > /tmp/semgrep.normalized.json
pnpm --filter @security-workbench/cli start skills run dedupe_scanner_results --input-file /tmp/semgrep.normalized.json > /tmp/semgrep.deduped.json
pnpm --filter @security-workbench/cli start skills run scanner_summary --input-file /tmp/semgrep.deduped.json --format pretty
pnpm --filter @security-workbench/cli start skills run parse_pem_certificate --input-file "$PWD/fixtures/certificates/example-cert.pem" --format pretty
pnpm --filter @security-workbench/cli start skills run parse_pem_certificate --input-file "$PWD/fixtures/certificates/example-cert.pem" > /tmp/certificate.parsed.json
pnpm --filter @security-workbench/cli start skills run review_certificate --input-file /tmp/certificate.parsed.json --format pretty
pnpm --filter @security-workbench/cli start skills run parse_jwt --input-file "$PWD/fixtures/jwt/alg-none.jwt" > /tmp/jwt.parsed.json
pnpm --filter @security-workbench/cli start skills run review_jwt --input-file /tmp/jwt.parsed.json --format pretty
pnpm --filter @security-workbench/cli start skills run parse_sbom --input-file "$PWD/fixtures/sbom/cyclonedx.json" > /tmp/sbom.parsed.json
pnpm --filter @security-workbench/cli start skills run review_sbom --input-file /tmp/sbom.parsed.json --format pretty
pnpm --filter @security-workbench/cli start skills run parse_lockfiles --input-file "$PWD/fixtures/lockfiles/package-lock.json" > /tmp/lockfile.parsed.json
pnpm --filter @security-workbench/cli start skills run review_package --input-file /tmp/lockfile.parsed.json --format pretty
pnpm --filter @security-workbench/cli start skills run parse_package_json --input-file "$PWD/fixtures/package-json/basic-package.json" > /tmp/package.parsed.json
pnpm --filter @security-workbench/cli start skills run review_package --input-file /tmp/package.parsed.json --format pretty
pnpm --filter @security-workbench/cli start skills run parse_email_headers --input-file "$PWD/fixtures/email/auth-results-headers.txt" > /tmp/email-headers.parsed.json
pnpm --filter @security-workbench/cli start skills run review_email_header --input-file /tmp/email-headers.parsed.json --format pretty
pnpm --filter @security-workbench/cli start skills run parse_http_headers --input-file "$PWD/fixtures/http-headers/security-headers.txt" > /tmp/http-headers.parsed.json
pnpm --filter @security-workbench/cli start skills run review_security_headers --input-file /tmp/http-headers.parsed.json --format pretty
pnpm --filter @security-workbench/cli start skills run normalize_indicators --input-file "$PWD/fixtures/iocs/defanged-indicators.txt" --format pretty
pnpm --filter @security-workbench/cli start skills run extract_defanged_urls --input-file "$PWD/fixtures/iocs/defanged-indicators.txt" --format pretty
pnpm --filter @security-workbench/cli start skills run extract_defanged_urls --input-file "$PWD/fixtures/iocs/defanged-indicators.txt" > /tmp/urls.extracted.json
pnpm --filter @security-workbench/cli start skills run review_url --input-file /tmp/urls.extracted.json --format pretty
pnpm --filter @security-workbench/cli start skills run parse_browser_extension_manifest --input-file "$PWD/fixtures/browser-extension/manifest-v3-basic.json" --format pretty
pnpm --filter @security-workbench/cli start skills run parse_ip_prefix_list --input-file "$PWD/fixtures/ip-prefixes/mixed-prefixes.txt" --format pretty
pnpm --filter @security-workbench/cli start skills run parse_asn_list --input-file "$PWD/fixtures/asn/asn-list.txt" --format pretty
pnpm --filter @security-workbench/cli start skills run parse_asn_allow_deny_list --input-file "$PWD/fixtures/asn/asn-allow-deny-list.txt" --format pretty
pnpm --filter @security-workbench/cli start skills run parse_asn_observations --input-file "$PWD/fixtures/asn/asn-observations.txt" --format pretty
pnpm --filter @security-workbench/cli start skills run parse_bgp_prefix_table --input-file "$PWD/fixtures/asn/bgp-prefix-table.txt" --format pretty
```

## Current completed chains

The first registered artifact-to-finding workflow is browser extension permission review:

```text
parse_browser_extension_manifest
  → review_browser_extension_permissions
  → score_browser_extension_risk
  → generate_browser_extension_finding
```

The second registered workflow is static-analysis triage:

```text
parse_sarif
  → review_static_analysis_results
  → score_static_analysis_attention
  → generate_static_analysis_triage_summary
```

Additional registered parser-to-reviewer workflows cover unambiguous local review chains:

```text
parse_pem_certificate
  → review_certificate

parse_jwt
  → review_jwt

parse_sbom
  → review_sbom

parse_package_json
  → review_package

parse_lockfiles
  → review_package
```

Detailed behavior lives in the core parser, reviewer, scoring, and output plugin docs.

## Validation

```bash
pnpm build
pnpm test
pnpm typecheck:test
./security-workbench-full-smoke.sh
```

## Security scanning

Security Workbench has a Semgrep baseline for local SAST validation. The baseline focuses on implementation findings and intentionally excludes fixture/test artifacts that contain synthetic attacker-shaped inputs.

See `docs/SECURITY_MODEL.md` for the Semgrep command, expected result, and exclusion rationale.

## Documentation

```text
docs/ENGINEERING.md          runtime, repo layout, implementation rules
docs/ROADMAP.md              current backlog and implementation order
docs/SECURITY_MODEL.md       trust boundaries, privacy, exposure, output safety
docs/FIXTURES.md             fixture policy and inventory
docs/recipes/README.md       copy/paste workflow recipes
docs/plugins/README.md       plugin and skill inventory
docs/plugins/*.md            per-plugin behavior and limits
```

## Security posture

Default posture:

```text
network disabled unless explicitly enabled
persistence disabled unless explicitly enabled
redaction enabled by default
external binaries denied by default
plugin-owned filesystem access denied by default
API/web/MCP exposure not implemented
```

Local means control-owned: artifacts stay inside the user's security boundary until external analysis is explicitly justified.
