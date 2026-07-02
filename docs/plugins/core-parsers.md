# Plugin: core-parsers

Deterministic local artifact/document parsers.

Status:

```text
Package: plugins/core-parsers
NPM name: @security-workbench/core-parsers
Quality: core
Execution: local-only
Network: none
Persistence: none
External binaries: none
Implemented skills: 24
```

## Purpose

`core-parsers` converts bounded text artifacts into structured observations, warnings, and evidence-ready metadata.

Parser boundary:

```text
no network
no filesystem access
no external binaries
no execution of artifact content
no risk scoring
no findings
```

## Implemented skills

| Skill | Input | Output summary |
|---|---|---|
| `parse_http_headers` | HTTP header text | status line, normalized headers, duplicates, malformed/folded lines |
| `parse_dockerfile` | Dockerfile text | stages, instructions, base images, ENV/ARG keys, COPY/ADD, runtime surfaces |
| `parse_github_actions_workflow` | workflow YAML | triggers, permissions, jobs, steps, action uses, contexts, redacted run steps |
| `parse_trufflehog_ndjson` | TruffleHog NDJSON | detectors, sources, verification counts, redacted secret metadata |
| `parse_sarif` | SARIF JSON | runs, tools, rules, results, locations, fingerprints, suppressions, fixes, taxa |
| `parse_semgrep_json` | Semgrep native JSON | results, paths, severities, metadata, skipped paths, and errors |
| `parse_checkov_json` | Checkov native JSON | failed/passed/skipped checks, resources, paths, severities, and parsing errors |
| `parse_grype_json` | Grype native JSON | vulnerability matches, packages, source/distro metadata, and matcher details |
| `normalize_scanner_results` | parsed Semgrep/Checkov/Grype output | common scanner-result observations, severities, statuses, paths/resources, package/vulnerability identifiers |
| `dedupe_scanner_results` | normalized scanner results | unique scanner results, duplicate groups, source result references, and dedupe counts |
| `scanner_summary` | normalized/deduplicated/merged scanner results | count-based scanner summary, limitations, and compact observed result records |
| `merge_scanner_results` | normalized or deduplicated scanner result outputs | merged scanner-result collection, duplicate counts, source refs, and scanner/source inventories |
| `parse_pem_certificate` | PEM certificate text | X.509 subjects, issuers, validity dates, fingerprints, SANs, and public key metadata |
| `parse_lockfiles` | npm/pnpm/yarn lockfiles | package names, versions, dependency edges, importer names, and root dependency sections |
| `parse_sbom` | CycloneDX or SPDX SBOM JSON | components/packages, versions, suppliers, licenses, identifiers, external references, and dependency metadata |
| `parse_package_json` | package.json | package metadata, scripts, dependencies, repository/bin/workspaces |
| `parse_csv` | CSV text | rows, records, headers, delimiter, line endings, irregular rows |
| `parse_yaml` | YAML text | JSON-compatible documents, summaries, warnings |
| `parse_browser_extension_manifest` | extension manifest JSON | permissions, host permissions, content scripts, background, web resources |
| `parse_ip_prefix_list` | newline-oriented IP/prefix list | IPv4/IPv6 hosts and CIDR prefixes, comments, duplicates, malformed lines, prefix lengths |
| `parse_asn_list` | newline-oriented ASN list | AS-prefixed and bare ASNs, comments, optional notes, duplicates, malformed lines |
| `parse_asn_allow_deny_list` | ASN allow/deny policy list | allow/deny action, ASN, optional reasons, duplicate entries, conflicting actions |
| `parse_asn_observations` | ASN observation list | observed ASN rows with optional indicators, sources, timestamps, repeated ASN summaries |
| `parse_bgp_prefix_table` | BGP prefix/origin ASN table | IPv4/IPv6 CIDR prefixes, origin ASNs, duplicates, conflicting origins, prefix lengths |

## Planned parser candidates

```text
parse_requirements_txt
parse_csp
parse_set_cookie_headers
parse_rir_whois_text
parse_mac_address_list
parse_oui_registry
```

## Security requirements

Parsers must:

```text
treat input as hostile
enforce bounded inputs through runtime policy
perform schema/type checks before parsing
return structured parse errors
include malformed-input tests
avoid emitting obvious secrets
preserve observations, not conclusions
```

For sensitive values, prefer:

```text
presence flag
length
hash
redacted preview
key/claim names
```

## Permission declaration

Every skill declares:

```ts
permissions: {
  network: "none",
  filesystem: "none",
  sends: [],
  persists: false,
  runs_external_binaries: false,
}
```

## Exposure intent

Core parser exposure metadata records future adapter policy only. It does not expose API/web/MCP today.

Current intent:

```text
surfaces: cli, api, web, mcp
default_exposure: enabled
hosted_default: allowlist_only
requires_authentication: true
rate_limit_recommended: true
audit_required: true
risk: low or medium depending on artifact sensitivity
```

## Current package shape

```text
plugins/core-parsers/src/
  index.ts
  localOnlyPermissions.ts
  nativeParserUtils.ts
  parseBrowserExtensionManifest.ts
  parseCsv.ts
  parseDockerfile.ts
  parseGithubActionsWorkflow.ts
  parseHttpHeaders.ts
  parsePackageJson.ts
  parseSarif.ts
  parseSemgrepJson.ts
  parseCheckovJson.ts
  parseGrypeJson.ts
  parsePemCertificate.ts
  parseLockfiles.ts
  parseSbom.ts
  normalizeScannerResults.ts
  dedupeScannerResults.ts
  scannerSummary.ts
  mergeScannerResults.ts
  parseIpPrefixList.ts
  parseAsnList.ts
  parseAsnAllowDenyList.ts
  parseAsnObservations.ts
  parseBgpPrefixTable.ts
  parseTrufflehogNdjson.ts
  parseYaml.ts
plugins/core-parsers/tests/
  parse*.test.ts
```

## Fixture examples

Run from repo root:

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
pnpm --filter @security-workbench/cli start skills run parse_lockfiles --input-file "$PWD/fixtures/lockfiles/package-lock.json" --format pretty
pnpm --filter @security-workbench/cli start skills run parse_sbom --input-file "$PWD/fixtures/sbom/cyclonedx.json" --format pretty
pnpm --filter @security-workbench/cli start skills run parse_github_actions_workflow --input-file "$PWD/fixtures/github-actions/basic-workflow.yml" --format pretty
pnpm --filter @security-workbench/cli start skills run parse_dockerfile --input-file "$PWD/fixtures/dockerfile/multi-stage.Dockerfile" --format pretty
pnpm --filter @security-workbench/cli start skills run parse_http_headers --input-file "$PWD/fixtures/http-headers/security-headers.txt" --format pretty
pnpm --filter @security-workbench/cli start skills run parse_browser_extension_manifest --input-file "$PWD/fixtures/browser-extension/manifest-v3-basic.json" --format pretty
pnpm --filter @security-workbench/cli start skills run parse_ip_prefix_list --input-file "$PWD/fixtures/ip-prefixes/mixed-prefixes.txt" --format pretty
```

## Test themes

```text
skill registration
local-only permissions
valid artifact parsing
malformed input handling
optional/malformed shape warnings
redaction-sensitive behavior
pretty output coverage through CLI tests
fixture-backed smoke coverage
```

## Role in workflows

```text
parse_package_json              → package_manifest_review
parse_csv                       → export/review helpers
parse_yaml                      → IaC/config/detection-rule plugins
parse_browser_extension_manifest → browser_extension_review
parse_dockerfile                → container_build_review
parse_github_actions_workflow   → ci_workflow_review
parse_trufflehog_ndjson         → secret-scanner normalization
parse_sarif                     → scanner normalization/code scanning review
parse_semgrep_json              → scanner native-output parsing/normalization/summary
parse_checkov_json              → scanner native-output parsing/normalization
parse_grype_json                → scanner native-output parsing/normalization
parse_pem_certificate           → certificate_review
parse_lockfiles                 → lockfile_review
parse_sbom                      → sbom_review
parse_ip_prefix_list            → infrastructure/local-registry/prefix-membership workflows
parse_asn_list                  → ASN/local-registry/infrastructure-clustering workflows
parse_asn_allow_deny_list       → ASN policy review and local membership workflows
parse_asn_observations           → ASN concentration/reuse review workflows
parse_bgp_prefix_table           → prefix/origin ASN review workflows
```
