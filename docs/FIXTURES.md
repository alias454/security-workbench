# Fixtures

Security Workbench includes fake, non-sensitive fixture inputs under `fixtures/` for CLI examples, demos, smoke tests, manual development checks, plugin tests, and future workflow examples.

## Purpose

Fixtures are for:

```text
manual CLI runs
README and docs examples
smoke-test coverage
demo workflows
parser and reviewer examples
plugin examples
workflow golden tests
future UI/API/MCP sample payloads
```

Unit tests may still use small inline inputs when that is clearer.

## Policy

Fixtures must be safe to commit and share.

```text
no real customer data
no real credentials or tokens
no real incident artifacts
no proprietary logs
use reserved example domains
use documentation IP ranges
keep files small enough for manual review
name intentionally malformed inputs clearly
```

Use reserved domains:

```text
example.com
example.net
example.org
invalid
localhost
```

Use documentation IP ranges:

```text
192.0.2.0/24
198.51.100.0/24
203.0.113.0/24
```

## Plugin fixture policy

Top-level fixtures are shared examples.

Package-specific golden tests or plugin-only examples may live under:

```text
plugins/<plugin>/testdata/
packages/<package>/testdata/
```

Domain plugins should include fixtures that demonstrate:

```text
valid input
malformed input
edge-case input
safe warning behavior
policy refusal behavior where applicable
example workflow input
example workflow output when workflows exist
```

Network/provider plugins must not require live external services for default tests. Use mocked fixtures for deterministic tests.

## Inventory

| Fixture | Primary skills |
|---|---|
| `fixtures/sarif/codeql-results.sarif` | `parse_sarif` run, rule, result, location, fingerprint, suppression, fix, and taxonomy observations |
| `fixtures/sarif/multi-run.sarif` | `parse_sarif` multi-run scanner output observations |
| `fixtures/sarif/malformed-shapes.sarif` | `parse_sarif` malformed-shape warning behavior |
| `fixtures/sarif/minimal.sarif` | `parse_sarif` minimal valid SARIF envelope |
| `fixtures/trufflehog/git-results.ndjson` | `parse_trufflehog_ndjson` detector, source, verification, and redacted-secret observations |
| `fixtures/trufflehog/source-metadata.ndjson` | `parse_trufflehog_ndjson` source metadata and structured data key observations |
| `fixtures/trufflehog/malformed-lines.ndjson` | `parse_trufflehog_ndjson` malformed-line and non-object warning behavior |
| `fixtures/trufflehog/lowercase-fields.ndjson` | `parse_trufflehog_ndjson` case-insensitive field handling |
| `fixtures/github-actions/basic-workflow.yml` | `parse_github_actions_workflow` trigger, permission, job, and step observations |
| `fixtures/github-actions/permissions-workflow.yml` | `parse_github_actions_workflow` permission and secret-name reference observations |
| `fixtures/github-actions/reusable-workflow.yml` | `parse_github_actions_workflow` reusable workflow job observations |
| `fixtures/github-actions/malformed-workflow.yml` | `parse_github_actions_workflow` warning behavior |
| `fixtures/dockerfile/multi-stage.Dockerfile` | `parse_dockerfile` multi-stage build observations |
| `fixtures/dockerfile/sensitive-env.Dockerfile` | `parse_dockerfile` ENV/ARG key and redaction behavior |
| `fixtures/dockerfile/add-copy.Dockerfile` | `parse_dockerfile` ADD/COPY path observations |
| `fixtures/dockerfile/malformed.Dockerfile` | `parse_dockerfile` warning behavior |
| `fixtures/http-headers/basic-response.txt` | `parse_http_headers` |
| `fixtures/http-headers/security-headers.txt` | `parse_http_headers` observed response headers |
| `fixtures/http-headers/duplicate-headers.txt` | `parse_http_headers` duplicate header behavior |
| `fixtures/http-headers/malformed-headers.txt` | `parse_http_headers` warning behavior |
| `fixtures/email/sample-headers.txt` | `parse_email_headers` |
| `fixtures/email/auth-results-headers.txt` | `parse_email_headers` |
| `fixtures/csv/assets.csv` | `parse_csv` |
| `fixtures/csv/users.csv` | `parse_csv` |
| `fixtures/csv/irregular-rows.csv` | `parse_csv` warning behavior |
| `fixtures/yaml/app-config.yaml` | `parse_yaml` |
| `fixtures/yaml/multi-document.yaml` | `parse_yaml` multi-document behavior |
| `fixtures/package-json/basic-package.json` | `parse_package_json` |
| `fixtures/package-json/workspace-package.json` | `parse_package_json` workspace metadata |
| `fixtures/iocs/mixed-iocs.txt` | `extract_iocs`, specialized extractors, fanging utilities |
| `fixtures/identifiers/cves-and-uuids.txt` | `extract_cves`, `extract_uuids` |
| `fixtures/jwt/alg-none.jwt` | `parse_jwt` |
| `fixtures/browser-extension/manifest-v3-basic.json` | `parse_browser_extension_manifest` |
| `fixtures/urls/urls.txt` | URL and IOC extraction workflows |

## Future fixture families

Candidate future fixture folders:

```text
fixtures/cloudformation/
fixtures/kubernetes/
fixtures/certificates/
fixtures/http-headers/
fixtures/dockerfile/
fixtures/scanner-results/
fixtures/sarif/
fixtures/sbom/
fixtures/shortlinks/
fixtures/url-triage/
fixtures/ai-agent/
```

## Common commands

Run from the repository root.

```bash
pnpm --filter @security-workbench/cli start skills run parse_sarif --input-file "$PWD/fixtures/sarif/codeql-results.sarif" --format pretty
pnpm --filter @security-workbench/cli start skills run parse_http_headers --input-file "$PWD/fixtures/http-headers/security-headers.txt" --format pretty
pnpm --filter @security-workbench/cli start skills run parse_dockerfile --input-file "$PWD/fixtures/dockerfile/multi-stage.Dockerfile" --format pretty
pnpm --filter @security-workbench/cli start skills run parse_email_headers --input-file "$PWD/fixtures/email/sample-headers.txt" --format pretty
pnpm --filter @security-workbench/cli start skills run parse_csv --input-file "$PWD/fixtures/csv/assets.csv" --format pretty
pnpm --filter @security-workbench/cli start skills run parse_yaml --input-file "$PWD/fixtures/yaml/app-config.yaml" --format pretty
pnpm --filter @security-workbench/cli start skills run parse_package_json --input-file "$PWD/fixtures/package-json/basic-package.json" --format pretty
pnpm --filter @security-workbench/cli start skills run extract_iocs --input-file "$PWD/fixtures/iocs/mixed-iocs.txt" --format pretty
pnpm --filter @security-workbench/cli start skills run parse_jwt --input-file "$PWD/fixtures/jwt/alg-none.jwt" --format pretty
```

Use `$PWD/...` for fixture paths because `pnpm --filter` may execute from the package directory rather than the repository root.

## Fixture versus testdata

Use top-level fixtures for shared examples:

```text
fixtures/
```

Use package-local testdata for golden tests or package-specific cases:

```text
plugins/<plugin>/testdata/
packages/<package>/testdata/
```

Do not duplicate large fixture inventories across docs. This file is the canonical fixture inventory.


### `github-actions/`

Synthetic GitHub Actions workflow fixtures covering trigger forms, permission blocks, reusable workflow jobs, action uses, checkout observations, context references, secret-name references, and malformed-shape warning behavior. These fixtures are local YAML artifacts and do not require GitHub access or workflow execution.


### `trufflehog/`

Synthetic TruffleHog NDJSON scanner-output fixtures covering detector/source metadata, verification states, raw-secret redaction behavior, structured data key inventories, malformed lines, non-object lines, and case-insensitive common field handling. These fixtures are fake local scanner outputs and do not contain real secrets.
