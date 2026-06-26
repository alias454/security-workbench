# Security Workbench fixtures

This directory contains small, fake, non-sensitive sample inputs for manual CLI runs, demos, smoke tests, and documentation examples.

## Fixture policy

Fixtures must be safe to commit and share:

- Do not include real customer data, real secrets, real tokens, or real incident artifacts.
- Prefer reserved domains such as `example.com`, `example.net`, and `example.org`.
- Prefer documentation IP ranges such as `192.0.2.0/24`, `198.51.100.0/24`, and `203.0.113.0/24`.
- Keep files small and human-reviewable.
- Keep intentionally malformed samples obvious and isolated.
- Treat fixture values as attacker-controlled input when they are rendered or passed downstream.

## Runnable examples

From the repository root:

```bash
pnpm --filter @security-workbench/cli start skills run parse_http_headers --input-file "$PWD/fixtures/http-headers/security-headers.txt" --format pretty
pnpm --filter @security-workbench/cli start skills run parse_dockerfile --input-file "$PWD/fixtures/dockerfile/multi-stage.Dockerfile" --format pretty
pnpm --filter @security-workbench/cli start skills run parse_github_actions_workflow --input-file "$PWD/fixtures/github-actions/basic-workflow.yml" --format pretty
pnpm --filter @security-workbench/cli start skills run parse_trufflehog_ndjson --input-file "$PWD/fixtures/trufflehog/git-results.ndjson" --format pretty
pnpm --filter @security-workbench/cli start skills run parse_sarif --input-file "$PWD/fixtures/sarif/codeql-results.sarif" --format pretty
pnpm --filter @security-workbench/cli start skills run parse_email_headers --input-file "$PWD/fixtures/email/sample-headers.txt" --format pretty
pnpm --filter @security-workbench/cli start skills run parse_csv --input-file "$PWD/fixtures/csv/assets.csv" --format pretty
pnpm --filter @security-workbench/cli start skills run parse_yaml --input-file "$PWD/fixtures/yaml/app-config.yaml" --format pretty
pnpm --filter @security-workbench/cli start skills run parse_package_json --input-file "$PWD/fixtures/package-json/basic-package.json" --format pretty
pnpm --filter @security-workbench/cli start skills run extract_iocs --input-file "$PWD/fixtures/iocs/mixed-iocs.txt" --format pretty
pnpm --filter @security-workbench/cli start skills run parse_jwt --input-file "$PWD/fixtures/jwt/alg-none.jwt" --format pretty
```

## Fixture inventory

| Path | Intended skills |
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
| `fixtures/csv/users.csv` | `parse_csv`, later reviewer/enrichment workflows |
| `fixtures/csv/irregular-rows.csv` | `parse_csv` warning behavior |
| `fixtures/yaml/app-config.yaml` | `parse_yaml` |
| `fixtures/yaml/multi-document.yaml` | `parse_yaml` multi-document behavior |
| `fixtures/package-json/basic-package.json` | `parse_package_json` |
| `fixtures/package-json/workspace-package.json` | `parse_package_json` workspace metadata |
| `fixtures/iocs/mixed-iocs.txt` | `extract_iocs`, `defang_iocs`, `refang_iocs`, specialized extractors |
| `fixtures/identifiers/cves-and-uuids.txt` | `extract_cves`, `extract_uuids` |
| `fixtures/jwt/alg-none.jwt` | `parse_jwt` |
| `fixtures/urls/urls.txt` | URL and IOC extraction workflows |


## Browser extension fixtures

```text
fixtures/browser-extension/manifest-v3-basic.json
```

The browser extension fixture is fake, non-sensitive, and uses reserved example domains. It supports parser examples for `parse_browser_extension_manifest`.


### `identifiers/`

Identifier extraction fixtures.

- `cves-and-uuids.txt` contains mixed-case CVE identifiers and canonical UUIDs.
- Used by `extract_cves` and `extract_uuids` smoke coverage.

<!-- browser-extension-common-variants -->
### `browser-extension/`

Synthetic WebExtensions-style manifest fixtures covering common Manifest V2, Manifest V3, Chromium, Firefox/Gecko, Safari-compatible, and unknown-key variants. These fixtures are intentionally local and do not require installing or running extension code.
<!-- /browser-extension-common-variants -->

### `http-headers/`

Synthetic HTTP response header fixtures covering a basic response, common response header observations, duplicate header names, and malformed/folded-line warning behavior. These fixtures are local text artifacts and do not require making requests.

### `dockerfile/`

Synthetic Dockerfile fixtures covering multi-stage builds, ENV/ARG key observation with sensitive-looking value redaction, ADD/COPY source and destination parsing, and malformed/unmodeled instruction warning behavior. These fixtures are local text artifacts and do not require Docker, image builds, or registry access.


### `github-actions/`

Synthetic GitHub Actions workflow fixtures covering trigger forms, permission blocks, reusable workflow jobs, action uses, checkout observations, context references, secret-name references, and malformed-shape warning behavior. These fixtures are local YAML artifacts and do not require GitHub access or workflow execution.


### `trufflehog/`

Synthetic TruffleHog NDJSON scanner-output fixtures covering detector/source metadata, verification states, raw-secret redaction behavior, structured data key inventories, malformed lines, non-object lines, and case-insensitive common field handling. These fixtures are fake local scanner outputs and do not contain real secrets.

### `sarif/`

Synthetic SARIF scanner-output fixtures covering SARIF run/rule/result structure, file locations, fingerprints, suppressions, fixes, taxa, multiple runs, minimal valid envelopes, and malformed-shape warning behavior. These fixtures are fake local scanner outputs and do not require scanner execution, repository access, or network access.
