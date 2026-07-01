# Fixtures

Fixtures are fake, non-sensitive sample inputs under `fixtures/`.

Used for:

```text
manual CLI runs
README examples
smoke tests
parser/reviewer examples
future workflow golden tests
```

## Policy

```text
no real customer data
no real credentials/tokens
no real incident artifacts
no proprietary logs
use example.com/example.net/example.org
use documentation IP ranges
keep files small and reviewable
name malformed samples clearly
```

## Inventory

```text
fixtures/browser-extension/   parse_browser_extension_manifest, review_browser_extension_permissions
fixtures/certificates/        parse_pem_certificate
fixtures/csv/                 parse_csv
fixtures/dockerfile/          parse_dockerfile
fixtures/email/               parse_email_headers
fixtures/github-actions/      parse_github_actions_workflow
fixtures/http-headers/        parse_http_headers
fixtures/ip-prefixes/         parse_ip_prefix_list
fixtures/asn/                 ASN parser fixtures
fixtures/identifiers/         extract_cves, extract_uuids
fixtures/iocs/                extract_iocs and fang/refang helpers
fixtures/jwt/                 parse_jwt
fixtures/lockfiles/           parse_lockfiles
fixtures/package-json/        parse_package_json
fixtures/sarif/               parse_sarif
fixtures/scanners/            parse_semgrep_json, parse_checkov_json, parse_grype_json
fixtures/trufflehog/          parse_trufflehog_ndjson
fixtures/urls/                URL/IOC extraction
fixtures/yaml/                parse_yaml
```

## Common commands

```bash
pnpm --filter @security-workbench/cli start skills run parse_sarif --input-file "$PWD/fixtures/sarif/codeql-results.sarif" --format pretty
pnpm --filter @security-workbench/cli start skills run parse_trufflehog_ndjson --input-file "$PWD/fixtures/trufflehog/git-results.ndjson" --format pretty
pnpm --filter @security-workbench/cli start skills run parse_semgrep_json --input-file "$PWD/fixtures/scanners/semgrep-results.json" --format pretty
pnpm --filter @security-workbench/cli start skills run parse_checkov_json --input-file "$PWD/fixtures/scanners/checkov-results.json" --format pretty
pnpm --filter @security-workbench/cli start skills run parse_grype_json --input-file "$PWD/fixtures/scanners/grype-results.json" --format pretty
pnpm --filter @security-workbench/cli start skills run parse_pem_certificate --input-file "$PWD/fixtures/certificates/example-cert.pem" --format pretty
pnpm --filter @security-workbench/cli start skills run parse_lockfiles --input-file "$PWD/fixtures/lockfiles/package-lock.json" --format pretty
pnpm --filter @security-workbench/cli start skills run parse_github_actions_workflow --input-file "$PWD/fixtures/github-actions/basic-workflow.yml" --format pretty
pnpm --filter @security-workbench/cli start skills run parse_dockerfile --input-file "$PWD/fixtures/dockerfile/multi-stage.Dockerfile" --format pretty
pnpm --filter @security-workbench/cli start skills run parse_http_headers --input-file "$PWD/fixtures/http-headers/security-headers.txt" --format pretty
pnpm --filter @security-workbench/cli start skills run parse_browser_extension_manifest --input-file "$PWD/fixtures/browser-extension/manifest-v3-basic.json" --format pretty
pnpm --filter @security-workbench/cli start skills run parse_csv --input-file "$PWD/fixtures/csv/assets.csv" --format pretty
pnpm --filter @security-workbench/cli start skills run parse_yaml --input-file "$PWD/fixtures/yaml/app-config.yaml" --format pretty
pnpm --filter @security-workbench/cli start skills run parse_package_json --input-file "$PWD/fixtures/package-json/basic-package.json" --format pretty
pnpm --filter @security-workbench/cli start skills run parse_ip_prefix_list --input-file "$PWD/fixtures/ip-prefixes/mixed-prefixes.txt" --format pretty
pnpm --filter @security-workbench/cli start skills run parse_asn_list --input-file "$PWD/fixtures/asn/asn-list.txt" --format pretty
pnpm --filter @security-workbench/cli start skills run parse_asn_allow_deny_list --input-file "$PWD/fixtures/asn/asn-allow-deny-list.txt" --format pretty
pnpm --filter @security-workbench/cli start skills run parse_asn_observations --input-file "$PWD/fixtures/asn/asn-observations.txt" --format pretty
pnpm --filter @security-workbench/cli start skills run parse_bgp_prefix_table --input-file "$PWD/fixtures/asn/bgp-prefix-table.txt" --format pretty
pnpm --filter @security-workbench/cli start skills run parse_jwt --input-file "$PWD/fixtures/jwt/alg-none.jwt" --format pretty
pnpm --filter @security-workbench/cli start skills run extract_iocs --input-file "$PWD/fixtures/iocs/mixed-iocs.txt" --format pretty
```

Use `$PWD/...` because `pnpm --filter` may run from package directories.

## Fixture versus package testdata

```text
fixtures/                       shared repo examples
plugins/<plugin>/testdata/      plugin-specific golden inputs
packages/<package>/testdata/    package-specific golden inputs
```
