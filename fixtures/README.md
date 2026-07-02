# Security Workbench fixtures

Small, fake, non-sensitive sample inputs for CLI examples, smoke tests, and parser/reviewer development.

Policy:

```text
no real customer data
no real secrets/tokens
no real incident artifacts
use reserved example domains
use documentation IP ranges
keep files small and reviewable
```

Inventory:

```text
browser-extension/   parse_browser_extension_manifest
certificates/        parse_pem_certificate
csv/                 parse_csv
dockerfile/          parse_dockerfile
email/               parse_email_headers
github-actions/      parse_github_actions_workflow
http-headers/        parse_http_headers
ip-prefixes/         parse_ip_prefix_list
identifiers/         extract_cves, extract_uuids
iocs/                extract_iocs, normalize_indicators, extract_defanged_urls, and fang/refang helpers
jwt/                 parse_jwt, review_jwt
lockfiles/           parse_lockfiles
package-json/        parse_package_json
sarif/               parse_sarif
scanners/            parse_semgrep_json, parse_checkov_json, parse_grype_json
trufflehog/          parse_trufflehog_ndjson
urls/                URL and IOC extraction
yaml/                parse_yaml
```

Run examples from repo root:

```bash
pnpm --filter @security-workbench/cli start skills run parse_sarif --input-file "$PWD/fixtures/sarif/codeql-results.sarif" --format pretty
pnpm --filter @security-workbench/cli start skills run parse_trufflehog_ndjson --input-file "$PWD/fixtures/trufflehog/git-results.ndjson" --format pretty
pnpm --filter @security-workbench/cli start skills run parse_semgrep_json --input-file "$PWD/fixtures/scanners/semgrep-results.json" --format pretty
pnpm --filter @security-workbench/cli start skills run parse_checkov_json --input-file "$PWD/fixtures/scanners/checkov-results.json" --format pretty
pnpm --filter @security-workbench/cli start skills run parse_grype_json --input-file "$PWD/fixtures/scanners/grype-results.json" --format pretty
pnpm --filter @security-workbench/cli start skills run parse_pem_certificate --input-file "$PWD/fixtures/certificates/example-cert.pem" --format pretty
pnpm --filter @security-workbench/cli start skills run parse_lockfiles --input-file "$PWD/fixtures/lockfiles/package-lock.json" --format pretty
pnpm --filter @security-workbench/cli start skills run parse_sbom --input-file "$PWD/fixtures/sbom/cyclonedx.json" --format pretty
pnpm --filter @security-workbench/cli start skills run parse_browser_extension_manifest --input-file "$PWD/fixtures/browser-extension/manifest-v3-basic.json" --format pretty
pnpm --filter @security-workbench/cli start skills run extract_iocs --input-file "$PWD/fixtures/iocs/mixed-iocs.txt" --format pretty
pnpm --filter @security-workbench/cli start skills run extract_defanged_urls --input-file "$PWD/fixtures/iocs/defanged-indicators.txt" --format pretty
pnpm --filter @security-workbench/cli start skills run parse_ip_prefix_list --input-file "$PWD/fixtures/ip-prefixes/mixed-prefixes.txt" --format pretty
pnpm --filter @security-workbench/cli start skills run parse_asn_list --input-file "$PWD/fixtures/asn/asn-list.txt" --format pretty
pnpm --filter @security-workbench/cli start skills run parse_asn_allow_deny_list --input-file "$PWD/fixtures/asn/asn-allow-deny-list.txt" --format pretty
pnpm --filter @security-workbench/cli start skills run parse_asn_observations --input-file "$PWD/fixtures/asn/asn-observations.txt" --format pretty
pnpm --filter @security-workbench/cli start skills run parse_bgp_prefix_table --input-file "$PWD/fixtures/asn/bgp-prefix-table.txt" --format pretty
```
