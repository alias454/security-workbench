# Plugin: core-utilities

Deterministic local utility primitives.

Status:

```text
Package: plugins/core-utilities
NPM name: @security-workbench/core-utilities
Quality: core
Execution: local-only
Network: none
Persistence: none
External binaries: none
Implemented skills: 39
```

## Purpose

`core-utilities` provides boring, reusable building blocks:

```text
encoding/decoding
hashing
JSON utilities
URL utilities
text normalization
line utilities
IOC extraction
fang/refang helpers
lightweight parser-category utilities
```

## Skill inventory

| Skill group | Skills |
|---|---|
| Encoding/decoding | `base64_encode`, `base64_decode`, `base32_encode`, `base32_decode`, `hex_encode`, `hex_decode`, `url_encode`, `url_decode`, `rot13` |
| Text decoders | `html_entity_decode`, `unicode_escape_decode`, `quoted_printable_decode` |
| Hashing/entropy | `identify_hash`, `md5_hash`, `sha1_hash`, `sha256_hash`, `sha512_hash`, `calculate_entropy` |
| JSON | `json_parse`, `json_format` |
| Normalization/lines | `string_normalize`, `trim_lines`, `remove_empty_lines`, `dedupe_lines`, `sort_lines`, `count_lines` |
| IOC helpers | `defang_iocs`, `refang_iocs`, `extract_iocs`, `extract_urls`, `extract_domains`, `extract_emails`, `extract_ipv4`, `extract_hashes`, `extract_cves`, `extract_uuids` |
| Parser-lite | `parse_url`, `parse_jwt`, `parse_email_headers` |

## Boundary

This plugin must remain local-only:

```text
no network
no filesystem reads/writes
no persistence
no external binaries
no hidden side effects
```

File reading is a CLI/API/UI boundary behavior. Skills receive a bounded string.

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

## Behavior notes

```text
base64/base32/hex decoders are strict
json_parse/json_format use JSON.parse only
text decoders do not execute decoded content
calculate_entropy does not classify secrets
string_normalize performs NFC only
line utilities operate on one multiline string
extractors are pattern-based, not intelligence lookups
parse_url redacts credentials
parse_jwt does not verify signatures and does not expose the raw signature segment
parse_email_headers performs no DNS/SPF/DKIM/DMARC/reputation checks
```

CSV/YAML/artifact-aware parsing belongs in `core-parsers`, not here.

## Exposure policy

Exposure annotations can be backfilled before hosted/API/MCP use. Until then, future non-CLI adapters should treat missing exposure metadata as disabled or allowlist-only.

## Common commands

```bash
pnpm --filter @security-workbench/cli start skills list --category transform --format table
pnpm --filter @security-workbench/cli start skills list --category parser --format table
pnpm --filter @security-workbench/cli start skills run extract_iocs --input-file "$PWD/fixtures/iocs/mixed-iocs.txt" --format pretty
pnpm --filter @security-workbench/cli start skills run parse_jwt --input-file "$PWD/fixtures/jwt/alg-none.jwt" --format pretty
pnpm --filter @security-workbench/cli start skills run parse_jwt --input-file "$PWD/fixtures/jwt/alg-none.jwt" > /tmp/jwt.parsed.json
pnpm --filter @security-workbench/cli start skills run review_jwt --input-file /tmp/jwt.parsed.json --format pretty
pnpm --filter @security-workbench/cli start skills run parse_email_headers --input-file "$PWD/fixtures/email/sample-headers.txt" --format pretty
```

## Test themes

```text
valid behavior
non-string rejection
strict malformed input rejection where relevant
local-only permission declarations
index registration coverage
redaction-sensitive URL/JWT behavior
email header folding behavior
IOC extraction and deduplication
line utility behavior
CLI input-file behavior through CLI tests
```

## Role in plugins

Core utilities are the substrate. Domain plugins should reuse these primitives instead of duplicating them.

Examples:

```text
plugin-url-triage      → parse_url, url_decode, extract_urls, defang_iocs
plugin-email           → parse_email_headers, extract_urls, extract_emails
plugin-scanner-normalize → json_parse, extract_cves, line utilities
plugin-browser-extension → json_parse, extract_domains
```
