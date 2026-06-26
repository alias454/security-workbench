# Plugin: core-utilities

## Status

Implemented baseline plugin.

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

`core-utilities` provides deterministic, local-only utility primitives: transformations, normalization, hashing, JSON utilities, URL utilities, text decoding, line utilities, structured extraction, and lightweight parser-category skills.

These skills are safe primitives for analysts, the CLI, future pipelines, and later dedicated parser/reviewer plugins.

The plugin must remain boring:

```text
no network calls
no filesystem reads
no filesystem writes
no persistence
no external binaries
no hidden side effects
```

File reading is allowed only at the CLI/API/UI input boundary. Skills in this plugin still receive a string and do not receive file permissions.

## Current skills

| Skill | Category | Status | Network | Summary |
|---|---:|---:|---:|---|
| `base64_decode` | transform | implemented | none | Decode a strict padded Base64 string as UTF-8. |
| `base64_encode` | transform | implemented | none | Encode UTF-8 input as padded Base64. |
| `url_encode` | transform | implemented | none | Percent-encode input with encodeURIComponent. |
| `url_decode` | transform | implemented | none | Decode percent-encoded input with strict error handling. |
| `hex_encode` | transform | implemented | none | Encode UTF-8 input as lowercase hexadecimal. |
| `hex_decode` | transform | implemented | none | Decode strict even-length hexadecimal into UTF-8 text. |
| `identify_hash` | parser | implemented | none | Identify likely hash digest algorithms from hexadecimal digest length. |
| `md5_hash` | transform | implemented | none | Compute MD5 over UTF-8 input and return lowercase hex. |
| `sha1_hash` | transform | implemented | none | Compute SHA-1 over UTF-8 input and return lowercase hex. |
| `sha256_hash` | transform | implemented | none | Compute SHA-256 over UTF-8 input and return lowercase hex. |
| `sha512_hash` | transform | implemented | none | Compute SHA-512 over UTF-8 input and return lowercase hex. |
| `json_parse` | parser | implemented | none | Parse JSON text into a structured JSON value. |
| `json_format` | transform | implemented | none | Parse and pretty-print JSON with two-space indentation. |
| `calculate_entropy` | transform | implemented | none | Calculate Shannon entropy over Unicode code points. |
| `string_normalize` | transform | implemented | none | Normalize Unicode text to NFC without trimming or case folding. |
| `defang_iocs` | transform | implemented | none | Defang common IOC text. |
| `refang_iocs` | transform | implemented | none | Refang common defanged IOC text. |
| `extract_iocs` | parser | implemented | none | Extract simple URLs, domains, IPv4s, emails, and SHA-256 hashes. |
| `html_entity_decode` | transform | implemented | none | Decode common HTML named and numeric entities. |
| `unicode_escape_decode` | transform | implemented | none | Decode JavaScript-style Unicode and character escapes without eval. |
| `quoted_printable_decode` | transform | implemented | none | Decode strict quoted-printable text. |
| `parse_url` | parser | implemented | none | Parse a URL into structured components while redacting credentials. |
| `trim_lines` | transform | implemented | none | Trim leading and trailing whitespace from each logical line. |
| `remove_empty_lines` | transform | implemented | none | Remove empty and whitespace-only lines. |
| `dedupe_lines` | transform | implemented | none | Remove duplicate lines while preserving first-seen order. |
| `sort_lines` | transform | implemented | none | Sort lines in deterministic ascending code-unit order. |
| `count_lines` | transform | implemented | none | Count total, empty, and non-empty logical lines. |
| `base32_encode` | transform | implemented | none | Encode UTF-8 input as RFC4648 padded Base32. |
| `base32_decode` | transform | implemented | none | Decode strict RFC4648 padded Base32 into UTF-8 text. |
| `rot13` | transform | implemented | none | Apply ROT13 to ASCII letters while preserving other characters. |
| `extract_urls` | parser | implemented | none | Extract simple HTTP and HTTPS URLs from text. |
| `extract_domains` | parser | implemented | none | Extract simple domain names from text, URLs, and email addresses. |
| `extract_emails` | parser | implemented | none | Extract email addresses from text. |
| `extract_ipv4` | parser | implemented | none | Extract valid IPv4 addresses from text. |
| `extract_hashes` | parser | implemented | none | Extract MD5, SHA-1, SHA-256, and SHA-512 hex hashes from text. |
| `extract_cves` | parser | implemented | none | Extract CVE identifiers from text without validating external existence. |
| `extract_uuids` | parser | implemented | none | Extract canonical UUID values from text. |
| `parse_jwt` | parser | implemented | none | Decode JWT header and payload without verifying the signature or exposing the raw signature. |
| `parse_email_headers` | parser | implemented | none | Parse an RFC822-style email header block into normalized header fields. |

Parser-category skills intentionally live in `core-utilities` when they are lightweight local utility parsers. Richer artifact and document parsers remain in `core-parsers`.

## Permission declaration

Every skill in this plugin must declare:

```ts
permissions: {
  network: "none",
  filesystem: "none",
  sends: [],
  persists: false,
  runs_external_binaries: false,
}
```

## Exposure policy

`packages/schemas` now supports optional skill exposure metadata for future CLI/API/web/MCP adapter enforcement.

Current `core-utilities` skills remain governed by runtime permission metadata. Exposure annotations can be backfilled later as a separate review pass before hosted API or MCP exposure.

Until that backfill is complete, future hosted/MCP adapters should treat unreviewed or missing exposure metadata as disabled or allowlist-only, depending on the adapter profile.

## Security behavior

### Network

This plugin must never perform network calls.

Runtime expectations:

```text
allow_network=false      allowed
allow_network=true       still no network use
network_used             always false
external_sinks           always []
```

### Filesystem

This plugin must not read or write files directly.

`--input-file` is a CLI feature. The CLI performs bounded UTF-8 file acquisition and passes the resulting text string into the runtime. Skills still declare `filesystem: "none"`.

Current `--input-file` controls:

```text
reject both --input and --input-file together
reject neither
stat file before reading
reject directories
enforce maximum file size before read
re-check maximum size after read
read valid UTF-8 only
no globbing
no recursive reads
no archive parsing
```

### Persistence

This plugin must not persist input, output, intermediate state, logs, caches, or artifacts.

### Input size

Runtime input-size enforcement happens before skill execution.

Default policy:

```yaml
max_artifact_size_mb: 10
```

Oversized input should produce a structured policy refusal before the skill runs.

### Redaction

Runtime redaction is enabled by default.

Parser-lite skills also avoid exposing obvious reusable secrets where practical:

```text
parse_url reports credential presence but does not expose raw username/password.
parse_jwt reports signature metadata but does not expose the raw signature segment.
parse_email_headers preserves header fields but does not perform external lookups.
```

## Input-file behavior

`--input-file` passes the entire file contents as one string to the selected skill.

Current flow:

```text
CLI reads bounded UTF-8 file → runtime receives one string → selected skill runs once
```

There is no automatic CSV mode, per-line mode, row loop, archive extraction, or format detection yet.

### Multiline text

A file like this:

```text
https://evil.example.com/path
admin@example.com
192.168.1.10
```

passed to `defang_iocs`, `extract_iocs`, or line utilities is treated as one string containing newlines. Newlines are preserved unless a specific skill changes them.

### CSV text

A CSV file is treated as plain text. `defang_iocs`, `extract_iocs`, and specialized extractors may still be useful on CSV-shaped text, but the plugin does not understand CSV quoting, headers, rows, or columns.

CSV-aware behavior now belongs to `parse_csv` in `core-parsers`. `core-utilities` skills still treat CSV-shaped input as plain text unless a transform explicitly changes that text.

## Skill behavior notes

### Encoding/decoding utilities

```text
base64_encode
base64_decode
base32_encode
base32_decode
url_encode
url_decode
hex_encode
hex_decode
rot13
```

These operate on strings only and reject non-string input.

`base64_decode` is intentionally strict and requires padded Base64. Node's native Base64 decoder is permissive, so validation happens before decoding.

`base32_decode` is strict RFC4648 padded Base32. It normalizes lowercase input to uppercase but rejects malformed padding and invalid lengths.

`hex_decode` requires strict even-length hexadecimal.

`rot13` only substitutes ASCII letters and preserves all other characters.

### Text decoders

```text
html_entity_decode
unicode_escape_decode
quoted_printable_decode
```

These decode text only. They do not execute decoded content.

Decoded output can contain active-looking HTML, JavaScript, URLs, or terminal-sensitive text. Interface layers and exporters must escape rendered output.

### JSON utilities

```text
json_parse
json_format
```

These use `JSON.parse` only. They do not execute code, load schemas, fetch remote references, or persist parsed content.

`json_parse` is categorized as a parser because it returns a structured JSON value. `json_format` is categorized as a transform because it returns formatted text. Both require the whole input string to be valid JSON. With `--input-file`, the entire file must be valid JSON.

### Hashing

`identify_hash` is categorized as a parser because it returns structured observations about a digest string. Explicit hash skills are transforms because they compute MD5, SHA-1, SHA-256, and SHA-512 output from input text.

The skill hashes the exact UTF-8 string it receives. With `--input-file`, this includes all newline characters read from the file.

### Entropy

`calculate_entropy` computes Shannon entropy over Unicode code points.

It does not classify whether the input is secret, random, benign, malicious, or suspicious. Classification belongs in a reviewer skill.

### String normalization

`string_normalize` normalizes to Unicode NFC only.

It intentionally does not:

```text
trim whitespace
lowercase
case fold
strip control characters
normalize paths
```

Those behaviors can change meaning and should be separate explicit skills later.

### Line utilities

```text
trim_lines
remove_empty_lines
dedupe_lines
sort_lines
count_lines
```

These are pipeline-friendly data preparation primitives. They still run as one skill execution over one multiline string.

Design notes:

```text
trim_lines trims each logical line.
remove_empty_lines removes empty and whitespace-only lines.
dedupe_lines removes exact duplicate lines and preserves first-seen order.
sort_lines sorts by deterministic case-sensitive JavaScript code-unit order.
count_lines counts logical lines after CRLF/CR normalization.
```

Future `--input-mode lines` should remain separate because it changes CLI execution semantics from one skill run to many skill runs.

### IOC fang utilities

`defang_iocs` performs idempotent text replacement:

```text
https:// → hxxps://
http://  → hxxp://
.        → [.] 
@        → [@]
```

`refang_iocs` reverses common forms:

```text
hxxps:// → https://
hxxp://  → http://
[.]      → .
(.)      → .
{.}      → .
[dot]    → .
(dot)    → .
{dot}    → .
[@]      → @
(@)      → @
{@}      → @
[at]     → @
(at)     → @
{at}     → @
```

Refanged output can produce live-looking URLs. CLI output is plain JSON, but future UI/Markdown/export rendering must avoid making refanged URLs clickable by default.

### IOC extraction

`extract_iocs` and the specialized extractor skills are parser-category, pattern-based, and local-only.

It extracts:

```text
urls
domains
ipv4_addresses
email_addresses
sha256_hashes
```

Specialized extractors split that behavior into focused skills:

```text
extract_urls
extract_domains
extract_emails
extract_ipv4
extract_hashes
extract_cves
extract_uuids
```

Extractor behavior is pattern-based. It does not:

```text
perform DNS lookup
validate domain registration
score maliciousness
contact reputation services
extract every possible IOC type
parse nested documents
understand CSV rows or JSON fields structurally
```

### Parser-lite utilities

```text
parse_url
parse_jwt
parse_email_headers
```

These are deterministic local parser primitives currently implemented in `core-utilities`.

`parse_jwt` does not verify signatures and does not expose the raw signature segment.

`parse_email_headers` parses header text only and performs no DNS, SPF, DKIM, DMARC, or reputation checks.

## CLI discovery examples

Run all examples from the repository root.

```bash
pnpm --filter @security-workbench/cli start skills list
```

```bash
pnpm --filter @security-workbench/cli start skills list --format table
```

```bash
pnpm --filter @security-workbench/cli start skills list --category parser --format table
```

```bash
pnpm --filter @security-workbench/cli start skills describe parse_jwt
```

```bash
pnpm --filter @security-workbench/cli start skills describe identify_hash --format tsv
```

## Skill examples

### Encoding and decoding

```bash
pnpm --filter @security-workbench/cli start skills run base64_encode --input "Hello Security Workbench"
pnpm --filter @security-workbench/cli start skills run base64_decode --input "SGVsbG8gU2VjdXJpdHkgV29ya2JlbmNo"
pnpm --filter @security-workbench/cli start skills run base32_encode --input "hello"
pnpm --filter @security-workbench/cli start skills run base32_decode --input "NBSWY3DP"
pnpm --filter @security-workbench/cli start skills run hex_encode --input "Hello"
pnpm --filter @security-workbench/cli start skills run hex_decode --input "48656c6c6f"
pnpm --filter @security-workbench/cli start skills run url_encode --input "hello world?x=1&y=2"
pnpm --filter @security-workbench/cli start skills run url_decode --input "hello%20world%3Fx%3D1%26y%3D2"
pnpm --filter @security-workbench/cli start skills run rot13 --input "uryyb jbeyq"
```

### Text decoding

```bash
pnpm --filter @security-workbench/cli start skills run html_entity_decode --input 'Tom &amp; Jerry &lt;tag&gt; &#x41;'
pnpm --filter @security-workbench/cli start skills run unicode_escape_decode --input 'hello\n\u0041\u{1F600}'
pnpm --filter @security-workbench/cli start skills run quoted_printable_decode --input 'caf=C3=A9=0Aline2'
```

### JSON

```bash
pnpm --filter @security-workbench/cli start skills run json_parse --input '{"ioc":"hxxps://evil[.]example[.]com","severity":"test"}'
pnpm --filter @security-workbench/cli start skills run json_format --input '{"user":"brandon","roles":["security","builder"],"enabled":true}'
```

With a file:

```bash
cat > /tmp/sample.json <<'EOF'
{"url":"https://evil.example.com","email":"admin@example.com","enabled":true}
EOF

pnpm --filter @security-workbench/cli start skills run json_format --input-file /tmp/sample.json
```

### Hashing and entropy

```bash
pnpm --filter @security-workbench/cli start skills run identify_hash --input "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
pnpm --filter @security-workbench/cli start skills run md5_hash --input "hello"
pnpm --filter @security-workbench/cli start skills run sha1_hash --input "hello"
pnpm --filter @security-workbench/cli start skills run sha256_hash --input "hello"
pnpm --filter @security-workbench/cli start skills run sha512_hash --input "hello"
pnpm --filter @security-workbench/cli start skills run calculate_entropy --input "aaaaaaaa"
pnpm --filter @security-workbench/cli start skills run calculate_entropy --input "a8F!zQ91pL"
pnpm --filter @security-workbench/cli start skills run sha256_hash --input-file /tmp/sample.json
```

### Line utilities

```bash
pnpm --filter @security-workbench/cli start skills run trim_lines --input-file /tmp/iocs.txt
pnpm --filter @security-workbench/cli start skills run remove_empty_lines --input-file /tmp/iocs.txt
pnpm --filter @security-workbench/cli start skills run dedupe_lines --input-file /tmp/iocs.txt
pnpm --filter @security-workbench/cli start skills run sort_lines --input-file /tmp/iocs.txt
pnpm --filter @security-workbench/cli start skills run count_lines --input-file /tmp/iocs.txt
```

### IOC defang, refang, and extraction

```bash
pnpm --filter @security-workbench/cli start skills run defang_iocs --input "https://evil.example.com/path admin@example.com"
pnpm --filter @security-workbench/cli start skills run refang_iocs --input "hxxps://evil[.]example[.]com/path admin[@]example[.]com"
pnpm --filter @security-workbench/cli start skills run extract_iocs --input "Visit hxxps://evil[.]example[.]com, email admin[@]example[.]com, IP 192.168.1.10, hash 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
```

With a multiline file:

```bash
cat > /tmp/iocs.txt <<'EOF'
https://evil.example.com/path
admin@example.com
hxxps://already[.]defanged[.]example
192.168.1.10
2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
EOF

pnpm --filter @security-workbench/cli start skills run extract_urls --input-file /tmp/iocs.txt
pnpm --filter @security-workbench/cli start skills run extract_domains --input-file /tmp/iocs.txt
pnpm --filter @security-workbench/cli start skills run extract_emails --input-file /tmp/iocs.txt
pnpm --filter @security-workbench/cli start skills run extract_ipv4 --input-file /tmp/iocs.txt
pnpm --filter @security-workbench/cli start skills run extract_hashes --input-file /tmp/iocs.txt
```

### Identifier extraction

`extract_cves` matches CVE identifiers in the form `CVE-YYYY-NNNN...`, normalizes matches to uppercase, deduplicates results, and does not validate external existence. `extract_uuids` matches canonical hyphenated UUIDs, normalizes matches to lowercase, and deduplicates results.

### Parser-lite skills

```bash
pnpm --filter @security-workbench/cli start skills run parse_url --input "https://user:pass@example.com/path?x=1"
```

Expected behavior: credential presence is preserved with booleans, but raw username/password are not exposed.

```bash
pnpm --filter @security-workbench/cli start skills run parse_jwt --input "<jwt>"
```

Expected behavior: header/payload are decoded, signature metadata is reported, and signature verification is explicitly false.

```bash
pnpm --filter @security-workbench/cli start skills run parse_email_headers --input-file /tmp/headers.txt
```

Expected behavior: header fields are parsed locally with no authentication, reputation, or DNS lookups.


## Fixture-backed examples

Fixture files live at repo root under `fixtures/` and contain fake, non-sensitive data.

Run examples from the repository root so `$PWD` expands to an absolute repo path before `pnpm --filter` changes package context.

```bash
pnpm --filter @security-workbench/cli start skills run parse_email_headers --input-file "$PWD/fixtures/email/sample-headers.txt" --format pretty
pnpm --filter @security-workbench/cli start skills run parse_jwt --input-file "$PWD/fixtures/jwt/alg-none.jwt" --format pretty
pnpm --filter @security-workbench/cli start skills run extract_iocs --input-file "$PWD/fixtures/iocs/mixed-iocs.txt" --format pretty
pnpm --filter @security-workbench/cli start skills run extract_urls --input-file "$PWD/fixtures/urls/urls.txt" --format pretty
```

## Test coverage

Current tests live in:

```text
plugins/core-utilities/tests/
```

Required test themes:

```text
valid transform behavior
non-string rejection
strict malformed input rejection where applicable
local-only permission declarations
index registration coverage
redaction-sensitive URL behavior
JWT signature non-exposure
email header parsing and folding behavior
IOC extraction and deduplication
line utility behavior
input-file behavior through CLI tests
```

Run:

```bash
pnpm --filter @security-workbench/core-utilities test
pnpm --filter @security-workbench/core-utilities typecheck:test
```

Full gate:

```bash
pnpm build
pnpm test
pnpm typecheck:test
```

## Current limitations

```text
base64_decode only supports strict padded Base64.
base64_decode assumes UTF-8 output.
base32_decode only supports strict RFC4648 padded Base32.
string_normalize only performs NFC normalization.
extract_iocs and extract_* are simple pattern matching, not full IOC intelligence.
extract_iocs and extract_* do not perform enrichment or validation.
extract_iocs and extract_* do not structurally parse CSV, JSON, HTML, or email bodies. Use parser skills such as `parse_csv`, `json_parse`, or `parse_email_headers` when structure matters.
parse_url accepts one URL string, not a multiline URL list.
parse_url does not perform DNS, reputation, or reachability checks.
parse_url does not inspect page content.
parse_jwt does not verify signatures.
parse_email_headers does not perform SPF, DKIM, DMARC, DNS, or reputation checks.
```

These limitations are intentional. Enrichment, risk analysis, batch execution, findings, and richer artifact parsing belong in later plugins and pipelines.

## Done criteria

This plugin is acceptable when:

```text
all skills are deterministic
all skills are local-only
all skills declare permissions
all skills have tests
all tests pass
test typechecking passes
no output leaks obvious secrets by default
runtime policy metadata shows no network use
```

<!-- security-workbench-progress-pr2i-defang-idempotency -->

## Recent progress

```text
PR 2I — defang idempotency implemented
PR 5C.1 — repo-root fixtures added for manual CLI runs and smoke coverage
```

`defang_iocs` avoids double-defanging already-defanged IOC tokens.


---

## Role in the plugin system

`core-utilities` is the always-installed primitive layer for Security Workbench.

It should stay small, deterministic, and broadly useful. Domain behavior belongs in optional plugins that depend on this package instead of duplicating its primitives.

Examples:

| Domain plugin | Core utilities reused |
|---|---|
| `plugin-url-triage` | `parse_url`, `url_decode`, `extract_urls`, `defang_iocs`, `dedupe_lines` |
| `plugin-email` | `parse_email_headers`, `extract_urls`, `extract_emails`, `defang_iocs` |
| `plugin-scanner-normalize` | `json_parse`, `extract_cves`, `extract_urls`, line utilities |
| `plugin-cloudformation` | `json_parse`, `parse_yaml` via core-parsers, redaction helpers |
| `plugin-browser-extension` | `json_parse`, `extract_urls`, `extract_domains` |

Design rule:

```text
Core utilities provide building blocks.
Domain plugins provide analyst workflows.
```

Avoid adding a primitive only because it is interesting. Prefer primitives that support recurring workflows listed in `docs/ANALYST_WORKFLOWS.md`.
