# Plugin: core-reviewers

Deterministic local reviewer skills that interpret parsed artifacts into evidence-backed signals.

Status:

```text
Package: plugins/core-reviewers
NPM name: @security-workbench/core-reviewers
Quality: core
Execution: local-only
Network: none
Persistence: none
External binaries: none
Implemented skills: 3
```

## Purpose

`core-reviewers` consumes parsed artifact output and emits structured evidence and signals.

Reviewer boundary:

```text
consume parser output
preserve observed vs inferred separation
emit evidence references
emit review signals
no network
no external enrichment
no scoring
no findings
```

## Implemented skills

| Skill | Input | Output summary |
|---|---|---|
| `review_browser_extension_permissions` | `parse_browser_extension_manifest` output or JSON run result | evidence-backed signals for extension permission and exposure surfaces |
| `review_static_analysis_results` | `parse_sarif` output or JSON run result | evidence-backed signals for SARIF static-analysis result triage |
| `review_certificate` | `parse_pem_certificate` output or JSON run result | evidence-backed signals for parsed X.509 certificate metadata |

## `review_browser_extension_permissions`

Reviews parsed browser extension manifest observations.

Input must be one of:

```text
parse_browser_extension_manifest output object
JSON string containing parse_browser_extension_manifest output
JSON string containing a full skill run result whose output is parse_browser_extension_manifest output
```

It reports:

```text
reviewed surfaces
broad host permissions
broad optional host permissions
wildcard host permissions
notable API permissions
notable optional API permissions
broad content script matches
background context presence
externally_connectable presence
web accessible resource presence
update_url presence
oauth2 presence
content_security_policy absence/presence observations
evidence records
signal records
source parser warning count
```

It does not:

```text
score risk
claim maliciousness
install or execute extensions
contact browser stores
resolve update URLs
perform network lookups
generate findings
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

## Fixture example

Run from repo root:

```bash
pnpm --filter @security-workbench/cli start skills run parse_browser_extension_manifest \
  --input-file "$PWD/fixtures/browser-extension/manifest-v2-broad-hosts.json" \
  > /tmp/browser-extension.parsed.json

pnpm --filter @security-workbench/cli start skills run review_browser_extension_permissions \
  --input-file /tmp/browser-extension.parsed.json \
  --format pretty
```

## Test themes

```text
skill registration
local-only permissions
parsed-output validation
JSON run-result input handling
evidence-backed signal generation
minimal low-surface output
malformed input rejection
pretty output coverage through CLI tests
fixture-backed smoke coverage
```


## `review_static_analysis_results`

Reviews parsed SARIF observations and emits evidence-backed static-analysis triage signals.

It reports:

```text
source parser and warning count
SARIF tool names
rule and result counts
result levels
suppressed result count
fix availability count
new result count
affected artifact URIs
affected rule IDs
evidence records
signal records
```

It does not:

```text
run scanners
inspect source files
verify true-positive or false-positive status
perform CVE, EPSS, KEV, package, or repository enrichment
score risk
generate findings
```

## Static-analysis example

Run from repo root:

```bash
pnpm --filter @security-workbench/cli start skills run parse_sarif \
  --input-file "$PWD/fixtures/sarif/codeql-results.sarif" \
  > /tmp/static-analysis.parsed.json

pnpm --filter @security-workbench/cli start skills run review_static_analysis_results \
  --input-file /tmp/static-analysis.parsed.json \
  --format pretty
```


## `review_certificate`

Reviews parsed PEM certificate observations and emits evidence-backed certificate metadata signals.

Input must be one of:

```text
parse_pem_certificate output object
JSON string containing parse_pem_certificate output
JSON string containing a full skill run result whose output is parse_pem_certificate output
```

It reports:

```text
source parser and warning count
reviewed certificate count
CA certificate count
self-issued certificate count
missing subjectAltName count for non-CA certificates
small public key observations
long encoded validity-window observations
invalid PEM certificate block observations
evidence records
signal records
explicit limitations
```

It does not:

```text
validate certificate chains or trust anchors
perform hostname matching
check revocation status
query certificate transparency logs
use current time to classify expiration or not-yet-valid status
perform network lookups
score risk
generate findings
```

## Certificate review example

Run from repo root:

```bash
pnpm --filter @security-workbench/cli start skills run parse_pem_certificate \
  --input-file "$PWD/fixtures/certificates/example-cert.pem" \
  > /tmp/certificate.parsed.json

pnpm --filter @security-workbench/cli start skills run review_certificate \
  --input-file /tmp/certificate.parsed.json \
  --format pretty
```
