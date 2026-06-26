# Plugin: core-parsers

## Status

Implemented deterministic parser plugin.

```text
Package: plugins/core-parsers
NPM name: @security-workbench/core-parsers
Quality: core
Execution: local-only
Network: none
Persistence: none
External binaries: none
Implemented skills: 9
```

## Purpose

`core-parsers` provides deterministic, local-only parsers for common security artifacts.

Parser skills convert raw artifacts into structured objects, evidence-ready observations, warnings, and normalized metadata. They must not make risk claims by themselves unless the claim is directly observed and evidence-backed.

Parser output should feed reviewer, scoring, finding, export, and future workflow plugins.

## Current parser status

`core-utilities` intentionally owns lightweight utility parsers. `core-parsers` owns richer artifact and document parsers.

| Skill | Input | Output | Current location | Status |
|---|---|---|---|---|
| `parse_url` | URL string | structured URL components | `core-utilities` | implemented bootstrap parser |
| `parse_jwt` | JWT string | decoded JWT header/payload metadata | `core-utilities` | implemented bootstrap parser |
| `parse_email_headers` | raw header block | normalized email header fields | `core-utilities` | implemented bootstrap parser |
| `parse_http_headers` | raw HTTP header block or response preamble | normalized header fields and observed structure | `core-parsers` | implemented |
| `parse_dockerfile` | Dockerfile text | build-stage, instruction, file-transfer, and runtime-surface observations | `core-parsers` | implemented |
| `parse_github_actions_workflow` | GitHub Actions workflow YAML | trigger, permission, job, step, action-use, and context-reference observations | `core-parsers` | implemented |
| `parse_trufflehog_ndjson` | TruffleHog NDJSON scanner output | result, detector, source, verification, metadata, and redacted-secret observations | `core-parsers` | implemented |
| `parse_sarif` | SARIF JSON scanner output | run, rule, result, location, fingerprint, suppression, fix, and taxonomy observations | `core-parsers` | implemented |
| `parse_package_json` | JSON package manifest | normalized package metadata | `core-parsers` | implemented |
| `parse_csv` | CSV text | rows, inferred records, structural metadata, warnings | `core-parsers` | implemented |
| `parse_yaml` | YAML text | JSON-compatible values, document summaries, warnings | `core-parsers` | implemented |
| `parse_browser_extension_manifest` | JSON manifest | normalized browser extension manifest | `core-parsers` | implemented |
| `parse_pem_certificate` | PEM certificate | parsed certificate metadata | `core-parsers` planned | planned later |

Lightweight utility parsers should stay in `core-utilities`. Move a parser into `core-parsers` only when it becomes a richer artifact, document, or domain parser with a dedicated observed model.

## Implemented skills

### `parse_http_headers`

`parse_http_headers` parses bounded UTF-8 HTTP header text into normalized header observations without making network requests, scoring risk, or generating findings.

It accepts either a raw HTTP header block or an HTTP response header preamble. If a blank line is present, content after the blank line is ignored as body content.

It reports:

```text
artifact identity
status line presence
HTTP version/status code/reason phrase when a response status line is present
line ending style
header count
unique header name count
duplicate header names
malformed line count
folded continuation line count
normalized header array
normalized header name inventory
presence of common response header fields
Set-Cookie count
Location presence
warnings for malformed or folded lines
```

It preserves header values as strings. It does not interpret cookie attributes, evaluate embedded values, retrieve URLs, make network calls, persist input, or call external binaries.

It rejects:

```text
empty input
input with no valid header fields
```

### `parse_dockerfile`

`parse_dockerfile` parses bounded UTF-8 Dockerfile text into structured build-stage and instruction observations without building images, pulling base images, making registry requests, scoring risk, or generating findings.

It reports:

```text
artifact identity
line ending style
physical line count
logical instruction count
blank/comment line counts
parser directives
instruction counts
normalized instruction array
unknown instruction inventory
stage inventory
base image references
EXPOSE values
USER values and final USER value
WORKDIR values
ENV and ARG keys
redacted sensitive-looking ENV/ARG values
LABEL keys
COPY and ADD source/destination observations
URL-like ADD source observations
HEALTHCHECK, ENTRYPOINT, CMD, and SHELL presence
command form counts
warnings for malformed, unmodeled, or incomplete structures
```

It supports common Dockerfile instructions including:

```text
FROM
RUN
CMD
LABEL
EXPOSE
ENV
ADD
COPY
ENTRYPOINT
VOLUME
USER
WORKDIR
ARG
ONBUILD
STOPSIGNAL
HEALTHCHECK
SHELL
```

It preserves observations only. It does not interpret package-manager commands, validate image provenance, inspect image contents, pull images, make network calls, persist input, run external binaries, or execute Dockerfile instructions.

It rejects:

```text
empty input
input with no valid Dockerfile instructions
```


### `parse_github_actions_workflow`

`parse_github_actions_workflow` parses bounded UTF-8 GitHub Actions workflow YAML into structured CI workflow observations without contacting GitHub, resolving action references, executing workflow commands, scoring risk, or generating findings.

It reports:

```text
artifact identity
line ending style
physical line count
top-level key inventory
workflow name and run-name presence
trigger form and event inventory
scheduled trigger cron entry count
top-level permission block shape
job-level permission block count
top-level ENV keys
defaults and concurrency presence
job inventory
job runs-on and needs values
job reusable workflow references
job matrix, container, services, environment, defaults, concurrency, and timeout presence
step counts
action uses
checkout step observations
run step presence with command content redacted
step ENV and with keys
referenced GitHub Actions contexts
referenced secret names
warnings for malformed, unmodeled, or incomplete structures
```

It intentionally does not preserve raw `run` command bodies in structured output. It records that command content was present, how many command lines were declared, and which expression contexts or secret names were referenced.

It rejects:

```text
empty input
invalid YAML
multiple YAML documents
non-mapping workflow documents
workflow documents without a jobs mapping
workflow documents without any valid jobs
```

### `parse_trufflehog_ndjson`

`parse_trufflehog_ndjson` parses bounded UTF-8 TruffleHog NDJSON scanner output into structured result observations without contacting external services, exposing raw secret values, scoring risk, or generating findings.

It treats each nonblank input line as one JSON record. Malformed lines and non-object lines are preserved as warnings while valid result records continue to be parsed.

It reports:

```text
artifact identity
line ending style
physical, NDJSON, and blank line counts
valid record count
malformed and non-object line counts
detector name and type inventory
decoder name inventory
source name and source type inventory
repository, file, and file:line observations when present
verified, unverified, and unknown verification counts
raw secret presence counts
raw secret length and SHA-256 hash metadata
scanner-redacted or generated redacted secret values
extra data and structured data key inventories
source metadata key inventory
unknown top-level key inventory
normalized per-result records
warnings for malformed or unmodeled structures
```

It intentionally does not emit raw `Raw` or `RawV2` secret values. When raw secret fields are present, it records presence, length, and SHA-256 hash only. If TruffleHog provides a `Redacted` value, that value is preserved. If only a raw value is present, the parser emits a generated redaction marker containing only the length.

It rejects:

```text
empty input
input with no valid result records
```


### `parse_sarif`

`parse_sarif` parses bounded UTF-8 SARIF JSON scanner output into structured static-analysis observations without contacting external services, resolving scanner metadata, scoring risk, or generating findings.

It reports:

```text
artifact identity and SARIF version
schema presence
line ending style
run count
tool driver names and versions
tool extension names
automation IDs
invocation count
artifact URI inventory
rule inventory
result inventory
result levels and kinds
baseline states
result locations and file/line references
fingerprint and partial-fingerprint keys
suppression counts and kinds
fix presence counts
taxonomy/taxa IDs
rule tags
property key inventories
unknown top-level, run, rule, and result keys
malformed-shape warnings
```

It preserves scanner-provided result messages and location metadata as observations. It does not decide whether a scanner result is a true positive, evaluate severity correctness, fetch source files, contact GitHub or scanner services, apply fixes, execute artifact content, or make remediation recommendations.

It rejects:

```text
non-string input
empty input
invalid JSON
non-object JSON
input without a non-empty runs array
input without any valid SARIF run objects
```

### `parse_package_json`

`parse_package_json` parses bounded UTF-8 `package.json` text into normalized observed metadata without installing packages, running scripts, performing registry lookups, scoring risk, or generating findings.

It reports:

```text
artifact identity
name/version/description presence
license/private/type/packageManager fields
scripts summary
dependency section summaries
engines summary
repository summary
bin/workspaces presence
warnings for malformed optional field shapes
```

It rejects:

```text
invalid JSON
arrays
null
non-object package manifests
```

It uses shared safe JSON object parsing helpers from `packages/schemas`.

### `parse_csv`

`parse_csv` parses bounded UTF-8 CSV text into table rows and inferred records.

It reports:

```text
artifact identity
delimiter
quote character
line ending
UTF-8 BOM presence
row count
data row count
column count
header inference result
headers
rows
records
irregular rows
warnings
```

It preserves values as strings. It does not evaluate formulas, infer data types, execute content, make network calls, persist input, or run external binaries.

It supports common CSV behavior:

```text
comma delimiter
double quote quoting
escaped quotes as ""
LF, CRLF, and CR line endings
trailing final newline
UTF-8 BOM stripping with presence reporting
```

It rejects malformed quoted fields and excessively large cells/column counts according to implementation limits.

### `parse_yaml`

`parse_yaml` parses bounded UTF-8 YAML text into JSON-compatible values.

It reports:

```text
artifact identity
document count
top-level value type
top-level keys for object documents
primary value
documents
document summaries
warnings
```

It supports multi-document YAML and standard JSON-compatible scalar/object/array structures.

It rejects malformed YAML and unsupported/custom tags. It does not perform includes, remote retrieval, code execution, persistence, or external binary execution.

### `parse_browser_extension_manifest`

`parse_browser_extension_manifest` parses bounded UTF-8 browser extension manifest JSON into normalized observed metadata without installing extensions, executing extension code, performing browser-store lookups, scoring risk, or generating findings.

It reports:

```text
artifact identity
manifest_version/name/version fields
description presence
permissions
optional_permissions
host_permissions
optional_host_permissions
content_scripts metadata
background shape
externally_connectable matches
web_accessible_resources metadata
content_security_policy presence
oauth2 presence
update_url presence
icons presence
action presence
warnings for malformed optional field shapes
```

It rejects:

```text
invalid JSON
arrays
null
non-object manifests
```

It preserves observations only. Permission risk review belongs in reviewer/scoring stages.

## Non-goals

This plugin must not:

```text
perform network lookups
score risk
generate findings
call external services
persist artifacts
execute artifact content
extract archives
shell out to external parsers
load plugins dynamically
```

Examples of behavior that belongs elsewhere:

| Behavior | Destination |
|---|---|
| JWT weakness review | `core-reviewers` / `core-scoring` |
| Browser extension permission risk | `core-reviewers` / `core-scoring` |
| Package registry lookup | `core-enrichment` |
| CVE/OSV/GHSA lookup | `core-enrichment` |
| Finding generation | `core-output` |
| Markdown/JSON export | `core-output` |
| Pipeline orchestration | `workflow-pack-basic` or `pipelines/` |

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

File input is handled by the CLI/API/UI boundary. Parser skills still receive a bounded string and do not receive filesystem permissions.

## Exposure policy

`packages/schemas` supports optional skill exposure metadata. Exposure metadata is separate from runtime permissions.

```text
permissions = what a skill can do
exposure    = where a skill should be reachable
```

The implemented `core-parsers` skills declare exposure metadata suitable for future adapter enforcement:

```text
surfaces: cli, api, web, mcp
default_exposure: enabled
hosted_default: allowlist_only
requires_authentication: true
rate_limit_recommended: true
audit_required: true
risk: low
```

Current hosted input caps are intentionally smaller than the runtime maximum and are declared per skill.

This does not expose MCP/API/web today. It records the policy contract future adapters should enforce.

## Security requirements

### Input handling

Parser skills must treat all input as hostile.

Required controls:

```text
runtime input-size limit before parsing
schema/type checks before parsing
structured parse errors
no eval
no dynamic import from input
no archive extraction in v0
no path reads from artifact content
bounded recursion/depth where relevant
malformed fixture tests
```

### JSON parsing

For JSON artifacts:

```text
accept UTF-8 string input
JSON.parse only
reject invalid JSON clearly
reject arrays when object is required
reject null
reject unsupported versions where relevant
preserve unknown fields only when useful and bounded
```

### CSV parsing

For CSV artifacts:

```text
accept UTF-8 string input
strip and report UTF-8 BOM
preserve cell values as strings
preserve row/column observations
report irregular rows
reject malformed quoted fields
do not evaluate formulas
do not coerce types
```

### YAML parsing

For YAML artifacts:

```text
accept UTF-8 string input
parse to JSON-compatible values
support multi-document inputs
reject malformed YAML
reject unsupported/custom tags
do not resolve file includes
do not retrieve remote content
```

### Evidence preservation

Parser skills should preserve observed fields as evidence-ready data.

Bad parser output:

```json
{
  "risk": "high"
}
```

Better parser output:

```json
{
  "artifact": {
    "type": "browser_extension_manifest",
    "manifest_version": 3,
    "name": "Example"
  },
  "observed": {
    "host_permissions": ["<all_urls>"]
  },
  "warnings": []
}
```

Risk belongs to reviewer/scoring stages.

### Redaction

Parser skills must avoid emitting obvious secrets where possible.

Examples:

```text
authorization headers
cookies
JWT signatures
private keys
tokens in URLs
embedded credentials
```

If a sensitive field must be represented, prefer:

```text
presence flag
hash
length
algorithm
claim names
redacted preview
```

## Fixture examples

Fixture files live at repo root under `fixtures/` and contain fake, non-sensitive data.

Run examples from the repository root so `$PWD` expands to an absolute repo path before `pnpm --filter` changes package context.

```bash
pnpm --filter @security-workbench/cli start skills run parse_http_headers --input-file "$PWD/fixtures/http-headers/security-headers.txt" --format pretty
pnpm --filter @security-workbench/cli start skills run parse_dockerfile --input-file "$PWD/fixtures/dockerfile/multi-stage.Dockerfile" --format pretty
pnpm --filter @security-workbench/cli start skills run parse_github_actions_workflow --input-file "$PWD/fixtures/github-actions/basic-workflow.yml" --format pretty
pnpm --filter @security-workbench/cli start skills run parse_trufflehog_ndjson --input-file "$PWD/fixtures/trufflehog/git-results.ndjson" --format pretty
pnpm --filter @security-workbench/cli start skills run parse_sarif --input-file "$PWD/fixtures/sarif/codeql-results.sarif" --format pretty
pnpm --filter @security-workbench/cli start skills run parse_package_json --input-file "$PWD/fixtures/package-json/basic-package.json" --format pretty
pnpm --filter @security-workbench/cli start skills run parse_browser_extension_manifest --input-file "$PWD/fixtures/browser-extension/manifest-v3-basic.json" --format pretty
pnpm --filter @security-workbench/cli start skills run parse_csv --input-file "$PWD/fixtures/csv/assets.csv" --format pretty
pnpm --filter @security-workbench/cli start skills run parse_csv --input-file "$PWD/fixtures/csv/irregular-rows.csv" --format pretty
pnpm --filter @security-workbench/cli start skills run parse_yaml --input-file "$PWD/fixtures/yaml/app-config.yaml" --format pretty
pnpm --filter @security-workbench/cli start skills run parse_yaml --input-file "$PWD/fixtures/yaml/multi-document.yaml" --format pretty
```

## Parser examples

### `parse_http_headers`

```bash
pnpm --filter @security-workbench/cli start skills run parse_http_headers \
  --input-file "$PWD/fixtures/http-headers/security-headers.txt" \
  --format pretty
```

Expected behavior:

```text
normalize response/header fields
report status line metadata when present
count headers and duplicate header names
report common response header field presence
return warnings for malformed or folded lines
do not perform network requests
do not score risk
```

### `parse_dockerfile`

```bash
pnpm --filter @security-workbench/cli start skills run parse_dockerfile \
  --input-file "$PWD/fixtures/dockerfile/multi-stage.Dockerfile" \
  --format pretty
```

Expected behavior:

```text
normalize Dockerfile instructions
report build stages and base image references
preserve COPY and ADD source/destination observations
report ENV and ARG keys
redact sensitive-looking ENV and ARG values
report command form counts
return warnings for malformed or unmodeled instructions
do not build images
do not pull images
do not perform registry lookups
do not execute Dockerfile instructions
do not score risk
```


### `parse_github_actions_workflow`

```bash
pnpm --filter @security-workbench/cli start skills run parse_github_actions_workflow \
  --input-file "$PWD/fixtures/github-actions/basic-workflow.yml" \
  --format pretty
```

Expected behavior:

```text
parse GitHub Actions workflow YAML
report trigger event inventory
report top-level and job-level permissions blocks
report job and step counts
report action uses and checkout observations
report reusable workflow references
report matrix, container, services, environment, defaults, concurrency, and timeout presence
report referenced contexts and secret names
redact raw run command content
return warnings for malformed or unmodeled structures
do not contact GitHub
do not resolve action references
do not execute workflow commands
do not score risk
```

### `parse_trufflehog_ndjson`

```bash
pnpm --filter @security-workbench/cli start skills run parse_trufflehog_ndjson \
  --input-file "$PWD/fixtures/trufflehog/git-results.ndjson" \
  --format pretty
```

Expected behavior:

```text
parse TruffleHog NDJSON scanner output
parse valid result lines while warning on malformed lines
report detector, decoder, source, and verification inventories
report source metadata keys, repositories, files, and file:line references
report raw secret presence, length, and SHA-256 hash metadata
preserve scanner-redacted values or generated redaction markers
do not emit raw Raw or RawV2 secret values
do not contact external services
do not score risk
```


### `parse_sarif`

```bash
pnpm --filter @security-workbench/cli start skills run parse_sarif \
  --input-file "$PWD/fixtures/sarif/codeql-results.sarif" \
  --format pretty
```

Expected behavior:

```text
parse SARIF JSON scanner output
report runs, tool drivers, rules, results, and locations
report result levels, baseline states, suppressions, fixes, fingerprints, tags, and taxa IDs
return warnings for malformed or unmodeled structures
do not contact external services
do not fetch source files
do not apply fixes
do not decide whether scanner results are true positives
do not score risk
```

### `parse_package_json`

```bash
pnpm --filter @security-workbench/cli start skills run parse_package_json \
  --input-file "$PWD/fixtures/package-json/basic-package.json" \
  --format pretty
```

Expected behavior:

```text
normalize package name and version
summarize scripts and dependency sections
preserve observed metadata
return warnings for malformed optional fields
do not install packages
do not execute scripts
do not perform registry lookups
do not score risk
```

### `parse_csv`

```bash
pnpm --filter @security-workbench/cli start skills run parse_csv \
  --input-file "$PWD/fixtures/csv/assets.csv" \
  --format pretty
```

Expected behavior:

```text
return rows
infer records when a header is detected
report irregular rows when present
keep values as strings
do not evaluate formulas
do not coerce types
```

### `parse_yaml`

```bash
pnpm --filter @security-workbench/cli start skills run parse_yaml \
  --input-file "$PWD/fixtures/yaml/app-config.yaml" \
  --format pretty
```

Expected behavior:

```text
return JSON-compatible values
report document count
summarize documents
reject unsupported/custom tags
do not resolve includes
do not retrieve remote content
```

### Bootstrap parser: `parse_url`

Currently implemented in `core-utilities`:

```bash
pnpm --filter @security-workbench/cli start skills run parse_url \
  --input "https://user:pass@example.com/path?x=1"
```

Expected behavior: one URL per run. Multiline URL lists are not supported yet.

### Bootstrap parser: `parse_jwt`

Currently implemented in `core-utilities`:

```bash
pnpm --filter @security-workbench/cli start skills run parse_jwt \
  --input-file "$PWD/fixtures/jwt/alg-none.jwt" \
  --format pretty
```

Expected behavior:

```text
decode header and payload
report signature presence/length
report signature_verified=false
do not expose the raw signature segment
do not perform key lookup or signature verification
```

### Bootstrap parser: `parse_email_headers`

Currently implemented in `core-utilities`:

```bash
pnpm --filter @security-workbench/cli start skills run parse_email_headers \
  --input-file "$PWD/fixtures/email/auth-results-headers.txt" \
  --format pretty
```

Expected behavior:

```text
preserve normalized header fields
preserve repeated header order where relevant
handle folded continuation lines
perform no DNS, SPF, DKIM, DMARC, or reputation lookups
```

### `parse_browser_extension_manifest`

```bash
pnpm --filter @security-workbench/cli start skills run parse_browser_extension_manifest \
  --input-file "$PWD/fixtures/browser-extension/manifest-v3-basic.json" \
  --format pretty
```

Expected behavior:

```text
normalize manifest identity and version fields
preserve permission and host permission observations
summarize content scripts, background, externally connectable, and web accessible resources
return warnings for malformed optional fields
do not score permission risk
do not generate findings
do not perform browser-store lookups
do not install or execute extension code
```

## Current package shape

```text
plugins/core-parsers/
├── src/
│   ├── index.ts
│   ├── localOnlyPermissions.ts
│   ├── parseBrowserExtensionManifest.ts
│   ├── parseCsv.ts
│   ├── parseDockerfile.ts
│   ├── parseGithubActionsWorkflow.ts
│   ├── parseHttpHeaders.ts
│   ├── parsePackageJson.ts
│   ├── parseSarif.ts
│   ├── parseTrufflehogNdjson.ts
│   └── parseYaml.ts
├── tests/
│   ├── parseBrowserExtensionManifest.test.ts
│   ├── parseCsv.test.ts
│   ├── parseDockerfile.test.ts
│   ├── parseGithubActionsWorkflow.test.ts
│   ├── parseHttpHeaders.test.ts
│   ├── parsePackageJson.test.ts
│   ├── parseSarif.test.ts
│   ├── parseTrufflehogNdjson.test.ts
│   └── parseYaml.test.ts
├── package.json
├── tsconfig.json
├── tsconfig.test.json
└── vitest.config.ts
```

Planned future parser modules may add:

```text
parsePemCertificate.ts
```

## Policy behavior

Expected runtime policy behavior:

```text
allow_network=false      allowed
allow_network=true       allowed, but still no network use
persist_inputs=false     allowed
redact_secrets=true      default
```

Expected run metadata:

```json
{
  "policy": {
    "allow_network": false,
    "network_used": false,
    "external_sinks": []
  }
}
```

## Test coverage

Current tests live in:

```text
plugins/core-parsers/tests/
```

Current test themes:

```text
skill export and registration
common package metadata normalization
absent optional sections
bundled dependency arrays
malformed optional field warnings
invalid JSON rejection
array/null rejection
CSV quoting and escaped quote behavior
CSV header inference
CSV irregular row warnings
YAML scalar/object/array parsing
YAML multi-document parsing
YAML malformed input rejection
YAML unsupported/custom tag rejection
browser extension manifest normalization
browser extension manifest malformed optional field warnings
browser extension manifest invalid JSON/object rejection
Dockerfile stage and base-image observation
Dockerfile line-continuation handling
Dockerfile sensitive-looking ENV/ARG value redaction
Dockerfile malformed and unmodeled instruction warnings
HTTP header response preamble, duplicate header, folded-line, and malformed-line behavior
GitHub Actions trigger, permission, job, step, action-use, context, and secret-name observations
GitHub Actions raw run command redaction
TruffleHog NDJSON detector, source, verification, metadata, and malformed-line observations
TruffleHog raw secret non-exposure and redacted metadata behavior
SARIF run, rule, result, location, fingerprint, suppression, fix, taxonomy, and malformed-shape observations
local-only permission declarations
```

Run:

```bash
pnpm --filter @security-workbench/core-parsers test
pnpm --filter @security-workbench/core-parsers typecheck:test
```

Full gate:

```bash
pnpm build
pnpm test
pnpm typecheck:test
```

## Current limitations

The parser plugin does not currently support:

```text
archive extraction
remote retrieval
registry lookup
source code inspection
JavaScript execution
permission scoring
risk classification
finding generation
PEM certificate parsing
```

Those can be added later through explicit parser/reviewer/enrichment boundaries.

## Done criteria

This plugin remains acceptable when:

```text
package builds
plugin package tests pass
test typechecking passes
skills are registered through plugin index
all skills are local-only
all skills declare permissions
hosted/API/MCP exposure intent is explicit where reviewed
malformed inputs fail safely
outputs are structured
outputs preserve observations
outputs do not overstate risk
fixture examples remain fake and runnable from the repo root
```

<!-- browser-extension-common-variants -->
### Browser extension manifest coverage

`parse_browser_extension_manifest` parses common WebExtensions-style manifest files across Manifest V2 and Manifest V3. The parser records common Chromium, Firefox/Gecko, and Safari-compatible fields as observations, including background model, action surfaces, content scripts, host permission sources, browser-specific settings, declarative net request metadata, web-accessible resource format, and unknown top-level keys.

The parser does not score risk, validate extension store compatibility, install packages, run extension code, or perform network lookups. Risk interpretation belongs in reviewer/scoring plugins.
<!-- /browser-extension-common-variants -->


---

## Role in the plugin system

`core-parsers` owns richer artifact and document parsers that many domain plugins can reuse.

A parser should preserve structure and observations. Domain review belongs in reviewer plugins or workflow packs.

Examples:

| Parser | Downstream plugin/workflow |
|---|---|
| `parse_package_json` | `plugin-packages`, `package_review` |
| `parse_csv` | SaaS export review, IAM export review, scanner normalization helpers |
| `parse_yaml` | `plugin-cloudformation`, `plugin-kubernetes`, `plugin-terraform`, detection rules |
| `parse_browser_extension_manifest` | `plugin-browser-extension`, `browser_extension_review` |
| `parse_dockerfile` | `plugin-container`, `container_build_review` |
| `parse_github_actions_workflow` | `plugin-ci`, `ci_workflow_review` |
| `parse_trufflehog_ndjson` | scanner normalization, secret-scanner review |
| `parse_sarif` | scanner normalization, code scanning review, CI security summaries |

Design rule:

```text
Parsers observe.
Reviewers interpret.
Scorers prioritize.
Findings publish.
```

Do not expand parser behavior into risk review just to make a workflow look complete. Add a reviewer skill instead.
