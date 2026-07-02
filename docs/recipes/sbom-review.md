# SBOM review recipe

Review a CycloneDX or SPDX SBOM for observed inventory quality using the current local CLI workflow.

This recipe documents the registered `sbom_review` workflow and the equivalent manual skill chain.

## Goal

Turn an SBOM into evidence-backed inventory-quality review signals through deterministic local steps:

```text
parse_sbom
  -> review_sbom
```

## Input

A CycloneDX JSON or SPDX JSON SBOM.

Example fixtures:

```text
fixtures/sbom/cyclonedx.json
fixtures/sbom/spdx.json
```

## Run the registered workflow

Run from the repo root:

```bash
pnpm --filter @security-workbench/cli start workflows run sbom_review \
  --input-file "$PWD/fixtures/sbom/cyclonedx.json" \
  --format pretty
```

## Run the manual skill chain

Use the manual chain when debugging intermediate parser or reviewer behavior.

Build the CLI once and capture the repo root for stable paths:

```bash
pnpm --filter @security-workbench/cli build
REPO_ROOT="$(pwd)"
```

The chained JSON steps below run the built CLI directly so redirected files contain only JSON output.

### 1. Parse the SBOM

```bash
(cd apps/cli && node dist/main.js skills run parse_sbom \
  --input-file "$REPO_ROOT/fixtures/sbom/cyclonedx.json") \
  > /tmp/security-workbench-sbom.parsed.json
```

### 2. Review SBOM inventory quality

```bash
(cd apps/cli && node dist/main.js skills run review_sbom \
  --input-file /tmp/security-workbench-sbom.parsed.json \
  --format pretty)
```

## Expected output

The final command should print an SBOM review object that includes:

```text
source parser
SBOM format and spec version
reviewed component count
package and service counts
dependency and relationship counts
identifier and external reference counts
signals
evidence
limitations
```

## What this recipe observes

This recipe can surface SBOM inventory-quality signals such as:

```text
no components observed
component version not observed
component license not observed
component supplier not observed
unresolved download location observed
external references observed
```

## What this recipe does not do

This recipe intentionally does not:

```text
perform vulnerability lookup
query OSV, GHSA, NVD, EPSS, or CISA KEV
perform package reputation lookup
validate maintainer trust
validate provenance or signatures
claim exploitability
claim dependency reachability
score risk
generate findings
persist results
send data externally
```

## Security posture

All skills in this recipe are local-only:

```text
Network: none
Persistence: none
External binaries: none
```

File reading occurs only at the CLI `--input-file` acquisition boundary. Plugin skills receive bounded text or JSON input from the runtime.
