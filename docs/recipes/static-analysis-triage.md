# Static-analysis triage recipe

Review SARIF scanner output for deterministic local triage using the current CLI workflow.

This recipe documents the registered `static_analysis_triage` workflow and the equivalent manual skill chain.

## Goal

Turn SARIF scanner output into a draft triage summary through deterministic local steps:

```text
parse_sarif
  -> review_static_analysis_results
  -> score_static_analysis_attention
  -> generate_static_analysis_triage_summary
```

## Input

A SARIF JSON file.

Example fixture:

```text
fixtures/sarif/codeql-results.sarif
```

## Run the registered workflow

Run from the repo root:

```bash
pnpm --filter @security-workbench/cli start workflows run static_analysis_triage \
  --input-file "$PWD/fixtures/sarif/codeql-results.sarif" \
  --format pretty
```

## Run the manual skill chain

Use the manual chain when debugging intermediate parser, reviewer, scorer, or output behavior.

Build the CLI once and capture the repo root for stable paths:

```bash
pnpm --filter @security-workbench/cli build
REPO_ROOT="$(pwd)"
```

The chained JSON steps below run the built CLI directly so redirected files contain only JSON output.

### 1. Parse SARIF

```bash
(cd apps/cli && node dist/main.js skills run parse_sarif \
  --input-file "$REPO_ROOT/fixtures/sarif/codeql-results.sarif") \
  > /tmp/security-workbench-static-analysis.parsed.json
```

### 2. Review static-analysis results

```bash
(cd apps/cli && node dist/main.js skills run review_static_analysis_results \
  --input-file /tmp/security-workbench-static-analysis.parsed.json) \
  > /tmp/security-workbench-static-analysis.review.json
```

### 3. Score review attention

```bash
(cd apps/cli && node dist/main.js skills run score_static_analysis_attention \
  --input-file /tmp/security-workbench-static-analysis.review.json) \
  > /tmp/security-workbench-static-analysis.score.json
```

### 4. Generate triage summary

```bash
(cd apps/cli && node dist/main.js skills run generate_static_analysis_triage_summary \
  --input-file /tmp/security-workbench-static-analysis.score.json \
  --format pretty)
```

## Expected output

The final command should print a draft triage summary that includes:

```text
source format
score
review attention
risk level
confidence
observed behavior
inferred risk
recommended triage actions
open questions
limitations
```

The exact score depends on the scanner output.

## What this recipe observes

This recipe can surface SARIF-derived signals such as:

```text
tool and run metadata
rules and result levels
result locations
baseline state
suppressions
fix availability
fingerprint metadata
```

## What this recipe does not do

This recipe intentionally does not:

```text
inspect source code files
run scanners
contact scanner services
perform CVE, EPSS, KEV, package, or repository enrichment
verify true-positive or false-positive status
claim exploitability
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
