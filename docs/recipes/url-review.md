# URL review recipe

Review defanged or messy URL indicators for observed URL structure using the current local CLI skill chain.

This recipe documents the manual chain. There is no registered `url_review` workflow yet.

## Goal

Turn a mixed indicator artifact into evidence-backed URL structure observations through deterministic local steps:

```text
normalize_indicators
  -> extract_defanged_urls
  -> review_url
```

## Input

A pasted or file-based text artifact containing URL candidates, including defanged forms.

Example fixture:

```text
fixtures/iocs/defanged-indicators.txt
```

## Run the manual skill chain

Build the CLI once and capture the repo root for stable paths:

```bash
pnpm --filter @security-workbench/cli build
REPO_ROOT="$(pwd)"
```

The chained JSON steps below run the built CLI directly so redirected files contain only JSON output.

### 1. Normalize candidate indicators

```bash
(cd apps/cli && node dist/main.js skills run normalize_indicators   --input-file "$REPO_ROOT/fixtures/iocs/defanged-indicators.txt")   > /tmp/security-workbench-url.indicators.json
```

### 2. Extract defanged URL candidates

```bash
(cd apps/cli && node dist/main.js skills run extract_defanged_urls   --input-file /tmp/security-workbench-url.indicators.json)   > /tmp/security-workbench-url.extracted.json
```

### 3. Review URL structure

```bash
(cd apps/cli && node dist/main.js skills run review_url   --input-file /tmp/security-workbench-url.extracted.json   --format pretty)
```

## Expected output

The final command should print a URL review object that includes:

```text
source parser
reviewed URL count
plain HTTP observations
userinfo observations
IP-literal host observations
non-default port observations
punycode host observations
query, fragment, and redirect-like parameter observations
signals
evidence
limitations
```

## What this recipe observes

This recipe can surface URL-structure signals such as:

```text
plain HTTP
userinfo in URL authority
IP-literal host
non-default port
punycode host
long hostname or URL
many subdomain labels
query parameters
fragment
redirect-like parameter names
script or executable-like file extension
```

## What this recipe does not do

This recipe intentionally does not:

```text
perform DNS lookup
fetch URLs
follow redirects
perform reputation checks
inspect landing-page content
perform typosquat or brand-impersonation analysis
classify a URL as phishing, spam, malicious, benign, safe, or unsafe
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
