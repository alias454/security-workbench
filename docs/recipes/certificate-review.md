# Certificate review recipe

Review a PEM certificate artifact for observed certificate metadata using the current local CLI workflow.

This recipe documents the registered `certificate_review` workflow and the equivalent manual skill chain.

## Goal

Turn a PEM certificate artifact into evidence-backed review signals through deterministic local steps:

```text
parse_pem_certificate
  -> review_certificate
```

## Input

A PEM-encoded certificate file.

Example fixture:

```text
fixtures/certificates/example-cert.pem
```

## Run the registered workflow

Run from the repo root:

```bash
pnpm --filter @security-workbench/cli start workflows run certificate_review \
  --input-file "$PWD/fixtures/certificates/example-cert.pem" \
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

### 1. Parse the PEM certificate

```bash
(cd apps/cli && node dist/main.js skills run parse_pem_certificate \
  --input-file "$REPO_ROOT/fixtures/certificates/example-cert.pem") \
  > /tmp/security-workbench-certificate.parsed.json
```

### 2. Review certificate metadata

```bash
(cd apps/cli && node dist/main.js skills run review_certificate \
  --input-file /tmp/security-workbench-certificate.parsed.json \
  --format pretty)
```

## Expected output

The final command should print a certificate review object that includes:

```text
source parser
reviewed certificate count
valid and invalid certificate counts
subjects and issuers
public key metadata
signals
evidence
limitations
```

## What this recipe observes

This recipe can surface parsed-certificate signals such as:

```text
CA certificate presence
self-issued certificate observation
missing observed subject alternative name
weak public key observation
long validity window observation
invalid PEM block observation
```

## What this recipe does not do

This recipe intentionally does not:

```text
validate certificate chains
perform hostname matching
check revocation
query certificate transparency logs
classify current-time expiration status
contact external services
claim trustworthiness
claim malicious or benign behavior
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
