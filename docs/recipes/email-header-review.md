# Email header review recipe

Review email headers for observed routing, authentication-result, and identity-mismatch metadata using the current local CLI skill chain.

This recipe documents the manual chain. There is no registered `email_header_review` workflow yet.

## Goal

Turn email header text into evidence-backed header review signals through deterministic local steps:

```text
parse_email_headers
  -> review_email_header
```

## Input

An email header block copied from a message or saved as a text file.

Example fixture:

```text
fixtures/email/auth-results-headers.txt
```

## Run the manual skill chain

Build the CLI once and capture the repo root for stable paths:

```bash
pnpm --filter @security-workbench/cli build
REPO_ROOT="$(pwd)"
```

The chained JSON steps below run the built CLI directly so redirected files contain only JSON output.

### 1. Parse email headers

```bash
(cd apps/cli && node dist/main.js skills run parse_email_headers   --input-file "$REPO_ROOT/fixtures/email/auth-results-headers.txt")   > /tmp/security-workbench-email-headers.parsed.json
```

### 2. Review email header observations

```bash
(cd apps/cli && node dist/main.js skills run review_email_header   --input-file /tmp/security-workbench-email-headers.parsed.json   --format pretty)
```

## Expected output

The final command should print an email header review object that includes:

```text
source parser
header count
duplicate header observations
Received header count
Authentication-Results observations
From/To/Subject/Date/Message-ID presence
Reply-To, Return-Path, and Sender domain observations
signals
evidence
limitations
```

## What this recipe observes

This recipe can surface header-derived signals such as:

```text
duplicate header names
missing Authentication-Results
failed or error authentication-result text
missing Received chain
missing Message-ID
missing Date
Reply-To and From domain mismatch
Return-Path and From domain mismatch
Sender and From domain mismatch
```

## What this recipe does not do

This recipe intentionally does not:

```text
perform DNS lookup
validate SPF, DKIM, DMARC, ARC, or BIMI
perform reputation checks
inspect message body, attachments, links, or landing pages
classify a message as phishing, spam, malicious, benign, delivered, or blocked
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
