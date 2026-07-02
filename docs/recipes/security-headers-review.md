# Security headers review recipe

Review HTTP response headers for observed security-header and cookie-attribute metadata using the current local CLI skill chain.

This recipe documents the manual chain. There is no registered `security_headers_review` workflow yet.

## Goal

Turn HTTP response/header text into evidence-backed security header observations through deterministic local steps:

```text
parse_http_headers
  -> review_security_headers
```

## Input

HTTP response headers copied from a response, proxy, scanner, or saved text artifact.

Example fixture:

```text
fixtures/http-headers/security-headers.txt
```

## Run the manual skill chain

Build the CLI once and capture the repo root for stable paths:

```bash
pnpm --filter @security-workbench/cli build
REPO_ROOT="$(pwd)"
```

The chained JSON steps below run the built CLI directly so redirected files contain only JSON output.

### 1. Parse HTTP headers

```bash
(cd apps/cli && node dist/main.js skills run parse_http_headers   --input-file "$REPO_ROOT/fixtures/http-headers/security-headers.txt")   > /tmp/security-workbench-security-headers.parsed.json
```

### 2. Review security header observations

```bash
(cd apps/cli && node dist/main.js skills run review_security_headers   --input-file /tmp/security-workbench-security-headers.parsed.json   --format pretty)
```

## Expected output

The final command should print a security headers review object that includes:

```text
source parser
status and header counts
duplicate header observations
Content-Security-Policy observations
Strict-Transport-Security observations
frame-protection observations
X-Content-Type-Options, Referrer-Policy, and Permissions-Policy presence
Set-Cookie Secure, HttpOnly, and SameSite observations
signals
evidence
limitations
```

## What this recipe observes

This recipe can surface header-derived signals such as:

```text
missing Content-Security-Policy
CSP unsafe-inline token observed
CSP wildcard source observed
missing or short Strict-Transport-Security max-age
missing includeSubDomains
missing frame protection
missing X-Content-Type-Options
missing Referrer-Policy
missing Permissions-Policy
missing cookie Secure, HttpOnly, or SameSite attributes
```

## What this recipe does not do

This recipe intentionally does not:

```text
perform HTTP requests
validate browser policy behavior
validate TLS, DNS, redirects, or live endpoint state
perform reputation checks
classify an endpoint as secure, insecure, exploitable, malicious, benign, compliant, or non-compliant
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
