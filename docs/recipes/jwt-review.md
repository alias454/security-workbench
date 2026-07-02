# JWT review recipe

Review a JWT for observed header, claim, and signature metadata using the current local CLI workflow.

This recipe documents the registered `jwt_review` workflow and the equivalent manual skill chain.

## Goal

Turn a JWT into evidence-backed review signals through deterministic local steps:

```text
parse_jwt
  -> review_jwt
```

## Input

A JWT string, either inline or in a text file.

Example fixture:

```text
fixtures/jwt/alg-none.jwt
```

## Run the registered workflow

Run from the repo root:

```bash
pnpm --filter @security-workbench/cli start workflows run jwt_review \
  --input-file "$PWD/fixtures/jwt/alg-none.jwt" \
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

### 1. Parse the JWT

```bash
(cd apps/cli && node dist/main.js skills run parse_jwt \
  --input-file "$REPO_ROOT/fixtures/jwt/alg-none.jwt") \
  > /tmp/security-workbench-jwt.parsed.json
```

### 2. Review JWT metadata

```bash
(cd apps/cli && node dist/main.js skills run review_jwt \
  --input-file /tmp/security-workbench-jwt.parsed.json \
  --format pretty)
```

## Expected output

The final command should print a JWT review object that includes:

```text
source parser
algorithm and type metadata
signature presence
observed header parameter names
observed claim names
registered claim coverage
temporal claim observations
signals
evidence
limitations
```

## What this recipe observes

This recipe can surface parsed-JWT signals such as:

```text
signature was not verified by the parser
unsecured alg=none observation
missing signature segment
missing expiration claim
long exp/iat validity window
inconsistent temporal claims
remote key-reference headers
embedded JWK header
critical header
sensitive-looking claim names without copying claim values
```

## What this recipe does not do

This recipe intentionally does not:

```text
verify JWT signatures
validate issuer
validate audience
fetch JWKS, JKU, X5U, or other key material
perform token introspection
classify current-time expiration status
copy raw sensitive claim values into evidence
contact external services
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
