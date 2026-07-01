# Browser extension review recipe

Review a browser extension manifest for permission and browser-surface risk using the current local CLI skill chain.

This recipe is the current manual form of the future `browser_extension_review` workflow.

## Goal

Turn a browser extension manifest into a draft finding through deterministic local steps:

```text
parse_browser_extension_manifest
  -> review_browser_extension_permissions
  -> score_browser_extension_risk
  -> generate_browser_extension_finding
```

## Input

A WebExtensions-style `manifest.json` file.

Example fixture:

```text
fixtures/browser-extension/manifest-v2-broad-hosts.json
```

## Run the recipe

Run from the repo root.

Build the CLI once and capture the repo root for stable paths:

```bash
pnpm --filter @security-workbench/cli build
REPO_ROOT="$(pwd)"
```

The chained JSON steps below run the built CLI directly so redirected files contain only JSON output.

### 1. Parse the manifest

```bash
(cd apps/cli && node dist/main.js skills run parse_browser_extension_manifest \
  --input-file "$REPO_ROOT/fixtures/browser-extension/manifest-v2-broad-hosts.json") \
  > /tmp/security-workbench-browser-extension.parsed.json
```

### 2. Review permission surfaces

```bash
(cd apps/cli && node dist/main.js skills run review_browser_extension_permissions \
  --input-file /tmp/security-workbench-browser-extension.parsed.json) \
  > /tmp/security-workbench-browser-extension.review.json
```

### 3. Score review attention

```bash
(cd apps/cli && node dist/main.js skills run score_browser_extension_risk \
  --input-file /tmp/security-workbench-browser-extension.review.json) \
  > /tmp/security-workbench-browser-extension.score.json
```

### 4. Generate draft finding output

```bash
(cd apps/cli && node dist/main.js skills run generate_browser_extension_finding \
  --input-file /tmp/security-workbench-browser-extension.score.json \
  --format pretty)
```

## Expected output

The final command should print a draft finding summary that includes:

```text
artifact identity
finding id
score
review attention
risk level
confidence
observed behavior
inferred risk
recommended review actions
open questions
limitations
```

The exact score depends on the input manifest.

For the broad-host fixture, the output should indicate high review attention because the fixture includes broad host access and other permission surfaces.

## What this recipe observes

This recipe can surface manifest-derived signals such as:

```text
broad host permissions
<all_urls>
notable API permissions
broad content script matches
background context
externally_connectable
web_accessible_resources
update_url
oauth2
content_security_policy observations
```

## What this recipe does not do

This recipe intentionally does not:

```text
install the extension
execute extension code
inspect extension source files beyond the manifest
contact browser stores
resolve update URLs
perform publisher reputation lookup
perform host or domain reputation lookup
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

## Troubleshooting

If a later step fails, inspect the previous output file first:
