# Package review recipe

Review parsed package manifest or lockfile artifacts for observed package metadata and inventory-quality signals.

This recipe documents the manual `review_package` skill chains. It is not a registered workflow yet because package review has two valid parser entry points.

## Goal

Turn a package manifest or lockfile into evidence-backed package review signals through deterministic local steps.

Manifest chain:

```text
parse_package_json
  -> review_package
```

Lockfile chain:

```text
parse_lockfiles
  -> review_package
```

## Input

Supported artifact examples:

```text
fixtures/package-json/basic-package.json
fixtures/lockfiles/package-lock.json
fixtures/lockfiles/pnpm-lock.yaml
fixtures/lockfiles/yarn.lock
```

## Run the package manifest chain

Build the CLI once and capture the repo root for stable paths:

```bash
pnpm --filter @security-workbench/cli build
REPO_ROOT="$(pwd)"
```

Parse `package.json`:

```bash
(cd apps/cli && node dist/main.js skills run parse_package_json \
  --input-file "$REPO_ROOT/fixtures/package-json/basic-package.json") \
  > /tmp/security-workbench-package.parsed.json
```

Review parsed package metadata:

```bash
(cd apps/cli && node dist/main.js skills run review_package \
  --input-file /tmp/security-workbench-package.parsed.json \
  --format pretty)
```

## Run the lockfile chain

Parse a lockfile:

```bash
(cd apps/cli && node dist/main.js skills run parse_lockfiles \
  --input-file "$REPO_ROOT/fixtures/lockfiles/package-lock.json") \
  > /tmp/security-workbench-lockfile.parsed.json
```

Review parsed lockfile inventory:

```bash
(cd apps/cli && node dist/main.js skills run review_package \
  --input-file /tmp/security-workbench-lockfile.parsed.json \
  --format pretty)
```

## Why this is not a registered workflow yet

`review_package` supports more than one parser output:

```text
parse_package_json output
parse_lockfiles output
```

A registered workflow should avoid ambiguous input routing. Future work can add explicit workflow variants such as:

```text
package_manifest_review
lockfile_review
```

or add safe workflow input routing after repeated need proves it is worth the extra abstraction.

## Expected output

The final command should print a package review object that includes:

```text
source parser
package or lockfile metadata
observed dependency sections
lockfile package inventory counts
signals
evidence
limitations
```

## What this recipe observes

This recipe can surface package metadata signals such as:

```text
missing observed license
missing observed repository
missing observed package manager
missing observed engines
lifecycle scripts observed
optional dependencies observed
bundled dependencies observed
empty lockfile inventory observed
lockfile package version not observed
lockfile dependency graph observed
root dev, optional, or peer dependencies observed
```

## What this recipe does not do

This recipe intentionally does not:

```text
install packages
execute lifecycle scripts
inspect package tarballs
query package registries
perform vulnerability lookup
perform package reputation lookup
validate maintainer trust
claim malicious or benign behavior
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
