# Package review recipe

Review parsed package manifest or lockfile artifacts for observed package metadata and inventory-quality signals.

This recipe documents two registered workflow variants because `review_package` has two valid parser entry points.

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

## Run the package manifest workflow

Build the CLI once and capture the repo root for stable paths:

```bash
pnpm --filter @security-workbench/cli build
REPO_ROOT="$(pwd)"
```

Run the explicit `package_manifest_review` workflow:

```bash
(cd apps/cli && node dist/main.js workflows run package_manifest_review \
  --input-file "$REPO_ROOT/fixtures/package-json/basic-package.json" \
  --format pretty)
```

## Run the lockfile workflow

Run the explicit `lockfile_review` workflow:

```bash
(cd apps/cli && node dist/main.js workflows run lockfile_review \
  --input-file "$REPO_ROOT/fixtures/lockfiles/package-lock.json" \
  --format pretty)
```

## Manual skill chains

Use the manual chain when inspecting intermediate parser output.

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

Parse and review a lockfile:

```bash
(cd apps/cli && node dist/main.js skills run parse_lockfiles \
  --input-file "$REPO_ROOT/fixtures/lockfiles/package-lock.json") \
  > /tmp/security-workbench-lockfile.parsed.json

(cd apps/cli && node dist/main.js skills run review_package \
  --input-file /tmp/security-workbench-lockfile.parsed.json \
  --format pretty)
```

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
