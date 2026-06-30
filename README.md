# Security Workbench

Security Workbench is a CLI workbench for repeatable security artifact tasks: parse, transform, normalize, review, and export.

The current build is intentionally local and deterministic. Routine artifacts such as encoded blobs, URLs, headers, JSON, CSV, YAML, Dockerfiles, GitHub Actions workflows, scanner outputs, JWTs, and manifests should be parsed and normalized before deciding whether AI or external enrichment is needed.

```text
artifact or text blob
  → parse / transform
  → extract useful structure
  → review supported signals
  → score review attention
  → generate draft finding output
```

## Current status

Implemented:

```text
TypeScript monorepo
pnpm workspace
packages/schemas
packages/core
plugins/core-utilities
plugins/core-parsers
plugins/core-reviewers
plugins/core-scoring
plugins/core-output
apps/cli
single-skill registry and runner
runtime policy enforcement
safe bounded --input-file handling
runtime redaction helpers
fixture-backed smoke script
```

Current interface:

```text
CLI only
```

Not implemented yet:

```text
plugin manifest loader
plugin install commands
workflow runner
generic output/export plugins
external enrichment
REST API
web UI
MCP server
local persistence
```

## Install

```bash
pnpm install
```

## Common commands

```bash
pnpm --filter @security-workbench/cli start skills list
pnpm --filter @security-workbench/cli start skills describe parse_sarif
pnpm --filter @security-workbench/cli start skills run json_parse --input '{"ok":true}'
```

Fixture examples use `$PWD` from the repo root:

```bash
pnpm --filter @security-workbench/cli start skills run parse_sarif --input-file "$PWD/fixtures/sarif/codeql-results.sarif" --format pretty
pnpm --filter @security-workbench/cli start skills run parse_trufflehog_ndjson --input-file "$PWD/fixtures/trufflehog/git-results.ndjson" --format pretty
pnpm --filter @security-workbench/cli start skills run parse_browser_extension_manifest --input-file "$PWD/fixtures/browser-extension/manifest-v3-basic.json" --format pretty
```

## Validation

```bash
pnpm build
pnpm test
pnpm typecheck:test
./security-workbench-full-smoke.sh
```

## Documentation

```text
docs/ENGINEERING.md          runtime, repo layout, implementation rules
docs/ROADMAP.md              current backlog and implementation order
docs/SECURITY_MODEL.md       trust boundaries, privacy, exposure, output safety
docs/FIXTURES.md             fixture policy and inventory
docs/plugins/README.md       plugin and skill inventory
docs/plugins/*.md            per-plugin behavior and limits
```

## Security posture

Default posture:

```text
network disabled unless explicitly enabled
persistence disabled unless explicitly enabled
redaction enabled by default
external binaries denied by default
plugin-owned filesystem access denied by default
API/web/MCP exposure not implemented
```

Local means control-owned: artifacts stay inside the user's security boundary until external analysis is explicitly justified.
