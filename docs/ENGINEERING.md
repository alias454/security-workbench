# Engineering Context

This is the primary implementation handoff document for future work.

## Current implementation

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
```

Current interface:

```text
CLI only
```

Current capability:

```text
single-skill registry and runner
runtime policy enforcement
input size enforcement
redaction helpers
safe bounded CLI --input-file handling
CLI skills list / describe / run
JSON, table, TSV, and pretty output where supported
fixture-backed smoke coverage
source audit in full smoke script
```

Current skill inventory is canonical in:

```text
docs/plugins/README.md
docs/plugins/core-utilities.md
docs/plugins/core-parsers.md
docs/plugins/core-reviewers.md
docs/plugins/core-scoring.md
docs/plugins/core-output.md
```

Avoid duplicating volatile skill counts outside plugin docs unless needed for a release note.

## Repo layout

```text
packages/schemas   shared contracts and safe JSON parse helpers
packages/core      runtime, registry, policy, input limits, redaction, runner
plugins/*          skill implementations, tests, and plugin docs
apps/cli           argument parsing, input acquisition, runtime call, formatting
fixtures/          fake shared inputs for docs, smoke tests, and demos
docs/              engineering, roadmap, security model, fixtures, plugin docs
```

The CLI must remain a thin adapter. Analysis logic belongs in plugins.

## Core flow

Target model:

```text
Artifact → Skill → Signal → Evidence → Risk Score → Finding / Export
```

The same analysis path should be reused by the CLI, future workflow runner, REST API, local web UI, and MCP adapters. Adapters acquire input and render output; skills and workflows own analysis behavior.

Current implementation covers local transform, parser, initial reviewer, initial scoring, and initial output skills. Generic export plugins, workflow runner, web/API/MCP adapters, persistence, and enrichment are future work.

Design rule:

```text
Parsers observe.
Reviewers interpret.
Scorers prioritize.
Findings publish.
```

## Runtime policy

Default policy:

```yaml
allow_network: false
persist_inputs: false
redact_secrets: true
max_artifact_size_mb: 10
approved_sinks: []
```

Implemented skills are local-only. Network-capable, filesystem-capable, persistent, provider-backed, or external-binary skills must be added explicitly and gated by policy.

## CLI input model

```text
--input       passes one string to the runtime
--input-file  CLI reads one bounded UTF-8 file, then passes one string to the runtime
```

`--input-file` is adapter input acquisition. It does not grant plugin filesystem permission.

Current file controls:

```text
reject both --input and --input-file together
reject neither
stat before read
reject directories
enforce max size before and after read
valid UTF-8 only
no globbing
no recursive reads
no archive extraction
```

## Skill categories

Current:

```text
transform
parser
reviewer
scoring
output
```

Planned:

```text
enrichment
```

## Plugin model

Current:

```text
official plugins wired directly by CLI
manifest loader not implemented
plugin install/search/update not implemented
third-party plugin execution not enabled
```

Plugin ownership rules:

```text
core-utilities: small deterministic transforms and lightweight parser-category utilities
core-parsers: richer local artifact/document parsers
reviewer plugins: evidence-backed interpretation
scoring plugins: prioritization
output plugins: export/finding generation
enrichment plugins: explicit external disclosure or local registry lookup
```

Plugin installation is a trust decision. Manifest metadata is not a sandbox.

## Pipeline direction

The current workflow runner supports narrow registered workflows. Workflow definitions are validated at registration for required fields, duplicate step IDs, known skill names, and `input_from` references. General pipeline/DAG execution is not implemented.

Pipeline classes:

```text
transform recipe: clean, decode, extract, normalize, export
review pipeline: parse, preserve evidence, review, score, finding/export
enrichment pipeline: parse, approve disclosure, enrich, review, score, export
```

Start with narrow registered workflows before general DAG support. Candidate workflows and implementation order are tracked in `docs/ROADMAP.md`.

## Future adapters

Planned later:

```text
REST API
web UI
MCP server
```

All future adapters must use the same runtime path and fail closed on missing or unreviewed exposure metadata. Expose workflow-level tools before broad raw-skill exposure. MCP should wrap stable workflows first and should not become a separate analysis engine.

## Validation commands

```bash
pnpm build
pnpm test
pnpm typecheck:test
./security-workbench-full-smoke.sh
```

For targeted work:

```bash
pnpm --filter @security-workbench/core-parsers test
pnpm --filter @security-workbench/core-parsers typecheck:test
pnpm --filter @security-workbench/core-utilities test
pnpm --filter @security-workbench/cli test
```

## Engineering rules

```text
keep core small
keep skills deterministic unless explicitly declared otherwise
keep parser output free of risk claims
preserve observed vs inferred separation
redact obvious secrets by default
add malformed-input tests for parsers
update owning plugin docs when skill behavior changes
update roadmap when implementation priority changes
move completed roadmap detail into README/plugin docs instead of leaving stale task lists
run the full gate before release or public push
```
