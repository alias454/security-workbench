# Contributing to Security Workbench

## Purpose

Security Workbench is intended to be community-driven while remaining secure by default. Contributors should be able to add skills, parsers, reviewers, pipelines, exporters, docs, and fixtures without changing the core runtime unnecessarily.

The project values:

```text
correctness
security
simplicity
maintainability
observability
practical usefulness
```

---

## Contribution types

You can contribute:

```text
skills
parsers
reviewers
pipelines
plugins
enrichment connectors
scoring models
export templates
UI panels
test fixtures
schemas
documentation
examples
security reviews
bug reports
research methodology
```

---

## Principles

### Do not overstate evidence

A suspicious signal is not proof. Inference must be labeled as inference.

### Preserve evidence

Findings should reference evidence records. Parsers should preserve observations.

### Respect local-first defaults

No hidden network calls. No hidden persistence.

### Keep code testable

Prefer small functions, typed inputs/outputs, fixtures, and clear failure cases.

### Prefer explicit behavior

Avoid magic config loading, hidden fallbacks, silent failures, or undeclared side effects.

### Keep the runtime small

Analysis behavior belongs in plugins. The runtime owns registration, execution, policy, redaction, and shared result handling.

---

## Adding a skill

A skill contribution should include:

```text
skill metadata
permission declaration
implementation
unit tests
malformed input tests
fixtures or examples when useful
README/docs update
```

Future skills may also require:

```text
input schema
output schema
golden output tests
exposure metadata
```

Required behavior:

```text
return structured data
do not print from skill logic
do not make undeclared network calls
do not persist artifacts directly
do not execute untrusted artifact content
fail clearly on malformed input
```

Recommended directory:

```text
plugins/<plugin-name>/src/<skill-name>.ts
```

---

## Adding a parser

Parser skills should:

```text
treat input as hostile
use reviewed parser dependencies only
apply bounded parsing behavior
return observations and warnings
avoid risk scoring
avoid findings
avoid network lookups
avoid filesystem access from artifact content
include malformed fixtures/tests
```

Risk review belongs in reviewer/scoring plugins, not parser primitives.

---

## Adding a pipeline

Pipeline support is not implemented yet.

When implemented, a pipeline contribution should include:

```text
pipeline definition
description
input type/schema
output type/schema
example input
example output
golden output test
policy behavior test
```

Pipelines should compose registered skills rather than hardcoding analysis behavior in adapters.

---

## Adding enrichment

External enrichment is not implemented yet.

A future enrichment connector must include:

```text
source name
source documentation
network permission declaration
data sent externally
timeout behavior
rate-limit behavior
cache behavior
failure behavior
tests with mocked responses
```

External lookups must be disabled by default unless runtime policy enables them.

---

## Fixtures and testdata

Security Workbench uses two related concepts.

### Shared fixtures

Top-level fixtures live under:

```text
fixtures/
```

Use these for:

```text
manual CLI examples
demos
smoke tests
docs examples
shared fake artifact samples
```

Fixture policy and inventory live in:

```text
docs/FIXTURES.md
fixtures/README.md
```

### Package-local testdata

Package-local testdata may be used for golden tests or internal test cases:

```text
plugins/<plugin>/testdata/
packages/<package>/testdata/
```

Golden output changes should be intentional and reviewed.

---

## Coding standards

General rules:

```text
small focused functions
typed inputs and outputs
minimal dependencies
clear errors
no silent failures
I/O separated from business logic
no hardcoded paths except test-local paths
```

Comments should explain why, not merely what.

Public modules, public functions, and plugin contracts should be documented.

---

## Testing requirements

Expected tests, as applicable:

```text
schema tests
unit tests
fixture tests
golden output tests
malformed input tests
network-disabled tests for enrichment skills
redaction tests for sensitive artifacts
policy behavior tests
exposure policy tests for hosted/API/MCP surfaces
```

Baseline commands:

```bash
pnpm build
pnpm test
pnpm typecheck:test
./security-workbench-full-smoke.sh
```

Package-specific examples:

```bash
pnpm --filter @security-workbench/core-utilities test
pnpm --filter @security-workbench/core-parsers test
pnpm --filter @security-workbench/cli test
```

---

## Security review checklist

Before merging, check:

```text
Does this make hidden network calls?
Does this log secrets?
Does this persist raw inputs?
Does this execute untrusted artifact content?
Does this overstate confidence?
Does every signal/finding have evidence?
Does it handle malformed input cleanly?
Does it fail closed when policy blocks execution?
Does it add unnecessary dependencies?
Does docs/smoke coverage need updating?
```

---

## Plugin quality labels

Plugins may be labeled:

```text
core
stable
beta
experimental
unreviewed
deprecated
```

New community plugins normally start as `experimental` or `unreviewed`.

Promotion requires:

```text
docs
tests
fixtures
security review
clear ownership
stable schemas
```

---

## Documentation expectations

Every plugin should document:

```text
what it does
what inputs it accepts
what outputs it returns
whether it uses network
what data it sends externally
example runs
known limitations
```

Every public pipeline should eventually document:

```text
workflow purpose
input artifact type
steps
network behavior
expected outputs
example finding
```

Keep docs layered:

```text
docs/plugins/README.md        plugin and skill inventory
docs/plugins/<plugin>.md      per-plugin behavior
docs/ROADMAP.md               current status and next work
docs/ARCHITECTURE.md          runtime and component model
docs/THREAT_MODEL.md          risks and controls
docs/PRIVACY_MODEL.md         data handling
docs/EXPOSURE_POLICY.md       API/Web/MCP exposure rules
docs/FIXTURES.md              fixture inventory and policy
```

Avoid duplicating full skill inventories outside plugin docs.

---

## Documentation maintenance

Security Workbench documentation is layered. Not every PR should update every document.

| Document | Update cadence | Purpose |
|---|---|---|
| `README.md` | When install, quickstart, or headline status changes | Project front door |
| `docs/ROADMAP.md` | When milestones, next work, completed work, or deferred work changes | Canonical implementation status |
| `docs/plugins/README.md` | When plugin packages or skill counts change | Plugin index and inventory overview |
| `docs/plugins/<plugin>.md` | When that plugin gains, removes, or materially changes skills | Per-plugin behavior and examples |
| `docs/FIXTURES.md` | When top-level fixtures are added, removed, or renamed | Fixture policy and inventory |
| `docs/ARCHITECTURE.md` | Only when component boundaries or execution model changes | Stable design anchor |
| `docs/THREAT_MODEL.md` | Only when trust boundaries, threats, or controls change | Stable security model |
| `docs/PRIVACY_MODEL.md` | Only when data handling, network, persistence, or redaction posture changes | Stable privacy model |
| `docs/EXPOSURE_POLICY.md` | When exposure metadata semantics or reviewed exposure posture changes | API/web/MCP exposure control |
| `docs/security/pre-api-mcp-plugin-gate.md` | Only when release-blocking security criteria change | External-surface security gate |
| `docs/plugins/README.md` | When skill contract expectations change | Skill specification |
| `docs/pipelines/README.md` | When pipeline contract expectations change | Pipeline specification |

Avoid duplicating full skill inventories outside the plugin docs. Link to the plugin index instead.

Use two fixture locations deliberately:

```text
fixtures/   fake demo/manual/smoke inputs safe to commit and share
testdata/   package-specific golden/unit test inputs and expected outputs
```

## Documentation ownership

Documentation should avoid duplicating current-state facts across many files.

| Fact | Canonical home |
|---|---|
| Plugin package index and skill inventory | `docs/plugins/README.md` |
| Per-plugin behavior and examples | `docs/plugins/<plugin>.md` |
| Current roadmap and completed milestones | `docs/ROADMAP.md` |
| Runtime and adapter architecture | `docs/ARCHITECTURE.md` |
| Security threats and controls | `docs/THREAT_MODEL.md` |
| Privacy and data-handling posture | `docs/PRIVACY_MODEL.md` |
| API/web/MCP exposure rules | `docs/EXPOSURE_POLICY.md` |
| Fixture policy and inventory | `docs/FIXTURES.md` |

Architecture, threat model, and privacy model docs should change only when boundaries, controls, or data-handling posture change. Plugin-only changes usually update the owning plugin doc, `docs/plugins/README.md`, fixtures, and the roadmap.

## Pull request checklist

Before opening a PR:

```text
[ ] Code is small and focused.
[ ] Runtime boundaries are preserved.
[ ] Permissions are declared.
[ ] Exposure metadata is added where needed.
[ ] Tests are added or updated.
[ ] Fixtures are added or updated where useful.
[ ] Golden outputs are updated intentionally.
[ ] Network behavior is declared.
[ ] Redaction behavior is considered.
[ ] Documentation is updated.
[ ] Smoke coverage is updated if behavior changed.
[ ] No hidden persistence is introduced.
[ ] No unnecessary dependencies are added.
```

---

## Issue types

Recommended labels:

```text
bug
skill
parser
reviewer
pipeline
plugin
enrichment
scoring
exporter
ui
api
cli
mcp
privacy
security
docs
good-first-issue
needs-design
```

---

## Maintainer review priorities

Review should prioritize:

```text
correctness
security
local-first behavior
evidence quality
testability
maintainability
clarity
```

Performance matters, but not at the expense of correctness or safety.
