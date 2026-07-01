# Plugin: <name>

Short purpose statement.

## Status

```text
Package:
NPM name:
Quality:
Execution:
Network:
Persistence:
External binaries:
Implemented skills:
```

## Purpose

What recurring analyst/security-engineering task this plugin supports.

## Skills

| Skill | Category | Status | Summary |
|---|---|---|---|
| `<skill_name>` | parser/reviewer/enrichment/scoring/output | planned/implemented | short summary |

## Boundaries

```text
what this plugin does
what this plugin explicitly does not do
what requires network/provider/persistence approval
```

## Permissions

List expected skill permissions and any policy requirements.

## Schemas

List input and output schemas, or note why schema coverage is not implemented yet.

## Privacy and exposure

Document network behavior, external sends, persistence, future API/web/MCP exposure intent, and any redaction behavior.

## Examples

Show one CLI command for the main skill or workflow.

## Fixtures

List fixture folders or package testdata.

## Tests

```bash
pnpm --filter <package> test
pnpm --filter <package> typecheck:test
```

## Contribution checklist

```text
manifest entry or registered skill metadata
input/output schema coverage when stable
privacy declaration
fixtures
unit tests
malformed-input tests for parsers
README/plugin doc update
example run
license compatibility note when adding dependencies or external data
```

## Notes

Keep plugin docs concise. Detailed behavior belongs in tests and code comments when needed.
