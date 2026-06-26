# Plugin Documentation Template

Use this template for plugin package documentation. A plugin README should be implementation-focused, security-explicit, and short enough that contributors keep it current.

This template assumes the current Security Workbench baseline:

```text
TypeScript monorepo
local-first runtime
default-deny network policy
input size limits enforced by runtime
redaction enabled by default
skills exposed through the shared runtime path
```

---

# Plugin: `<plugin-name>`

## Purpose

Describe what this plugin provides and why it exists.

Example:

```text
`core-utilities` provides local-only deterministic transform and parser primitives used by the CLI and future pipelines.
```

## Status

| Field | Value |
|---|---|
| Package | `<npm package name>` |
| Quality label | `core | stable | beta | experimental | unreviewed | deprecated` |
| Runtime compatibility | `>=0.1.0 <1.0.0` |
| Maintainer | `<name/team>` |
| License | `<license>` |

## Included skills

| Skill | Category | Execution mode | Network | Summary |
|---|---:|---|---|---|
| `<skill_name>` | `<category>` | `local_only` | `none` | `<summary>` |

Example:

| Skill | Category | Execution mode | Network | Summary |
|---|---:|---|---|---|
| `base64_decode` | transform | `local_only` | `none` | Strictly decodes padded Base64 input. |
| `parse_url` | parser | `local_only` | `none` | Parses a URL and redacts embedded credentials from output. |

## Included pipelines

List included pipelines or state `None`.

| Pipeline | Summary |
|---|---|
| `<pipeline_name>` | `<summary>` |

## Permissions

Plugins must declare behavior that affects trust, privacy, or local system state.

| Permission | Value |
|---|---|
| Network | `none | optional | required` |
| Filesystem | `none | read_input_only | read_write` |
| External data sent | `[]` or list data classes |
| Persists input/output | `true | false` |
| Runs external binaries | `true | false` |

Example for local-only transform plugins:

```json
{
  "network": "none",
  "filesystem": "none",
  "sends": [],
  "persists": false,
  "runs_external_binaries": false
}
```

## Input behavior

Describe accepted input types and hard rejection behavior.

Required details:

```text
input type
max useful size, if lower than runtime max
accepted encoding
strictness rules
malformed input behavior
whether credentials/secrets are accepted
```

Example:

```text
`base64_decode` accepts a string containing strict padded Base64. Whitespace is normalized before validation. Malformed or unpadded input is rejected.
```

## Output behavior

Describe output shape and redaction behavior.

Required details:

```text
structured output fields
whether output may contain raw input
whether sensitive fields are redacted
whether evidence references are included
warning/error behavior
```

Example:

```json
{
  "decoded": "Hello"
}
```

For URL parsing:

```json
{
  "href": "https://%5BREDACTED%5D:%5BREDACTED%5D@example.com/path",
  "username_present": true,
  "password_present": true
}
```

## Runtime policy behavior

Describe how the plugin behaves under default policy.

Default policy:

```yaml
allow_network: false
persist_inputs: false
redact_secrets: true
max_artifact_size_mb: 10
approved_sinks: []
```

A plugin must fail closed when its requested permissions exceed runtime policy.

## Security properties

Document what the plugin intentionally does not do.

Examples:

```text
does not make network calls
does not read arbitrary filesystem paths
does not write files
does not execute artifact content
does not invoke external binaries
does not persist inputs
redacts sensitive values before output where applicable
```

## Examples

Use commands that work through the shared CLI/runtime path.

```bash
pnpm --filter @security-workbench/cli start skills list

pnpm --filter @security-workbench/cli start skills run base64_decode \
  --input "SGVsbG8="

pnpm --filter @security-workbench/cli start skills run parse_url \
  --input "https://user:pass@example.com/path"
```

## Tests

List test locations and how to run them.

```bash
pnpm --filter <package-name> test
pnpm --filter <package-name> typecheck:test
```

Required plugin test types:

```text
skill success tests
malformed input tests
policy behavior tests if permissions are not local-only
redaction tests when output could include secrets
fixture/golden tests for non-trivial analyzers
```

## Fixtures

List fixture directories.

```text
fixtures/
testdata/
examples/
```

If the plugin has no fixtures yet, say so explicitly.

## Limitations

State intentional non-goals and unsafe assumptions.

Example:

```text
This plugin only accepts inline string input in the current CLI baseline.
It does not parse files, archives, compressed content, or remote resources.
```

## Review checklist

Before merging a plugin change:

```text
[ ] Plugin permissions are declared.
[ ] No undeclared network behavior exists.
[ ] No filesystem behavior exceeds declared permissions.
[ ] No untrusted artifact content is executed.
[ ] Inputs are validated before parsing.
[ ] Runtime input size limits are preserved.
[ ] Outputs are structured JSON.
[ ] Sensitive values are redacted or explicitly marked sensitive.
[ ] Tests cover success, failure, and redaction behavior.
[ ] Docs include examples and limitations.
```

---

# Current core-utilities README example

Use this as the first concrete plugin README.

```markdown
# core-utilities

Core local-only transform and parser skills for Security Workbench.

## Skills

| Skill | Category | Execution mode | Network | Summary |
|---|---:|---|---|---|
| `base64_decode` | transform | `local_only` | `none` | Strictly decodes padded Base64 input. |
| `parse_url` | parser | `local_only` | `none` | Parses a URL and redacts embedded credentials from output. |

## Permissions

```json
{
  "network": "none",
  "filesystem": "none",
  "sends": [],
  "persists": false,
  "runs_external_binaries": false
}
```

## Security behavior

- No network calls.
- No filesystem access.
- No persistence.
- No external binaries.
- Base64 input must be strict padded Base64.
- URL credentials are not exposed in `href`; presence is reported with booleans.

## Development

```bash
pnpm --filter @security-workbench/core-utilities test
pnpm --filter @security-workbench/core-utilities typecheck:test
```

## Examples

```bash
pnpm --filter @security-workbench/cli start skills run base64_decode --input "SGVsbG8="
pnpm --filter @security-workbench/cli start skills run parse_url --input "https://user:pass@example.com/path"
```

## Limitations

Current CLI support is inline `--input` only. File input, pipelines, and browser-extension parsing are intentionally deferred until the runtime hardening layer is stable.
```