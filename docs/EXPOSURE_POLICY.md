# Exposure Policy

Security Workbench separates package/build trust, skill execution permissions, and tool exposure.

```text
Build dependency   -> how code is resolved and built
Skill permission   -> what a skill may do at execution time
Tool exposure      -> where a skill may be exposed: CLI, API, Web, MCP
Plugin trust       -> whether plugin code should be installed/enabled
```

`workspace:*` only controls monorepo dependency resolution. It does not decide whether a skill is safe to expose through API, Web, or MCP.

## Current status

Implemented:

```text
exposure policy TypeScript contracts in packages/schemas
optional SkillMetadata.exposure field
exposureForProfile helper
exposure tests
reviewed exposure annotations for current core-parsers skills
```

Not implemented yet:

```text
REST API exposure enforcement
Web UI exposure enforcement
MCP tool allowlist enforcement
per-surface runtime authorization
rate limiting
audit persistence
plugin manifest exposure validation
plugin trust-tier enforcement
```

Missing exposure metadata must not be treated as permission to expose a skill in hosted/API/Web/MCP adapters. Future adapters should fail closed or require explicit allowlists for missing exposure declarations.

## Surfaces

```text
cli  command-line use
api  REST or local HTTP API adapters
web  local or hosted Web UI adapters
mcp  Model Context Protocol adapters
```

## Deployment profiles

```text
local        trusted user on a local machine
self_hosted  shared or team-controlled deployment
hosted       externally reachable or multi-user deployment
```

## Exposure defaults

```text
enabled         adapter may expose the skill by default
allowlist_only  adapter must explicitly allowlist the skill
disabled        adapter must not expose the skill by default
```

## Required distinction

Skill permissions answer what the skill can do:

```text
network
filesystem
sends
persists
runs_external_binaries
```

Exposure policy answers where the skill should be reachable:

```text
surfaces
default exposure
hosted default
authentication expectation
rate-limit recommendation
audit requirement
input-size recommendation
risk level
rationale
```

A skill can be local and still require hosted allowlisting because it parses attacker-controlled content and returns attacker-controlled fields.

## Recommended exposure posture

### CLI

CLI exposure may be broad for installed local plugins because a local user explicitly installed and invoked the workbench.

Even then, CLI commands must show permission metadata and preserve runtime policy refusals.

### API and Web

API and Web adapters must:

```text
use allowlists for shared/hosted deployments
enforce request size limits
escape or safely render attacker-controlled output
preserve runtime redaction
audit shared/hosted runs
require authentication where exposure metadata says so
```

### MCP

MCP should be conservative.

Recommended MCP defaults:

```text
Expose stable workflow-level tools before raw skills.
Keep raw skills allowlist-only unless reviewed.
Disable network/provider tools unless explicitly approved.
Audit agent-triggered runs.
Return structured JSON and structured refusals.
Preserve observed/inferred/evidence boundaries.
```

Bad MCP surface:

```text
Expose every low-level parser/transform/enricher as an agent tool by default.
```

Better MCP surface:

```text
security.inspect
security.review_jwt
security.review_email_headers
security.review_package
security.review_browser_extension
security.workflow_run
```

## Plugin exposure

Plugins must declare exposure intent in their manifests once the plugin loader exists.

Plugin-level exposure metadata should include:

```text
allowed surfaces
hosted default
MCP default
authentication requirement
rate-limit recommendation
audit requirement
network/provider behavior
known unsafe outputs
```

A plugin can be installed for CLI use but still disabled for API/Web/MCP exposure.

## Current annotated skills

Current `core-parsers` skills have reviewed exposure metadata:

```text
parse_package_json
parse_csv
parse_yaml
parse_browser_extension_manifest
```

Current posture for these parser primitives:

```text
surfaces: cli, api, web, mcp
default_exposure: enabled
hosted_default: allowlist_only
requires_authentication: true
rate_limit_recommended: true
audit_required: true
risk: low
```

Rationale:

```text
They are local-only and do not perform enrichment, persistence, or external binary execution.
They parse attacker-controlled text and may return attacker-controlled fields.
Hosted and MCP adapters should therefore require explicit allowlisting, authentication, rate limits, and audit.
```

Current `core-utilities` skills remain governed by runtime permission metadata. Exposure annotations can be backfilled later as a separate review pass before hosted API or MCP exposure. Until then, hosted/API/Web/MCP adapters should keep missing exposure metadata disabled or allowlist-only.

## Adapter enforcement requirements

Future adapters must:

```text
read exposure metadata
apply deployment profile
apply explicit allowlists
enforce authentication where required
enforce hosted input caps where required
record audit metadata where required
preserve runtime redaction
refuse missing or disabled exposure metadata in hosted/shared contexts
show plugin/source metadata where useful
```

API, Web, MCP, hosted mode, plugin manifest loading, third-party plugins, and network-capable enrichment remain blocked by:

```text
docs/security/pre-api-mcp-plugin-gate.md
```
