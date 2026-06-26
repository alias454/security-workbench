# Pre-API/MCP/Plugin-Loader Security Gate

## Purpose

This gate prevents external interface and plugin-expansion work from outrunning the security boundary.

It applies to API, web, MCP, hosted/shared deployment, plugin manifest loading, third-party/community plugin execution, plugin installation, and network-capable enrichment plugins.

Routine parser, transform, fixture, and documentation updates should not change this checklist unless the project is changing a major trust boundary.

## Status

Required before enabling any of the following:

```text
REST API
Web UI with shared/hosted access
MCP server
hosted/shared deployment mode
plugin manifest loader
plugin install command
third-party/community plugin execution
network-capable enrichment plugins
provider/API enrichment plugins
plugin-owned filesystem access
plugin-owned persistence
```

## Release-blocking rule

API, MCP, hosted mode, plugin manifest loading, plugin installation, network-capable plugins, and third-party plugin execution must not be enabled until this checklist is satisfied or each exception is explicitly documented with rationale and compensating controls.

## Required checklist

```text
1. Runtime schema validation exists for skill inputs and outputs.
2. Plugin manifests have a versioned JSON schema.
3. Plugin manifest validation fails closed.
4. Plugin permissions are enforced by runtime policy, not only declared as metadata.
5. Network-capable skills cannot run unless policy explicitly enables network access.
6. Network-capable skills declare destinations, sinks, and data sent externally.
7. Approved sinks are enforced before any provider/API enrichment call.
8. Filesystem access is denied by default and explicitly scoped when introduced.
9. Plugin-owned filesystem reads/writes are tested and policy-gated.
10. External process execution is denied by default.
11. Dynamic evaluation of untrusted artifact content is forbidden.
12. Redaction covers both token-shaped secrets and sensitive key names.
13. CLI/API/Web/MCP all call the same runtime execution path.
14. Agent-facing tools return structured refusal/error responses.
15. Artifact size limits are enforced before skill execution.
16. File input is bounded and does not rely only on stat-before-read.
17. Optional enrichment can fail closed with clear policy errors.
18. Findings must preserve evidence and distinguish observed vs inferred risk.
19. Dependency audit runs in CI or documented release checks.
20. Source audit checks for network/fs/shell/eval APIs before release.
21. Tests cover policy refusals, redaction, oversized input, and permission denial.
22. Plugin installation records source, version, trust tier, and integrity metadata where available.
23. Plugin dependency resolution detects missing, duplicate, or incompatible plugin dependencies.
24. Plugin removal/disable behavior is tested.
25. Hosted/API/Web/MCP exposure fails closed for missing exposure metadata.
26. Agent-facing exposure prefers workflow-level tools over broad low-level raw-skill exposure.
27. Network/provider result metadata records source and method.
28. Raw sensitive inputs are not persisted by default.
29. Exporters escape unsafe content for their target format.
30. Audit metadata exists for agent-triggered, hosted/shared, network, and plugin-loaded runs.
```

## Current implementation notes

Current baseline controls include:

```text
input size enforcement before skill execution
bounded CLI --input-file
policy refusal for network-required skills
redaction for token-shaped values and sensitive key names
source-audit smoke coverage
local parser/transform skill set
fixture-backed CLI smoke examples
permission metadata on implemented skills
exposure policy contracts
```

Known gaps before this gate is fully satisfied:

```text
runtime JSON Schema validation for skill inputs and outputs
plugin manifest schema and loader
plugin install/remove/update commands
plugin source/integrity metadata
plugin dependency resolver
API/MCP/Web structured refusal response adapters
network-capable skill sink enforcement
CI/release dependency audit workflow
plugin-owned filesystem policy model
hosted/API/MCP adapter allowlist enforcement
audit persistence
provider credential handling
workflow-level agent tool allowlists
```

## Exception process

Any exception must document:

```text
item number
reason the item is not satisfied
risk introduced
compensating control
owner
expiration or revisit point
```

Exceptions should be rare. Hosted, agent-facing, network-capable, or third-party plugin execution should default to blocked when in doubt.

## Future automation

A future command should make this gate machine-checkable:

```bash
pnpm security:gate
```

Potential checks:

```text
source audit for network/filesystem/shell/dynamic-evaluation APIs
dependency audit
redaction test suite
policy refusal test suite
oversized input test suite
schema validation test suite
plugin manifest validation
plugin permission validation
exposure metadata validation
fixture inventory validation
workflow golden output validation
```
