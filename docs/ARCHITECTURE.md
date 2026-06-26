# Security Workbench — Architecture

## Purpose

Security Workbench is an analyst workbench for repeatable security artifact tasks: parse, transform, enrich, review, and export.

The architecture is intentionally layered: the runtime stays small, analysis behavior lives in plugins, workflows compose skills, profiles curate plugin bundles, and interface adapters call the same execution path.

Core flow:

```text
Artifact → Skill → Signal → Evidence → Risk → Finding → Export
```

Implementation relationship:

```text
Analyst task → Workflow / Pipeline → Skill → Plugin implementation → Runtime execution
```

## Current status

Security Workbench is currently a deterministic CLI workbench with local parser and transform primitives. It is not yet the full plugin/workflow platform.

Implemented:

```text
TypeScript monorepo
pnpm workspace
packages/schemas
packages/core
plugins/core-utilities
plugins/core-parsers
apps/cli
single-skill registry and runner
runtime policy enforcement
input size enforcement
redaction helpers
structured errors and run results
safe bounded CLI --input-file handling
CLI skill list/describe/run workflows
CLI output formats: json, table, tsv, pretty where applicable
schema/result contracts
safe JSON parse helpers
exposure policy contracts
fixture-backed CLI examples
full smoke script with source audit
```

Current interfaces:

```text
CLI: implemented
REST API: not implemented
Web UI: not implemented
MCP server: not implemented
```

Current skill inventory is maintained in the plugin docs:

```text
docs/plugins/README.md
docs/plugins/core-utilities.md
docs/plugins/core-parsers.md
```

Current high-level inventory counts are intentionally maintained in the plugin docs rather than this architecture document because skill counts change as plugins land.

Current implemented skill categories remain:

```text
transform
parser
```

## Product layers

### Core primitives

Core primitives are the always-available substrate:

```text
JSON/YAML/CSV parsing and formatting
encoding and decoding
hashing and hash identification
URL parsing
IOC extraction
line cleanup
defang/refang
redaction helpers
lightweight token/header parsing
safe output helpers
```

### Domain plugins

Plugins add optional domain depth:

```text
url-triage
email
certificates
packages
browser-extension
scanner-normalize
cloudformation
kubernetes
terraform
iam-policy
vulnerability-intake
ai-agent
```

### Workflows and pipelines

Workflows compose registered skills.

Workflow classes:

```text
transform recipe   clean, decode, extract, normalize, export
review pipeline    parse, preserve evidence, review, score, export
```

### Profiles

Profiles curate plugin bundles:

```text
minimal
analyst
appsec
cloud
cti
ai-security
```

Profiles are convenience bundles. They do not bypass plugin trust, permission checks, or exposure rules.

## Runtime model

### Core runtime responsibilities

Current responsibilities:

```text
register skills
list skills
resolve skills
run one skill at a time
enforce input size limits
enforce network, persistence, filesystem, and external-binary policy
redact outputs and errors by default
return structured run results
```

Future responsibilities:

```text
load plugin manifests
validate plugin manifests
register plugin capabilities
register pipelines
validate input/output schemas
run declarative pipelines
capture audit metadata
control persistence
serve API, Web UI, and MCP adapters through the same execution path
```

The core runtime must not contain most analysis logic.

## Plugin architecture

Implemented plugin packages:

```text
plugins/core-utilities
plugins/core-parsers
```

Future plugin work:

```text
security-workbench.plugin.json schema
manifest loader
install/remove/update commands
plugin diagnostics
profile installation
pipeline registration
policy validation against plugin manifests
source/integrity checks
trust tiers
```

Plugin loading must fail closed.

A plugin is code. Manifest metadata is not a sandbox. Plugin installation must be treated as a trust decision.

## Capability and permission model

Security Workbench should distinguish capability labels from policy enforcement.

Capability labels:

```text
local
network-direct
provider
active
external-binary
filesystem-read
filesystem-write
persistence
explicit-opt-in
```

Runtime policy governs whether declared behavior is allowed.

Current default policy:

```yaml
allow_network: false
persist_inputs: false
redact_secrets: true
max_artifact_size_mb: 10
approved_sinks: []
```

Current enforcement:

```text
network_required skills are refused unless allow_network=true
persists=true skills are refused unless persist_inputs=true
external binary execution is refused
read_write filesystem access requires persistence approval
permissions.network must match execution.network_access
input size is enforced before skill execution
```

Current implemented skills are local-only.

## CLI adapter

The CLI is the only implemented adapter today.

Current responsibilities:

```text
parse arguments
validate command usage
acquire bounded text input from --input or --input-file
call the shared runtime
print structured or human-readable output
set exit codes
```

The CLI must remain a thin adapter. It must not implement analysis logic.

Current command families:

```text
skills list
skills describe
skills run
```

Planned command families:

```text
workflow run
review
inspect
plugin list/search/info/install/remove/enable/disable
profile list/info/install/use
```

## Data model

Security Workbench separates raw observations from conclusions.

```text
Artifact: input or derived object
Evidence: raw or normalized observation
Signal: security-relevant observation derived from evidence
Risk: scoring or prioritization result
Finding: publishable output with evidence, risk, confidence, and action guidance
Export: user-facing or machine-readable representation
```

Current skills mostly produce structured transform/parser output. Finding generation is not implemented yet.

## Trust boundaries

Current trust boundaries:

```text
CLI arguments → CLI parser
user-selected file path → CLI bounded file reader
input string → runtime
runtime → plugin skill
plugin skill → structured result
runtime → terminal output
```

Future trust boundaries:

```text
plugin package source → plugin installer
plugin manifest → manifest validator
plugin code → core runtime
user artifact → parser skill
runtime → external enrichment provider
runtime → local storage
agent/MCP caller → runtime
web UI/browser → API
runtime → export output
```

Controls at these boundaries are tracked in `docs/THREAT_MODEL.md`, `docs/PRIVACY_MODEL.md`, `docs/EXPOSURE_POLICY.md`, and `docs/security/pre-api-mcp-plugin-gate.md`.

## Interface roadmap

Implemented:

```text
CLI
```

Planned later:

```text
REST API
Web UI
MCP server
```

Future API, Web UI, and MCP should expose stable workflow-level tools before broad raw-skill exposure.

API, Web UI, MCP, hosted mode, plugin manifest loading, network-capable plugins, and third-party plugin execution are blocked behind:

```text
docs/security/pre-api-mcp-plugin-gate.md
```

## Non-goals for the first release

```text
cloud sync
user accounts
plugin marketplace
full graph database
real-time monitoring
full vulnerability management
full CyberChef parity
full SaaS integrations
hard sandboxing of arbitrary third-party plugins
universal unknown-artifact identification
```

## Architecture done criteria

The architecture remains healthy when:

```text
CLI/API/Web/MCP adapters share one runtime path
analysis logic stays in plugins
core primitives stay boring and reusable
plugins declare permissions and capabilities
policy is enforced before execution
outputs stay structured
observed facts and inferred risk remain separate
network and persistence remain explicit
new surfaces fail closed by default
community plugin expansion does not outrun the security gate
```
