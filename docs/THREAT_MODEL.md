# Security Workbench — Threat Model

## Purpose

Security Workbench processes untrusted and sensitive security artifacts. It also plans to support plugins, workflows, profiles, enrichment, and agentic execution. These create meaningful trust boundaries.

This document identifies current threats, mitigations, required controls, and release blockers.

## Product context

Security Workbench is an analyst workbench for repeatable security artifact tasks: parse, transform, enrich, review, and export.

The workbench model intentionally invites many utilities and plugins. That breadth is useful, but it makes plugin trust, permissions, external disclosure, and output safety core security concerns.

## Current implementation status

Implemented controls:

```text
strict CLI argument parsing
safe bounded CLI --input-file support
runtime input size limits
structured statuses: completed, failed, refused
network-required skill refusal
skill permission metadata
redaction enabled by default
redaction for outputs and errors
URL credential redaction
JWT signature non-exposure
local transform and parser skills
safe JSON object parsing helpers
exposure policy metadata contracts
CLI skill list/describe/run inspection
fixture-backed smoke coverage
source audit in full smoke
unit tests and test typechecking
```

Not implemented yet:

```text
archive parsing
web UI
REST API
MCP
plugin manifest loader
plugin install command
pipeline runner
runtime schema validation
local storage
external enrichment
model-assisted analysis
hard sandboxing
```

## Assets

Primary assets:

```text
raw input artifacts
parsed artifacts
evidence records
signals
findings
local run history
plugin code
plugin manifests
runtime configuration
API/MCP access if added later
external enrichment credentials if added later
```

Sensitive artifact examples:

```text
JWTs
API keys
private keys
email headers
URLs
logs
identity exports
SaaS admin exports
AI workflow definitions
package manifests
SBOMs
URLs containing credentials
cookies
webhook URLs
cloud credentials
kubeconfigs
provider API keys
```

## Current trust boundaries

```text
CLI user → CLI parser
user-provided --input string → runtime
user-selected --input-file path → CLI bounded file reader
bounded file content string → runtime
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
runtime → local storage
runtime → external enrichment provider
agent/MCP caller → runtime
web UI/browser → API
runtime → export output
```

## Threats and controls

### 1. Malicious or overbroad plugin

Threats:

```text
artifact exfiltration
undeclared network calls
local file reads or writes
secret logging
misleading skill metadata
external binary execution
supply-chain compromise
overstated findings
```

Current controls:

```text
skill permission metadata
network disabled by default
external binary execution refused by runtime policy
persistence refused unless policy allows it
read_write filesystem access refused unless persistence is allowed
official plugins only
skills list/describe expose metadata
```

Required future controls:

```text
plugin manifest schema validation
plugin permission enforcement
plugin allowlist and denylist
plugin source, integrity, and trust-tier metadata
plugin review process
registration audit
release checksums or signatures where practical
dependency review for plugin packages
plugin install/remove/disable tests
```

Important limitation:

```text
Manifest permissions are not a sandbox. Plugins are code and must be treated as trust-bearing dependencies.
```

### 2. Unsafe artifact parsing

Threats:

```text
parser bugs
resource exhaustion
path traversal
unsafe deserialization
code execution
prototype pollution
terminal/UI injection
```

Current controls:

```text
runtime input size limits
safe bounded CLI file input
strict URL parsing via URL constructor
strict Base64 and Base32 validation
JSON utilities use JSON.parse only
JSON-backed parsers use shared safe JSON object helpers
text decoders do not execute decoded content
parse_jwt does not verify signatures or expose raw signatures
parse_email_headers performs no external authentication checks
parse_package_json does not install packages or run scripts
parse_csv does not evaluate formulas or coerce types
parse_yaml rejects custom tags and unsupported remote/include behavior
parse_browser_extension_manifest preserves manifest observations without scoring permissions or executing extension code
no archive parsing
no dynamic artifact execution
no external binaries
```

Required future controls:

```text
schema validation
parser-specific size and depth limits
timeouts for expensive operations
structured parse errors
malformed fixture tests
fuzz-style parser fixtures where useful
safe UI/terminal/export rendering
```

### 3. Accidental network disclosure

Threats:

```text
sensitive artifacts sent to external enrichment sources
agent-triggered external disclosure
hidden telemetry or analytics
provider API key leakage
```

Current controls:

```text
network disabled by default
no network-capable skills implemented
network_required skills refused unless allow_network=true
run results include policy metadata
skills list/describe expose network posture
no telemetry policy
```

Required future controls:

```text
sends/sinks declarations
approved_sinks enforcement
explicit UI/CLI/API/MCP disclosure
policy errors when network is disabled
redaction and minimization before lookup
audit of external calls
source/method metadata for enrichment results
```

### 4. Secret leakage into output, logs, or exports

Threats:

```text
tokens, keys, cookies, URLs, or raw logs emitted to terminal output
sensitive values in errors
audit logs leaking raw artifacts
future UI/MCP/export leakage
clickable refanged URLs
```

Current controls:

```text
redaction enabled by default
outputs redacted by runtime
errors redacted by runtime
URL credentials redacted
JWT-looking values redacted
Bearer tokens redacted
private keys redacted
GitHub tokens redacted
AWS access keys redacted
sensitive key-name redaction
parse_url avoids raw credential output
parse_jwt avoids raw signature output
pretty output defangs IOC-like values by default
```

Required future controls:

```text
sensitive field annotations
hash instead of raw value where possible
no raw input logging
verbose mode that still redacts by default
terminal control stripping
HTML and Markdown escaping
export-specific escaping
```

### 5. Unsafe plugin installation

Threats:

```text
installing arbitrary malicious package from URL
plugin typosquatting
manifest/entrypoint path traversal
dependency confusion
postinstall script execution
plugin replacement or downgrade
unreviewed plugin enabled for MCP/API
```

Required future controls:

```text
manifest validation before install
source allowlist or explicit trust prompt
integrity pinning where practical
no package lifecycle scripts during install
entrypoint restricted to package root
plugin name namespace validation
dependency resolution and conflict detection
install disabled by default or enable after explicit approval
exposure disabled for API/Web/MCP unless reviewed
plugin trust tier visible
```

### 6. Tool exposure drift

Threat:

A future adapter may expose every registered skill as an API, Web, or MCP tool without considering deployment profile, authentication, rate limits, audit, or attacker-controlled output.

Current controls:

```text
SkillExposurePolicy contracts exist
SkillMetadata supports optional exposure metadata
core-parsers skills declare reviewed exposure metadata
API/Web/MCP are not implemented yet
pre-API/MCP/plugin-loader gate exists
```

Required future controls:

```text
fail-closed adapter behavior for missing exposure metadata
explicit MCP/API/Web allowlists
authentication for shared or hosted exposure
rate limits for attacker-controlled artifact parsers
audit records for agent-triggered runs
redaction before returning output to agents or browsers
workflow-level MCP tools before broad raw-skill exposure
```

### 7. Unsafe agent tool calls

Threats:

```text
agent submits sensitive data to tools
agent enables network or persistence unexpectedly
agent over-trusts low-level parser output
agent chains outputs into unsafe actions
agent calls provider enrichers with sensitive data
```

Current controls:

```text
MCP not implemented
runtime defaults deny network/persistence
runtime policy can refuse unsafe behavior
exposure policy contracts exist
```

Required future controls:

```text
MCP tool allowlist
pipeline-first agent exposure
network approval
no destructive tools initially
structured outputs with evidence and confidence
audit agent-triggered runs
hosted/shared raw skills allowlist-only unless reviewed
```

### 8. Overstated or unsupported findings

Threat:

The tool may generate authoritative-sounding findings from weak evidence or model-assisted inference.

Current controls:

```text
finding generation not implemented
model-assisted output not implemented
current transform/parser primitives do not generate findings
parse_jwt explicitly reports no signature verification
parse_email_headers performs parsing only, not authentication conclusions
```

Required future controls:

```text
findings require evidence references
observed vs inferred fields
confidence levels
open questions section
model-assisted output labeling
review and golden tests for finding templates
```

## Release-blocking gate

API, MCP, hosted mode, plugin manifest loading, plugin installation, third-party plugin execution, and network-capable enrichment are blocked by:

```text
docs/security/pre-api-mcp-plugin-gate.md
```
