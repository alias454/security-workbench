# Security Workbench — Privacy Model

## Purpose

Security Workbench handles sensitive security artifacts: tokens, headers, manifests, package metadata, URLs, domains, logs, SaaS exports, AI workflow descriptions, identity data, scanner outputs, and provider enrichment results.

The privacy model defines how the platform avoids accidental disclosure and keeps external processing explicit.

## Product context

Security Workbench is an analyst workbench for repeatable security artifact tasks: parse, transform, enrich, review, and export.

Privacy is important because many of those tasks are currently handled by pasting artifacts into random web tools. Security Workbench should provide a safer, repeatable path with clear disclosure boundaries.

## Current status

Implemented privacy controls:

```text
network disabled by default
no network-capable skills currently implemented
no application persistence currently implemented
runtime input size limit
redaction enabled by default
redaction applied to skill output
redaction applied to error messages
URL credentials redacted from parse_url output
JWT signatures not exposed by parse_jwt
skill permissions include network/filesystem/persistence/external-binary metadata
safe bounded UTF-8 --input-file support
local skill metadata discovery through skills list and skills describe
local parser skills for package.json, CSV, YAML, browser extension manifests, URL, JWT, and email headers
exposure policy contracts for future API/Web/MCP allowlists
fixture data policy for fake demo inputs
```

Not implemented yet:

```text
Web UI
REST API
MCP
SQLite/local store
external enrichment
plugin manifest loader
plugin install command
approved sink enforcement
field-level sensitivity annotations
hash-only evidence storage
```

## Privacy principles

1. **Useful without external disclosure**
   - Core parsing and transforms should work without sending data anywhere.

2. **Explicit network opt-in**
   - Network enrichment is disabled unless policy explicitly enables it.

3. **Visible external disclosure**
   - If data is sent externally, output metadata must show what was sent, where, and by which plugin/skill.

4. **Sensitive value minimization**
   - Send the minimum data required for enrichment.
   - Prefer normalized values or hashes where possible.

5. **No hidden telemetry**
   - No analytics, crash upload, usage tracking, or project telemetry by default.

6. **Persistence is controlled**
   - Sensitive inputs must not be stored unless explicitly configured.

7. **Redaction by default**
   - Logs, errors, audit records, UI previews, exports, and MCP traces should avoid raw secrets and sensitive values.

8. **One policy model**
   - CLI, future API, future Web UI, and future MCP must use the same runtime policy behavior.

## Default policy

Current runtime policy:

```yaml
allow_network: false
persist_inputs: false
redact_secrets: true
max_artifact_size_mb: 10
approved_sinks: []
```

Planned extended policy:

```yaml
allow_network: false
persist_inputs: false
persist_intermediate: false
persist_metadata: true
redact_secrets: true
max_artifact_size_mb: 10
approved_sinks: []
telemetry: false
allowed_plugins: []
blocked_plugins: []
allowed_mcp_tools: []
```

## Data classes

### Low sensitivity

```text
public CVE IDs
public package names
public domains
public repository URLs
public ATT&CK technique IDs
public certificate transparency entries
```

### Medium sensitivity

```text
URLs
email headers
IP addresses
package manifests
package lockfiles
browser extension manifests
SBOMs
security scanner outputs
CSV/YAML exports without secrets
CloudFormation/Kubernetes/Terraform snippets without secrets
```

### High sensitivity

```text
JWTs
API keys
private keys
session tokens
raw logs with user/customer data
identity exports
SaaS admin exports
AI workflow configs with connector scopes
internal hostnames
URLs containing credentials
webhook URLs
cookies
OAuth tokens
provider API keys
kubeconfigs
cloud credentials
```

High-sensitivity data must not be sent externally by default.

## Capability privacy modes

| Mode | Privacy implication |
|---|---|
| `local` | No external disclosure by the skill. |
| `network-direct` | Sends data to target infrastructure or direct protocol endpoints. |
| `provider` | Sends data to a third-party API/corpus. |
| `active` | Target may observe the request as probing/scanning. |
| `persistence` | Data may survive beyond the current run. |

## Network behavior

Skill network modes:

```text
local_only
network_optional
network_required
```

Current implemented skills are `local_only`.

Runner behavior:

```text
network_required + allow_network=false → status: refused
```

Every future network-capable skill must declare:

```text
what it sends
where it sends it
whether the call is direct or provider-backed
whether the target can observe the call
whether credentials are required
how failures behave
```

## External sink declaration

Future network-capable skills must declare external sinks.

Example:

```json
{
  "network_access": "optional",
  "sends": ["domain", "url"],
  "sinks": ["urlscan"],
  "approval_required": true
}
```

Runtime output must show whether network was used and which external sinks received data.

No network-capable skill should merge until sink metadata and policy enforcement exist.

## Plugin privacy model

Plugins must declare:

```text
network behavior
data sent externally
filesystem behavior
persistence behavior
external binary behavior
known limitations
```

A plugin install system must display those declarations before enabling a plugin.

Community or unreviewed plugins should be treated as trust-bearing dependencies. Installing a plugin means executing code, not just loading data.

## Redaction requirements

Redaction applies to:

```text
skill outputs
errors
logs
audit records
UI previews
exported diagnostics
MCP tool traces
plugin install diagnostics where relevant
```

Current redaction helper targets:

```text
URL credentials
Bearer tokens
JWT-looking values
GitHub tokens
AWS access keys
private keys
sensitive key-name values such as password, api_key, token, authorization, cookie, set-cookie, client_secret, privateKey
```

Important limitation:

```text
Regex and key-name redaction are not enough.
Skills should eventually mark sensitive fields explicitly.
```

## Persistence model

### Current state

No application persistence is implemented.

### Default persisted later

```text
run ID
pipeline name
skill names
plugin names and versions
status
non-sensitive metadata
warnings
network usage metadata
external sink names
export references
```

### Not persisted by default

```text
raw inputs
intermediate sensitive artifacts
raw tokens
raw logs
raw identity exports
raw SaaS exports
raw credentials
provider API keys
```

UI/API/CLI/MCP must make persistence state visible if persistence is added.

## Tool exposure privacy model

Exposure policy is separate from skill execution permission. A local skill can still be inappropriate to expose broadly through hosted API, hosted Web, or MCP.

Future API, Web, and MCP adapters must:

```text
respect exposure metadata
use explicit allowlists for hosted/shared deployments
require authentication where exposure policy says so
rate limit attacker-controlled artifact parsers
audit agent-triggered runs
preserve redaction before returning data to agents or browsers
prefer workflow-level tools over raw low-level skills for agent exposure
```

Missing exposure metadata must fail closed for hosted/API/Web/MCP surfaces.

## Telemetry policy

Default:

```text
No telemetry.
No external analytics.
No crash report upload.
No usage tracking.
```

If telemetry is ever added, it must be:

```text
off by default
clearly documented
configurable
non-sensitive
removable
```

## Privacy done criteria

Current baseline privacy criteria:

```text
network disabled by default
local skill behavior
runtime enforces policy before execution
input size limits implemented
safe bounded file input implemented
redaction helpers implemented
skill output redacted by default
errors redacted by default
raw sensitive inputs not persisted
fixture data is fake and documented
```

First public release privacy criteria:

```text
network-capable skills declare sends/sinks
approved sinks enforced
runtime output shows whether network was used
logs redact sensitive values
raw sensitive inputs are not persisted by default
MCP tools follow the same policy model or MCP is omitted
file input is bounded and explicitly controlled
plugin install displays permission and privacy behavior
community/unreviewed plugins are clearly labeled
```
