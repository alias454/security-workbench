# Security Model

Security Workbench processes untrusted and sometimes sensitive security artifacts. This file consolidates threat model, privacy posture, exposure policy, output safety, and release gates.

## Default posture

```text
network disabled unless explicitly enabled
persistence disabled unless explicitly enabled
redaction enabled by default
external binaries denied by default
plugin-owned filesystem access denied by default
hosted/API/MCP exposure not implemented
```

Local means control-owned: the artifact stays inside the user's security boundary until external analysis is explicitly justified.

## Current controls

```text
strict CLI argument parsing
bounded --input-file handling
runtime input size limits
structured completed/failed/refused statuses
registered skill runner
registered workflow runner
workflow definition validation
network disabled by default
persistence disabled by default
external binaries refused
skill permission metadata
redaction enabled by default
safe JSON parsing helpers
local transform/parser/reviewer/scoring/output skills
generic draft finding and export helpers
fixture-backed smoke coverage
source audit in full smoke
Semgrep public baseline validation
pnpm supply-chain install policy
```

Not implemented:

```text
archive parsing
web UI
REST API
MCP
plugin loader
plugin install
general pipeline/DAG execution
full skill input/output schema validation
local storage
external enrichment
model-assisted analysis
hard sandboxing
```

## Assets

```text
raw input artifacts
parsed artifacts
evidence records
signals/findings
plugin code
plugin manifests
runtime configuration
future API/MCP access
future provider credentials
future run history
```

## Current trust boundaries

```text
CLI user → CLI parser
user --input string → runtime
user --input-file path → CLI bounded file reader
bounded string → runtime
runtime → plugin skill
runtime → registered workflow steps
plugin output → runtime redaction
runtime result → terminal
```

Future trust boundaries:

```text
plugin package → installer
plugin manifest → manifest validator
runtime → external provider
runtime → local storage
agent/API/web caller → runtime
runtime → exported report/finding
```

## Runtime permissions

Current local-only skill permission baseline:

```ts
permissions: {
  network: "none",
  filesystem: "none",
  sends: [],
  persists: false,
  runs_external_binaries: false,
}
```

`--input-file` is adapter input acquisition, not plugin filesystem permission.

## Privacy and external disclosure

Current behavior:

```text
CLI only
no telemetry
no network-capable skills
no persistence
no external binaries
bounded input-file read at CLI boundary
runtime redaction enabled by default
```

Future network/provider skills must declare:

```text
what data is sent
where it is sent
why it is needed
whether the sink must be approved
how results are sourced
whether data is cached or persisted
```

Network/provider enrichers must be explicit opt-in through policy and user action.

## Local registry lookups

Local registry lookups are allowed when they use bundled, cached, or user-supplied data and do not contact external services.

Examples:

```text
OUI/MAC vendor registry snapshot
ASN/prefix registry snapshot
internal allow/deny lists
cloud range snapshots
```

Network update commands for registry data are future enrichment behavior and need explicit disclosure and policy.

## Exposure policy

Exposure metadata is separate from runtime permissions:

```text
permissions = what a skill may do
exposure    = where a skill may be reachable: CLI, API, web, MCP
```

Current state:

```text
CLI implemented
API not implemented
web not implemented
MCP not implemented
```

Future non-CLI adapters must fail closed:

```text
missing exposure metadata → disabled or allowlist-only
hosted/shared contexts → allowlist-only by default
MCP tools → workflow-level first, raw skills only after review
```

A skill exposed beyond local CLI should have:

```text
input size cap
clear permission metadata
redaction behavior
rate-limit recommendation
audit requirement
authentication requirement for shared/hosted use
malformed-input tests
safe output rendering notes
known limitations
```

## Output safety

Outputs should be structured, evidence-ready, and safe to render.

Core rules:

```text
preserve observations
separate observations from inferences
redact obvious secrets by default
avoid clickable dangerous output in pretty/Markdown views
avoid terminal/control-sequence injection
keep parser output free of risk claims
include warnings for malformed or unmodeled input
```

Parser output should generally return:

```json
{
  "artifact": {},
  "observed": {},
  "warnings": []
}
```

Prefer sensitive-value representations such as:

```text
presence flag
length
hash
claim/key names
redacted preview
```

Avoid emitting:

```text
raw tokens
raw private keys
raw JWT signatures
raw cookies
authorization values
embedded credentials
```

Markdown/HTML/Web exports must escape rendered content and avoid making refanged URLs clickable by default.

## Primary threats

### Malicious or overbroad plugin

```text
artifact exfiltration
undeclared network calls
local file reads/writes
secret logging
external binary execution
misleading metadata
```

Required controls:

```text
permission metadata
policy enforcement
manifest validation before plugin loading
plugin trust tiers later
install diagnostics later
```

### Unsafe artifact parsing

```text
resource exhaustion
unsafe deserialization
code execution
path traversal
prototype pollution
terminal/UI/export injection
```

Current controls:

```text
input size limits
JSON.parse only for JSON
YAML custom tags rejected
CSV formulas not evaluated
no archive extraction
no dynamic artifact execution
no external binaries
malformed tests for parsers
```

### Accidental network disclosure

```text
sending artifacts to providers
agent-triggered disclosure
hidden telemetry
provider key leakage
```

Required future controls:

```text
sends/sinks declarations
approved_sinks enforcement
explicit source/method metadata
user/policy disclosure before network calls
```

### Unsupported findings

The tool must not emit authoritative conclusions from weak evidence. Draft findings and exports are supported, but they must remain evidence-linked and conservative.

```text
parsers do not score risk
reviewers must separate observed and inferred fields
scorers must explain deterministic prioritization
findings must cite evidence or source outputs
exports must not invent unsupported conclusions
```

## Pre-API/MCP/plugin gate

This checklist blocks API, MCP, hosted mode, plugin loading, third-party plugins, and network-capable enrichment.

Runtime/schema gates:

```text
broader runtime input/output schema validation
clear skill permission enforcement
structured audit metadata
bounded input and output sizes
safe error handling
redaction enabled by default
```

Exposure gates:

```text
fail-closed API/web/MCP adapters
explicit exposure allowlists
authentication for shared/hosted use
rate limits for attacker-controlled artifact parsing
audit records for agent/API-triggered runs
workflow-level MCP tools before broad raw-skill tools
```

Plugin gates:

```text
plugin manifest schema
manifest validation tests
permission/capability declarations
entrypoint validation
source/integrity/trust-tier metadata
install/remove/disable tests
no arbitrary URL install initially
no package lifecycle script execution during install
```

Network/provider gates:

```text
sends/sinks declarations
approved_sinks enforcement
external disclosure shown to user/policy
source/method metadata in outputs
provider error/rate-limit behavior
credential handling model
no hidden telemetry
```

Output/UI/export gates:

```text
terminal control stripping or safe rendering
Markdown/HTML escaping
non-clickable dangerous/refanged URLs by default
secret redaction in pretty/export views
model-assisted output labeled if introduced
```

Persistence gates:

```text
explicit opt-in
storage location documented
retention behavior documented
raw artifact minimization
delete/export behavior
audit metadata separated from sensitive artifact content
```

Required validation:

```bash
pnpm build
pnpm test
pnpm typecheck:test
./security-workbench-full-smoke.sh
```

Optional public Semgrep baseline:

```bash
semgrep scan --config auto
```

Stricter JSON gate form:

```bash
mkdir -p scan-results
semgrep scan \
  --config auto \
  --severity ERROR \
  --severity WARNING \
  --error \
  --exclude node_modules \
  --exclude dist \
  --exclude coverage \
  --json \
  --output scan-results/semgrep-public-baseline.json
```

Expected public baseline:

```text
0 findings
```

The Semgrep public baseline uses Semgrep OSS `--config auto` so first-time contributors and public reviewers can reproduce the scan without private rules. This baseline covers implementation SAST checks and package-manager hardening checks that Semgrep OSS reports for the repository.

Current pnpm workspace supply-chain policy:

```yaml
minimumReleaseAge: 10080
trustPolicy: no-downgrade
blockExoticSubdeps: true
trustPolicyExclude:
  - "vite@5.4.21"
```

The `vite@5.4.21` trust-policy exception is a narrow migration exception for the current lockfile. Revisit it during dependency maintenance and remove it after updating or refreshing the affected dependency trust state.

Optional maintainer-local Semgrep rules:

```bash
mkdir -p scan-results
semgrep scan \
  --config ../semgrep-rules \
  --severity ERROR \
  --severity WARNING \
  --error \
  --exclude node_modules \
  --exclude dist \
  --exclude coverage \
  --json \
  --output scan-results/semgrep-local-rules.json
```

The local rules path is optional and is not required for external contributors because it depends on a maintainer-local `../semgrep-rules` checkout.

The repository also uses `.semgrepignore` to exclude dependency/build/cache outputs, local scanner outputs, smoke artifacts, fixtures, and tests. Fixtures and tests intentionally contain malformed, synthetic, attacker-shaped, or security-shaped inputs that are expected to trigger generic scanner rules.
