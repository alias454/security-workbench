# Security Workbench — Plugin System

## Purpose

Plugins are the primary extension mechanism for Security Workbench.

The plugin system lets the base workbench stay small while specialized domains add deeper artifact support, validators, enrichers, reviewers, workflows, exports, and profile bundles.

## Product model

```text
Core primitives  → universal tools always available
Domain plugins   → optional capability packs
Profiles         → curated plugin bundles
Workflows        → repeatable analyst jobs
```

## Core versus plugins

### Core

Core should include stable primitives that most users and plugins reuse:

```text
JSON parse/format/validate
YAML parse/validate
CSV parse
Base64/Base32/hex encode/decode
URL encode/decode/parse
HTML/entity/unicode/quoted-printable decode
hashing and hash identification
line utilities
IOC extraction
fanging utilities
lightweight token/header parsers
redaction helpers
safe output/export helpers
```

Core must remain boring:

```text
no hidden network calls
no hidden persistence
no plugin-owned filesystem access
no external binaries
no risk claims without evidence
small dependencies
clear malformed-input behavior
```

### Plugins

Plugins provide domain depth:

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

A plugin may provide:

```text
skills
schemas
fixtures
tests
workflows
reviewers
enrichers
scorers
export templates
policy packs
profile membership metadata
```

## Plugin trust model

A plugin is code. Manifest metadata is not a sandbox.

Security Workbench should treat plugin installation as a trust decision, not just a package-management operation.

Trust tiers:

| Tier | Meaning |
|---|---|
| `core` | Ships with Security Workbench and is maintained as part of the project. |
| `official` | Maintained by project maintainers but optional. |
| `verified` | Community or partner plugin that passed documented review checks. |
| `community` | User-installed plugin with no project-maintainer guarantee. |
| `experimental` | Unstable or research-grade. |
| `unreviewed` | Arbitrary source; explicit warning required before install/run. |

## Capability labels

Each plugin and skill should declare execution behavior.

| Label | Meaning |
|---|---|
| `local` | Pure parse/transform/review. No network. |
| `network-direct` | Direct DNS, HTTP, TLS, RDAP, WHOIS, or similar protocol call. |
| `provider` | Calls a third-party API or intelligence corpus. |
| `active` | Performs behavior observable by target infrastructure beyond passive lookup. |
| `external-binary` | Runs a local executable. Denied by default. |
| `filesystem-read` | Reads plugin-owned or user-approved files. Denied by default. |
| `filesystem-write` | Writes output/cache/artifacts. Denied by default. |
| `persistence` | Stores data across runs. Disabled by default. |

Examples:

```text
parse_jwt                          local
expand_shortlink                   network-direct, explicit-opt-in
urlscan_lookup                     provider, explicit-opt-in
http_probe                         active, explicit-opt-in
kubernetes_live_cluster_inventory  network-direct, filesystem-read, explicit-opt-in
```

## Plugin manifest

A future plugin should ship a manifest such as `security-workbench.plugin.json`.

Example:

```json
{
  "schema_version": "sw.plugin.v1",
  "name": "@security-workbench/plugin-url-triage",
  "version": "0.1.0",
  "description": "URL parsing, shortlink expansion, redirect-chain inspection, and IOC export workflows.",
  "license": "MIT",
  "quality": "experimental",
  "entrypoint": "./dist/index.js",
  "requires": {
    "security_workbench": ">=0.1.0",
    "plugins": {
      "@security-workbench/core-utilities": ">=0.1.0"
    }
  },
  "capabilities": {
    "skills": [
      "detect_shortlinks",
      "expand_shortlink",
      "parse_redirect_chain"
    ],
    "workflows": [
      "url_triage",
      "extract_expand_defang_urls"
    ],
    "schemas": [
      "redirect_chain.schema.json"
    ]
  },
  "permissions": {
    "network": {
      "mode": "optional",
      "destinations": ["user_supplied_urls"],
      "sends": ["url", "domain", "ip"]
    },
    "filesystem": "none",
    "persistence": "none",
    "external_binaries": "none"
  },
  "exposure": {
    "surfaces": ["cli"],
    "hosted_default": "allowlist_only",
    "mcp_default": "disabled"
  },
  "maintainers": [
    {
      "name": "Example Maintainer",
      "url": "https://example.com"
    }
  ]
}
```

## Manifest required fields

```text
schema_version
name
version
description
entrypoint
requires
capabilities
permissions
```

## Manifest validation rules

The loader must fail closed.

Reject a plugin when:

```text
manifest is missing
manifest schema is invalid
plugin name is invalid or conflicts with installed plugin
version is invalid
entrypoint escapes package root
declared skills are missing or duplicate existing skill names
capabilities are undeclared or malformed
required dependencies are missing or incompatible
permissions are missing or broader than install policy allows
exposure metadata is missing for shared/hosted/agent-facing surfaces
package integrity verification fails
source trust policy refuses the source
```

## Plugin install lifecycle

Future install flow:

```text
resolve source
  → download or load package
  → verify source/integrity/signature where available
  → unpack to temporary isolated directory
  → read manifest
  → validate manifest schema
  → inspect package files
  → resolve dependencies
  → run source-audit checks
  → show permissions and trust tier
  → install disabled or prompt to enable
  → register plugin capabilities
  → run plugin self-test / smoke test
  → record installed metadata
```

The install UX can be simple:

```bash
sw plugin install @security-workbench/plugin-url-triage
sw plugin install ./dist/plugin-url-triage.tgz
sw plugin install github:org/security-workbench-plugin-url-triage
sw plugin install https://example.com/security-workbench-plugin-url-triage.tgz
```

But arbitrary URL installs should be the last stage, not the first implementation.

## Recommended staged implementation

### Stage 1 — official local plugins only

```text
plugins are workspace packages
CLI wires official plugins directly
no manifest loader
no third-party code
```

### Stage 2 — manifest validation for official plugins

```text
plugin.json schema exists
official plugins declare capabilities and permissions
loader validates manifests in repo
no external install yet
```

### Stage 3 — local path/tarball install

```text
sw plugin install ./plugin.tgz
manifest validation required
permissions shown
installed plugins disabled by default or enabled after approval
```

### Stage 4 — official registry

```text
sw plugin search
sw plugin install @security-workbench/plugin-cloudformation
signed checksums or lockfile metadata where practical
trust tiers and review status visible
```

### Stage 5 — arbitrary URL install

```text
sw plugin install https://example.com/plugin.tgz
explicit unreviewed warning
integrity pin recommended
strict policy gates
```

## Plugin commands

Future command set:

```bash
sw plugin list
sw plugin search <query>
sw plugin info <name>
sw plugin install <source>
sw plugin remove <name>
sw plugin enable <name>
sw plugin disable <name>
sw plugin update [name]
sw plugin doctor [name]
sw plugin trust <name>
sw plugin audit <name>
```

Useful details in `plugin info`:

```text
name
version
source
trust tier
installed path
capabilities
provided skills
provided workflows
required plugins
network behavior
data sent externally
filesystem behavior
persistence behavior
external binaries
exposure posture
known limitations
```

## Profiles

Profiles are curated bundles of plugins.

Example profiles:

| Profile | Plugins |
|---|---|
| `minimal` | core utilities and core parsers only |
| `analyst` | core, URL triage, email, certificates, IOC workflows |
| `appsec` | packages, browser extension, scanner normalize, SARIF, SBOM |
| `cloud` | CloudFormation, Kubernetes, Terraform, IAM policy |
| `cti` | URL/domain enrichment, passive DNS/provider plugins, vulnerability intake |
| `ai-security` | MCP/agent config review, prompt/tool schema review |

Future commands:

```bash
sw profile list
sw profile info analyst
sw profile install analyst
sw profile use analyst
sw profile diff minimal cloud
```

Profiles should be convenience bundles. They must not bypass plugin permissions, trust warnings, or source review.

## Plugin dependency rules

A domain plugin may depend on core primitives or other plugins.

Example:

```text
plugin-kubernetes
  requires core-yaml
  requires core-json
  provides Kubernetes-specific validation and review
```

Important split:

```text
plugin-kubernetes-manifest
  parses local YAML/JSON manifests
  no network

plugin-kubernetes-cluster
  queries a live cluster
  network and kubeconfig/filesystem access
  explicit opt-in
```

Parsing a manifest and querying a live system are different trust boundaries and should not be bundled casually.

## Network and provider plugins

Network-capable plugins must declare:

```text
what data they send
where they send it
whether calls are direct or provider-backed
whether the target can observe the request
whether credentials/API keys are required
how failures behave
rate-limit expectations
whether results are cached
```

Example:

```json
{
  "network": {
    "mode": "optional",
    "type": "provider",
    "sinks": ["urlscan"],
    "sends": ["url"],
    "approval_required": true
  }
}
```

## Exposure rules

Raw skills should not automatically become API, web, or MCP tools.

Default future posture:

```text
CLI exposure can be broad for installed/local plugins.
API/web/MCP exposure is allowlist-first.
Hosted/shared exposure requires authentication, rate limits, audit, redaction, and reviewed metadata.
Agent-facing surfaces should prefer stable workflow-level tools over many low-level primitive skills.
```

## Done criteria for plugin loader MVP

A plugin loader MVP is acceptable only when:

```text
manifest schema exists
manifest validation fails closed
plugin permissions are enforced by runtime policy
plugin dependencies are resolved and validated
plugin capabilities are registered explicitly
plugin source and trust tier are visible
plugin install can be disabled/removed cleanly
source audit runs against installed plugin code where practical
network/provider behavior is blocked unless policy enables it
API/web/MCP exposure remains disabled or allowlist-only
pre-API/MCP/plugin-loader security gate is satisfied or explicitly waived
```
