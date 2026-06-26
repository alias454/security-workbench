# Security Workbench

Security Workbench is an analyst workbench for repeatable security artifact tasks: parse, transform, enrich, review, and export.

The project exists because security analysts and engineers routinely need to validate, parse, decode, extract, normalize, enrich, review, and reformat artifacts quickly. The common failure mode is searching the web for a random JSON validator, JWT decoder, DNS lookup page, shortlink expander, email header parser, or CloudFormation validator and pasting sensitive or semi-sensitive data into whatever tool appears first.

Security Workbench provides a coherent workbench for that recurring artifact work.

```text
artifact or text blob
  → parse / validate / transform
  → extract useful indicators or structure
  → enrich when explicitly enabled
  → review supported artifact types
  → export JSON, Markdown, tables, or findings
```

## Product shape

Security Workbench is organized around four durable concepts:

```text
Core primitives  → always-available utilities used by everything else
Plugins          → installable domain capability packs
Profiles         → curated plugin bundles for common user types
Workflows        → repeatable chains of skills for analyst tasks
```

The initial implementation is a CLI with deterministic local parser and transform skills. Future interfaces such as API, web UI, and MCP should call the same runtime path rather than reimplementing analysis logic.

## Current implementation status

Implemented today:

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
safe bounded --input-file support
CLI skills list / describe / run
structured run results
fixture-backed examples
source-audited smoke script
```

Current registered skills are documented in `docs/plugins/README.md` and per-plugin docs.

Not implemented yet:

```text
plugin manifest loader
third-party/community plugin execution
plugin install command
pipeline runner
workflow CLI commands
external enrichment plugins
finding generation
REST API
web UI
MCP server
local persistence
```

## Core workflow types

Security Workbench should support both simple utilities and richer workflows.

### Transform recipes

CyberChef-like repeatable transformations:

```text
input blob
  → split lines
  → trim
  → extract URLs
  → dedupe
  → defang
  → export text or JSON
```

Transform recipes clean, convert, normalize, and extract. They do not need to produce findings.

### Review pipelines

Evidence-backed security reviews:

```text
artifact
  → parse
  → preserve observations
  → review supported risk signals
  → score or prioritize where supported
  → generate finding or Markdown summary
```

Review pipelines should distinguish observed facts, inferred risk, confidence, and open questions.

## Command model

The CLI should remain easy to understand:

```bash
# Exact primitive
sw skills run json_format --input-file template.json

# Known artifact review
sw review browser-extension --input-file manifest.json

# Saved workflow / recipe
sw workflow run ioc-cleanup --input-file slack-paste.txt

# Helper mode for supported detectors
sw inspect --input-file thing.txt

# Optional plugin management later
sw plugin install @security-workbench/plugin-url-triage
sw profile install analyst
```

`inspect` should only match supported detectors. It must not promise to understand arbitrary unknown blobs.

## Plugin system direction

The project should scale by letting the core stay boring while optional domain plugins add depth.

Examples:

```text
core-utilities      JSON, YAML, Base64, URL decode, IOC extraction, line tools
url-triage         shortlinks, redirect chains, URL/domain/IP lookup workflows
email              email headers, auth results, phishing extraction
certificates       PEM/X.509 parsing, SANs, expiry, CT lookup later
packages           package.json, lockfiles, scripts, dependency summaries
browser-extension  manifest parsing and permission review
scanner-normalize  SARIF, Semgrep, Checkov, TruffleHog, Grype, npm audit
cloudformation     template validation, references, risky resource review
kubernetes         manifest validation, workload/RBAC review
ai-agent           MCP/tool schema and agent workflow review
```

A plugin install system should be convenient, but plugin trust must not be casual. Plugins are code, not data. Manifest permissions help review and enforcement, but they are not a sandbox.

## Capability labels

Every skill or plugin should be explicit about execution behavior:

| Label | Meaning |
|---|---|
| `local` | Pure parse/transform/review. No network. |
| `network-direct` | Direct DNS, HTTP, TLS, RDAP, or similar protocol lookup. |
| `provider` | Calls an external API or corpus such as urlscan, VirusTotal, Censys, Shodan, SecurityTrails, OSV, or NVD. |
| `active` | Touches target infrastructure in a way that may be observable beyond passive lookup. |
| `explicit-opt-in` | Requires user/policy approval before running. |

## Security posture

Security Workbench should be useful for routine work while preserving clear trust boundaries.

Default posture:

```text
network disabled unless explicitly enabled
persistence disabled unless explicitly enabled
redaction enabled by default
external binaries denied by default
plugin-owned filesystem access denied by default
hosted/API/MCP exposure allowlisted by default
```

## Documentation map

```text
docs/PRODUCT_POSITIONING.md        product lane and USP
docs/ANALYST_WORKFLOWS.md          recurring analyst/security-engineer jobs
docs/PLUGIN_SYSTEM.md              plugin install, manifest, trust, profiles
docs/plugins/README.md             plugin and skill inventory
docs/pipelines/README.md           workflow/pipeline specification
docs/ARCHITECTURE.md               runtime and system architecture
docs/ROADMAP.md                    implementation path
docs/THREAT_MODEL.md               threats and required controls
docs/PRIVACY_MODEL.md              privacy and external disclosure model
docs/EXPOSURE_POLICY.md            API/web/MCP exposure rules
docs/OUTPUT_CONVENTIONS.md         JSON/pretty/export safety rules
docs/FIXTURES.md                   safe fixture policy and inventory
```
