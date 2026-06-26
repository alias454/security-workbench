# Security Workbench — Workflows and Pipelines

## Purpose

A workflow or pipeline is a declarative sequence of registered skills for a repeatable analyst task.

Pipelines define how artifacts move through parsing, transformation, review, optional enrichment, scoring, finding generation, and export without duplicating analysis logic in CLI, API, web, or MCP adapters.

Pipelines are planned, not implemented yet.

## Product relationship

Security Workbench is an analyst workbench for repeatable security artifact tasks: parse, transform, enrich, review, and export.

Pipelines are how those repeatable tasks become shareable and testable.

```text
Analyst task → Workflow / Pipeline → Skill → Plugin implementation → Runtime execution
```

## Current implementation status

Implemented today:

```text
single-skill runtime execution
skill registry
skill runner
policy enforcement
structured skill results
CLI skill execution
parser and transform primitives
```

Not implemented yet:

```text
pipeline runner
pipeline manifest schema
pipeline CLI commands
pipeline persistence
pipeline audit records
pipeline golden output tests
workflow packs
```

## Workflow classes

Security Workbench should support two major workflow classes.

### Transform recipes

CyberChef-like repeatable transformations.

Example:

```text
artifact
  → split_lines
  → trim_lines
  → extract_urls
  → normalize_urls
  → dedupe_lines
  → defang_iocs
  → export_text
```

Goal:

```text
clean
convert
extract
normalize
prepare handoff output
```

Transform recipes do not need to create findings.

### Review pipelines

Evidence-backed security reviews.

Example:

```text
browser extension manifest
  → parse_browser_extension_manifest
  → review_extension_permissions
  → review_content_scripts
  → score_permission_risk
  → generate_finding
  → export_markdown
```

Goal:

```text
show observations
interpret supported signals
preserve evidence
assign confidence or risk where supported
export useful output
```

Review pipelines must distinguish observed facts, inferred risk, confidence, and open questions.

## Pipeline principles

1. **Declarative**
   - Pipelines should be YAML-defined, not hardcoded in adapters.

2. **Composable**
   - Steps reference registered skills.

3. **Policy-aware**
   - Every step runs under runtime policy.
   - Runtime policy wins over pipeline defaults.

4. **Evidence-preserving**
   - Intermediate artifacts, signals, and evidence should be preserved where useful and policy allows it.

5. **Interface-neutral**
   - Pipelines must not depend on CLI, UI, API, or MCP behavior.

6. **Auditable**
   - Steps should have stable IDs and visible policy/network/persistence behavior.

7. **Fail closed**
   - Invalid pipeline definitions should not run.

## Pipeline file shape

Recommended file extension:

```text
.yaml
```

Example path:

```text
pipelines/browser_extension_review.yaml
```

Example review pipeline:

```yaml
name: browser_extension_review
version: 0.1.0
type: review
description: Review a browser extension manifest for permission and data-access risk.

input:
  type: browser_extension_manifest
  schema: browser_extension_manifest.schema.json

requires:
  plugins:
    - "@security-workbench/core-parsers >=0.1.0"
    - "@security-workbench/plugin-browser-extension >=0.1.0"

policy:
  default_allow_network: false
  persist_intermediate: false

steps:
  - id: parse
    skill: parse_browser_extension_manifest
    input:
      artifact: $.input

  - id: permissions
    skill: review_browser_extension_permissions
    input_from: parse

  - id: content_scripts
    skill: review_extension_content_scripts
    input_from: parse
    on_error: continue_with_warning

  - id: score
    skill: score_browser_extension_risk
    input_from:
      - permissions
      - content_scripts

  - id: finding
    skill: generate_finding
    input_from:
      - permissions
      - content_scripts
      - score

output:
  from: finding
  schema: finding.schema.json
```

Example transform recipe:

```yaml
name: extract_defang_urls
version: 0.1.0
type: transform
description: Extract URLs from a text blob, dedupe them, and defang the output.

input:
  type: text

requires:
  plugins:
    - "@security-workbench/core-utilities >=0.1.0"

steps:
  - id: extract
    skill: extract_urls
    input:
      text: $.input

  - id: dedupe
    skill: dedupe_lines
    input:
      text: $.steps.extract.output_as_lines

  - id: defang
    skill: defang_iocs
    input_from: dedupe

output:
  from: defang
  schema: text_output.schema.json
```

## Required fields

```text
name
version
type
description
input
steps
output
```

### `type`

Supported planned values:

```text
transform
review
enrichment
export
```

Most initial workflows should be either `transform` or `review`.

## Step fields

Required:

```text
id
skill
```

Optional:

```text
input
input_from
when
policy
on_error
timeout
persist_output
```

Example optional enrichment step:

```yaml
- id: urlhaus
  skill: lookup_urlhaus
  input_from: iocs
  when: $.policy.allow_network == true
  policy:
    approved_sinks:
      - urlhaus
  on_error: continue_with_warning
```

## Error behavior

Supported planned `on_error` values:

```text
fail
continue_with_warning
skip_downstream
return_partial
```

Default:

```text
fail
```

Guidance:

```text
parser failures usually fail the pipeline
optional enrichment failures usually continue with warning
scoring failures usually fail unless marked experimental
export failures should not invalidate the underlying analysis result
```

## Policy behavior

Pipeline policy may set defaults, but runtime policy wins.

Runtime behavior:

```text
a pipeline cannot enable network if run policy forbids it
a step cannot call an external sink unless approved
a plugin cannot exceed declared permissions
sensitive persistence is disabled unless explicitly allowed
```

## Run result shape

A pipeline run should return structured output similar to:

```json
{
  "run_id": "run_123",
  "pipeline": "browser_extension_review",
  "version": "0.1.0",
  "type": "review",
  "status": "completed",
  "artifact": {},
  "steps": [],
  "observations": [],
  "signals": [],
  "evidence": [],
  "risk": null,
  "finding": null,
  "exports": [],
  "policy": {
    "network_used": false,
    "external_sinks": []
  },
  "warnings": []
}
```

## Initial workflow candidates

Transform recipes:

```text
ioc_cleanup
extract_defang_urls
json_validate_format
url_decode_extract
scanner_summary
```

Review pipelines:

```text
url_review
jwt_review
email_header_review
package_review
browser_extension_review
cloudformation_review
kubernetes_manifest_review
cert_review
```

## Pipeline done criteria

A pipeline is complete when it has:

```text
YAML definition
owning plugin or workflow pack
input schema
output schema
example input
example output
golden output test
policy behavior test
failure behavior test
documentation entry
```

Before public API/web/MCP exposure, pipeline execution must also satisfy the pre-API/MCP/plugin-loader security gate.
