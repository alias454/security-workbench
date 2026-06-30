# Plugin: core-scoring

Deterministic local scoring skills that prioritize reviewed signals without generating findings.

## Status

```text
Package: plugins/core-scoring
NPM name: @security-workbench/core-scoring
Quality: core
Execution: local-only
Network: none
Persistence: none
External binaries: none
Implemented skills: 1
```

## Boundary

```text
Parsers observe.
Reviewers interpret with evidence.
Scorers prioritize reviewed signals.
Finding/export plugins publish output later.
```

Scoring skills must be deterministic, explainable, evidence-linked, and clear about limitations. A score is not a maliciousness verdict.

## Implemented skills

| Skill | Input | Output |
|---|---|---|
| `score_browser_extension_risk` | `review_browser_extension_permissions` output or JSON run result | deterministic browser extension review-attention score and risk assessment |

## `score_browser_extension_risk`

Scores browser extension permission review signals into a bounded review-attention assessment.

It reports:

```text
artifact identity
source review artifact reference
score model name
raw and capped score
review attention level
risk level
confidence
review signal count
contributing signal count
category scores
contributing signal types
unmatched signal types
risk assessment
per-signal score contributions
limitations
warnings
```

Scored inputs currently include:

```text
<all_urls>
broad required host permissions
broad optional host permissions
notable API permissions
notable optional API permissions
broad content script matches
background context
externally_connectable
web_accessible_resources
update_url
oauth2
content_security_policy not observed
```

It intentionally does not:

```text
install or execute extensions
inspect extension source code
contact browser stores
perform reputation lookup
perform network enrichment
generate findings
export Markdown or tickets
claim malicious or benign behavior
```

## Example chain

```bash
pnpm --filter @security-workbench/cli start skills run parse_browser_extension_manifest \
  --input-file "$PWD/fixtures/browser-extension/manifest-v2-broad-hosts.json" > /tmp/manifest.parsed.json

pnpm --filter @security-workbench/cli start skills run review_browser_extension_permissions \
  --input-file /tmp/manifest.parsed.json > /tmp/manifest.review.json

pnpm --filter @security-workbench/cli start skills run score_browser_extension_risk \
  --input-file /tmp/manifest.review.json \
  --format pretty
```

## Tests

```bash
pnpm --filter @security-workbench/core-scoring test
pnpm --filter @security-workbench/core-scoring typecheck:test
pnpm --filter @security-workbench/core-scoring build
```
