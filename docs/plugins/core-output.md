# Plugin: core-output

Deterministic local output skills that turn scored or reviewed evidence into draft findings and export-ready text.

## Status

```text
Package: plugins/core-output
NPM name: @security-workbench/core-output
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
Output skills generate findings and export text.
```

Output skills must remain evidence-linked. They may format or publish structured conclusions, but they must not invent evidence, perform enrichment, or silently change the underlying risk assessment.

## Implemented skills

| Skill | Input | Output |
|---|---|---|
| `generate_browser_extension_finding` | `score_browser_extension_risk` output or JSON run result | draft finding record plus Markdown summary |

## `generate_browser_extension_finding`

Generates a draft browser extension permission finding from deterministic browser extension scoring output.

It reports:

```text
artifact identity
source score artifact reference
source review artifact reference
source manifest artifact reference
finding template name
score and max score
review attention level
risk level
confidence
evidence reference count
signal reference count
structured FindingRecord
Markdown summary
limitations
warnings
```

It intentionally does not:

```text
inspect extension source code
install or execute extensions
contact browser stores
perform publisher or host reputation lookup
perform network enrichment
change score weighting
claim malicious or benign behavior
send findings to external systems
persist findings
```

## Example chain

```bash
pnpm --filter @security-workbench/cli start skills run parse_browser_extension_manifest \
  --input-file "$PWD/fixtures/browser-extension/manifest-v2-broad-hosts.json" > /tmp/manifest.parsed.json

pnpm --filter @security-workbench/cli start skills run review_browser_extension_permissions \
  --input-file /tmp/manifest.parsed.json > /tmp/manifest.review.json

pnpm --filter @security-workbench/cli start skills run score_browser_extension_risk \
  --input-file /tmp/manifest.review.json > /tmp/manifest.score.json

pnpm --filter @security-workbench/cli start skills run generate_browser_extension_finding \
  --input-file /tmp/manifest.score.json \
  --format pretty
```

## Tests

```bash
pnpm --filter @security-workbench/core-output test
pnpm --filter @security-workbench/core-output typecheck:test
pnpm --filter @security-workbench/core-output build
```
