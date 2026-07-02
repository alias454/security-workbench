# Recipes

Recipes are copy/paste workflows for running existing Security Workbench skills together.

Recipes document the intended sequence, inputs, outputs, and limits for repeatable local analysis. When a registered workflow exists, the recipe should show the workflow command first and keep manual skill-chain commands as a troubleshooting fallback.

## Available recipes

| Recipe | Purpose |
|---|---|
| [Browser extension review](browser-extension-review.md) | Parse a browser extension manifest, review permission surfaces, score review attention, and generate a draft finding. |
| [Static-analysis triage](static-analysis-triage.md) | Parse SARIF scanner output, review results, score review attention, and generate a draft triage summary. |
| [Certificate review](certificate-review.md) | Parse a PEM certificate artifact and review observed certificate metadata. |
| [JWT review](jwt-review.md) | Parse a JWT and review observed header, claim, and signature metadata. |
| [SBOM review](sbom-review.md) | Parse CycloneDX or SPDX SBOM JSON and review observed inventory quality. |
| [Package review](package-review.md) | Run package manifest or lockfile review through explicit package review workflow variants. |

## Recipe rules

Recipes should stay small and operational:

```text
goal
input artifact
commands
expected output
limits
validation
```

Recipes should not introduce new behavior that is not implemented in skills.

## Future direction

Registered workflows should stay aligned with recipes. Recipes remain useful for explaining what each workflow does, what it observes, and what it intentionally does not do.
