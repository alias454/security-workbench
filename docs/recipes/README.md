# Recipes

Recipes are copy/paste workflows for running existing Security Workbench skills together.

They are not a workflow runner yet. Until pipeline execution exists, recipes document the intended sequence, inputs, outputs, and limits for repeatable local analysis.

## Available recipes

| Recipe | Purpose |
|---|---|
| [Browser extension review](browser-extension-review.md) | Parse a browser extension manifest, review permission surfaces, score review attention, and generate a draft finding. |

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
