# Security Workbench — Product Positioning

## Core positioning

Security Workbench is an analyst workbench for repeatable security artifact tasks: parse, transform, enrich, review, and export.

The product should be understood as a practical workbench for security analysts and security engineers who repeatedly need to process artifacts quickly without building one-off scripts or pasting sensitive material into random online tools.

## Problem statement

Security work often includes small but recurring artifact tasks:

```text
validate this JSON
format this YAML
parse this JWT
decode this URL
extract indicators from this email
expand this shortlink
inspect this certificate
summarize this package manifest
normalize these scanner outputs
validate this CloudFormation template
review this browser extension manifest
```

The usual workflow is fragmented:

```text
search the web
open a random tool
paste the artifact
copy the result
repeat with another tool
write notes manually
```

That creates friction and avoidable trust risk:

```text
unknown tool owner
unknown telemetry/logging
unknown data retention
unknown JavaScript behavior
unknown validation quality
no repeatable workflow
no structured output
no evidence trail
```

Security Workbench replaces that ad hoc workflow with a reusable workbench.

## Product promise

```text
Give Security Workbench a supported artifact or text blob.
It can parse it, transform it, enrich it when allowed, review supported signals, and export useful output.
```

The product does not need to understand every possible blob. It should clearly report when an input is unsupported or ambiguous.

## Core user principle

```text
I have a thing.
Tell me what it is if you recognize it.
Tell me what matters.
Show the evidence.
Give me something I can use.
```

## Core verbs

Security Workbench revolves around five verbs:

| Verb | Meaning |
|---|---|
| Parse | Convert raw artifacts into structured observations. |
| Transform | Clean, decode, encode, normalize, defang, refang, format, or reshape data. |
| Enrich | Add external or contextual data when explicitly enabled. |
| Review | Interpret supported observations into signals, confidence, and risk notes. |
| Export | Produce JSON, Markdown, CSV, tables, IOC lists, or findings. |

## Not the primary positioning

Avoid making any of these the defining identity:

```text
CLI-first
local-first
web-first
agent-first
CyberChef replacement
SOAR alternative
SIEM alternative
threat-intelligence platform
vulnerability management platform
```

The current implementation is CLI-based and safe-by-default, but those are implementation facts and security posture choices, not the product's central identity.

## Category

Security Workbench lives between one-off utility tools and heavyweight platforms.

```text
CyberChef / DevToys / IT-Tools   one-off transforms and developer utilities
ViewDNS / MXToolbox              lookup utilities
IntelOwl / SpiderFoot            enrichment and OSINT automation
Tines / n8n / SOAR               orchestration across systems
OpenCTI / MISP                   threat-intel systems of record
DefectDojo                       vulnerability management
Security Workbench               repeatable artifact tasks and workflows
```

## Competitive stance

Security Workbench should not try to replace every adjacent product.

Use this stance:

```text
If you only need a one-off transform, CyberChef may already do it.
If you need a repeatable analyst workflow with structured output, use Security Workbench.
If you need an external intelligence corpus, Security Workbench can call one through an explicit enrichment plugin.
If you need orchestration across many business systems, Security Workbench can be called by Tines, n8n, SOAR, CI, a bot, or an agent.
```

## Differentiators

Security Workbench should optimize for:

```text
repeatable artifact workflows
small deterministic skills
clear plugin boundaries
structured output
evidence preservation
safe display defaults
explicit enrichment and external disclosure
installable domain depth without bloated core
usable primitives even before full workflows exist
```

## Product boundary

Security Workbench should not promise:

```text
universal artifact understanding
full CyberChef parity
full threat-intel corpus
full SOAR behavior
full SIEM behavior
full vuln-management lifecycle
safe execution of arbitrary community code without review
```

It should promise:

```text
supported artifacts
clear skill behavior
clear plugin capabilities
clear execution permissions
clear output
clear evidence
clear limitations
```
