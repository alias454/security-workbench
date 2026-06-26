# Security Policy

Security Workbench is a security-focused local analysis tool. Vulnerability reports are welcome.

## Supported versions

Security Workbench is currently pre-1.0.

| Version                 | Supported   |
| ----------------------- | ----------- |
| `main`                  | Yes         |
| Tagged pre-1.0 releases | Best effort |
| Older commits or forks  | No          |

## Reporting a vulnerability

Please report suspected vulnerabilities privately.

Preferred options:

1. Use GitHub private vulnerability reporting if it is enabled for this repository.
2. If private reporting is not available, contact the maintainers privately.

Do not include secrets, private keys, access tokens, customer data, or sensitive third-party artifacts in a report.

## What to include

Useful reports include:

* A clear description of the issue
* A minimal reproduction case
* The affected command, package, skill, or document
* Expected behavior
* Actual behavior
* Potential impact
* Relevant environment details

## In scope

Examples of in-scope issues:

* Unsafe handling of untrusted input
* Path traversal or unsafe file input behavior
* Policy bypasses
* Network access when network access should be disabled
* Persistence of input or output when persistence should be disabled
* Secret leakage in logs, errors, or structured output
* Unsafe parsing behavior
* Dependency or supply-chain risks affecting the runtime
* CLI behavior that could cause unintended security impact

## Out of scope

Examples of out-of-scope issues:

* Reports based only on missing future roadmap features
* Scanner output without an explained impact
* Social engineering
* Denial-of-service claims requiring unrealistic local resource exhaustion
* Vulnerabilities in third-party tools not controlled by this project
* Issues in forks or modified builds unless they also affect this repository

## Current security posture

The current MVP is local-first.

Current design constraints include:

* No network-capable skills by default
* No telemetry
* No persistence
* No external binaries
* No plugin-owned filesystem access
* Bounded file input through the CLI
* Runtime policy enforcement
* Redaction helpers

Any future network enrichment, persistence, plugin loading, API, web UI, MCP server, or pipeline execution should preserve explicit security boundaries and safe defaults.

## Disclosure

Please avoid public disclosure until the issue has been reviewed and, if needed, a fix is available.

The project will make a best-effort attempt to acknowledge reports, assess impact, and coordinate a fix.
