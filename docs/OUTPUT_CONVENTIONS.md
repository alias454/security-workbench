# Output conventions

Security Workbench separates machine-readable output from analyst-facing display.

The workbench handles repeatable security artifact tasks: parse, transform, enrich, review, and export. Output must support both automation and safe human use.

## Run output modes

- `--format json` returns the canonical structured run result for automation and downstream processing.
- `--format pretty` returns an analyst-readable display view.
- Pretty output is safe by default and defangs IOC-like values where practical.
- `--unsafe` is an explicit opt-out for pretty output when canonical/live-looking values are needed.
- `--unsafe` is not supported with JSON output because JSON is already the canonical machine-readable form.

## Safe display behavior

Human-facing output should avoid casually rendering clickable or copy-executable indicators.

Pretty output should defang common IOC-like values, including:

- HTTP and HTTPS URLs
- domain names
- email addresses
- IPv4 addresses

Examples:

| Canonical value | Safe display |
| --- | --- |
| `https://evil.example.com/path` | `hxxps://evil[.]example[.]com/path` |
| `admin@example.com` | `admin[@]example[.]com` |
| `192.0.2.10` | `192[.]0[.]2[.]10` |

## Parser output rule

Parsers may emit canonical normalized values for correlation and automation. Analyst-facing renderers should display those values safely by default.

Future parser schemas may preserve source, display, and canonical forms separately:

```json
{
  "value": "https://evil.example.com/path",
  "source_value": "hxxps://evil[.]example[.]com/path",
  "display_value": "hxxps://evil[.]example[.]com/path",
  "source_form": "defanged"
}
```

## Parser versus reviewer boundary

Parsers should emit observations. Reviewers should interpret risk. Scorers should assign priority or severity.

A parser may report that a browser extension has broad host permissions. A reviewer decides whether those permissions are risky in context.

## Enrichment output rule

Network/provider enrichment must label source and method.

Example:

```json
{
  "signal": "cohosted_domains_found",
  "value": 42,
  "source": "securitytrails",
  "method": "reverse_ip_lookup",
  "network_used": true,
  "external_sinks": ["securitytrails"],
  "confidence": "medium"
}
```

Do not make provider observations look like direct protocol facts.

Differentiate:

```text
DNS lookup returned this record.
SecurityTrails observed this historical/passive-DNS relation.
VirusTotal reported this reputation context.
urlscan observed this page behavior in a scan.
```

## Workflow output rule

Transform recipes may output transformed data, counts, warnings, and metadata.

Review pipelines should output:

```text
artifact type
workflow name and version
observed facts
evidence
signals
risk or priority when supported
confidence
open questions
recommendations
exports
policy metadata
warnings
```

## Export safety

Exporters must escape unsafe content for their target format.

| Format | Required behavior |
|---|---|
| JSON | Canonical machine-readable values; no Markdown escaping. |
| Markdown | Escape untrusted Markdown where needed; avoid clickable malicious links by default. |
| HTML | Escape artifact content; never render raw untrusted HTML. |
| CSV | Prevent formula injection where applicable. |
| Terminal | Avoid terminal-control effects and unsafe clickable output where practical. |

## Finding output rule

Findings must preserve evidence and distinguish:

```text
observed behavior
inferred risk
confidence
impact or blast radius
recommendation
open questions
```

A finding without evidence is not acceptable.
