# Security Workbench — Analyst Workflows

## Purpose

This document maps recurring security analyst and security-engineer tasks to Security Workbench capabilities.

The catalog should be organized by real work, not by random utilities. A skill or plugin belongs when it saves time during a recurring artifact task and can return structured, repeatable output.

## Inclusion test

Before adding a skill, plugin, or workflow, ask:

```text
Would an analyst or security engineer otherwise search for an online parser, validator, decoder, lookup, or formatter?
Does this save 5-20 minutes during a recurring task?
Can it run deterministically, or clearly label external enrichment?
Can it return structured output?
Can it chain with other skills?
Does it preserve useful evidence or output?
```

If yes, it is a candidate.

## Workflow families

### 1. Artifact cleanup and formatting

Common problem:

```text
I have messy copied text, JSON, YAML, CSV, logs, or command output and need it cleaned into something usable.
```

Representative tasks:

```text
validate JSON
format JSON
validate YAML
parse CSV
split lines
trim lines
remove blanks
sort and dedupe
normalize Unicode
redact secrets
convert output to table/Markdown/CSV/JSON
```

Likely skills:

```text
json_parse
json_format
yaml_parse
yaml_validate
csv_parse
trim_lines
remove_empty_lines
dedupe_lines
sort_lines
count_lines
redact_secrets
export_markdown
export_csv
```

Initial home:

```text
core-utilities
core-parsers
core-output later
```

### 2. IOC cleanup and handoff

Common problem:

```text
I have a blob from Slack, email, SIEM, EDR, a ticket, or a report and need clean indicators.
```

Representative tasks:

```text
extract URLs, domains, IPs, emails, hashes, CVEs, UUIDs
deduplicate indicators
classify IOC types
defang/refang indicators
produce a clean IOC table
export Markdown or JSON
```

Likely skills/workflows:

```text
extract_iocs
extract_urls
extract_domains
extract_ipv4
extract_emails
extract_hashes
extract_cves
extract_uuids
classify_iocs
defang_iocs
refang_iocs
dedupe_iocs
workflow: ioc_cleanup
workflow: extract_defang_urls
```

Initial home:

```text
core-utilities
url-triage plugin later
```

### 3. URL, domain, and IP triage

Common problem:

```text
I need to understand a suspicious URL, domain, or IP quickly.
```

Representative tasks:

```text
parse URL components
decode query params
detect punycode or unusual host shapes
extract registered domain
expand shortlinks
follow redirect chains
fetch HTTP headers
perform DNS/RDAP/TLS lookups
check certificate metadata
check passive DNS or reverse IP through providers
summarize infrastructure context
```

Capability split:

```text
local:
  parse_url
  url_decode
  extract_urls
  normalize_domain
  defang/refang

network-direct:
  dns_lookup
  rdap_lookup
  reverse_dns_ptr
  tls_certificate_fetch
  http_headers_fetch
  expand_shortlink
  expand_redirect_chain

provider:
  urlscan_lookup
  virustotal_url_lookup
  securitytrails_lookup
  shodan_lookup
  censys_lookup
  passive_dns_lookup
  reverse_ip_domains
```

Likely workflows:

```text
url_triage
expand_defang_shortlinks
domain_dns_summary
bad_neighborhood_summary
```

Initial home:

```text
core-utilities for local parsing
plugin-url-triage for network/provider workflows
```

### 4. Phishing email triage

Common problem:

```text
I have a reported email and need to extract what matters.
```

Representative tasks:

```text
parse headers
parse Authentication-Results
extract From, Reply-To, Return-Path, Message-ID
summarize Received chain
extract URLs and attachments
expand safe links / rewritten links
check SPF/DKIM/DMARC observations from headers
summarize sender alignment
export ticket-ready notes
```

Likely skills/workflows:

```text
parse_email_headers
parse_authentication_results
extract_received_chain
extract_email_urls
decode_safelinks
decode_proofpoint_urls
extract_attachment_metadata
analyze_email_headers
workflow: phishing_extract
workflow: email_header_review
```

Initial home:

```text
core-utilities for header parser
plugin-email for richer phishing workflows
```

### 5. JWT, token, and auth artifact inspection

Common problem:

```text
I need to inspect a token safely and quickly.
```

Representative tasks:

```text
decode JWT header and payload
report alg, typ, kid
convert exp, nbf, iat
inspect iss, aud, sub, scope
redact signatures or sensitive values
detect missing exp
detect alg none or weak patterns
summarize review notes
```

Likely skills/workflows:

```text
parse_jwt
convert_unix_timestamp
review_jwt_security
extract_oauth_scopes
redact_token_claims
workflow: jwt_review
```

Initial home:

```text
core-utilities for parse_jwt
core-reviewers or plugin-auth later
```

### 6. Certificate and TLS artifact review

Common problem:

```text
I need to inspect certificate content, SANs, issuer, expiry, or certificate history.
```

Representative tasks:

```text
parse PEM/X.509 certificate
extract subject, issuer, SANs, validity period
check expiration
summarize algorithms
fetch presented TLS certificate
query Certificate Transparency sources
compare related domains
```

Likely skills/workflows:

```text
parse_pem_certificate
extract_certificate_sans
check_certificate_dates
summarize_certificate
tls_certificate_fetch
certificate_transparency_lookup
workflow: cert_review
```

Initial home:

```text
plugin-certificates
```

### 7. Package and dependency review

Common problem:

```text
I need to review a package manifest, lockfile, or dependency output quickly.
```

Representative tasks:

```text
parse package.json
summarize scripts
find install/postinstall hooks
list dependency sections
extract repository URLs
parse lockfiles
look up package metadata later
look up OSV/GHSA later
export review notes
```

Likely skills/workflows:

```text
parse_package_json
parse_package_lock
parse_pnpm_lock
parse_yarn_lock
review_package_scripts
summarize_dependencies
osv_lookup
ghsa_lookup
workflow: package_review
```

Initial home:

```text
core-parsers for package.json parser
plugin-packages for richer review/enrichment
```

### 8. Browser extension review

Common problem:

```text
I need to understand whether a browser extension manifest asks for broad or risky permissions.
```

Representative tasks:

```text
parse manifest V2/V3
extract permissions and host permissions
inspect content scripts
inspect background/service worker
inspect externally_connectable
inspect web_accessible_resources
review broad host access
export evidence-backed notes
```

Likely skills/workflows:

```text
parse_browser_extension_manifest
review_extension_permissions
review_content_scripts
review_externally_connectable
review_web_accessible_resources
workflow: browser_extension_review
```

Initial home:

```text
core-parsers for parser
plugin-browser-extension for review workflow
```

### 9. Scanner output normalization

Common problem:

```text
I have outputs from multiple scanners and need a readable summary.
```

Representative tasks:

```text
parse SARIF
parse NDJSON
parse Semgrep JSON
parse Checkov JSON
parse TruffleHog NDJSON
parse Grype JSON
parse npm audit output
normalize severities
dedupe findings
export Markdown summary
```

Likely skills/workflows:

```text
parse_sarif
parse_ndjson
parse_semgrep_json
parse_checkov_json
parse_trufflehog_ndjson
parse_grype_json
normalize_findings
dedupe_findings
summarize_severity
workflow: scanner_summary
workflow: merge_scanner_results
```

Initial home:

```text
core-parsers for generic SARIF and TruffleHog NDJSON parser primitives
plugin-scanner-normalize for scanner-specific normalization, severity mapping, dedupe, and summaries
```

### 10. CloudFormation, Kubernetes, Terraform, and IaC review

Common problem:

```text
I need to validate or quickly review security-relevant infrastructure config.
```

Representative tasks:

```text
validate JSON/YAML syntax
validate CloudFormation template shape
resolve CloudFormation Ref/GetAtt/Sub/Join references
review public S3 bucket policy patterns
parse Kubernetes manifests
review privileged containers, hostPath, hostNetwork, capabilities
review Kubernetes RBAC
parse Terraform plan JSON
review IAM policies
```

Likely plugins:

```text
plugin-cloudformation
plugin-kubernetes
plugin-terraform
plugin-iam-policy
```

Initial workflows:

```text
cloudformation_validate
cloudformation_review
kubernetes_manifest_review
kubernetes_rbac_review
terraform_plan_summary
iam_policy_review
```

### 11. Vulnerability and advisory intake

Common problem:

```text
I have CVEs, advisories, package names, or scanner output and need a concise intake summary.
```

Representative tasks:

```text
extract CVEs
parse CVSS vectors
parse OSV records
parse GHSA advisories
lookup NVD/OSV/EPSS/CISA KEV when enabled
summarize affected versions
export ticket text
```

Likely skills/workflows:

```text
extract_cves
parse_cvss_vector
parse_osv_record
parse_ghsa_advisory
nvd_lookup
osv_lookup
epss_lookup
cisa_kev_lookup
workflow: vuln_intake
```

### 12. AI agent / MCP artifact review

Common problem:

```text
I need to review AI-agent configs, MCP servers, tool schemas, or workflow definitions for risky tool exposure.
```

Representative tasks:

```text
parse MCP config
parse tool schemas
inspect declared permissions
identify network/file/external-sink behavior
review prompt/tool injection surfaces
review agent workflow definitions
summarize exposure concerns
```

Likely skills/workflows:

```text
parse_mcp_config
parse_agent_tool_schema
review_tool_permissions
review_prompt_injection_surface
review_external_sinks
workflow: ai_agent_review
```

Initial home:

```text
plugin-ai-agent
```

## Prioritized plugin roadmap

### First wave

```text
url-triage
browser-extension
packages
email
certificates
```

### Second wave

```text
scanner-normalize
cloudformation
kubernetes
vulnerability-intake
iam-policy
```

### Later wave

```text
terraform
ai-agent
saas-export-review
detection-rule-helper
static-script-triage
```

## Workflow output requirements

Every workflow should document:

```text
inputs
provided skills
required plugins
optional enrichment sources
output formats
policy requirements
known limitations
example command
example output
```

Review workflows should additionally provide:

```text
observed facts
inferred risk
confidence
supporting evidence
open questions
recommended next action
```
