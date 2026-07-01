#!/usr/bin/env bash
set -u

# SMOKE_OUTPUT_MODE_PATCH=compact-v1
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
START_EPOCH="$(date +%s)"
VERBOSE=0
OUT=""

for arg in "$@"; do
  case "$arg" in
    --verbose)
      VERBOSE=1
      ;;
    --help|-h)
      cat <<'USAGE'
Usage: ./security-workbench-full-smoke.sh [output-file] [--verbose]

Default mode writes the full smoke log to the output file and prints compact
colored progress to the terminal. Use --verbose to also stream full command
logs to the terminal.
USAGE
      exit 0
      ;;
    --*)
      printf 'Unknown option: %s
' "$arg" >&2
      exit 2
      ;;
    *)
      if [[ -n "$OUT" ]]; then
        printf 'Unexpected extra argument: %s
' "$arg" >&2
        exit 2
      fi
      OUT="$arg"
      ;;
  esac
done

OUT="${OUT:-smoke-results-${TIMESTAMP}.txt}"
TMP_ROOT="$(mktemp -d -t security-workbench-smoke.XXXXXX)"
REPO_ROOT="$(pwd)"
FIXTURES_ROOT="$REPO_ROOT/fixtures"

PASS_COUNT=0
FAIL_COUNT=0
EXPECTED_FAIL_PASS_COUNT=0
EXPECTED_FAIL_FAIL_COUNT=0
ASSERT_PASS_COUNT=0
ASSERT_FAIL_COUNT=0

cleanup() {
  rm -rf "$TMP_ROOT"
}
trap cleanup EXIT

color_enabled() {
  [[ -t 1 && -z "${NO_COLOR:-}" ]]
}

if color_enabled; then
  RED=$'[31m'
  GREEN=$'[32m'
  YELLOW=$'[33m'
  BLUE=$'[34m'
  BOLD=$'[1m'
  RESET=$'[0m'
else
  RED=""
  GREEN=""
  YELLOW=""
  BLUE=""
  BOLD=""
  RESET=""
fi

log() {
  if [[ "$VERBOSE" -eq 1 ]]; then
    printf '%s
' "$*" | tee -a "$OUT"
  else
    printf '%s
' "$*" >>"$OUT"
  fi
}

log_section() {
  log ""
  log "================================================================================"
  log "$1"
  log "================================================================================"
}

render_command() {
  printf '$'
  for arg in "$@"; do
    printf ' %q' "$arg"
  done
  printf '
'
}

terminal_header() {
  if [[ "$VERBOSE" -eq 0 ]]; then
    printf '%s
' "${BOLD}Security Workbench smoke test${RESET}"
    printf 'timestamp=%s
' "$TIMESTAMP"
    printf 'output_file=%s
' "$OUT"
    printf '
'
  fi
}

terminal_status() {
  local status="$1"
  local name="$2"
  local color=""

  if [[ "$VERBOSE" -eq 1 ]]; then
    return
  fi

  case "$status" in
    PASS|PASS_EXPECTED_FAILURE|PASS_ASSERT_PATTERN_FOUND|PASS_ASSERT_PATTERN_NOT_FOUND|PASS_NO_UNEXPECTED_HITS)
      color="$GREEN"
      ;;
    FAIL|FAIL_EXPECTED_FAILURE_DID_NOT_FAIL|FAIL_ASSERT_COMMAND_FAILED|FAIL_ASSERT_PATTERN_FOUND|FAIL_ASSERT_PATTERN_NOT_FOUND|FAIL_UNEXPECTED_HITS)
      color="$RED"
      ;;
    *)
      color="$YELLOW"
      ;;
  esac

  printf '%b[%s]%b %s
' "$color" "$status" "$RESET" "$name"
}

format_duration() {
  local total="$1"
  local minutes=$((total / 60))
  local seconds=$((total % 60))
  if [[ "$minutes" -gt 0 ]]; then
    printf '%dm %02ds' "$minutes" "$seconds"
  else
    printf '%ds' "$seconds"
  fi
}

terminal_summary() {
  local overall="$1"
  local total_fails="$2"
  local elapsed_seconds="$3"
  local duration
  duration="$(format_duration "$elapsed_seconds")"

  if [[ "$VERBOSE" -eq 0 ]]; then
    printf '
%s
' "${BOLD}Summary${RESET}"
    printf '%s
' "-------"
    printf 'normal:            %s pass / %s fail
' "$PASS_COUNT" "$FAIL_COUNT"
    printf 'expected failures: %s pass / %s fail
' "$EXPECTED_FAIL_PASS_COUNT" "$EXPECTED_FAIL_FAIL_COUNT"
    printf 'assertions:        %s pass / %s fail
' "$ASSERT_PASS_COUNT" "$ASSERT_FAIL_COUNT"
    printf 'duration:          %s
' "$duration"
    printf 'output_file:       %s
' "$OUT"
    if [[ "$total_fails" -eq 0 ]]; then
      printf 'overall:           %b%s%b
' "$GREEN" "$overall" "$RESET"
    else
      printf 'overall:           %b%s%b
' "$RED" "$overall" "$RESET"
    fi
  else
    printf '
Smoke test complete: %s
Results written to: %s
Duration: %s
' "$overall" "$OUT" "$duration"
  fi
}

run_ok() {
  local name="$1"
  shift
  log_section "RUN: $name"
  if [[ "$VERBOSE" -eq 1 ]]; then
    render_command "$@" | tee -a "$OUT"
  else
    render_command "$@" >>"$OUT"
  fi
  "$@" >>"$OUT" 2>&1
  local rc=$?
  log ""
  log "exit_code=$rc"
  if [[ $rc -eq 0 ]]; then
    log "RESULT=PASS"
    PASS_COUNT=$((PASS_COUNT+1))
    terminal_status "PASS" "$name"
  else
    log "RESULT=FAIL"
    FAIL_COUNT=$((FAIL_COUNT+1))
    terminal_status "FAIL" "$name"
  fi
}

run_expect_fail() {
  local name="$1"
  shift
  log_section "RUN EXPECTED FAILURE: $name"
  if [[ "$VERBOSE" -eq 1 ]]; then
    render_command "$@" | tee -a "$OUT"
  else
    render_command "$@" >>"$OUT"
  fi
  "$@" >>"$OUT" 2>&1
  local rc=$?
  log ""
  log "exit_code=$rc"
  if [[ $rc -ne 0 ]]; then
    log "RESULT=PASS_EXPECTED_FAILURE"
    EXPECTED_FAIL_PASS_COUNT=$((EXPECTED_FAIL_PASS_COUNT+1))
    terminal_status "PASS" "expected failure: $name"
  else
    log "RESULT=FAIL_EXPECTED_FAILURE_DID_NOT_FAIL"
    EXPECTED_FAIL_FAIL_COUNT=$((EXPECTED_FAIL_FAIL_COUNT+1))
    terminal_status "FAIL" "expected failure did not fail: $name"
  fi
}

run_ok_reject_output_pattern() {
  local name="$1"
  local pattern="$2"
  shift 2
  local tmp_out="$TMP_ROOT/assert-${ASSERT_PASS_COUNT}-${ASSERT_FAIL_COUNT}.out"
  log_section "RUN ASSERT: $name"
  if [[ "$VERBOSE" -eq 1 ]]; then
    render_command "$@" | tee -a "$OUT"
  else
    render_command "$@" >>"$OUT"
  fi
  "$@" >"$tmp_out" 2>&1
  local rc=$?
  cat "$tmp_out" >>"$OUT"
  log ""
  log "exit_code=$rc"
  if [[ $rc -ne 0 ]]; then
    log "RESULT=FAIL_ASSERT_COMMAND_FAILED"
    ASSERT_FAIL_COUNT=$((ASSERT_FAIL_COUNT+1))
    terminal_status "FAIL" "$name"
    return
  fi
  if grep -Eq "$pattern" "$tmp_out"; then
    log "assert_pattern=$pattern"
    log "RESULT=FAIL_ASSERT_PATTERN_FOUND"
    ASSERT_FAIL_COUNT=$((ASSERT_FAIL_COUNT+1))
    terminal_status "FAIL" "$name"
  else
    log "assert_pattern=$pattern"
    log "RESULT=PASS_ASSERT_PATTERN_NOT_FOUND"
    ASSERT_PASS_COUNT=$((ASSERT_PASS_COUNT+1))
    terminal_status "PASS" "$name"
  fi
}

run_ok_require_output_pattern() {
  local name="$1"
  local pattern="$2"
  shift 2
  local tmp_out="$TMP_ROOT/assert-${ASSERT_PASS_COUNT}-${ASSERT_FAIL_COUNT}.out"
  log_section "RUN ASSERT: $name"
  if [[ "$VERBOSE" -eq 1 ]]; then
    render_command "$@" | tee -a "$OUT"
  else
    render_command "$@" >>"$OUT"
  fi
  "$@" >"$tmp_out" 2>&1
  local rc=$?
  cat "$tmp_out" >>"$OUT"
  log ""
  log "exit_code=$rc"
  if [[ $rc -ne 0 ]]; then
    log "RESULT=FAIL_ASSERT_COMMAND_FAILED"
    ASSERT_FAIL_COUNT=$((ASSERT_FAIL_COUNT+1))
    terminal_status "FAIL" "$name"
    return
  fi
  if grep -Eq "$pattern" "$tmp_out"; then
    log "assert_pattern=$pattern"
    log "RESULT=PASS_ASSERT_PATTERN_FOUND"
    ASSERT_PASS_COUNT=$((ASSERT_PASS_COUNT+1))
    terminal_status "PASS" "$name"
  else
    log "assert_pattern=$pattern"
    log "RESULT=FAIL_ASSERT_PATTERN_NOT_FOUND"
    ASSERT_FAIL_COUNT=$((ASSERT_FAIL_COUNT+1))
    terminal_status "FAIL" "$name"
  fi
}

CLI=(pnpm --filter @security-workbench/cli start)

: >"$OUT"
log "Security Workbench full smoke test"
log "timestamp=$TIMESTAMP"
log "repo_root=$REPO_ROOT"
log "tmp_root=$TMP_ROOT"
log "output_file=$OUT"
log "node_version=$(node --version 2>/dev/null || echo 'node not found')"
log "pnpm_version=$(pnpm --version 2>/dev/null || echo 'pnpm not found')"
terminal_header

run_ok_require_output_pattern "cli help shows discovery usage" 'security-workbench list' "${CLI[@]}" help
run_ok_require_output_pattern "cli list shows registered workflows" 'browser_extension_review' "${CLI[@]}" list

cat >"$TMP_ROOT/iocs.txt" <<'DATA'
 https://evil.example.com/path

https://evil.example.com/path
admin@example.com
admin@example.com
hxxps://already[.]defanged[.]example
admin[@]already[.]defanged
192.168.1.10
2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
DATA

cat >"$TMP_ROOT/sample.json" <<'DATA'
{"url":"https://evil.example.com","email":"admin@example.com","enabled":true,"roles":["security","builder"]}
DATA

cat >"$TMP_ROOT/package-json.txt" <<'DATA'
{"name":"example","version":"1.0.0","scripts":{"build":"tsc"},"dependencies":{"left-pad":"1.3.0"}}
DATA
cat >"$TMP_ROOT/sample.csv" <<'DATA'
name,email,note
Alice,alice@example.com,"hello, world"
Bob,bob@example.com,"said ""hi"""
DATA
cat >"$TMP_ROOT/sample.yaml" <<'DATA'
name: example
enabled: true
roles:
  - security
  - builder
nested:
  count: 2
DATA

cat >"$TMP_ROOT/headers.txt" <<'DATA'
From: Alice <alice@example.com>
To: Bob <bob@example.com>
Subject: Test message
Received: from mail.example.com by mx.example.net
Received: from laptop.local by mail.example.com
X-Custom: one
 folded value
DATA

cat >"$TMP_ROOT/quoted-printable.txt" <<'DATA'
Subject:=20Hello=20World=21
Body:=20caf=C3=A9
DATA

cat >"$TMP_ROOT/lines.txt" <<'DATA'
  beta

alpha
beta
  alpha

Gamma
DATA

cat >"$TMP_ROOT/base64.txt" <<'DATA'
SGVsbG8gU2VjdXJpdHkgV29ya2JlbmNo
DATA

cat >"$TMP_ROOT/exposure-audit.mjs" <<'DATA'
import { pathToFileURL } from "node:url";

const root = process.cwd();
const parsers = await import(pathToFileURL(`${root}/plugins/core-parsers/dist/index.js`).href);
const schemas = await import(pathToFileURL(`${root}/packages/schemas/dist/index.js`).href);

const skill = parsers.skills.find((candidate) => candidate.metadata.name === "parse_package_json");
if (!skill) {
  throw new Error("parse_package_json skill not found in core-parsers export");
}

const exposure = skill.metadata.exposure;
if (!exposure) {
  throw new Error("parse_package_json missing exposure metadata");
}

const requiredSurfaces = ["cli", "api", "web", "mcp"];
for (const surface of requiredSurfaces) {
  if (!exposure.surfaces.includes(surface)) {
    throw new Error(`parse_package_json exposure missing surface: ${surface}`);
  }
}

const checks = [
  ["default_exposure", exposure.default_exposure, "enabled"],
  ["hosted_default", exposure.hosted_default, "allowlist_only"],
  ["requires_authentication", exposure.requires_authentication, true],
  ["rate_limit_recommended", exposure.rate_limit_recommended, true],
  ["audit_required", exposure.audit_required, true],
  ["max_input_mb", exposure.max_input_mb, 1],
  ["risk", exposure.risk, "low"],
];

for (const [name, actual, expected] of checks) {
  if (actual !== expected) {
    throw new Error(`parse_package_json exposure ${name} expected ${expected}, received ${actual}`);
  }
}

const localCli = schemas.exposureForProfile(exposure, "cli", "local");
if (localCli.exposure !== "enabled") {
  throw new Error(`local CLI exposure expected enabled, received ${JSON.stringify(localCli)}`);
}

const hostedMcp = schemas.exposureForProfile(exposure, "mcp", "hosted");
if (hostedMcp.exposure !== "allowlist_only") {
  throw new Error(`hosted MCP exposure expected allowlist_only, received ${JSON.stringify(hostedMcp)}`);
}

console.log("parse_package_json exposure metadata OK");
DATA

# nosemgrep: semgrep-rules.generic.secrets.security.detected-jwt-token, semgrep-rules.generic.secrets.gitleaks.jwt, generic.secrets.security.detected-jwt-token.detected-jwt-token -- synthetic unsigned JWT smoke fixture, not a secret
JWT_NONE="eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjMiLCJyb2xlIjoiYWRtaW4ifQ."

run_ok "pnpm build" pnpm build
run_ok "parse_package_json exposure metadata audit" node "$TMP_ROOT/exposure-audit.mjs"
run_ok "pnpm test" pnpm test
run_ok "pnpm typecheck:test" pnpm typecheck:test

run_ok "skills list" "${CLI[@]}" skills list
run_ok "skills list --format table" "${CLI[@]}" skills list --format table
run_ok "skills list --format json" "${CLI[@]}" skills list --format json
run_ok "skills list --format tsv" "${CLI[@]}" skills list --format tsv
run_ok "skills list --category parser --format table" "${CLI[@]}" skills list --category parser --format table
run_ok "skills list --category parser --format json" "${CLI[@]}" skills list --category parser --format json

run_ok_require_output_pattern "parser list includes parse_http_headers" '^parse_http_headers[[:space:]]' "${CLI[@]}" skills list --category parser --format tsv
run_ok_require_output_pattern "parser list includes parse_dockerfile" '^parse_dockerfile[[:space:]]' "${CLI[@]}" skills list --category parser --format tsv
run_ok_require_output_pattern "parser list includes parse_github_actions_workflow" '^parse_github_actions_workflow[[:space:]]' "${CLI[@]}" skills list --category parser --format tsv
run_ok_require_output_pattern "parser list includes parse_trufflehog_ndjson" '^parse_trufflehog_ndjson[[:space:]]' "${CLI[@]}" skills list --category parser --format tsv
run_ok_require_output_pattern "parser list includes parse_sarif" '^parse_sarif[[:space:]]' "${CLI[@]}" skills list --category parser --format tsv
run_ok_require_output_pattern "parser list includes parse_semgrep_json" '^parse_semgrep_json[[:space:]]' "${CLI[@]}" skills list --category parser --format tsv
run_ok_require_output_pattern "parser list includes parse_checkov_json" '^parse_checkov_json[[:space:]]' "${CLI[@]}" skills list --category parser --format tsv
run_ok_require_output_pattern "parser list includes parse_grype_json" '^parse_grype_json[[:space:]]' "${CLI[@]}" skills list --category parser --format tsv
run_ok_require_output_pattern "parser list includes parse_pem_certificate" '^parse_pem_certificate[[:space:]]' "${CLI[@]}" skills list --category parser --format tsv
run_ok_require_output_pattern "parser list includes parse_lockfiles" '^parse_lockfiles[[:space:]]' "${CLI[@]}" skills list --category parser --format tsv
run_ok_require_output_pattern "parser list includes parse_package_json" '^parse_package_json[[:space:]]' "${CLI[@]}" skills list --category parser --format tsv
run_ok_require_output_pattern "parser list includes parse_csv" '^parse_csv[[:space:]]' "${CLI[@]}" skills list --category parser --format tsv
run_ok_require_output_pattern "parser list includes parse_yaml" '^parse_yaml[[:space:]]' "${CLI[@]}" skills list --category parser --format tsv
run_ok_require_output_pattern "parser list includes identify_hash" '^identify_hash[[:space:]]' "${CLI[@]}" skills list --category parser --format tsv
run_ok_require_output_pattern "parser list includes json_parse" '^json_parse[[:space:]]' "${CLI[@]}" skills list --category parser --format tsv
run_ok_require_output_pattern "parser list includes extract_iocs" '^extract_iocs[[:space:]]' "${CLI[@]}" skills list --category parser --format tsv
run_ok_require_output_pattern "parser list includes extract_hashes" '^extract_hashes[[:space:]]' "${CLI[@]}" skills list --category parser --format tsv
run_ok_require_output_pattern "parser list includes extract_cves" '^extract_cves[[:space:]]' "${CLI[@]}" skills list --category parser --format tsv
run_ok_require_output_pattern "parser list includes extract_uuids" '^extract_uuids[[:space:]]' "${CLI[@]}" skills list --category parser --format tsv
run_ok_reject_output_pattern "transform list excludes parser-observation skills" '^(identify_hash|json_parse|extract_iocs|extract_urls|extract_domains|extract_emails|extract_ipv4|extract_hashes|extract_cves|extract_uuids)[[:space:]]' "${CLI[@]}" skills list --category transform --format tsv
run_ok "skills list --category transform --format table" "${CLI[@]}" skills list --category transform --format table
run_ok "skills list --category transform --format tsv" "${CLI[@]}" skills list --category transform --format tsv
run_ok_require_output_pattern "transform list includes normalize_scanner_results" '^normalize_scanner_results[[:space:]]' "${CLI[@]}" skills list --category transform --format tsv
run_ok_require_output_pattern "transform list includes dedupe_scanner_results" '^dedupe_scanner_results[[:space:]]' "${CLI[@]}" skills list --category transform --format tsv

run_ok "workflows list" "${CLI[@]}" workflows list
run_ok "workflows list --format table" "${CLI[@]}" workflows list --format table
run_ok "workflows list --format json" "${CLI[@]}" workflows list --format json
run_ok_require_output_pattern "workflows list includes browser_extension_review" "^browser_extension_review[[:space:]]" "${CLI[@]}" workflows list --format tsv
run_ok_require_output_pattern "workflows list includes static_analysis_triage" "^static_analysis_triage[[:space:]]" "${CLI[@]}" workflows list --format tsv
run_ok "workflow browser_extension_review fixture" "${CLI[@]}" workflows run browser_extension_review --input-file "$FIXTURES_ROOT/browser-extension/manifest-v2-broad-hosts.json" --format pretty
run_ok_require_output_pattern "workflow browser_extension_review output includes finding" "Browser Extension Finding" "${CLI[@]}" workflows run browser_extension_review --input-file "$FIXTURES_ROOT/browser-extension/manifest-v2-broad-hosts.json" --format pretty
run_ok "workflow static_analysis_triage fixture" "${CLI[@]}" workflows run static_analysis_triage --input-file "$FIXTURES_ROOT/sarif/codeql-results.sarif" --format pretty
run_ok_require_output_pattern "workflow static_analysis_triage output includes summary" "Static-analysis triage summary" "${CLI[@]}" workflows run static_analysis_triage --input-file "$FIXTURES_ROOT/sarif/codeql-results.sarif" --format pretty
run_ok_require_output_pattern "workflow static_analysis_triage json includes step count" '"step_count": 4' "${CLI[@]}" workflows run static_analysis_triage --input-file "$FIXTURES_ROOT/sarif/codeql-results.sarif" --format json

run_ok "skills describe parse_jwt" "${CLI[@]}" skills describe parse_jwt
run_ok "skills describe parse_jwt --format table" "${CLI[@]}" skills describe parse_jwt --format table
run_ok "skills describe parse_jwt --format json" "${CLI[@]}" skills describe parse_jwt --format json
run_ok "skills describe parse_jwt --format tsv" "${CLI[@]}" skills describe parse_jwt --format tsv
run_ok "skills describe parse_email_headers --format table" "${CLI[@]}" skills describe parse_email_headers --format table
run_ok "skills describe parse_http_headers --format table" "${CLI[@]}" skills describe parse_http_headers --format table
run_ok "skills describe parse_dockerfile --format table" "${CLI[@]}" skills describe parse_dockerfile --format table
run_ok "skills describe parse_github_actions_workflow --format table" "${CLI[@]}" skills describe parse_github_actions_workflow --format table
run_ok "skills describe parse_trufflehog_ndjson --format table" "${CLI[@]}" skills describe parse_trufflehog_ndjson --format table
run_ok "skills describe parse_sarif --format table" "${CLI[@]}" skills describe parse_sarif --format table
run_ok "skills describe parse_semgrep_json --format table" "${CLI[@]}" skills describe parse_semgrep_json --format table
run_ok "skills describe parse_checkov_json --format table" "${CLI[@]}" skills describe parse_checkov_json --format table
run_ok "skills describe parse_grype_json --format table" "${CLI[@]}" skills describe parse_grype_json --format table
run_ok "skills describe parse_pem_certificate --format table" "${CLI[@]}" skills describe parse_pem_certificate --format table
run_ok "skills describe parse_lockfiles --format table" "${CLI[@]}" skills describe parse_lockfiles --format table
run_ok "skills describe normalize_scanner_results --format table" "${CLI[@]}" skills describe normalize_scanner_results --format table
run_ok "skills describe dedupe_scanner_results --format table" "${CLI[@]}" skills describe dedupe_scanner_results --format table
run_ok "skills describe review_static_analysis_results --format table" "${CLI[@]}" skills describe review_static_analysis_results --format table
run_ok "skills describe score_static_analysis_attention --format table" "${CLI[@]}" skills describe score_static_analysis_attention --format table
run_ok "skills describe generate_static_analysis_triage_summary --format table" "${CLI[@]}" skills describe generate_static_analysis_triage_summary --format table
run_ok "skills describe parse_package_json --format table" "${CLI[@]}" skills describe parse_package_json --format table
run_ok "skills describe parse_csv --format table" "${CLI[@]}" skills describe parse_csv --format table
run_ok "skills describe parse_yaml --format table" "${CLI[@]}" skills describe parse_yaml --format table
run_ok "skills describe parse_url --format json" "${CLI[@]}" skills describe parse_url --format json
run_ok "skills describe base64_decode --format table" "${CLI[@]}" skills describe base64_decode --format table
run_ok "skills describe extract_hashes --format tsv" "${CLI[@]}" skills describe extract_hashes --format tsv

run_ok "base64_encode" "${CLI[@]}" skills run base64_encode --input "Hello Security Workbench"
run_ok "base64_encode --format json" "${CLI[@]}" skills run base64_encode --input "Hello Security Workbench" --format json
run_ok "base64_encode --format pretty" "${CLI[@]}" skills run base64_encode --input "Hello Security Workbench" --format pretty
run_ok "base64_decode" "${CLI[@]}" skills run base64_decode --input "SGVsbG8gU2VjdXJpdHkgV29ya2JlbmNo"
run_ok "base64_decode from file" "${CLI[@]}" skills run base64_decode --input-file "$TMP_ROOT/base64.txt"
run_ok "base32_encode" "${CLI[@]}" skills run base32_encode --input "hello"
run_ok "base32_decode" "${CLI[@]}" skills run base32_decode --input "NBSWY3DP"
run_ok "hex_encode" "${CLI[@]}" skills run hex_encode --input "Hello"
run_ok "hex_decode" "${CLI[@]}" skills run hex_decode --input "48656c6c6f"
run_ok "url_encode" "${CLI[@]}" skills run url_encode --input "hello world?x=1&y=2"
run_ok "url_decode" "${CLI[@]}" skills run url_decode --input "hello%20world%3Fx%3D1%26y%3D2"
run_ok "rot13" "${CLI[@]}" skills run rot13 --input "uryyb jbeyq"
run_ok "identify_hash" "${CLI[@]}" skills run identify_hash --input "hello"
run_ok "md5_hash" pnpm --filter @security-workbench/cli start skills run md5_hash --input hello
run_ok "sha1_hash" pnpm --filter @security-workbench/cli start skills run sha1_hash --input hello
run_ok "sha256_hash" pnpm --filter @security-workbench/cli start skills run sha256_hash --input hello

run_ok "describe identify_hash" pnpm --filter @security-workbench/cli start skills describe identify_hash --format table
run_ok "identify_hash md5" pnpm --filter @security-workbench/cli start skills run identify_hash --input 5d41402abc4b2a76b9719d911017c592 --format pretty
run_ok "md5_hash" pnpm --filter @security-workbench/cli start skills run md5_hash --input hello --format pretty
run_ok "sha1_hash" pnpm --filter @security-workbench/cli start skills run sha1_hash --input hello --format pretty
run_ok "sha512_hash" pnpm --filter @security-workbench/cli start skills run sha512_hash --input hello --format pretty
run_ok "sha512_hash" pnpm --filter @security-workbench/cli start skills run sha512_hash --input hello
run_ok "json_parse inline" "${CLI[@]}" skills run json_parse --input '{"ioc":"hxxps://evil[.]example[.]com","severity":"test"}'
run_ok "json_format inline" "${CLI[@]}" skills run json_format --input '{"user":"brandon","roles":["security","builder"],"enabled":true}'
run_ok "json_format from file" "${CLI[@]}" skills run json_format --input-file "$TMP_ROOT/sample.json"
run_ok "parse_package_json from file" "${CLI[@]}" skills run parse_package_json --input-file "$TMP_ROOT/package-json.txt"
run_ok "parse_package_json --format pretty" "${CLI[@]}" skills run parse_package_json --input-file "$TMP_ROOT/package-json.txt" --format pretty
run_ok "parse_csv from file" "${CLI[@]}" skills run parse_csv --input-file "$TMP_ROOT/sample.csv"
run_ok "parse_csv --format pretty" "${CLI[@]}" skills run parse_csv --input-file "$TMP_ROOT/sample.csv" --format pretty
run_ok "parse_yaml from file" "${CLI[@]}" skills run parse_yaml --input-file "$TMP_ROOT/sample.yaml"
run_ok "parse_yaml --format pretty" "${CLI[@]}" skills run parse_yaml --input-file "$TMP_ROOT/sample.yaml" --format pretty
run_ok "parse_url credential redaction" "${CLI[@]}" skills run parse_url --input "https://user:pass@example.com/path?x=1"
run_ok "parse_jwt alg none" "${CLI[@]}" skills run parse_jwt --input "$JWT_NONE"
run_ok "parse_email_headers from file" "${CLI[@]}" skills run parse_email_headers --input-file "$TMP_ROOT/headers.txt"
run_ok "html_entity_decode" "${CLI[@]}" skills run html_entity_decode --input 'Alert: &lt;script&gt;test&lt;/script&gt; &amp; &#x41;'
run_ok "unicode_escape_decode" "${CLI[@]}" skills run unicode_escape_decode --input 'line1\nline2\t\u0041\u{1F600}'
run_ok "quoted_printable_decode inline" "${CLI[@]}" skills run quoted_printable_decode --input 'Subject:=20Hello=20World=21=0ABody:=20caf=C3=A9'
run_ok "quoted_printable_decode from file" "${CLI[@]}" skills run quoted_printable_decode --input-file "$TMP_ROOT/quoted-printable.txt"
run_ok "calculate_entropy low entropy" "${CLI[@]}" skills run calculate_entropy --input "aaaaaaaa"
run_ok "calculate_entropy mixed" "${CLI[@]}" skills run calculate_entropy --input "a8F!zQ91pL"
run_ok "string_normalize" "${CLI[@]}" skills run string_normalize --input "é"
run_ok "defang_iocs inline" "${CLI[@]}" skills run defang_iocs --input "https://evil.example.com/path admin@example.com"
run_ok "defang_iocs already-defanged inline" "${CLI[@]}" skills run defang_iocs --input "hxxps://already[.]defanged[.]example admin[@]example[.]com"
run_ok_reject_output_pattern "defang_iocs idempotency assertion" '\[\[\.\]\]|\[\[@\]\]' "${CLI[@]}" skills run defang_iocs --input "hxxps://already[.]defanged[.]example admin[@]example[.]com"
run_ok "defang_iocs from file" "${CLI[@]}" skills run defang_iocs --input-file "$TMP_ROOT/iocs.txt"
run_ok_reject_output_pattern "defang_iocs from file idempotency assertion" '\[\[\.\]\]|\[\[@\]\]' "${CLI[@]}" skills run defang_iocs --input-file "$TMP_ROOT/iocs.txt"
run_ok "refang_iocs inline" "${CLI[@]}" skills run refang_iocs --input "hxxps://evil[.]example[.]com/path admin[@]example[.]com"
run_ok "refang_iocs alternate forms" "${CLI[@]}" skills run refang_iocs --input "evil(dot)example[dot]com admin(at)example(.)com"
run_ok "extract_iocs from file" "${CLI[@]}" skills run extract_iocs --input-file "$TMP_ROOT/iocs.txt"
run_ok "extract_urls from file" "${CLI[@]}" skills run extract_urls --input-file "$TMP_ROOT/iocs.txt"
run_ok "extract_domains from file" "${CLI[@]}" skills run extract_domains --input-file "$TMP_ROOT/iocs.txt"
run_ok "extract_emails from file" "${CLI[@]}" skills run extract_emails --input-file "$TMP_ROOT/iocs.txt"
run_ok "extract_ipv4 from file" "${CLI[@]}" skills run extract_ipv4 --input-file "$TMP_ROOT/iocs.txt"
run_ok "extract_hashes from file" "${CLI[@]}" skills run extract_hashes --input-file "$TMP_ROOT/iocs.txt"
run_ok "extract_cves from fixture" "${CLI[@]}" skills run extract_cves --input-file "$FIXTURES_ROOT/identifiers/cves-and-uuids.txt"
run_ok "extract_uuids from fixture" "${CLI[@]}" skills run extract_uuids --input-file "$FIXTURES_ROOT/identifiers/cves-and-uuids.txt"
run_ok "trim_lines from file" "${CLI[@]}" skills run trim_lines --input-file "$TMP_ROOT/lines.txt"
run_ok "remove_empty_lines from file" "${CLI[@]}" skills run remove_empty_lines --input-file "$TMP_ROOT/lines.txt"
run_ok "dedupe_lines from file" "${CLI[@]}" skills run dedupe_lines --input-file "$TMP_ROOT/lines.txt"
run_ok "sort_lines from file" "${CLI[@]}" skills run sort_lines --input-file "$TMP_ROOT/lines.txt"
run_ok "count_lines from file" "${CLI[@]}" skills run count_lines --input-file "$TMP_ROOT/lines.txt"

run_expect_fail "skills list rejects bad --format" "${CLI[@]}" skills list --format yaml
run_expect_fail "skills list rejects bad --category" "${CLI[@]}" skills list --category banana
run_expect_fail "skills run rejects unsupported --format" "${CLI[@]}" skills run base64_encode --input "Hello" --format table
run_expect_fail "skills run rejects list-only --category" "${CLI[@]}" skills run base64_encode --input "Hello" --category transform
run_expect_fail "skills describe requires skill name" "${CLI[@]}" skills describe
run_expect_fail "skills describe rejects bad --format" "${CLI[@]}" skills describe parse_jwt --format yaml
run_expect_fail "skills describe rejects --category" "${CLI[@]}" skills describe parse_jwt --category parser
run_expect_fail "skills describe rejects unknown skill" "${CLI[@]}" skills describe no_such_skill
run_expect_fail "reject both --input and --input-file" "${CLI[@]}" skills run base64_encode --input "Hello" --input-file "$TMP_ROOT/base64.txt"
run_expect_fail "reject directory as --input-file" "${CLI[@]}" skills run base64_encode --input-file "$TMP_ROOT"
run_expect_fail "base32_decode rejects bad middle padding" "${CLI[@]}" skills run base32_decode --input "NBS=Y3DP"
run_expect_fail "base32_decode rejects invalid length" "${CLI[@]}" skills run base32_decode --input "NBSWY3D"
run_expect_fail "json_parse rejects invalid JSON" "${CLI[@]}" skills run json_parse --input '{bad json}'
run_expect_fail "parse_http_headers rejects no valid headers" "${CLI[@]}" skills run parse_http_headers --input $'HTTP/1.1 200 OK\nnot a header'
run_expect_fail "parse_dockerfile rejects no valid instructions" "${CLI[@]}" skills run parse_dockerfile --input $'# comment only\n\n# syntax=docker/dockerfile:1'
run_expect_fail "parse_github_actions_workflow rejects missing jobs" "${CLI[@]}" skills run parse_github_actions_workflow --input $'name: No Jobs\non: push'
run_expect_fail "parse_trufflehog_ndjson rejects no valid records" "${CLI[@]}" skills run parse_trufflehog_ndjson --input $'{bad json}\n[]'
run_expect_fail "parse_sarif rejects missing runs" "${CLI[@]}" skills run parse_sarif --input '{"version":"2.1.0"}'
run_expect_fail "parse_semgrep_json rejects missing results" "${CLI[@]}" skills run parse_semgrep_json --input '{"version":"1.0.0"}'
run_expect_fail "parse_checkov_json rejects missing results" "${CLI[@]}" skills run parse_checkov_json --input '{"check_type":"terraform"}'
run_expect_fail "parse_grype_json rejects missing matches" "${CLI[@]}" skills run parse_grype_json --input '{"descriptor":{"name":"grype"}}'
run_expect_fail "parse_pem_certificate rejects no certificate block" "${CLI[@]}" skills run parse_pem_certificate --input 'not a certificate'
run_expect_fail "parse_lockfiles rejects unknown content" "${CLI[@]}" skills run parse_lockfiles --input 'not a lockfile'
run_expect_fail "parse_package_json rejects invalid JSON" "${CLI[@]}" skills run parse_package_json --input '{bad json}'
run_expect_fail "parse_package_json rejects arrays" "${CLI[@]}" skills run parse_package_json --input '[]'
run_expect_fail "parse_package_json rejects null" "${CLI[@]}" skills run parse_package_json --input 'null'
run_expect_fail "parse_csv rejects malformed quoted field" "${CLI[@]}" skills run parse_csv --input $'name,note\nAlice,"unterminated'
run_expect_fail "parse_yaml rejects malformed YAML" "${CLI[@]}" skills run parse_yaml --input $'name: [unterminated'
run_expect_fail "parse_ip_prefix_list rejects no valid entries" "${CLI[@]}" skills run parse_ip_prefix_list --input-file "$FIXTURES_ROOT/ip-prefixes/no-valid-prefixes.txt"
run_expect_fail "parse_asn_list rejects no valid entries" "${CLI[@]}" skills run parse_asn_list --input-file "$FIXTURES_ROOT/asn/no-valid-asn-list.txt"
run_expect_fail "parse_asn_allow_deny_list rejects no valid entries" "${CLI[@]}" skills run parse_asn_allow_deny_list --input-file "$FIXTURES_ROOT/asn/no-valid-asn-allow-deny-list.txt"
run_expect_fail "parse_asn_observations rejects no valid entries" "${CLI[@]}" skills run parse_asn_observations --input-file "$FIXTURES_ROOT/asn/no-valid-asn-observations.txt"
run_expect_fail "parse_bgp_prefix_table rejects no valid entries" "${CLI[@]}" skills run parse_bgp_prefix_table --input-file "$FIXTURES_ROOT/asn/no-valid-bgp-prefix-table.txt"
run_expect_fail "parse_url rejects invalid URL" "${CLI[@]}" skills run parse_url --input "not a url"


# PR 5C.1 fixture-backed CLI examples
run_ok "fixture parse_http_headers security headers" "${CLI[@]}" skills run parse_http_headers --input-file "$FIXTURES_ROOT/http-headers/security-headers.txt" --format pretty
run_ok "fixture parse_dockerfile multi-stage" "${CLI[@]}" skills run parse_dockerfile --input-file "$FIXTURES_ROOT/dockerfile/multi-stage.Dockerfile" --format pretty
run_ok "fixture parse_dockerfile sensitive env" "${CLI[@]}" skills run parse_dockerfile --input-file "$FIXTURES_ROOT/dockerfile/sensitive-env.Dockerfile" --format pretty
run_ok "fixture parse_dockerfile add copy" "${CLI[@]}" skills run parse_dockerfile --input-file "$FIXTURES_ROOT/dockerfile/add-copy.Dockerfile" --format pretty
run_ok "fixture parse_dockerfile malformed" "${CLI[@]}" skills run parse_dockerfile --input-file "$FIXTURES_ROOT/dockerfile/malformed.Dockerfile" --format pretty
run_ok "fixture parse_github_actions_workflow basic" "${CLI[@]}" skills run parse_github_actions_workflow --input-file "$FIXTURES_ROOT/github-actions/basic-workflow.yml" --format pretty
run_ok "fixture parse_github_actions_workflow permissions" "${CLI[@]}" skills run parse_github_actions_workflow --input-file "$FIXTURES_ROOT/github-actions/permissions-workflow.yml" --format pretty
run_ok "fixture parse_github_actions_workflow reusable" "${CLI[@]}" skills run parse_github_actions_workflow --input-file "$FIXTURES_ROOT/github-actions/reusable-workflow.yml" --format pretty
run_ok "fixture parse_github_actions_workflow malformed" "${CLI[@]}" skills run parse_github_actions_workflow --input-file "$FIXTURES_ROOT/github-actions/malformed-workflow.yml" --format pretty
run_ok "fixture parse_trufflehog_ndjson git results" "${CLI[@]}" skills run parse_trufflehog_ndjson --input-file "$FIXTURES_ROOT/trufflehog/git-results.ndjson" --format pretty
run_ok "fixture parse_trufflehog_ndjson source metadata" "${CLI[@]}" skills run parse_trufflehog_ndjson --input-file "$FIXTURES_ROOT/trufflehog/source-metadata.ndjson" --format pretty
run_ok "fixture parse_trufflehog_ndjson malformed lines" "${CLI[@]}" skills run parse_trufflehog_ndjson --input-file "$FIXTURES_ROOT/trufflehog/malformed-lines.ndjson" --format pretty
run_ok "fixture parse_trufflehog_ndjson lowercase fields" "${CLI[@]}" skills run parse_trufflehog_ndjson --input-file "$FIXTURES_ROOT/trufflehog/lowercase-fields.ndjson" --format pretty
run_ok_reject_output_pattern "parse_trufflehog_ndjson pretty output hides raw secrets" 'fixture-aws-secret-value' "${CLI[@]}" skills run parse_trufflehog_ndjson --input-file "$FIXTURES_ROOT/trufflehog/git-results.ndjson" --format pretty
run_ok_require_output_pattern "parse_trufflehog_ndjson pretty output includes detector summary" 'Detector names \(2\)' "${CLI[@]}" skills run parse_trufflehog_ndjson --input-file "$FIXTURES_ROOT/trufflehog/git-results.ndjson" --format pretty
run_ok "fixture parse_sarif codeql results" "${CLI[@]}" skills run parse_sarif --input-file "$FIXTURES_ROOT/sarif/codeql-results.sarif" --format pretty
run_ok "fixture parse_sarif multi run" "${CLI[@]}" skills run parse_sarif --input-file "$FIXTURES_ROOT/sarif/multi-run.sarif" --format pretty
run_ok "fixture parse_sarif malformed shapes" "${CLI[@]}" skills run parse_sarif --input-file "$FIXTURES_ROOT/sarif/malformed-shapes.sarif" --format pretty
run_ok "fixture parse_sarif minimal" "${CLI[@]}" skills run parse_sarif --input-file "$FIXTURES_ROOT/sarif/minimal.sarif" --format pretty
run_ok_require_output_pattern "parse_sarif pretty output includes result levels" 'Result levels \(2\)' "${CLI[@]}" skills run parse_sarif --input-file "$FIXTURES_ROOT/sarif/codeql-results.sarif" --format pretty
run_ok_require_output_pattern "parse_sarif pretty output includes location refs" 'src/app\[.\]ts:42' "${CLI[@]}" skills run parse_sarif --input-file "$FIXTURES_ROOT/sarif/codeql-results.sarif" --format pretty
run_ok "fixture parse_semgrep_json results" "${CLI[@]}" skills run parse_semgrep_json --input-file "$FIXTURES_ROOT/scanners/semgrep-results.json" --format pretty
run_ok_require_output_pattern "parse_semgrep_json pretty output includes result count" '"result_count": 2' "${CLI[@]}" skills run parse_semgrep_json --input-file "$FIXTURES_ROOT/scanners/semgrep-results.json" --format pretty
run_ok "fixture parse_checkov_json results" "${CLI[@]}" skills run parse_checkov_json --input-file "$FIXTURES_ROOT/scanners/checkov-results.json" --format pretty
run_ok_require_output_pattern "parse_checkov_json pretty output includes failed count" '"failed_count": 1' "${CLI[@]}" skills run parse_checkov_json --input-file "$FIXTURES_ROOT/scanners/checkov-results.json" --format pretty
run_ok "fixture parse_grype_json results" "${CLI[@]}" skills run parse_grype_json --input-file "$FIXTURES_ROOT/scanners/grype-results.json" --format pretty
run_ok_require_output_pattern "parse_grype_json pretty output includes match count" '"match_count": 1' "${CLI[@]}" skills run parse_grype_json --input-file "$FIXTURES_ROOT/scanners/grype-results.json" --format pretty

SCANNER_NORMALIZE_INPUT="$TMP_ROOT/semgrep.parsed.json"
SCANNER_DEDUPE_INPUT="$TMP_ROOT/semgrep.normalized.json"
SCANNER_DEDUPE_SCRIPT="$TMP_ROOT/scanner-normalize-dedupe.sh"
cat >"$SCANNER_DEDUPE_SCRIPT" <<SCRIPT
#!/usr/bin/env bash
set -euo pipefail
pnpm --filter @security-workbench/cli start skills run parse_semgrep_json --input-file "$FIXTURES_ROOT/scanners/semgrep-results.json" > "$SCANNER_NORMALIZE_INPUT"
pnpm --filter @security-workbench/cli start skills run normalize_scanner_results --input-file "$SCANNER_NORMALIZE_INPUT" --format pretty
pnpm --filter @security-workbench/cli start skills run normalize_scanner_results --input-file "$SCANNER_NORMALIZE_INPUT" > "$SCANNER_DEDUPE_INPUT"
pnpm --filter @security-workbench/cli start skills run dedupe_scanner_results --input-file "$SCANNER_DEDUPE_INPUT" --format pretty
SCRIPT
chmod +x "$SCANNER_DEDUPE_SCRIPT"

run_ok "fixture normalize/dedupe scanner results" "$SCANNER_DEDUPE_SCRIPT"
run_ok_require_output_pattern "normalize_scanner_results pretty output includes normalized count" '"normalized_result_count": 2' "$SCANNER_DEDUPE_SCRIPT"
run_ok_require_output_pattern "dedupe_scanner_results pretty output includes unique count" '"unique_result_count": 2' "$SCANNER_DEDUPE_SCRIPT"
run_ok "fixture parse_pem_certificate example cert" "${CLI[@]}" skills run parse_pem_certificate --input-file "$FIXTURES_ROOT/certificates/example-cert.pem" --format pretty
run_ok_require_output_pattern "parse_pem_certificate pretty output includes certificate count" '"valid_certificate_count": 1' "${CLI[@]}" skills run parse_pem_certificate --input-file "$FIXTURES_ROOT/certificates/example-cert.pem" --format pretty
run_ok "fixture parse_lockfiles package lock" "${CLI[@]}" skills run parse_lockfiles --input-file "$FIXTURES_ROOT/lockfiles/package-lock.json" --format pretty
run_ok "fixture parse_lockfiles pnpm lock" "${CLI[@]}" skills run parse_lockfiles --input-file "$FIXTURES_ROOT/lockfiles/pnpm-lock.yaml" --format pretty
run_ok "fixture parse_lockfiles yarn lock" "${CLI[@]}" skills run parse_lockfiles --input-file "$FIXTURES_ROOT/lockfiles/yarn.lock" --format pretty
run_ok_require_output_pattern "parse_lockfiles pretty output includes package count" '"package_count": 2' "${CLI[@]}" skills run parse_lockfiles --input-file "$FIXTURES_ROOT/lockfiles/package-lock.json" --format pretty
run_ok "fixture parse_http_headers duplicate headers" "${CLI[@]}" skills run parse_http_headers --input-file "$FIXTURES_ROOT/http-headers/duplicate-headers.txt" --format pretty
run_ok "fixture parse_http_headers malformed headers" "${CLI[@]}" skills run parse_http_headers --input-file "$FIXTURES_ROOT/http-headers/malformed-headers.txt" --format pretty
run_ok "fixture parse_email_headers sample" "${CLI[@]}" skills run parse_email_headers --input-file "$FIXTURES_ROOT/email/sample-headers.txt" --format pretty
run_ok "fixture parse_csv assets" "${CLI[@]}" skills run parse_csv --input-file "$FIXTURES_ROOT/csv/assets.csv" --format pretty
run_ok "fixture parse_csv irregular rows" "${CLI[@]}" skills run parse_csv --input-file "$FIXTURES_ROOT/csv/irregular-rows.csv" --format pretty
run_ok "fixture parse_yaml app config" "${CLI[@]}" skills run parse_yaml --input-file "$FIXTURES_ROOT/yaml/app-config.yaml" --format pretty
run_ok "fixture parse_yaml multi-document" "${CLI[@]}" skills run parse_yaml --input-file "$FIXTURES_ROOT/yaml/multi-document.yaml" --format pretty
run_ok "fixture parse_package_json basic" "${CLI[@]}" skills run parse_package_json --input-file "$FIXTURES_ROOT/package-json/basic-package.json" --format pretty
run_ok "fixture parse_ip_prefix_list mixed prefixes" "${CLI[@]}" skills run parse_ip_prefix_list --input-file "$FIXTURES_ROOT/ip-prefixes/mixed-prefixes.txt" --format pretty
run_ok "fixture parse_ip_prefix_list malformed prefixes" "${CLI[@]}" skills run parse_ip_prefix_list --input-file "$FIXTURES_ROOT/ip-prefixes/malformed-prefixes.txt" --format pretty
run_ok_require_output_pattern "parse_ip_prefix_list pretty output includes IPv6 count" 'IPv6 entries: 2' "${CLI[@]}" skills run parse_ip_prefix_list --input-file "$FIXTURES_ROOT/ip-prefixes/mixed-prefixes.txt" --format pretty
run_ok_require_output_pattern "parse_ip_prefix_list pretty output includes duplicate summary" 'Duplicate entries: 1' "${CLI[@]}" skills run parse_ip_prefix_list --input-file "$FIXTURES_ROOT/ip-prefixes/mixed-prefixes.txt" --format pretty
run_ok "fixture parse_asn_list ASN list" "${CLI[@]}" skills run parse_asn_list --input-file "$FIXTURES_ROOT/asn/asn-list.txt" --format pretty
run_ok "fixture parse_asn_list malformed ASN list" "${CLI[@]}" skills run parse_asn_list --input-file "$FIXTURES_ROOT/asn/malformed-asn-list.txt" --format pretty
run_ok_require_output_pattern "parse_asn_list pretty output includes unique ASN count" 'Unique ASNs: 3' "${CLI[@]}" skills run parse_asn_list --input-file "$FIXTURES_ROOT/asn/asn-list.txt" --format pretty
run_ok_require_output_pattern "parse_asn_list pretty output includes duplicate summary" 'Duplicate entries: 1' "${CLI[@]}" skills run parse_asn_list --input-file "$FIXTURES_ROOT/asn/asn-list.txt" --format pretty
run_ok "fixture parse_asn_allow_deny_list policy list" "${CLI[@]}" skills run parse_asn_allow_deny_list --input-file "$FIXTURES_ROOT/asn/asn-allow-deny-list.txt" --format pretty
run_ok "fixture parse_asn_allow_deny_list malformed policy list" "${CLI[@]}" skills run parse_asn_allow_deny_list --input-file "$FIXTURES_ROOT/asn/malformed-asn-allow-deny-list.txt" --format pretty
run_ok_require_output_pattern "parse_asn_allow_deny_list pretty output includes conflict summary" 'Conflicting entries: 1' "${CLI[@]}" skills run parse_asn_allow_deny_list --input-file "$FIXTURES_ROOT/asn/asn-allow-deny-list.txt" --format pretty
run_ok_require_output_pattern "parse_asn_allow_deny_list pretty output includes deny count" 'Deny entries: 2' "${CLI[@]}" skills run parse_asn_allow_deny_list --input-file "$FIXTURES_ROOT/asn/asn-allow-deny-list.txt" --format pretty
run_ok "fixture parse_asn_observations observations" "${CLI[@]}" skills run parse_asn_observations --input-file "$FIXTURES_ROOT/asn/asn-observations.txt" --format pretty
run_ok "fixture parse_asn_observations malformed observations" "${CLI[@]}" skills run parse_asn_observations --input-file "$FIXTURES_ROOT/asn/malformed-asn-observations.txt" --format pretty
run_ok_require_output_pattern "parse_asn_observations pretty output includes repeated summary" 'Repeated ASNs: 1' "${CLI[@]}" skills run parse_asn_observations --input-file "$FIXTURES_ROOT/asn/asn-observations.txt" --format pretty
run_ok_require_output_pattern "parse_asn_observations pretty output includes source summary" 'With indicator/source/timestamp: 4/3/1' "${CLI[@]}" skills run parse_asn_observations --input-file "$FIXTURES_ROOT/asn/asn-observations.txt" --format pretty
run_ok "fixture parse_bgp_prefix_table prefix table" "${CLI[@]}" skills run parse_bgp_prefix_table --input-file "$FIXTURES_ROOT/asn/bgp-prefix-table.txt" --format pretty
run_ok "fixture parse_bgp_prefix_table malformed prefix table" "${CLI[@]}" skills run parse_bgp_prefix_table --input-file "$FIXTURES_ROOT/asn/malformed-bgp-prefix-table.txt" --format pretty
run_ok_require_output_pattern "parse_bgp_prefix_table pretty output includes conflict summary" 'Conflicting prefixes: 1' "${CLI[@]}" skills run parse_bgp_prefix_table --input-file "$FIXTURES_ROOT/asn/bgp-prefix-table.txt" --format pretty
run_ok_require_output_pattern "parse_bgp_prefix_table pretty output includes IPv6 count" 'IPv6 prefixes: 1' "${CLI[@]}" skills run parse_bgp_prefix_table --input-file "$FIXTURES_ROOT/asn/bgp-prefix-table.txt" --format pretty
run_ok "fixture extract_iocs mixed" "${CLI[@]}" skills run extract_iocs --input-file "$FIXTURES_ROOT/iocs/mixed-iocs.txt" --format pretty

run_ok_require_output_pattern "extract_iocs pretty output defangs URLs" 'hxxps://evil\[.\]example\[.\]com/path' "${CLI[@]}" skills run extract_iocs --input-file "$FIXTURES_ROOT/iocs/mixed-iocs.txt" --format pretty
run_ok_reject_output_pattern "extract_iocs pretty output hides raw URLs" 'https://evil\.example\.com/path' "${CLI[@]}" skills run extract_iocs --input-file "$FIXTURES_ROOT/iocs/mixed-iocs.txt" --format pretty
run_ok_require_output_pattern "extract_iocs unsafe pretty output allows raw URLs" 'https://evil\.example\.com/path' "${CLI[@]}" skills run extract_iocs --input-file "$FIXTURES_ROOT/iocs/mixed-iocs.txt" --format pretty --unsafe
run_expect_fail "skills run rejects unsafe with json format" "${CLI[@]}" skills run extract_iocs --input-file "$FIXTURES_ROOT/iocs/mixed-iocs.txt" --format json --unsafe

run_ok "skills describe parse_browser_extension_manifest --format table" \
  pnpm --filter @security-workbench/cli start skills describe parse_browser_extension_manifest --format table

run_ok "skills describe parse_ip_prefix_list --format table" \
  pnpm --filter @security-workbench/cli start skills describe parse_ip_prefix_list --format table

run_ok "skills describe parse_asn_list --format table" \
  pnpm --filter @security-workbench/cli start skills describe parse_asn_list --format table

run_ok "skills describe parse_asn_allow_deny_list --format table" \
  pnpm --filter @security-workbench/cli start skills describe parse_asn_allow_deny_list --format table

run_ok "skills describe parse_asn_observations --format table" \
  pnpm --filter @security-workbench/cli start skills describe parse_asn_observations --format table

run_ok "skills describe parse_bgp_prefix_table --format table" \
  pnpm --filter @security-workbench/cli start skills describe parse_bgp_prefix_table --format table

run_ok_require_output_pattern "parser list includes parse_ip_prefix_list" '^parse_ip_prefix_list[[:space:]]' \
  pnpm --filter @security-workbench/cli start skills list --category parser --format tsv

run_ok_require_output_pattern "parser list includes parse_asn_list" '^parse_asn_list[[:space:]]' \
  pnpm --filter @security-workbench/cli start skills list --category parser --format tsv

run_ok_require_output_pattern "parser list includes parse_asn_allow_deny_list" '^parse_asn_allow_deny_list[[:space:]]' \
  pnpm --filter @security-workbench/cli start skills list --category parser --format tsv

run_ok_require_output_pattern "parser list includes parse_asn_observations" '^parse_asn_observations[[:space:]]' \
  pnpm --filter @security-workbench/cli start skills list --category parser --format tsv

run_ok_require_output_pattern "parser list includes parse_bgp_prefix_table" '^parse_bgp_prefix_table[[:space:]]' \
  pnpm --filter @security-workbench/cli start skills list --category parser --format tsv

run_ok_require_output_pattern "parser list includes parse_browser_extension_manifest" '^parse_browser_extension_manifest[[:space:]]' \
  pnpm --filter @security-workbench/cli start skills list --category parser --format tsv

run_ok "fixture parse_browser_extension_manifest v3 basic" \
  pnpm --filter @security-workbench/cli start skills run parse_browser_extension_manifest --input-file "$FIXTURES_ROOT/browser-extension/manifest-v3-basic.json" --format pretty

# Browser extension common-variant fixture coverage
run_ok "fixture parse_browser_extension_manifest v2 basic" "${CLI[@]}" skills run parse_browser_extension_manifest --input-file "$FIXTURES_ROOT/browser-extension/manifest-v2-basic.json" --format pretty
run_ok "fixture parse_browser_extension_manifest v2 broad hosts" "${CLI[@]}" skills run parse_browser_extension_manifest --input-file "$FIXTURES_ROOT/browser-extension/manifest-v2-broad-hosts.json" --format pretty
run_ok "fixture parse_browser_extension_manifest v3 dnr" "${CLI[@]}" skills run parse_browser_extension_manifest --input-file "$FIXTURES_ROOT/browser-extension/manifest-v3-dnr.json" --format pretty
run_ok "fixture parse_browser_extension_manifest firefox gecko" "${CLI[@]}" skills run parse_browser_extension_manifest --input-file "$FIXTURES_ROOT/browser-extension/manifest-firefox-gecko.json" --format pretty
run_ok "fixture parse_browser_extension_manifest firefox legacy applications" "${CLI[@]}" skills run parse_browser_extension_manifest --input-file "$FIXTURES_ROOT/browser-extension/manifest-firefox-legacy-applications.json" --format pretty
run_ok "fixture parse_browser_extension_manifest safari compatible" "${CLI[@]}" skills run parse_browser_extension_manifest --input-file "$FIXTURES_ROOT/browser-extension/manifest-safari-compatible.json" --format pretty
run_ok "fixture parse_browser_extension_manifest unknown keys" "${CLI[@]}" skills run parse_browser_extension_manifest --input-file "$FIXTURES_ROOT/browser-extension/manifest-unknown-keys.json" --format pretty

run_expect_fail "parse_browser_extension_manifest rejects invalid JSON" \
  pnpm --filter @security-workbench/cli start skills run parse_browser_extension_manifest --input '{bad json}'

run_ok "skills describe review_browser_extension_permissions --format table" \
  pnpm --filter @security-workbench/cli start skills describe review_browser_extension_permissions --format table

run_ok_require_output_pattern "reviewer list includes review_browser_extension_permissions" '^review_browser_extension_permissions[[:space:]]' \
  pnpm --filter @security-workbench/cli start skills list --category reviewer --format tsv

run_expect_fail "review_browser_extension_permissions rejects raw manifest" \
  pnpm --filter @security-workbench/cli start skills run review_browser_extension_permissions --input '{"manifest_version":3,"name":"Raw"}'

BROWSER_EXT_REVIEW_INPUT="$TMP_ROOT/browser-extension-v2-broad-hosts.parsed.json"
BROWSER_EXT_REVIEW_SCRIPT="$TMP_ROOT/review-browser-extension-permissions.sh"
cat >"$BROWSER_EXT_REVIEW_SCRIPT" <<SCRIPT
#!/usr/bin/env bash
set -euo pipefail
pnpm --filter @security-workbench/cli start skills run parse_browser_extension_manifest --input-file "$FIXTURES_ROOT/browser-extension/manifest-v2-broad-hosts.json" > "$BROWSER_EXT_REVIEW_INPUT"
pnpm --filter @security-workbench/cli start skills run review_browser_extension_permissions --input-file "$BROWSER_EXT_REVIEW_INPUT" --format pretty
SCRIPT
chmod +x "$BROWSER_EXT_REVIEW_SCRIPT"

run_ok "fixture review_browser_extension_permissions v2 broad hosts" "$BROWSER_EXT_REVIEW_SCRIPT"
run_ok_require_output_pattern "review_browser_extension_permissions pretty output includes broad host signal" 'Broad host permissions \(1\)' "$BROWSER_EXT_REVIEW_SCRIPT"
run_ok_require_output_pattern "review_browser_extension_permissions pretty output includes signal type" 'browser_extension\.broad_host_permissions_present' "$BROWSER_EXT_REVIEW_SCRIPT"

run_ok "skills describe score_browser_extension_risk --format table" \
  pnpm --filter @security-workbench/cli start skills describe score_browser_extension_risk --format table

run_ok_require_output_pattern "scoring list includes score_browser_extension_risk" '^score_browser_extension_risk[[:space:]]' \
  pnpm --filter @security-workbench/cli start skills list --category scoring --format tsv

run_expect_fail "score_browser_extension_risk rejects raw manifest" \
  pnpm --filter @security-workbench/cli start skills run score_browser_extension_risk --input '{"manifest_version":3,"name":"Raw"}'

BROWSER_EXT_SCORE_INPUT="$TMP_ROOT/browser-extension-v2-broad-hosts.review.json"
BROWSER_EXT_SCORE_SCRIPT="$TMP_ROOT/score-browser-extension-risk.sh"
cat >"$BROWSER_EXT_SCORE_SCRIPT" <<SCRIPT
#!/usr/bin/env bash
set -euo pipefail
pnpm --filter @security-workbench/cli start skills run parse_browser_extension_manifest --input-file "$FIXTURES_ROOT/browser-extension/manifest-v2-broad-hosts.json" > "$BROWSER_EXT_REVIEW_INPUT"
pnpm --filter @security-workbench/cli start skills run review_browser_extension_permissions --input-file "$BROWSER_EXT_REVIEW_INPUT" > "$BROWSER_EXT_SCORE_INPUT"
pnpm --filter @security-workbench/cli start skills run score_browser_extension_risk --input-file "$BROWSER_EXT_SCORE_INPUT" --format pretty
SCRIPT
chmod +x "$BROWSER_EXT_SCORE_SCRIPT"

run_ok "fixture score_browser_extension_risk v2 broad hosts" "$BROWSER_EXT_SCORE_SCRIPT"
run_ok_require_output_pattern "score_browser_extension_risk pretty output includes score" 'Browser Extension Risk Score' "$BROWSER_EXT_SCORE_SCRIPT"
run_ok_require_output_pattern "score_browser_extension_risk pretty output includes attention" 'Review attention: ' "$BROWSER_EXT_SCORE_SCRIPT"
run_ok_require_output_pattern "score_browser_extension_risk pretty output includes contribution" 'browser_extension\.all_urls_permission_present' "$BROWSER_EXT_SCORE_SCRIPT"

run_ok "skills describe generate_browser_extension_finding --format table" \
  pnpm --filter @security-workbench/cli start skills describe generate_browser_extension_finding --format table

run_ok_require_output_pattern "output list includes generate_browser_extension_finding" '^generate_browser_extension_finding[[:space:]]' \
  pnpm --filter @security-workbench/cli start skills list --category output --format tsv

run_ok_require_output_pattern "output list includes generate_finding" '^generate_finding[[:space:]]' \
  pnpm --filter @security-workbench/cli start skills list --category output --format tsv
run_ok_require_output_pattern "output list includes export_markdown" '^export_markdown[[:space:]]' \
  pnpm --filter @security-workbench/cli start skills list --category output --format tsv
run_ok_require_output_pattern "output list includes export_json" '^export_json[[:space:]]' \
  pnpm --filter @security-workbench/cli start skills list --category output --format tsv

run_ok "skills describe generate_finding --format table" \
  pnpm --filter @security-workbench/cli start skills describe generate_finding --format table
run_ok "skills describe export_markdown --format table" \
  pnpm --filter @security-workbench/cli start skills describe export_markdown --format table
run_ok "skills describe export_json --format table" \
  pnpm --filter @security-workbench/cli start skills describe export_json --format table

run_expect_fail "generate_browser_extension_finding rejects raw manifest" \
  pnpm --filter @security-workbench/cli start skills run generate_browser_extension_finding --input '{"manifest_version":3,"name":"Raw"}'

BROWSER_EXT_FINDING_INPUT="$TMP_ROOT/browser-extension-v2-broad-hosts.score.json"
BROWSER_EXT_FINDING_SCRIPT="$TMP_ROOT/generate-browser-extension-finding.sh"
cat >"$BROWSER_EXT_FINDING_SCRIPT" <<SCRIPT
#!/usr/bin/env bash
set -euo pipefail
pnpm --filter @security-workbench/cli start skills run parse_browser_extension_manifest --input-file "$FIXTURES_ROOT/browser-extension/manifest-v2-broad-hosts.json" > "$BROWSER_EXT_REVIEW_INPUT"
pnpm --filter @security-workbench/cli start skills run review_browser_extension_permissions --input-file "$BROWSER_EXT_REVIEW_INPUT" > "$BROWSER_EXT_SCORE_INPUT"
pnpm --filter @security-workbench/cli start skills run score_browser_extension_risk --input-file "$BROWSER_EXT_SCORE_INPUT" > "$BROWSER_EXT_FINDING_INPUT"
pnpm --filter @security-workbench/cli start skills run generate_browser_extension_finding --input-file "$BROWSER_EXT_FINDING_INPUT" --format pretty
SCRIPT
chmod +x "$BROWSER_EXT_FINDING_SCRIPT"

run_ok "fixture generate_browser_extension_finding v2 broad hosts" "$BROWSER_EXT_FINDING_SCRIPT"
run_ok_require_output_pattern "generate_browser_extension_finding pretty output includes finding" 'Browser Extension Finding' "$BROWSER_EXT_FINDING_SCRIPT"
run_ok_require_output_pattern "generate_browser_extension_finding pretty output includes score" 'Score: [0-9]+/100' "$BROWSER_EXT_FINDING_SCRIPT"
run_ok_require_output_pattern "generate_browser_extension_finding pretty output includes finding id" 'finding_browser_extension_permission_review' "$BROWSER_EXT_FINDING_SCRIPT"

STATIC_WORKFLOW_EXPORT_INPUT="$TMP_ROOT/static-analysis.workflow.json"
STATIC_EXPORT_SCRIPT="$TMP_ROOT/static-analysis-generic-exports.sh"
cat >"$STATIC_EXPORT_SCRIPT" <<SCRIPT
#!/usr/bin/env bash
set -euo pipefail
pnpm --filter @security-workbench/cli start workflows run static_analysis_triage --input-file "$FIXTURES_ROOT/sarif/codeql-results.sarif" > "$STATIC_WORKFLOW_EXPORT_INPUT"
pnpm --filter @security-workbench/cli start skills run generate_finding --input-file "$STATIC_WORKFLOW_EXPORT_INPUT" --format pretty
pnpm --filter @security-workbench/cli start skills run export_markdown --input-file "$STATIC_WORKFLOW_EXPORT_INPUT" --format pretty
pnpm --filter @security-workbench/cli start skills run export_json --input-file "$STATIC_WORKFLOW_EXPORT_INPUT" --format pretty
SCRIPT
chmod +x "$STATIC_EXPORT_SCRIPT"

run_ok "fixture generic output helpers static-analysis workflow" "$STATIC_EXPORT_SCRIPT"
run_ok_require_output_pattern "generate_finding/export_markdown/export_json output includes generic finding" 'generic_finding' "$STATIC_EXPORT_SCRIPT"
run_ok_require_output_pattern "export_markdown output includes markdown export" 'markdown_export' "$STATIC_EXPORT_SCRIPT"
run_ok_require_output_pattern "export_json output includes json export" 'json_export' "$STATIC_EXPORT_SCRIPT"

run_ok "fixture parse_jwt alg none" "${CLI[@]}" skills run parse_jwt --input-file "$FIXTURES_ROOT/jwt/alg-none.jwt" --format pretty

log_section "SOURCE AUDIT: suspicious API scan"
log "Expected hits: bounded readFile/stat in apps/cli/src/args.ts and filesystem helpers in CLI tests."
log "Expected benign text hit: unicode_escape_decode description contains 'without eval'."
log "Unexpected hits: fetch, child_process, exec, spawn, process.env, network modules, or filesystem use inside runtime/plugin packages."

AUDIT_RAW="$TMP_ROOT/source-audit-raw.txt"
AUDIT_UNEXPECTED="$TMP_ROOT/source-audit-unexpected.txt"

grep -RInE '\b(fetch|XMLHttpRequest|WebSocket|child_process|exec|spawn|fork|eval|Function|process\.env|fs\.|readFile|writeFile|appendFile|rmSync|unlink|mkdir|net\.|dns\.|http\.|https\.)\b' apps packages plugins --exclude-dir=node_modules --exclude-dir=dist >"$AUDIT_RAW" 2>&1 || true
cat "$AUDIT_RAW" >>"$OUT"

awk '
  /^apps\/cli\/src\/args\.ts:1:import \{ readFile, stat \} from "node:fs\/promises";$/ { next }
  /^apps\/cli\/src\/args\.ts:[0-9]+:    content = await readFile\(filePath\);$/ { next }
  /^apps\/cli\/tests\/args\.test\.ts:1:import \{ mkdir, mkdtemp, rm, writeFile \} from "node:fs\/promises";$/ { next }
  /^apps\/cli\/tests\/args\.test\.ts:[0-9]+:      await writeFile\(file, / { next }
  /^plugins\/core-utilities\/src\/unicodeEscapeDecode\.ts:[0-9]+:    description: "Decode common JavaScript-style Unicode and character escapes without eval\.",$/ { next }
  { print }
' "$AUDIT_RAW" >"$AUDIT_UNEXPECTED"

if [[ -s "$AUDIT_UNEXPECTED" ]]; then
  log ""
  log "SOURCE_AUDIT_RESULT=FAIL_UNEXPECTED_HITS"
  if [[ "$VERBOSE" -eq 1 ]]; then
    cat "$AUDIT_UNEXPECTED" | tee -a "$OUT"
  else
    cat "$AUDIT_UNEXPECTED" >>"$OUT"
  fi
  ASSERT_FAIL_COUNT=$((ASSERT_FAIL_COUNT+1))
  terminal_status "FAIL" "source audit"
else
  log ""
  log "SOURCE_AUDIT_RESULT=PASS_NO_UNEXPECTED_HITS"
  ASSERT_PASS_COUNT=$((ASSERT_PASS_COUNT+1))
  terminal_status "PASS" "source audit"
fi

TOTAL_FAILS=$((FAIL_COUNT + EXPECTED_FAIL_FAIL_COUNT + ASSERT_FAIL_COUNT))
ELAPSED_SECONDS=$(($(date +%s) - START_EPOCH))
ELAPSED_DISPLAY="$(format_duration "$ELAPSED_SECONDS")"

log_section "SUMMARY"
log "normal_passes=$PASS_COUNT"
log "normal_failures=$FAIL_COUNT"
log "expected_failure_passes=$EXPECTED_FAIL_PASS_COUNT"
log "expected_failure_failures=$EXPECTED_FAIL_FAIL_COUNT"
log "assertion_passes=$ASSERT_PASS_COUNT"
log "assertion_failures=$ASSERT_FAIL_COUNT"
log "duration_seconds=$ELAPSED_SECONDS"
log "duration=$ELAPSED_DISPLAY"
log "output_file=$OUT"
if [[ $TOTAL_FAILS -eq 0 ]]; then
  log "OVERALL_RESULT=PASS"
  terminal_summary "PASS" "$TOTAL_FAILS" "$ELAPSED_SECONDS"
  exit 0
else
  log "OVERALL_RESULT=FAIL"
  terminal_summary "FAIL" "$TOTAL_FAILS" "$ELAPSED_SECONDS"
  exit 1
fi
