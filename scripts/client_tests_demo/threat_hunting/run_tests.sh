#!/usr/bin/env bash
#
# run_tests.sh — automated test runner for the OpenTARS Threat Hunting API client.
#
# Executes a T1-T17 test plan against a running server, driving
# api_client_threat_hunting.py through a representative, non-destructive hunt
# lifecycle: create a package, attach evidence, start generation, register and
# test a SIEM connector, approve the package, generate/read a report, and read
# the cross-hunt tracking dashboard — then cleans up (archives) the package
# and deletes the connector it created. Every run creates a fresh results
# directory test-client-<epoch>/ containing:
#   - T1..T17 markdown files (one per test: command + captured response)
#   - script-run.log   the exact api_client_threat_hunting.py invocation per test
#                       (password masked; API keys are not used by this runner)
#   - execution.log    timestamps, per-test status/exit code, and any errors
#
# Connection and credentials are read from a .env file (default: ./.env.test,
# resolved next to this script) — same host/port/url + skip_tls_verify shape as
# the Threat Intel demo runner. A single account is used throughout (needs
# threat-researcher or admin — see docs/api-threat-hunting.md's role table);
# unlike the Threat Intel demo there is no separate push/read split here.
#
# T7/T8 (generate-start/generate-status) and T13 (report-generate) exercise
# LLM-backed pipeline steps. Without an LLM provider configured on the server
# they still complete (report-generate has a deterministic fallback summary;
# generate-start starts the pipeline regardless and its run simply ends in a
# failed/degraded state) — this runner records whatever the server returns
# rather than requiring an LLM to be present, mirroring how the Threat Intel
# demo records HTTP 503 for its own LLM-dependent NL-query tests.
#
# Usage:
#   ./run_tests.sh [ENV_FILE]
#   ./run_tests.sh --env /path/to/.env.test
#   ./run_tests.sh -k | --insecure        # skip TLS verification (self-signed)
#
# The results directory is NOT committed (see .gitignore in this folder); it is
# for local verification only.

set -u

# ── locate ourselves ─────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
API_CLIENT="${SCRIPT_DIR}/api_client_threat_hunting.py"

# Prefer the project virtualenv python, fall back to python3.
if [ -x "${REPO_ROOT}/.venv/bin/python" ]; then
  PYTHON="${REPO_ROOT}/.venv/bin/python"
else
  PYTHON="$(command -v python3 || command -v python)"
fi

# ── parse args ───────────────────────────────────────────────────────────────
ENV_FILE="${SCRIPT_DIR}/.env.test"
CLI_INSECURE=0    # -k/--insecure on the command line overrides the env-file value
USAGE="Usage: $0 [ENV_FILE] [--env <path>] [-k|--insecure]"
while [ $# -gt 0 ]; do
  case "$1" in
    --env)
      ENV_FILE="${2:?--env requires a path}"; shift 2 ;;
    -k|--insecure)
      CLI_INSECURE=1; shift ;;
    -h|--help)
      echo "${USAGE}"; exit 0 ;;
    -*)
      echo "Unknown option: $1" >&2
      echo "${USAGE}" >&2
      exit 2 ;;
    *)
      ENV_FILE="$1"; shift ;;
  esac
done

# Resolve a relative ENV_FILE against the script dir for convenience.
if [ ! -e "${ENV_FILE}" ] && [ -e "${SCRIPT_DIR}/${ENV_FILE}" ]; then
  ENV_FILE="${SCRIPT_DIR}/${ENV_FILE}"
fi

if [ ! -r "${ENV_FILE}" ]; then
  echo "Error: env file not readable: ${ENV_FILE}" >&2
  exit 1
fi
if [ ! -f "${API_CLIENT}" ]; then
  echo "Error: api_client_threat_hunting.py not found at ${API_CLIENT}" >&2
  exit 1
fi

# ── tolerant .env parser ─────────────────────────────────────────────────────
# Accepts `key=value` and `key:value`. Ignores blank lines and `#` comments.
# Splits on the FIRST delimiter only, so values may contain '=' or ':'.
HOST=""; PORT=""; URL=""; SKIP_TLS=""
USER_HUNT=""; PASS_HUNT=""
while IFS= read -r raw || [ -n "${raw}" ]; do
  line="${raw%$'\r'}"                      # strip trailing CR
  case "${line}" in
    ''|'#'*) continue ;;
  esac
  rest_eq="${line#*=}"; rest_co="${line#*:}"
  if [ "${rest_eq}" != "${line}" ] && { [ "${rest_co}" = "${line}" ] || [ ${#rest_eq} -ge ${#rest_co} ]; }; then
    key="${line%%=*}"; val="${rest_eq}"
  else
    key="${line%%:*}"; val="${rest_co}"
  fi
  key="$(printf '%s' "${key}" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
  val="$(printf '%s' "${val}" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
  # For connection keys ONLY, strip a trailing whitespace-preceded inline
  # comment; credential values are kept verbatim.
  cval="$(printf '%s' "${val}" | sed -e 's/[[:space:]]\{1,\}#.*$//' -e 's/[[:space:]]*$//')"
  case "${key}" in
    host)            HOST="${cval}" ;;
    port)            PORT="${cval}" ;;
    url|base_url)    URL="${cval}" ;;
    skip_tls_verify) SKIP_TLS="${cval}" ;;
    user_hunt)       USER_HUNT="${val}" ;;
    pass_hunt)       PASS_HUNT="${val}" ;;
  esac
done < "${ENV_FILE}"

missing=""
[ -n "${USER_HUNT}" ] || missing="${missing} user_hunt"
[ -n "${PASS_HUNT}" ] || missing="${missing} pass_hunt"
if [ -n "${missing}" ]; then
  echo "Error: ${ENV_FILE} is missing required key(s):${missing}" >&2
  echo "Expected: a target (url, OR host with optional port) plus user_hunt, pass_hunt" >&2
  echo "See .env.example for the canonical format." >&2
  exit 1
fi

# Target: either a full base URL, or host (+ optional port). Same resolution
# rules as the Threat Intel demo runner — see its README for the full writeup.
if [ -n "${URL}" ]; then
  case "${URL}" in
    http://*|https://*) ;;
    *)
      echo "Error: 'url' must include a scheme, e.g. https://host or https://host/alias" >&2
      echo "       (got: ${URL})" >&2
      exit 1 ;;
  esac
  if [ -n "${HOST}" ] || [ -n "${PORT}" ]; then
    echo "Warning: both 'url' and host/port set in ${ENV_FILE}; using url and ignoring host/port." >&2
  fi
  BASE_URL="${URL%/}"
else
  if [ -z "${HOST}" ]; then
    echo "Error: no target in ${ENV_FILE}: set 'url', or 'host' (port optional)" >&2
    echo "See .env.example for the canonical format." >&2
    exit 1
  fi
  scheme="http://"
  authority="${HOST}"
  case "${HOST}" in
    http://*)  scheme="http://";  authority="${HOST#http://}" ;;
    https://*) scheme="https://"; authority="${HOST#https://}" ;;
  esac
  authority="${authority%/}"
  if [ -n "${PORT}" ]; then
    case "${authority}" in
      *:[0-9]*)
        echo "Warning: 'host' already includes a port; ignoring the separate 'port=${PORT}'." >&2 ;;
      *)
        authority="${authority}:${PORT}" ;;
    esac
  fi
  BASE_URL="${scheme}${authority}"
fi

INSECURE=0
case "$(printf '%s' "${SKIP_TLS}" | tr '[:upper:]' '[:lower:]')" in
  1|true|yes|on) INSECURE=1 ;;
esac
[ "${CLI_INSECURE}" -eq 1 ] && INSECURE=1

INSECURE_ARGS=()
if [ "${INSECURE}" -eq 1 ]; then
  INSECURE_ARGS=( --insecure )
fi

# ── results directory ────────────────────────────────────────────────────────
EPOCH="$(date +%s)"
OUT_DIR="${SCRIPT_DIR}/test-client-${EPOCH}"
mkdir -p "${OUT_DIR}"
RUN_LOG="${OUT_DIR}/script-run.log"
EXEC_LOG="${OUT_DIR}/execution.log"
: > "${RUN_LOG}"
: > "${EXEC_LOG}"

ts() { date '+%Y-%m-%dT%H:%M:%S%z'; }
exec_log() { printf '%s %s\n' "$(ts)" "$*" >> "${EXEC_LOG}"; }

exec_log "run started: env=${ENV_FILE} base_url=${BASE_URL} out_dir=${OUT_DIR}"
exec_log "python=${PYTHON}"
if [ "${INSECURE}" -eq 1 ]; then
  exec_log "TLS certificate verification DISABLED (--insecure): accepting self-signed / untrusted certs"
fi

# A small sample file for the evidence-add-file test.
SAMPLE_FILE="${OUT_DIR}/sample-evidence.txt"
cat > "${SAMPLE_FILE}" <<'EOF'
Threat hunting demo evidence file.
Example indicators for local verification only: 203.0.113.10, evil-example.test
EOF

# ── per-test driver ──────────────────────────────────────────────────────────
# run_test <num> <slug> <title> <description> -- <api_client args...>
# Sets LAST_OUT (raw stdout, for chaining ids into later tests).
LAST_OUT=""
run_test() {
  local num="$1" slug="$2" title="$3" desc="$4"
  shift 4
  [ "$1" = "--" ] && shift

  local md="${OUT_DIR}/T${num}-${slug}.md"
  local args=( --url "${BASE_URL}" "${INSECURE_ARGS[@]}" --username "${USER_HUNT}" --password "${PASS_HUNT}" "$@" )
  local disp=( api_client_threat_hunting.py --url "${BASE_URL}" "${INSECURE_ARGS[@]}" --username "${USER_HUNT}" --password '***' "$@" )

  printf 'T%s %s\n' "${num}" "${disp[*]}" >> "${RUN_LOG}"
  exec_log "T${num} ${slug} start (user=${USER_HUNT})"

  local out err rc
  out="$("${PYTHON}" "${API_CLIENT}" "${args[@]}" 2> "${OUT_DIR}/.stderr")"
  rc=$?
  err="$(cat "${OUT_DIR}/.stderr")"
  rm -f "${OUT_DIR}/.stderr"
  LAST_OUT="${out}"

  local pretty
  if [ -n "${out}" ] && pretty="$(printf '%s' "${out}" | "${PYTHON}" -m json.tool 2>/dev/null)"; then
    :
  else
    pretty="${out}"
  fi

  {
    printf '# T%s — %s\n\n' "${num}" "${title}"
    printf '%s\n\n' "${desc}"
    printf -- '- **Account:** `%s`\n' "${USER_HUNT}"
    printf -- '- **Base URL:** `%s`\n' "${BASE_URL}"
    printf -- '- **Exit code:** `%s`\n\n' "${rc}"
    printf '## Command\n\n```bash\n%s\n```\n\n' "${disp[*]}"
    if [ -n "${pretty}" ]; then
      printf '## Response\n\n```json\n%s\n```\n' "${pretty}"
    fi
    if [ -n "${err}" ]; then
      printf '\n## Errors / diagnostics\n\n```\n%s\n```\n' "${err}"
    fi
  } > "${md}"

  if [ "${rc}" -eq 0 ]; then
    exec_log "T${num} ${slug} ok (exit=0)"
  else
    exec_log "T${num} ${slug} FAILED (exit=${rc})"
    [ -n "${err}" ] && exec_log "T${num} ${slug} stderr: $(printf '%s' "${err}" | tr '\n' ' ')"
  fi
  return 0
}

# Extract a JSON field from LAST_OUT (used to chain ids between tests).
json_field() {
  printf '%s' "${LAST_OUT}" | "${PYTHON}" -c "import json,sys; print(json.load(sys.stdin).get('$1') or '')" 2>/dev/null
}

HUNT_NAME="th-client-demo-$(date +%s)"

# ── T1: create a hunt package ──────────────────────────────────────────────
run_test 1 create-package "Create a hunt package" \
  "Create a new draft hunt package." \
  -- packages-create --name "${HUNT_NAME}" --description "Local demo run, safe to delete."
PKG_ID="$(json_field id)"
exec_log "captured PKG_ID=${PKG_ID}"

# ── T2: list packages with a search filter ──────────────────────────────────
run_test 2 list-packages-search "List packages, filtered by deep search" \
  "List packages, searching for this run's own package name (issue-local-020 deep search)." \
  -- packages-list --search "${HUNT_NAME}"

# ── T3: add manual-text evidence ─────────────────────────────────────────────
run_test 3 evidence-add-text "Add manual text evidence" \
  "Attach a manual text note as evidence to the package." \
  -- evidence-add-text "${PKG_ID}" --text "Demo evidence: suspicious login attempts from 203.0.113.10." --label "Demo note"

# ── T4: add file evidence ────────────────────────────────────────────────────
run_test 4 evidence-add-file "Upload a file as evidence" \
  "Upload a small local text file as evidence (parsed later, during generation)." \
  -- evidence-add-file "${PKG_ID}" "${SAMPLE_FILE}"

# ── T5: list evidence ─────────────────────────────────────────────────────────
run_test 5 evidence-list "List evidence items" \
  "Confirm both evidence items were attached." \
  -- evidence-list "${PKG_ID}"

# ── T6: list IOCs (pre-generation, expect empty) ─────────────────────────────
run_test 6 iocs-list-empty "List IOCs before generation" \
  "IOC extraction happens during the analysis pipeline run, not at evidence-upload time — expect an empty list here." \
  -- iocs-list "${PKG_ID}"

# ── T7-T8: start generation and poll status (LLM-backed; see header note) ────
run_test 7 generate-start "Start hunt generation" \
  "Start the LLM analysis pipeline. Requires an LLM provider configured on the server for a full run; without one the run still starts and its status reflects the failure." \
  -- generate-start "${PKG_ID}"

run_test 8 generate-status "Poll generation status" \
  "Poll the generation status once, immediately after starting it." \
  -- generate-status "${PKG_ID}"

# ── T9-T11: SIEM connector lifecycle ─────────────────────────────────────────
run_test 9 connector-create "Create a SIEM connector" \
  'Register a Splunk connector profile pointing at a placeholder URL (not a real SIEM — connection will fail; see T10).' \
  -- connectors-create --data '{"name": "demo-splunk", "kind": "splunk", "base_url": "https://splunk.example.test:8089", "auth_method": "token", "api_token": "placeholder"}'
CONN_ID="$(json_field id)"
exec_log "captured CONN_ID=${CONN_ID}"

run_test 10 connector-test "Test the SIEM connector" \
  "Test the connector's connection. Expected to report ok:false — the base_url is a non-routable placeholder, not a real SIEM." \
  -- connectors-test "${CONN_ID}"

run_test 11 connector-delete "Delete the SIEM connector" \
  "Clean up the demo connector." \
  -- connectors-delete "${CONN_ID}"

# ── T12: approve the package ─────────────────────────────────────────────────
run_test 12 approve-package "Move the package to approved" \
  "Reports require the package to be approved or completed — update its status directly for this demo (normally reached via the approve-generation flow)." \
  -- packages-update "${PKG_ID}" --status approved

# ── T13-T14: report ───────────────────────────────────────────────────────────
run_test 13 report-generate "Generate the hunt report" \
  "Manually trigger report generation. The executive summary has a deterministic fallback when no LLM is configured, so this succeeds either way." \
  -- report-generate "${PKG_ID}"

run_test 14 report-get "Get the latest report" \
  "Read back the report just generated." \
  -- report-get "${PKG_ID}"

# ── T15-T16: cross-hunt tracking ─────────────────────────────────────────────
run_test 15 tracking-dashboard "Threat Intel Tracking dashboard" \
  "Cross-hunt aggregation: IOCs, CVEs, threat actors, campaigns, malware families, TTPs." \
  -- tracking-dashboard

run_test 16 tracking-hunts "Threat Intel Tracking hunts list" \
  "List every non-archived hunt with its correlation-inclusion state — the demo package should appear here." \
  -- tracking-hunts

# ── T17: cleanup ──────────────────────────────────────────────────────────────
run_test 17 delete-package "Archive (delete) the demo package" \
  "Clean up — archive the package created by this run." \
  -- packages-delete "${PKG_ID}"

exec_log "run finished: results in ${OUT_DIR}"
echo "Done. Results: ${OUT_DIR}"
echo "  - markdown:      T1..T17-*.md"
echo "  - command log:   script-run.log"
echo "  - execution log: execution.log"
