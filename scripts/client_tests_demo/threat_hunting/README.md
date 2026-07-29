# Threat Hunting API Client — Demo Test Runner

This folder contains an automated demo of the standalone Threat Hunting API
client (`api_client_threat_hunting.py`, in this directory — issue-local-029),
driven by `run_tests.sh`. It runs a T1–T17 test plan against a running
OpenTARS server and saves the results to disk. Same format as
`scripts/client_tests_demo/threat_intel/`, adapted for the Threat Hunting API.

For the full endpoint reference this client wraps, see
[`docs/api-threat-hunting.md`](../../../docs/api-threat-hunting.md).

Contents:

- `api_client_threat_hunting.py` — the standalone client itself (dependency-free,
  stdlib only). Covers every `/api/threat-hunting/*` route: packages, evidence,
  IOCs, generation/runs, SIEM connectors, execution, reports, Threat
  Intelligence, comparison, run comments, and cross-hunt tracking.
- `run_tests.sh` — the test runner (bash). Reads connection + credentials from
  a `.env` file and executes T1–T17: create a hunt package, attach evidence,
  start generation, register/test/delete a SIEM connector, approve the
  package, generate/read a report, and read the tracking dashboard — then
  archives the demo package. Non-destructive to any other data on the server.
- `.env.example` — template for the `.env.test` you create (see below).
- `T1-*.md` … `T17-*.md` — **sample recordings from an earlier run**, kept as a
  reference for the expected command + response shape of each test.

## How to run

**1. Configure connection + credentials.** Copy the example env file and edit it
(`run_tests.sh` reads `./.env.test` by default):

```bash
cp .env.example .env.test
```

Fill in `.env.test` (the parser accepts either `=` or `:` as the delimiter):

```
host=192.168.0.10
port=8000
user_hunt=analyst    # threat-researcher or admin — every test is a write
pass_hunt=...
```

Real `.env*` files are **gitignored** — only `.env.example` is committed. See
`.env.example` for the full `host`/`port`/`url`/`skip_tls_verify` targeting
rules — identical to the Threat Intel demo runner's.

**2. Run the plan.**

```bash
./run_tests.sh                      # uses ./.env.test
./run_tests.sh --env /path/to.env   # or point at another env file
./run_tests.sh -k                   # also skip TLS cert verification (insecure)
```

**3. Inspect the results.** Each run creates a fresh `test-client-<epoch>/`
directory containing:

- `T1..T17-*.md` — one markdown file per test (the exact command run + the
  captured API response),
- `script-run.log` — the `api_client_threat_hunting.py` invocation for each
  test, with the password masked,
- `execution.log` — timestamps, per-test status, and any errors.

These `test-client-*/` directories are **gitignored** — they are for local
verification only and are never committed.

## Tests

| Test | What it does |
|---|---|
| `T1-create-package` | Create a new draft hunt package |
| `T2-list-packages-search` | List packages, deep-search-filtered by this run's package name |
| `T3-evidence-add-text` | Attach a manual text note as evidence |
| `T4-evidence-add-file` | Upload a small local file as evidence |
| `T5-evidence-list` | Confirm both evidence items landed |
| `T6-iocs-list-empty` | List IOCs before generation (expect empty — extraction happens during the pipeline run) |
| `T7-generate-start` | Start the LLM analysis pipeline |
| `T8-generate-status` | Poll generation status once |
| `T9-connector-create` | Register a SIEM (Splunk) connector profile |
| `T10-connector-test` | Test the connector's connection (expected to fail — placeholder URL) |
| `T11-connector-delete` | Delete the demo connector |
| `T12-approve-package` | Move the package to `approved` (reports require approved/completed) |
| `T13-report-generate` | Manually trigger report generation |
| `T14-report-get` | Read back the generated report |
| `T15-tracking-dashboard` | Cross-hunt Threat Intel Tracking aggregation |
| `T16-tracking-hunts` | List hunts with their correlation-inclusion state |
| `T17-delete-package` | Archive the demo package (cleanup) |

**T7/T8 and T13 are LLM-backed** (hunt generation, report executive summary).
`report-generate` has a deterministic fallback summary and always succeeds
even without an LLM provider configured; `generate-start` always starts (its
*run* then ends in a degraded/failed state without a provider) — this runner
records whatever the server actually returns rather than requiring an LLM to
be present, mirroring how the Threat Intel demo records HTTP `503` for its
own LLM-dependent natural-language-query tests.

**T9/T10** register a connector pointing at a non-routable placeholder
`base_url` — `T10-connector-test` is expected to report `"ok": false`; that is
the correct, recorded behavior, not a runner bug.

## Using a scoped API key instead of a session login (issue-local-029)

`run_tests.sh` always authenticates with a session login (`--username`), since
several of its tests (connectors, execution/approval, comments) have no
API-key scope at all — see the scope table in `docs/api-threat-hunting.md`.

To exercise the **scoped API-key** path directly, call the client with
`--api-key` instead of `--username`/`--password`. Create a key from
**Configuration → General → API Access** in the web UI (admin only); its
`api_key` value (`<client_id>.<secret>`) is shown exactly once.

```bash
# Everything the issue-local-029 default profile covers:
# hunts:create, evidence:add, reports:download, iocs:read,
# threat_intel:read, threat_intel_tracking:read
API_KEY='ak_xxxxxxxxxxxx.yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy'

./api_client_threat_hunting.py --url http://HOST:8000 --api-key "$API_KEY" \
  packages-create --name "Programmatic hunt"

./api_client_threat_hunting.py --url http://HOST:8000 --api-key "$API_KEY" \
  packages-list

# A route the key's scopes don't cover (e.g. packages-update, no hunts:update
# scope in the default profile) correctly fails with 403:
./api_client_threat_hunting.py --url http://HOST:8000 --api-key "$API_KEY" \
  packages-update PKG_ID --description "x"
```

See `api_client_threat_hunting.py --help` for the full command list (every
`/api/threat-hunting/*` route has a subcommand), and
`docs/api-threat-hunting.md` for the complete scope-to-route reference.
