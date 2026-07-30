<p align="center">
  <img src="docs/assets/tars-logo.png" alt="OpenTARS" width="480" />
</p>

<h1 align="center">OpenTARS</h1>
<p align="center"><strong>Threat Agentic Research System</strong></p>

<p align="center">
  A standalone, self-hosted <strong>Threat Intelligence and Agentic Threat Hunting platform</strong>.
  It ingests, normalizes, and correlates threat intel from multiple sources, and drives end-to-end
  threat hunts through an LLM-powered agent pipeline built on
  <a href="https://github.com/langchain-ai/langgraph">LangGraph</a>.
</p>

---

## Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/Mizton-Labs/OpenTARS.git
cd OpenTARS

# 2. Start the application
./opentars start
```

The runner script automatically:

- Creates a Python virtual environment (`.venv/`) using `uv` (falls back to `python3 -m venv` + `pip` if `uv` isn't installed)
- Installs all Python dependencies from `backend/requirements.txt`
- Builds the frontend if `frontend/dist/` does not exist
- Starts the backend on **`127.0.0.1:8000`** (localhost only by default)

Open your browser at **http://localhost:8000**.

> By default the server binds to localhost only. To expose it on your network or use a different
> port, see [Binding & ports](#binding--ports).

> **Authentication is on by default.** The first time you start the app, a default `admin` account
> is provisioned and its password is displayed in the terminal and written to
> `data/first-run-admin-credentials.txt` (mode `0600`). Change the password on first login. To run
> without authentication (local / trusted-network, single-user use), start with
> `./opentars start --disable-auth` or set `auth_enabled: false` in
> `config/application.yaml`. See [Authentication](#authentication-optional) for roles and setup.

### Prerequisites

| Dependency | Version | Notes |
|---|---|---|
| Python | 3.10+ | Required for the backend |
| Node.js | 18+ | Required for the frontend |
| npm | 9+ | Bundled with Node.js |
| uv | latest | Recommended Python package manager |

**Install uv:**

```bash
# macOS / Linux
curl -LsSf https://astral.sh/uv/install.sh | sh

# Windows
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"

# Homebrew
brew install uv
```

> If `uv` is not installed, the startup script falls back to `python3 -m venv` + `pip` automatically.

---

## Features

### Threat Intel

Ingest, normalize, and search threat intelligence from any combination of sources:

- **Ingestion** — local file upload, remote URL pull, an authenticated push listener, and scheduled
  RSS / API pulls. Accepts JSON, NDJSON, CSV/TSV, and XML, including `.gz`/`.zip` compressed payloads.
- **Normalization** — an LLM-powered engine maps raw feed fields onto a canonical schema, with
  **Smart Mappings** proposals an admin reviews and approves rather than blindly trusting.
- **Viewer** — browse raw and normalized event tables side by side, with a configurable column
  picker, full-text search, and a natural-language (LLM) query box.
- **Watchers** — saved filters that continuously evaluate incoming events and publish matches to a
  public syndication URL (JSON/CSV/XML/RSS) and, optionally, push them to a webhook, Discord, Slack,
  or Microsoft Teams.

### Threat Hunting

An agentic, LangGraph-driven pipeline that turns raw evidence into a structured, reviewable hunt:

- **Hunt Packages** — gather evidence from uploaded files (PDF/DOCX/TXT/CSV), fetched URLs, imported
  watcher events, or manual notes.
- **Agent pipeline** — generates threat context, hypotheses, hunting leads, MITRE ATT&CK TTPs, SPL
  query drafts, and a Deep Retrohunt IOC set with noise scoring and defanging — all shown live in an
  interactive workflow visualization (timeline, Mermaid, or ReactFlow).
- **Operator approval gate** — every run pauses for human review before execution; nothing reaches
  the SIEM without explicit sign-off.
- **SIEM execution** — runs the approved SPL query against Splunk and interprets the results with an
  LLM-backed findings summary.
- **Two-phase Threat Intel Analyst** — correlates each run's actors, malware families, campaigns, and
  IOCs against every other hunt package in the instance, both before and after execution.
- **Threat Intel Tracking dashboard** — a cross-hunt view aggregating correlated IOCs, CVEs, threat
  actors, campaigns, and TTPs across every non-excluded hunt, with per-hunt include/exclude controls.
- **Comparison Module** — an "Assess & Compare" action that runs an LLM-backed comparison across a
  chosen subset of a package's runs, producing a combined report (Markdown/PDF/JSON download).
  Downstream reports (per-run and comparison) are professionally branded, structured, and exportable.
- **Evidence content viewer** — every uploaded evidence item stays accessible after upload: a sidebar
  list plus a content pane that renders PDFs inline and plaintext/extracted content in full.
- **Dashboard** — the module's default view: hunt/run/evidence/IOC/hypothesis/lead/query counts,
  two activity-over-time charts (hunts and IOCs per day), per-model breakdowns, and the threat
  actors/campaigns/malware families/MITRE techniques identified across every hunt. Every panel links
  straight to the matching **Data Explorer** category — the underlying row-level data, one click away.

### Search & Assistant

- **Global search** — a search icon on every page finds hunt packages, threat intel (raw and
  normalized), watchers, settings pages, and documentation by keyword, scoped to whatever the
  signed-in user's role can already see.
- **Assistant chatbot** — ask a plain-English question and get an answer sourced from your own data,
  with the matching results cited alongside it. Retrieval is deterministic and role-scoped exactly
  like the search box; the model only ever summarizes results the asking user could already reach,
  and it has no ability to create, change, or execute anything.
- **Saved sessions** — conversations are automatically saved (default name is a timestamp), and can
  be renamed, exported (Markdown/JSON/PDF), or deleted from a top bar available both in the search
  drawer and on the Assistant's own full-page sidebar entry — the same conversation either way.

### Configuration

- **LLM providers** — OpenAI, Anthropic (native API), Ollama, any OpenAI-compatible endpoint, and
  Azure AI Foundry (both its unified Model Inference API and its Anthropic-native passthrough mode).
  A staged Add-Provider wizard (Connect → Discover → Test → Add) and a config-drift-safe write-only
  API key model keep credentials out of logs and off disk in plaintext views.
- **SIEM connector profiles** (Splunk), feed sources, field defaults, application/branding settings,
  and user management all live in the same admin Configuration area.
- **Authentication** — session-based login with four roles (`admin`, `threat-researcher`,
  `threat-viewer`, `feed-sender`), optional SSO/OIDC, per-user theme preferences, and an
  admin-configurable password policy.
- **Scoped API access keys** — admin-issued bearer tokens for programmatic access to
  `/api/threat-hunting/*`, authorized purely by an explicit, per-key set of scopes rather than the
  key holder's own role — a key can never reach configuration, user management, or LLM-provider
  endpoints, no matter what scopes it holds. A key's secret is shown exactly once, at creation. See
  [`docs/api-threat-hunting.md`](docs/api-threat-hunting.md) for the full scope reference.
- **Config-drift notice** — every live, operator-editable config file
  (`application.yaml`/`sources.yaml`/`feed-fields.yaml`/`normalizer-config.yaml`) is gitignored, so
  an operator's customizations never conflict with an upgrade. When a new release ships config content
  a deployment doesn't have yet (e.g. a new built-in field), admins see a top-bar notice with a review
  screen — nothing changes until they explicitly select and apply it.

---

## Threat Hunting Workflow

```
1. Create Hunt Package     — name, description, tags
2. Add Evidence            — upload files (PDF/DOCX/TXT/CSV), fetch URLs,
                             import watcher events, paste manual notes
3. Generate Analysis       — LangGraph agents produce: threat context,
                             hypotheses, hunting leads, TTPs, SPL drafts,
                             Deep Retrohunt IOC CSV, preliminary Threat Intel
4. Operator Approval       — review draft, approve or reject/revise
5. SIEM Execution          — run SPL query against Splunk, collect events,
                             LLM-interpreted findings, final Threat Intel pass
6. Report                  — assembled executive summary + full structured
                             report; export as PDF, Markdown, or JSON
```

---

## Development Mode

Runs the backend and the Vite dev server separately for hot-reload on frontend changes:

```bash
./opentars start --dev
```

| Service | URL |
|---|---|
| Frontend (Vite) | http://localhost:5173 |
| Backend API | http://localhost:8000/api |
| API docs (Swagger) | http://localhost:8000/docs |

> URLs above assume `app_base_prefix` is empty (the default). When set, all
> URLs are served under `<prefix>/...` — e.g. `http://localhost:8000/feeds/api`.
> See `config/application.yaml` and the `--base-prefix` CLI flag.
>
> Reverse-proxy aliases (e.g. nginx `location /feeds/ → backend root`) work
> with no configuration: the frontend auto-detects the alias from
> `window.location` and uses it for routing, API fetches, and the displayed
> push URL. Set `app_base_prefix` explicitly only to PIN a specific prefix.

> Node modules are installed automatically on first run if `frontend/node_modules/` is absent.

---

## Commands

```
./opentars start [options]        Start the application
./opentars stop                   Stop all running processes
./opentars restart [options]      Stop then start (options forwarded to start)
./opentars status                 Show running process status
./opentars --reset-db             Delete and recreate all source databases
./opentars --reset-source <NAME>  Reset a single source database
./opentars --reset-admin-password Reset the admin password (see Authentication)
./opentars help                   Show full usage
```

### `start` / `restart` options

| Option | Description |
|---|---|
| `--dev` | Run uvicorn in the **foreground** with logs streamed to the terminal (Ctrl+C to stop). Without it, the server runs backgrounded. |
| `--bind <ip[:port]>` | Address (and optional port) to bind. Accepts `ip`, `ip:port`, or `:port`. If no port is given, **8000** is used. Default: `127.0.0.1:8000`. See [Binding & ports](#binding--ports). |
| `--base-prefix <value>` | Override `app_base_prefix` from `config/application.yaml` for this run only (via `OPENTARS_BASE_PREFIX`). Must start with `/`, must not end with `/`, must not contain `//`. Use `""` (empty string) to mount at root. |
| `--disable-auth` | Force-disable authentication for this run (via `OPENTARS_ENABLE_AUTH=0`, overriding the yaml). Authentication is **on by default**. See [Authentication](#authentication-optional). |

> Runtime PID and port state are written to `.pids/` (gitignored). `stop`/`status`
> read the persisted port, so they work correctly even when the server was
> started on a custom `--bind` port.

---

## Binding & ports

By default the server binds to **`127.0.0.1:8000`** — reachable only from the
local machine. Use `--bind` to change the address and/or port:

```bash
./opentars start --bind 0.0.0.0          # all interfaces, port 8000
./opentars start --bind 0.0.0.0:9000     # all interfaces, port 9000
./opentars start --bind :9000            # localhost (127.0.0.1), port 9000
./opentars start --bind 192.168.1.10:8000  # a specific interface
```

- Syntax is `ip:port`. A bare `ip` keeps the default port (8000); a bare `:port`
  keeps the default address (`127.0.0.1`).
- The port must be between **1 and 65535** — an out-of-range value is rejected.
- Binding to `0.0.0.0` exposes the service on **all network interfaces**. Only do
  this on trusted networks, and consider enabling [authentication](#authentication-optional).

---

## Authentication (optional)

Authentication is **enabled by default** — the app shows a login screen and
requires valid credentials. To disable it for local / trusted-network,
single-user use, pass `--disable-auth` per-run, set
`OPENTARS_ENABLE_AUTH=0`, or set `auth_enabled: false` in
`config/application.yaml`. The CLI flag and env var take precedence over the yaml.

```bash
./opentars start --disable-auth
```

When enabled:

<a id="user-roles"></a>

- **Roles.** Four roles:
  - `admin` — full access including Configuration, Normalizer, Threat Hunting, and User Management.
  - `threat-researcher` — full Threat Hunting access (create, edit, approve, execute hunt packages) plus read access to the Threat Intel Viewer.
  - `threat-viewer` — read-only access to hunt packages, reports, and the Threat Intel Viewer. The natural-language query endpoint (`POST /api/query/nl`) is available to this role.
  - `feed-sender` — listener-only machine account that may **only** POST to `/api/ingest/listener` — ideal for unattended push automation.

  The sidebar and API enforce role gating server-side independently of the UI.
- **SSO/OIDC.** Optional single sign-on via an OpenID Connect provider, configured from the admin
  Configuration area — see `config/sso.yaml.example` for the template.
- **Sessions.** Login is session-cookie based; all API `401`s funnel through a
  single handler and the UI redirects to the login screen.
- **First-run admin.** On first start with auth enabled, an `admin` account is
  provisioned with a random password written to
  `data/first-run-admin-credentials.txt` (mode `0600`, **gitignored**, never
  logged). You must change this password on first login; delete the file
  afterwards.
- **Reset the admin password** without starting the server:

  ```bash
  ./opentars --reset-admin-password
  ```

  This generates a new random password, prints it, writes it to the same `0600`
  credential file, and forces a password change on the next admin login.
- **Password policy.** Minimum-length and composition rules are enforced on both
  the backend and the frontend (create-user, self-service change, and admin
  reset all require a confirm-match field).
- **Self-service Account** page (change your own password, pick a personal theme) and an admin-only
  **User Management** tab (create/delete users, reset passwords) live in the app.

---

## Supported Feed Formats

Local uploads and remote pulls both accept:

- **JSON** (object or array of objects; well-known envelope keys like
  `vulnerabilities`, `data`, `results` are auto-extracted)
- **NDJSON** (one JSON object per line)
- **CSV / TSV** (auto-detected delimiter from `, \t ; |`)
- **XML** (flat one-level-deep envelopes)

Both ingest paths also transparently decompress:

- **`.gz`** (single-layer gzip)
- **`.zip`** (must contain exactly one regular-file member; empty and
  multi-member archives are rejected)

The decompressed payload is verified to be one of the four plaintext
formats above before parsing. The default decompressed-size cap is
**100 MiB**, configurable in `config/application.yaml` under
`max_decompressed_bytes`. `.7z` is intentionally not supported (avoids
a non-stdlib dependency).

---

## Push Listener (API endpoint)

The push listener lets external tools POST threat-intel events straight into the
app over HTTP. It runs on the main application port (no separate port) and is
toggled from **Configuration → Listener Endpoint** (`listener.enabled` in
`config/sources.yaml`, enabled by default).

**Generic receive** — POST any JSON (a single object or an array of objects) to:

```bash
curl -X POST http://127.0.0.1:8000/api/ingest/listener \
  -H 'Content-Type: application/json' \
  -d '[{"indicator": "1.2.3.4", "threat_type": "c2"}]'
```

Events are indexed into a **feed named after the authenticated user** that
pushed them. When authentication is disabled the request is
anonymous and falls back to a **feed named `Received Feed <epoch>`** (the Unix
time of receipt). Every payload is logged (an INFO receipt summary in
`logs/audit.log`; the full body at DEBUG), and per-entry failures are logged with
detail in `logs/app.log`.

To push into an **explicitly-named** feed instead, POST to
`/api/ingest/push/<source_name>` (single object) or
`/api/ingest/push-batch/<source_name>` (array).

> When `auth_enabled` is on (the default), ingest endpoints require an admin session;
> with authentication disabled they are open.

---

## Watchers

A **Watcher** is a user-defined saved filter that continuously evaluates
ingested events and publishes the matches to a **public per-watcher feed URL**
(and, optionally, pushes them to a webhook). Use watchers to carve a focused
syndication feed out of the firehose — e.g. *"critical CVEs affecting nginx"* or
*"anything tagged ransomware from feedA"* — that downstream tools can poll
without touching the admin API.

Watchers are managed from the admin-only **Watchers** page (Summary / Config /
Activity tabs) and the admin-gated `/api/watchers/*` API. Definitions and
triggered-event history live in a dedicated `data/watchers.db`, kept separate
from `normalized.db` so they survive normalized-schema rebuilds.

### How matching works

Each watcher has one or more **conditions**, AND-combined. A condition is a
`field` + `value` plus a `match_type`:

| `match_type` | Matches when… |
|---|---|
| `exact` | field equals value |
| `contains` | value is a substring of the field |
| `wildcard` | field matches a `*`/`?` glob |
| `regex` | field matches the regular expression |
| `gte` / `lte` | numeric field is ≥ / ≤ a numeric value |

- Leave `field` empty (or `*`/`all`/`any`) to match the value against **any**
  field. `case_sensitive` (default off) applies to `exact`, `wildcard`, and
  `contains`.
- **Scope** is set per watcher: `dataset` (`all`, `raw`, or `normalized`) and
  `feeds` (a list of source names; empty = all feeds).
- `severity` (`low`/`medium`/`high`/`critical`) is a **classification label
  only** — it does not gate matching.

### Evaluation modes

| `mode` | When it evaluates |
|---|---|
| `realtime` | Automatically when an ingestion or normalizer run completes. |
| `scheduled` | On a fixed timer every `interval_sec` seconds (min 5). |

Each watcher tracks per-source high-water marks, so only **new** events are
considered on each pass. You can also press **Trigger** in the UI (or
`POST /api/watchers/{id}/trigger`) to evaluate immediately — this works even on
a disabled watcher.

### Public feed

Matched events are published at an **unauthenticated** syndication URL (it lives
outside `/api/`, so the auth layer does not guard it):

```bash
# JSON (default); also CSV and XML/RSS via the watcher's `format`
curl http://127.0.0.1:8000/feed/watcher/<watcher-id>/
```

The `<watcher-id>` is a slug derived from the watcher name. The feed serves the
most recent matches, capped by the watcher's `max_feed_events` (and the global
`watcher_max_events` ceiling, below).

### Webhook / HTTP delivery (optional)

Set `publish_target` to `webhook` or `http` to also **push** each match to an
external endpoint. The payload is shaped by `webhook_format`:

| `webhook_format` | Target |
|---|---|
| `generic` | Plain JSON POST (the OpenTARS envelope) |
| `discord` | Discord webhook |
| `slack` | Slack incoming webhook |
| `teams` | Microsoft Teams connector |

The format is auto-detected from the webhook URL host (and overridable). An
optional `auth_header` / `auth_value` pair attaches a custom auth header.
Delivery is per-event best-effort with automatic retries; failures are surfaced
in the **Activity** tab with the last error detail for inspection.

> **Admin-only by design.** Watcher webhook URLs are admin-configured and may
> target internal hosts, so all `/api/watchers/*` routes are restricted to
> `admin` accounts. Do not expose watcher configuration to non-admin roles.

### Retention

- **Per watcher:** `max_feed_events` bounds how many matches the feed keeps; a
  periodic cleanup job trims the stored feed every `cleanup_interval_sec`
  seconds (10–86400).
- **Global ceiling:** `watcher_max_events` in `config/application.yaml` caps
  retention across every watcher (default **1000**, range **10–100000**). It is
  editable from the UI or via `GET`/`POST /api/app/watcher-max-events`.

---

## Viewer & Normalization UI

Beyond the API and watchers, the web UI exposes the core day-to-day surfaces:

- **Viewer** — browse the **Raw** and **Normalized** event tables side by side,
  with a configurable column picker, full-text search, and a natural-language
  (LLM) query box. Raw and normalized are independent stores (see
  [Raw vs normalized](#get-normalized--normalized-events)).
- **Normalizer** — run and monitor the LLM-powered normalization engine, and
  review per-run history (counts, status, timing).
- **Smart Mappings** — an admin workspace for LLM-assisted field-mapping
  suggestions, with manual overrides that feed the canonical schema (see
  [Canonical schema reconciliation](#canonical-schema-reconciliation)).

---

## API Client Script

`scripts/api_client.py` is a standalone, dependency-free (Python standard library
only) client for the **Threat Intel** API (`/api/viewer`, `/api/normalizer`,
`/api/ingest`, `/api/query/nl`, …). Run it with any Python 3 — no virtualenv needed.
Every command prints a JSON document to stdout.

> For the **Threat Hunting** API instead, see
> [Threat Hunting API Client](#threat-hunting-api-client) below — a separate,
> equally dependency-free client covering every `/api/threat-hunting/*` route.

```bash
scripts/api_client.py --help          # full syntax for all commands
```

**Global options**

- `--url` — base API endpoint URL (default `http://127.0.0.1:8000`). Include the
  scheme; use an `https://…` URL (optionally with a path prefix) to reach a
  server behind a reverse proxy / alias. The value must contain no whitespace —
  a stray inline comment (e.g. copied from a `.env` template) is rejected with a
  clear error instead of an obscure urllib traceback.
- `--username` / `-u`, `--password` / `-p` — credentials for an auth-enabled
  server (omit entirely when auth is disabled — see [Authentication](#authentication) below).
- `--insecure` / `-k` — skip TLS certificate verification (accept self-signed /
  untrusted certs). **Insecure:** disables MITM protection for the request; only
  use on a trusted network against a server you can otherwise vouch for.

### `get-raw` — raw events

Fetch the raw events table as a JSON array.

```bash
# All feeds, up to 1000 events (the default)
scripts/api_client.py get-raw

# Only two named feeds
scripts/api_client.py get-raw feedA feedB

# Cap the number of events returned
scripts/api_client.py get-raw --max 50

# Exact-column filter: only critical-severity rows (repeatable, AND-combined)
scripts/api_client.py get-raw --field severity=critical
scripts/api_client.py get-raw --field severity=critical --field indicator_type=url
```

> `--field NAME=VALUE` is a **deterministic exact-match** filter (no LLM). The
> column name is validated server-side against the table's real columns;
> unknown or unsafe names are silently dropped rather than reaching SQL, so the
> flag cannot inject arbitrary queries. Use `query` (below) for fuzzy,
> natural-language matching instead.

### `get-normalized` — normalized events

Identical interface to `get-raw`, but reads the normalized data table.

```bash
# All normalized events, up to 1000
scripts/api_client.py get-normalized

# A single feed, capped at 20 events
scripts/api_client.py get-normalized feedA --max 20

# Exact-column filter, validated against the normalized schema
scripts/api_client.py get-normalized --field indicator_type=ipv4-addr
```

> **Raw vs normalized are independent stores.** `get-raw` (and
> `search`/`query --type raw`) read the as-ingested **raw** events; `get-normalized`
> (and the `--type normalized` variants) read the **normalized** table produced by
> the normalizer. The same `--field`/`search`/`query` filter run against each can
> return different rows — raw reflects original feed fields, normalized reflects
> the mapped/canonical schema.

> With no feed names, both `get-*` commands issue a single all-feeds request.
> With feed names, they request each feed in turn and merge the results,
> truncated to `--max` (default 1000).

### `send` — push events to the listener

POST a generic JSON (a single object or an array) to `/api/ingest/listener`. The
server indexes it into a feed named after the authenticated user (or a
`Received Feed <epoch>` feed when auth is disabled). The payload can come
from a file, an inline string, or stdin:

```bash
scripts/api_client.py send --file events.json
scripts/api_client.py send --data '[{"indicator": "1.2.3.4"}]'
cat events.json | scripts/api_client.py send
```

When auth is enabled, `send` requires an **admin** or **sender** account (a
`normal` user gets `403`).

### `search` — full-text search

Search the raw or normalized table via the server-side `?search=` query. The
term is matched against indexed text fields (indicator, title, description,
tags, actor, campaign, …). Accepts the same optional feed names and `--max` as
the `get-*` commands.

```bash
# Search raw events for "npm" (default --type raw)
scripts/api_client.py search "npm" --max 20

# Search the normalized table, restricted to one feed
scripts/api_client.py search "ransomware" feedA --type normalized
```

### `query` — natural-language query (LLM)

Ask a question in plain English. The server's LLM translates it into a
**constrained, whitelisted filter** (never raw SQL), runs that filter against
the local database through the same parameterized query layer used by the rest
of the API, and returns the matched rows plus the interpreted filter. This
requires an LLM provider to be configured on the server (the same one used by
smart-mode normalization); without one the endpoint returns `503`.

```bash
# Let the server/LLM choose the dataset (defaults to normalized)
scripts/api_client.py query "critical CVEs from 2026 affecting nginx"

# Force the raw table, restrict to one feed, cap results
scripts/api_client.py query "supply-chain compromise in npm packages" \
  --type raw --source feedA --max 50
```

`--type {raw,normalized}`, `--source <feed>`, and `--max <n>` are optional
overrides: when supplied they take precedence over the LLM's choice. The
response is JSON with `dataset`, `count`, `interpreted_filter`, and `results`.

When auth is enabled, `query` is a **read** operation — available to `admin`
and `normal` accounts; `sender` accounts get `403` (push-only).

### `list-feeds` — available feeds

List the available feeds with their per-source entry counts (plus a `__total__`
row), from the summary endpoint.

```bash
scripts/api_client.py list-feeds                 # raw catalogue (default)
scripts/api_client.py list-feeds --type normalized
```

### Demo runner — run the whole test plan with one command

`scripts/client_tests_demo/threat_intel/run_tests.sh` drives `api_client.py` through the full
T1–T11 test plan against a running server and saves every result to disk. It is
the easiest way to see the client in action end to end.

**1. Configure connection + credentials.** Copy the example env file and fill it
in (it is read from `scripts/client_tests_demo/threat_intel/.env.test` by default):

```bash
cp scripts/client_tests_demo/threat_intel/.env.example scripts/client_tests_demo/threat_intel/.env.test
# then edit .env.test:
#   host [+ port]          — target host; port is OPTIONAL (defaults: 80 http / 443 https).
#                            host may include a scheme (https://host); bare host -> http. OR
#   url                    — full base URL incl. scheme (reverse-proxy alias / path prefix);
#                            wins over host/port, must include http:// or https://
#   skip_tls_verify=true   — accept self-signed/untrusted TLS (insecure; or use -k)
#   user_push / pass_push  — account used to push events (T1; a sender or admin)
#   user_read / pass_read  — account used for reads/search/queries (T2–T11; normal or admin)
```

**2. Run it.**

```bash
bash scripts/client_tests_demo/threat_intel/run_tests.sh                 # uses .env.test
bash scripts/client_tests_demo/threat_intel/run_tests.sh --env /path/to/other.env
bash scripts/client_tests_demo/threat_intel/run_tests.sh -k              # also skip TLS verification
```

**3. Read the results.** Each run creates a fresh `test-client-<epoch>/`
directory inside `scripts/client_tests_demo/threat_intel/` containing:

- `T1..T11-*.md` — one markdown file per test (the command run + the captured response),
- `script-run.log` — the exact `api_client.py` invocation for each test (password masked),
- `execution.log` — timestamps, per-test status, and any errors.

These result directories are **gitignored** — they are for local verification
only and are never committed. The natural-language tests (T7–T9) require an LLM
provider configured on the server; without one they record an HTTP `503`. The
field-search tests (T10–T11) are deterministic `--field` filters that need no
LLM.

### Authentication

Authentication is **optional**. The client adapts to whichever mode the server
runs in.

**With auth enabled (the default).** Supply `--username`; the client logs in once and reuses
the session cookie for the request. Omit `--password` to be prompted securely
(it never touches your shell history):

```bash
# prompts for the password, then fetches raw events from an auth-enabled host
scripts/api_client.py --url http://192.168.0.10:8001 --username analyst get-raw

# non-interactive (e.g. CI): pass the password explicitly
scripts/api_client.py --url http://192.168.0.10:8001 -u bot -p "$SFI_PW" \
  send --file events.json

# HTTPS behind a reverse-proxy alias, accepting a self-signed cert (insecure)
scripts/api_client.py --url https://proxy.example.com/opentars -k \
  --username analyst get-raw
```

A dedicated **sender** account (see [User roles](#user-roles)) is the recommended
identity for unattended `send` automation — it can push to the listener and
nothing else. With auth enabled, `send` requires an **admin** or **sender**
account (a `normal` user gets `403`).

**Without auth (disabled).** When the server is started with `--disable-auth`,
run any command with no credentials. `send` succeeds for anyone:

```bash
# server started with --disable-auth, no credentials needed
scripts/api_client.py get-raw
scripts/api_client.py --url http://192.168.0.10:8001 get-normalized --max 50
scripts/api_client.py --url http://192.168.0.10:8001 send --data '[{"indicator": "1.2.3.4"}]'
```

---

## Threat Hunting API Client

`scripts/client_tests_demo/threat_hunting/api_client_threat_hunting.py` is a
standalone, dependency-free (Python standard library only) client covering
**every** `/api/threat-hunting/*` route: packages, evidence, IOCs,
generation/runs, SIEM connectors, execution, reports, Threat Intelligence,
comparison, run comments, cross-hunt tracking, and the Dashboard/Data
Explorer aggregate views. Full endpoint reference:
[`docs/api-threat-hunting.md`](docs/api-threat-hunting.md).

```bash
scripts/client_tests_demo/threat_hunting/api_client_threat_hunting.py --help
```

Authenticates the same two ways the API itself does — a session login
(`--username`/`--password`, any role) or, for automation, a **scoped API
access key** issued from Configuration → General → API Access
(`--api-key '<client_id>.<secret>'`); a key is authorized purely by its
granted scopes, and routes with no matching scope (connectors, execution,
approve/reject, comparison generation, …) require the session-login path
regardless of what scopes a key holds.

```bash
scripts/client_tests_demo/threat_hunting/api_client_threat_hunting.py \
  --url http://192.168.0.10:8000 --username analyst packages-list

scripts/client_tests_demo/threat_hunting/api_client_threat_hunting.py \
  --url http://192.168.0.10:8000 --api-key 'ak_9792056a7694.<secret>' \
  packages-create --name "Programmatic hunt"
```

A demo runner drives the client through a full T1–T17 test plan (create a
package, attach evidence, run generation, register/test a SIEM connector,
approve, generate/read a report, read the tracking dashboard, clean up) and
saves every result to disk — same format as the Threat Intel demo runner
above. See
[`scripts/client_tests_demo/threat_hunting/README.md`](scripts/client_tests_demo/threat_hunting/README.md)
for setup and the full test/command reference.

```bash
cp scripts/client_tests_demo/threat_hunting/.env.example \
   scripts/client_tests_demo/threat_hunting/.env.test
# edit .env.test: host/port (or url), user_hunt/pass_hunt (researcher or admin)

bash scripts/client_tests_demo/threat_hunting/run_tests.sh
```

---

## Canonical schema reconciliation

The normalizer's canonical namespace is sourced from
`config/feed-fields.yaml`. The derived `data/normalized.db` schema is
rebuilt on backend startup whenever its stored `schema_version` is older
than the engine's required version: the file is dropped, recreated from
the current yaml field list, and every source DB has its `normalized`
flag reset so the next normalizer run repopulates the table. Raw source
DBs are never touched — `normalized.db` is treated as regenerable data.

Operator-defined `manual_mappings` in `config/normalizer-config.yaml`
that still reference the engine's pre-021E-pre canonicals (`ip_address`,
`domain`, `hash`, `cve`, `timestamp`, `source_name_norm`) are
auto-translated to the equivalent yaml canonical names on load; each
change is logged at WARNING level and the file is rewritten in place.

---

## LLM Provider (optional)

The normalizer and the Threat Hunting agent pipeline can both call an external LLM for smart-mode
features (schema proposals, field-mapping suggestions, agentic hunting, natural-language query). The
plumbing is **disabled by default**.

### Supported provider kinds

| `kind`              | Notes |
|---|---|
| `openai`            | OpenAI public API |
| `anthropic`         | Anthropic public API only (`api.anthropic.com`) |
| `ollama`            | Local Ollama (no API key) |
| `openai_compatible` | Any server speaking OpenAI's chat-completions wire shape (Together, Groq, vLLM, LM Studio, …) |
| `azure_ai_foundry`  | Azure AI Foundry, in either of its two deployment modes (`api_style: unified` — the OpenAI-compatible Model Inference API, or `api_style: anthropic` — the Anthropic-native passthrough for Claude models) |

### Configuration

The real config lives at `config/llm-providers.yaml`, which is
**gitignored**. A documented template ships at
`config/llm-providers.yaml.example`. Populate the real file via:

```
PUT /api/llm/config        # write-only api_key semantics; see below
GET /api/llm/config        # returns redacted view (api_key == "***" if set)
GET /api/llm/providers     # listing without secrets
POST /api/llm/providers/{name}/test
                           # smoke-test: prefers list_models() (no token
                           # burn); falls back to a 1-token complete()
```

### Security properties

- **Default off.** `enabled: false` out of the box. Constructing a
  client while disabled raises `LLMDisabledError`.
- **Write-only API key.** `GET /api/llm/config` never returns the real
  key — `"***"` when set, `""` when unset. `PUT` accepts `"***"` as
  "keep existing"; any other string replaces.
- **TLS-skip is per-provider.** `skip_tls_verify: true` builds an
  unverified SSL context **per request** (never global) and emits a
  WARNING log including the provider name. Intended for self-hosted or
  lab use only.
- **No streaming, no history, no public `/complete` endpoint.** The
  plumbing exposes only config, listing, and a smoke-test endpoint.
- **Stdlib transport.** Uses `urllib.request` via `asyncio.to_thread`,
  with 5xx retries (exponential backoff) and timeout enforcement. No
  new runtime dependencies.

---

## Manual Dependency Setup

If you prefer to install dependencies before starting:

**Python (backend)**
```bash
uv venv .venv
uv pip install -r backend/requirements.txt --python .venv/bin/python
```

**Node.js (frontend)**
```bash
cd frontend && npm install
```

---

## Running Tests

```bash
./scripts/test.sh
```

Runs backend tests (`pytest`) and frontend tests (`vitest`).

---

## Project Layout

```
opentars                 # Startup script — entry point
mizton-threatbox          # Deprecated alias for ./opentars (forwards to it)
config/
  feed-fields.yaml          # Core + custom field definitions (gitignored — see below)
  sources.yaml              # Configured ingestion sources (gitignored — see below)
  application.yaml          # App-wide/branding settings (gitignored — see below)
  normalizer-config.yaml    # Normalizer mode + manual mappings (gitignored — see below)
backend/                    # Python / FastAPI backend
  requirements.txt          # Python dependencies
frontend/                   # React / TypeScript frontend
data/                       # SQLite databases (auto-created, gitignored)
  watchers.db               # Watcher definitions + triggered-event history
  threat_hunting.db         # Hunt packages, evidence, IOCs, runs, reports
  assistant_sessions.db     # Saved Assistant/SmartSearch chat sessions
docs/                       # Architecture, plans, session log
scripts/                    # check.sh, test.sh, security-check.sh, api_client.py,
                             # client_tests_demo/{threat_intel,threat_hunting}/
```

`config/application.yaml`, `config/sources.yaml`, `config/feed-fields.yaml`, and
`config/normalizer-config.yaml` hold **live, operator-editable instance state** and are
**gitignored** for the same reason as `config/llm-providers.yaml` above: the app writes to them at
runtime (branding, ingestion sources, custom fields, normalizer mappings), and tracking a file the
app itself edits meant every deployment's live customization permanently diverged its git HEAD
from upstream — including the commit hash shown on the About page. Each ships a documented
`config/<name>.yaml.example` template; the real file is bootstrapped from it automatically on
first read if absent, so a fresh clone/deploy still starts with working defaults. If a later
release introduces new config content a deployment doesn't have yet, an admin sees a top-bar
notice offering to add it — see [Config-drift notice](#configuration) above.

---

## Documentation

| Document | Audience | Contents |
|---|---|---|
| [`docs/platform-overview.md`](docs/platform-overview.md) | Everyone | Plain-language platform overview, capability diagram, agent team descriptions, role guide |
| [`docs/agent-architecture.md`](docs/agent-architecture.md) | Engineers | LangGraph/LangChain usage, tool-calling design, per-agent skill matrix, pipeline DAG, state management |
| [`docs/threat-hunting-framework-design.md`](docs/threat-hunting-framework-design.md) | Engineers | Full TH domain model: Hunt Package schema, evidence model, IOC model, SSRF policy, DB schema, API route map |
| [`docs/api-threat-hunting.md`](docs/api-threat-hunting.md) | Integrators | Full `/api/threat-hunting/*` endpoint reference: session vs. scoped API-key auth, every route's request/response shape, API-key management |
| [`docs/architecture.md`](docs/architecture.md) | Engineers | Whole-platform module map, data flows, config files, external dependencies |

---

## License

OpenTARS is released under the Apache License 2.0. See the
[`LICENSE`](LICENSE) file for the full terms.

This product includes third-party open-source software. Each bundled
dependency remains under its own license; see
[`THIRD-PARTY-NOTICES.md`](THIRD-PARTY-NOTICES.md) for the complete list of
runtime dependencies and their licenses.

## Development

OpenTARS is developed with a hybrid approach that combines AI-assisted, conversational coding using [OpenCode](https://opencode.ai) with manual development, review, and testing. Architecture, design decisions, and the final state of the code remain the maintainers' responsibility.

## Attribution

OpenTARS is based on a fork of [ThreatFeeds Lite](https://github.com/jusafing/ThreatFeeds-Lite), originally created by Javier S.A., and continued as Mizton-ThreatBox before this rebrand. The original project is licensed under the Apache License 2.0. OpenTARS continues from that foundation as its own tool with its own project identity and roadmap.
