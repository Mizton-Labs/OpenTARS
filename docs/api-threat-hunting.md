# Threat Hunting API Reference

This is the endpoint reference for `/api/threat-hunting/*` — hunt packages, evidence,
IOCs, LLM-driven hunt generation, SIEM connectors/execution, reports, Threat
Intelligence, run comparison, cross-hunt tracking, and the Dashboard/Data
Explorer aggregate views. It also documents the `/api/auth/api-keys/*`
management endpoints used to create and administer the scoped API keys that
can call this API programmatically (issue-local-029).

For the Threat Intel ingestion/query API (`/api/viewer`, `/api/normalizer`,
`/api/ingest`, `/api/query/nl`, …), see the **API Client Script** section of
the top-level `README.md` and `scripts/api_client.py`.

A companion, dependency-free CLI client for everything in this document lives at
`scripts/client_tests_demo/threat_hunting/api_client_threat_hunting.py` — see its
own `README.md` for setup and worked examples.

---

## Authentication

Every route below requires a valid credential when auth is enabled (the
default). Two independent credential types are accepted:

### 1. Session cookie (the web UI's auth)

Log in via `POST /api/auth/login` with `{"username", "password"}`; the
response sets a session cookie that authenticates subsequent requests. Access
is then gated by **role**:

| Role | Access to `/api/threat-hunting/*` |
|---|---|
| `admin` | Full access to every route in this document. |
| `threat-researcher` | Full read **and** write access to everything under `/api/threat-hunting/` (all HTTP methods). |
| `threat-viewer` | **Read-only**, and only `GET` requests whose path starts with `/api/threat-hunting/packages`, `/api/threat-hunting/dashboard`, or `/api/threat-hunting/explorer/` — this covers packages, evidence, IOCs, runs, reports, threat-intel, comparison reads, the Dashboard, and the Data Explorer (issue-local-032/033), but **not** `GET /connectors*` or `GET /tracking/*`. |
| `feed-sender` | No access to this API at all (listener-only account). |

### 2. API access key (scoped, programmatic — issue-local-029)

An admin creates a key from **Configuration → General → API Access**
(`GET`/`POST`/`PUT`/`DELETE /api/auth/api-keys*`, all session-cookie/admin-only
— see [API Access Key management](#api-access-key-management-admin-only) below).
The response's `api_key` value (`<client_id>.<secret>`) is shown **exactly
once** — only its hash is ever persisted.

Send it as a bearer token:

```
Authorization: Bearer ak_9792056a7694.RaNdOm-uRl-sAfE-sEcReT...
```

A key only authenticates at all when **Programmatic API access** is enabled
(`api_access_enabled`, off by default) — with it off, every API key request
gets `401` regardless of the key's own state.

**A key is authorized purely by its granted *scopes*, never by a role.** Each
scope is a curated, hardcoded allowlist of `(HTTP method, path pattern)` pairs,
deliberately confined to `/api/threat-hunting/*`. A request-level hard cap in
the auth middleware independently rejects *any* API-key request outside that
prefix — so a key holding every scope still cannot reach configuration,
user-management, or LLM-provider endpoints, and can never authenticate the
API-key management routes themselves (those resolve the session cookie
directly and never even look at the bearer token).

| Scope id | Label | Grants |
|---|---|---|
| `hunts:create` | Create hunt packages | `POST /packages` |
| `hunts:read` | List / view hunt packages | `GET /packages`, `GET /packages/{id}`, `GET /dashboard`, `GET /explorer/{category}` |
| `hunts:update` | Update hunt packages | `PUT /packages/{id}` |
| `hunts:delete` | Delete hunt packages | `DELETE /packages/{id}` |
| `evidence:add` | Add evidence | `POST /packages/{id}/evidence/{file,url,text,watcher}` |
| `evidence:read` | List evidence | `GET /packages/{id}/evidence` |
| `evidence:delete` | Delete evidence | `DELETE /packages/{id}/evidence/{item_id}` |
| `runs:generate` | Run hunt generation | `POST /packages/{id}/generate`, `GET .../generate/status`, `GET /packages/{id}/runs`, `GET /packages/{id}/runs/{run_id}/status` |
| `reports:download` | Download reports | `GET /packages/{id}/report[/markdown\|pdf]`, `GET /packages/{id}/runs/{run_id}/report[/markdown\|pdf]` |
| `iocs:read` | Download IOC list | `GET /packages/{id}/iocs` |
| `threat_intel:read` | Download Threat Intel reports | `GET /packages/{id}/threat-intel`, `GET /packages/{id}/runs/{run_id}/threat-intel` |
| `threat_intel_tracking:read` | Query Threat Intel Tracking data | `GET /tracking/dashboard`, `GET /tracking/hunts` |
| `comparison:read` | Download comparison reports | `GET /packages/{id}/comparison[/markdown\|pdf]` |

`GET /api/auth/api-keys/scopes` returns this list programmatically (id/label/
description) plus the **default profile** — exactly the issue-local-029 spec's
capability set: create a hunt package, add evidence, download every report
type, download the IOC list, download a run's Threat Intel report, and query
Threat Intel Tracking data. That is `hunts:create`, `evidence:add`,
`reports:download`, `iocs:read`, `threat_intel:read`,
`threat_intel_tracking:read`.

**Routes with no listed scope have no API-key path at all** — connectors,
execution, approve/reject/cancel, hypothesis/lead/IOC-verdict edits, run
comments, comparison *generation* (as opposed to reading an existing one), and
the tracking hunt include/exclude/delete actions are session-cookie-only,
regardless of what scopes a key holds. This is intentional: those are either
credential-bearing (SIEM connectors), destructive, or analyst-judgment
actions not meant for unattended automation.

### Errors

| Status | Meaning |
|---|---|
| `401` | No valid session cookie and no valid/enabled API key. |
| `403` | Authenticated, but the role (session) or scope (API key) doesn't cover this route — or, for an API key, the path falls outside `/api/threat-hunting/`. |
| `404` | Package / run / evidence item / connector / report not found. |
| `400` | Validation error (bad body, wrong package status for the action, …). |

---

## Conventions

- Base path: `/api/threat-hunting`. All paths below are relative to it unless
  noted (the API-key management routes are under `/api/auth` instead).
- All ids (`pkg_id`, `run_id`, evidence `item_id`, connector `conn_id`,
  comment `comment_id`) are opaque string UUIDs.
- Request and response bodies are JSON except file upload (`multipart/form-data`)
  and file download routes (binary/`text/markdown`/`application/pdf`).
- A hunt package has one **package-level** "latest" view (report, threat-intel,
  comparison) plus per-**run** history — most resources exist in both a
  package-scoped and a run-scoped form; the run-scoped form is the more
  precise one once a package has more than one generation run.

---

## Hunt Packages

| Method | Path | Session role | API-key scope |
|---|---|---|---|
| GET | `/packages` | viewer+ | `hunts:read` |
| POST | `/packages` | researcher+ | `hunts:create` |
| GET | `/packages/{pkg_id}` | viewer+ | `hunts:read` |
| PUT | `/packages/{pkg_id}` | researcher+ | `hunts:update` |
| DELETE | `/packages/{pkg_id}` | researcher+ | `hunts:delete` |
| POST | `/packages/{pkg_id}/clone` | researcher+ | — (session-only) |

**`GET /packages`** — list non-archived packages. Query params (issue-local-020):
`search` (deep search — matches name/description, this package's runs' stored
hypotheses/threat_context/ttp_analysis/deep_retrohunt JSON, and extracted
IOCs), `date_from`/`date_to` (ISO date bounds on `created_at`).

**`POST /packages`** — body `{"name": str, "description": str = ""}` → `201`
with the new package (status `draft`).

**`PUT /packages/{pkg_id}`** — body `{"name"?, "description"?, "status"?}`
(status ∈ `draft|planning|approved|executing|completed|archived`).

**`DELETE /packages/{pkg_id}`** — soft delete (`status → archived`); `204`.

**`POST /packages/{pkg_id}/clone`** — body `{"name": str}` → `201` with a new
`draft` package. Copies evidence items (including file blobs, `parse_status`
reset to `pending`) only — runs, reports, IOCs, and generation state are not
copied.

Response shape (`HuntPackageOut`): `id, name, description, status, created_by,
created_at, updated_at, evidence_count, generation_status, phases,
total_elapsed_s, run_created_at, runs[], run_count, hunt_id_display`.

---

## Evidence

| Method | Path | Session role | API-key scope |
|---|---|---|---|
| POST | `/packages/{pkg_id}/evidence/file` | researcher+ | `evidence:add` |
| POST | `/packages/{pkg_id}/evidence/url` | researcher+ | `evidence:add` |
| POST | `/packages/{pkg_id}/evidence/text` | researcher+ | `evidence:add` |
| POST | `/packages/{pkg_id}/evidence/watcher` | researcher+ | `evidence:add` |
| GET | `/packages/{pkg_id}/evidence` | viewer+ | `evidence:read` |
| DELETE | `/packages/{pkg_id}/evidence/{item_id}` | researcher+ | `evidence:delete` |
| GET | `/packages/{pkg_id}/evidence/{item_id}/pdf` | viewer+ | — (session-only) |
| GET | `/packages/{pkg_id}/evidence/{item_id}/download` | viewer+ | — (session-only) |

**`POST .../evidence/file`** — `multipart/form-data` with a `file` field (any
type — PDF, DOCX, TXT, CSV, JSON, XML, …; 50 MiB limit); optional
`?parser_mode=auto|...` query parameter. The blob is stored immediately with
`parse_status: "pending"` — text extraction and IOC extraction happen later,
during the analysis pipeline run (`POST .../generate`), not at upload time.

**`POST .../evidence/url`** — body `{"url": str, "label"?: str}`. Only
SSRF-validated here; the URL itself is fetched later by the pipeline.

**`POST .../evidence/text`** — body `{"text": str, "label"?: str, "source_ref"?: str}`.
Parsed immediately (`parse_status: "ok"`).

**`POST .../evidence/watcher`** — body
`{"watcher_id": str, "label"?: str, "max_events": int = 500}`. Pulls the
watcher's latest events from the internal watchers store as a snapshot.

**`GET .../evidence/{item_id}/pdf`** — inline PDF preview. Always serves as
`application/pdf` and verifies the blob's magic bytes server-side (`415` if
the stored content isn't actually a PDF) — the client-supplied `mime_type`
at upload time is never trusted for this.

**`GET .../evidence/{item_id}/download`** — original file bytes, always as
`application/octet-stream` with `Content-Disposition: attachment` (forces a
save rather than in-browser rendering, regardless of stored `mime_type`).

Response shape (`EvidenceItemOut`, on `add`/`list`): `id, hunt_package_id,
item_type, label, source_ref, content_hash, mime_type, fetch_url, final_url,
extracted_text, parser_used, parser_version, parse_status, parse_warnings[],
fetch_metadata{}, created_at, provenance_notes`.

---

## IOCs

| Method | Path | Session role | API-key scope |
|---|---|---|---|
| GET | `/packages/{pkg_id}/iocs` | viewer+ | `iocs:read` |

Query param `run_id` (optional) scopes to one run's independent IOC set;
omitted returns every row across all runs. Response items
(`ExtractedIOCOut`): `id, evidence_item_id, hunt_package_id, run_id, ioc,
ioc_type, ioc_description, noise_score, flagged_noisy, action, created_at`
(`action` ∈ `keep|remove`).

---

## Generation & Runs

| Method | Path | Session role | API-key scope |
|---|---|---|---|
| POST | `/packages/{pkg_id}/generate` | researcher+ | `runs:generate` |
| GET | `/packages/{pkg_id}/generate/status` | viewer+ | `runs:generate` |
| POST | `/packages/{pkg_id}/approve` | researcher+ | — (session-only, back-compat) |
| POST | `/packages/{pkg_id}/reject` | researcher+ | — (session-only, back-compat) |
| GET | `/packages/{pkg_id}/runs` | viewer+ | `runs:generate` |
| GET | `/packages/{pkg_id}/runs/{run_id}/status` | viewer+ | `runs:generate` |
| POST | `/packages/{pkg_id}/runs/{run_id}/approve` | researcher+ | — (session-only) |
| POST | `/packages/{pkg_id}/runs/{run_id}/reject` | researcher+ | — (session-only) |
| POST | `/packages/{pkg_id}/runs/{run_id}/cancel` | researcher+ | — (session-only) |
| PATCH | `/packages/{pkg_id}/runs/{run_id}/hypotheses/{hypothesis_id}` | researcher+ | — (session-only) |
| PATCH | `/packages/{pkg_id}/runs/{run_id}/hunting-leads/{lead_id}` | researcher+ | — (session-only) |
| PATCH | `/packages/{pkg_id}/runs/{run_id}/iocs` | researcher+ | — (session-only) |

**`POST .../generate`** — body
`{"provider_name"?, "model_name"?, "research_effort"? ("low"|"medium"|"high"),
"run_config"?: {"ioc_mode": "tagging_only"|"active_cleaning", "ioc_cleaning_options"?}}`.
Starts the LLM agent pipeline in the background (`202`); requires at least
one evidence item. Poll `GET .../generate/status` (package-level, latest run)
or `GET .../runs/{run_id}/status` (a specific run) for progress.

**`POST .../approve` / `.../reject`** — package-level convenience routes that
resolve the latest run; prefer the run-scoped
`POST .../runs/{run_id}/approve|reject` (body `{"notes": str = ""}`) for
explicit control once a package has more than one run.

**`POST .../runs/{run_id}/cancel`** — cancel a currently-running generation.

**`PATCH .../hypotheses/{hypothesis_id}`** — body `{"discarded": bool}`.
Analyst-set only; never overwritten by re-running the same run.

**`PATCH .../hunting-leads/{lead_id}`** — same shape/semantics, for hunting leads.

**`PATCH .../iocs`** — body `{"updates": [{"ioc": str, "ioc_type": str, "action": "keep"|"remove"}, ...]}`.
Batch-applies manual keep/remove verdicts, updating both the `extracted_iocs`
table and the run's `deep_retrohunt.sanitized_iocs` blob so every IOC view
stays consistent.

---

## SIEM Connectors

| Method | Path | Session role | API-key scope |
|---|---|---|---|
| GET | `/connectors` | — (researcher/admin only; not in viewer's package-prefixed allowlist) | — (session-only) |
| POST | `/connectors` | researcher+ | — (session-only) |
| GET | `/connectors/{conn_id}` | researcher+ | — (session-only) |
| PUT | `/connectors/{conn_id}` | researcher+ | — (session-only) |
| DELETE | `/connectors/{conn_id}` | researcher+ | — (session-only) |
| POST | `/connectors/{conn_id}/test` | researcher+ | — (session-only) |

Connector credentials are always masked in responses. Body (create/update):
`{"name", "kind": "splunk", "base_url", "auth_method": "token", "api_token"?,
"username"?, "password"?, "verify_tls": true, "default_index": "main",
"retrohunt_macro": "threathunt_ioc_search"}`. `POST .../test` returns
`{"ok": bool, "message": str, "server_info": dict|null}` and marks the
connector verified on success. No API-key scope reaches this group at all —
connectors hold live SIEM credentials, so they stay session-only by design.

---

## Execution

| Method | Path | Session role | API-key scope |
|---|---|---|---|
| POST | `/packages/{pkg_id}/execute` | researcher+ | — (session-only) |
| GET | `/packages/{pkg_id}/results` | viewer+ | — (session-only) |
| GET | `/packages/{pkg_id}/results/{result_id}` | viewer+ | — (session-only) |

**`POST .../execute`** — body
`{"connector_id", "spl", "earliest": "-24h", "latest": "now", "provider_name"?,
"model_name"?, "run_id"?}`. The package must be `approved` (or `completed`);
`202`, runs in the background. `run_id` links results to a specific
generation run.

---

## Reports

| Method | Path | Session role | API-key scope |
|---|---|---|---|
| GET | `/packages/{pkg_id}/report` | viewer+ | `reports:download` |
| POST | `/packages/{pkg_id}/report` | researcher+ | — (session-only) |
| GET | `/packages/{pkg_id}/report/list` | viewer+ | — (session-only) |
| GET | `/packages/{pkg_id}/report/markdown` | viewer+ | `reports:download` |
| GET | `/packages/{pkg_id}/report/pdf` | viewer+ | `reports:download` |
| GET | `/packages/{pkg_id}/runs/{run_id}/results` | viewer+ | — (session-only) |
| GET | `/packages/{pkg_id}/runs/{run_id}/report` | viewer+ | `reports:download` |
| POST | `/packages/{pkg_id}/runs/{run_id}/report` | researcher+ | — (session-only) |
| GET | `/packages/{pkg_id}/runs/{run_id}/report/markdown` | viewer+ | `reports:download` |
| GET | `/packages/{pkg_id}/runs/{run_id}/report/pdf` | viewer+ | `reports:download` |

**`GET .../report`** (package-level, latest) / **`GET .../runs/{run_id}/report`**
(a specific run) — `404` if none generated yet. JSON, including a pre-rendered
`full_report._markdown` when available.

**`POST .../report`** / **`POST .../runs/{run_id}/report`** — body
`{"provider_name"?, "model_name"?, "report_formats"?: {"pdf": bool, "markdown": bool}}`.
Package must be `approved` or `completed`. Idempotent — replaces any previous
report for that scope (package-level or that run).

**`.../report/markdown`, `.../report/pdf`** — download the latest report as
`text/markdown` / `application/pdf` (`Content-Disposition: attachment`). PDF
is rendered on demand from the stored report data.

**`GET .../report/list`** — every historical report for a package, newest first.

---

## Threat Intelligence (issue-local-020)

| Method | Path | Session role | API-key scope |
|---|---|---|---|
| GET | `/packages/{pkg_id}/runs/{run_id}/threat-intel` | viewer+ | `threat_intel:read` |
| GET | `/packages/{pkg_id}/threat-intel` | viewer+ | `threat_intel:read` |
| POST | `/packages/{pkg_id}/runs/{run_id}/threat-intel` | researcher+ | — (session-only) |

Threat Intelligence analysis normally runs automatically right after SIEM
execution completes, correlating the run's threat actors/IOCs/malware
families/campaigns against every other hunt package. `POST .../threat-intel`
(re-)triggers it on demand — for packages that skipped execution, or to pick
up new cross-package correlations after more hunts have been added.

Response fields: `threat_actors[], attribution{}, malware_families[],
campaigns[], related_vendors[], correlated_iocs[]` (each
`{ioc, ioc_type, other_hunt_package_id, other_run_id, other_hunt_name}`),
`summary`.

---

## Comparison Module (issue-local-020/021)

| Method | Path | Session role | API-key scope |
|---|---|---|---|
| POST | `/packages/{pkg_id}/compare` | researcher+ | — (session-only) |
| GET | `/packages/{pkg_id}/comparison` | viewer+ | `comparison:read` |
| GET | `/packages/{pkg_id}/comparison/markdown` | viewer+ | `comparison:read` |
| GET | `/packages/{pkg_id}/comparison/pdf` | viewer+ | `comparison:read` |

**`POST .../compare`** — body `{"provider_name"?, "model_name"?, "run_ids"?: [str, ...]}`
(omit `run_ids` to compare every run). Synchronous — a single LLM call;
persists and replaces the package's comparison report. Requires at least one
run. *Triggering* a comparison is session-only; once one exists, **reading**
it (JSON/Markdown/PDF) is available to a key holding `comparison:read`.

---

## Run Comments (issue-local-018)

| Method | Path | Session role | API-key scope |
|---|---|---|---|
| GET | `/packages/{pkg_id}/runs/{run_id}/comments` | viewer+ | — (session-only) |
| POST | `/packages/{pkg_id}/runs/{run_id}/comments` | researcher+ | — (session-only) |
| DELETE | `/packages/{pkg_id}/runs/{run_id}/comments/{comment_id}` | researcher+ | — (session-only) |

Body for create: `{"body": str}` (non-empty). Oldest-first on list.

---

## Threat Intel Tracking (issue-local-021)

Cross-hunt aggregation for the sidebar's "Threat Intel Tracking" section —
not prefixed by `/packages`, so **not** reachable by a `threat-viewer`
session even though it's read-only.

| Method | Path | Session role | API-key scope |
|---|---|---|---|
| GET | `/tracking/dashboard` | researcher+ | `threat_intel_tracking:read` |
| GET | `/tracking/hunts` | researcher+ | `threat_intel_tracking:read` |
| POST | `/tracking/hunts/{pkg_id}/exclude` | researcher+ | — (session-only) |
| DELETE | `/tracking/hunts/{pkg_id}` | researcher+ | — (session-only) |

**`GET /tracking/dashboard`** — query param `search` (substring filter on the
IOCs/CVEs panels). Returns `{iocs[], cves[], threat_actors[], campaigns[],
malware_families[], ttps[]}`, aggregated across every non-excluded hunt.

**`GET /tracking/hunts`** — every non-archived package with its
correlation-inclusion state.

**`POST .../exclude`** — body `{"excluded": bool}`. Reversible; removes/restores
a package from every dashboard aggregation above without touching its data.

**`DELETE /tracking/hunts/{pkg_id}`** — a real, permanent archive (same
mechanism as `DELETE /packages/{pkg_id}`), not a correlation-only toggle.

---

## Dashboard & Data Explorer (issue-local-032/033/034)

Unlike Threat Intel Tracking above, these two are reachable by a `threat-viewer`
session (their paths aren't `/packages`-prefixed, but they're explicitly
allowlisted anyway — see the role table at the top of this document).

| Method | Path | Session role | API-key scope |
|---|---|---|---|
| GET | `/dashboard` | viewer+ | `hunts:read` |
| GET | `/explorer/{category}` | viewer+ | `hunts:read` |

**`GET /dashboard`** — aggregate counts backing the Threat Hunting Dashboard
(the module's default view). Query params `search`, `date_from`, `date_to`
use the same deep-search/date-range rules as `GET /packages`, and filter
every hunt-scoped figure below the same way — the Threat Intel fields are the
one exception, deliberately global (see next paragraph). Response:

```
packages_total, packages_by_status{}, hunts_per_day[{date,count}],
runs_total, runs_by_model{}, hunts_by_model{},
evidence_total, evidence_by_type{},
hypotheses_total, hunting_leads_total, queries_total,
iocs_extracted_total, iocs_kept_total, iocs_per_day[{date,count}],
siem_searches_total, siem_searches_completed, siem_events_total,
threat_actors_total, campaigns_total, malware_families_total,
ttps_total, sources_processed
```

`hunts_per_day`/`iocs_per_day` are the matching rows bucketed by creation day,
ascending, with no fixed window — a narrow date filter yields a short series,
no filter yields the whole history. `threat_actors_total`/`campaigns_total`/
`malware_families_total`/`ttps_total`/`sources_processed` are **not** filtered
by `search`/`date_from`/`date_to` — same cross-hunt-aggregate convention as
`GET /tracking/dashboard` above.

**`GET /explorer/{category}`** — the row-level data behind one Dashboard
panel/stat card. `category` is one of:

```
hunts, runs, evidence, hypotheses, hunting_leads, queries, iocs,
siem_searches, threat_actors, campaigns, malware_families, ttps, feed_sources
```

An unknown category returns `404`. For the eight hunt-scoped categories
(`hunts` through `siem_searches`), `search`/`date_from`/`date_to` filter
exactly like `GET /dashboard`. For the five Threat Intel categories,
`date_from`/`date_to` are ignored and `search` instead matches the entity's
own name (or, for `ttps`, its MITRE technique id/name). Each row carries
enough of its owning hunt package (`hunt_package_id`, `hunt_id_display`,
`hunt_name`) to deep-link back to it; the response shape otherwise varies by
category — see `backend/threat_hunting/db.py::list_explorer_rows` for the
exact per-category fields.

```bash
curl -s -H "Authorization: Bearer ak_9792056a7694.<secret>" \
  "http://localhost:8000/api/threat-hunting/explorer/iocs?search=ransomware"
```

---

## API Access Key management (admin only)

Base path `/api/auth` (not `/api/threat-hunting`). **Session-cookie + admin
only** — these routes resolve the session cookie directly and never consult
`request.state.user`, so an API key structurally cannot authenticate itself
here, no matter what scopes it holds.

| Method | Path | Body | Response |
|---|---|---|---|
| GET | `/api-keys/config` | — | `{"enabled": bool}` |
| PUT | `/api-keys/config` | `{"enabled": bool}` | `{"enabled": bool}` |
| GET | `/api-keys/scopes` | — | `{"scopes": [{id,label,description}], "default_profile": [str]}` |
| GET | `/api-keys` | — | `[ApiKey]` (secret hash redacted) |
| POST | `/api-keys` | `{"name": str, "scopes": [str] = []}` | `ApiKey & {secret, api_key, endpoint}` — **the only time the secret is ever returned** |
| PUT | `/api-keys/{client_id}` | `{"name"?, "scopes"?, "enabled"?}` (partial) | `ApiKey` |
| DELETE | `/api-keys/{client_id}` | — | `{"status": "deleted", "client_id"}` |
| POST | `/api-keys/{client_id}/test` | — | `{"status": "ok"\|"warning"\|"error", "detail": str, "scopes": [str]}` |

`ApiKey` shape: `id, client_id, name, scopes[], enabled, created_by,
created_at, last_used_at`. Unknown scope ids sent in `POST`/`PUT` are silently
dropped (not rejected) so a client using a stale scope list from an older
server doesn't hard-fail.

`POST /api-keys/{client_id}/test` validates the stored record through the
exact same lookup/enabled logic `resolve_api_key` uses at request time — a
`"status": "ok"` result means the key will actually authenticate, without
ever needing (or seeing) the secret again. It reports `"warning"` if
`api_access_enabled` is currently off globally, and `"error"` if the
individual key is disabled.

---

## Examples

```bash
# Create a package, add a text note as evidence, and start generation
# (session-cookie auth; substitute a Bearer API key with hunts:create +
# evidence:add + runs:generate scopes to do the same programmatically)
curl -sb cookies.txt -c cookies.txt -X POST http://localhost:8000/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username": "analyst", "password": "..."}'

PKG_ID=$(curl -sb cookies.txt -X POST http://localhost:8000/api/threat-hunting/packages \
  -H 'Content-Type: application/json' \
  -d '{"name": "Suspicious login activity", "description": "..."}' | python3 -c \
  'import json,sys; print(json.load(sys.stdin)["id"])')

curl -sb cookies.txt -X POST "http://localhost:8000/api/threat-hunting/packages/${PKG_ID}/evidence/text" \
  -H 'Content-Type: application/json' \
  -d '{"text": "Analyst notes go here...", "label": "Initial notes"}'

curl -sb cookies.txt -X POST "http://localhost:8000/api/threat-hunting/packages/${PKG_ID}/generate" \
  -H 'Content-Type: application/json' -d '{}'

# Same package, with a scoped API key instead of a session cookie
curl -s -H "Authorization: Bearer ak_9792056a7694.<secret>" \
  "http://localhost:8000/api/threat-hunting/packages/${PKG_ID}/report/pdf" -o report.pdf

curl -s -H "Authorization: Bearer ak_9792056a7694.<secret>" \
  "http://localhost:8000/api/threat-hunting/packages/${PKG_ID}/iocs"

curl -s -H "Authorization: Bearer ak_9792056a7694.<secret>" \
  "http://localhost:8000/api/threat-hunting/tracking/dashboard?search=ransomware"
```
