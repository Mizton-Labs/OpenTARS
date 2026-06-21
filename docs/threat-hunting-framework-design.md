# Threat Hunting Framework — Design Document

**Status:** Phase 0 — Design  
**Last updated:** 2026-06-21  
**Source:** `.coding_agent/developer_notes/issue-local-002.md`

---

## 1. Purpose and Scope

Mizton-ThreatBox evolves from a Threat Intelligence feed aggregator into an
**agentic Threat Intel and Hunting Operations Framework**. The Threat Hunting
module is the second pillar of this framework, sitting alongside the existing
Threat Intel module.

**In scope:**

- Ingesting Threat Intel evidence packages (files, URLs, watcher feeds, manual
  notes).
- Extracting and normalizing IOCs and context from raw evidence.
- Generating Threat Hunting packages via LLM-powered agents:
  - Threat context summaries.
  - Hunting hypotheses with justification and relevance.
  - Structured hunting leads with sub-tasks.
  - Deep Retrohunt lead (always present when atomic IOCs exist).
  - Behavioral TTP analysis and detection query drafts.
- Operator approval gate before any execution.
- Executing approved hunting packages against configured SIEMs.
- Producing structured reports per task and per hunt.

**Out of scope (initial phases):**

- Real-time SIEM streaming.
- Automated response/remediation.
- Direct SOAR integration.
- Multi-tenant or multi-user concurrent hunts (future).

---

## 2. Role Model

The platform adopts four roles that replace the original `normal` / `sender`
model and extend it for Threat Hunting:

| Role | Platform access |
|---|---|
| `admin` | Full access: all configuration, user management, all Threat Intel and Threat Hunting operations. |
| `threat-researcher` | Full Threat Hunting access: create, edit, approve, and execute Hunt Packages. Read access to Threat Intel Viewer. Cannot access platform configuration. |
| `threat-viewer` | Read-only access to Hunt Packages and reports. Read access to Threat Intel Viewer. |
| `feed-sender` | Push-only machine account for feed/listener ingestion. No UI access beyond the push API. |

### Migration Notes

- The existing `normal` role maps to `threat-viewer` semantically.
- The existing `sender` role maps to `feed-sender`.
- New roles require schema migration to `users.db` (add new role values).
- Backend middleware allowlists must be updated for new role checks.
- The frontend sidebar, route guards, and configuration tabs must gate on the
  new role set.

---

## 3. Architecture Overview

```
┌────────────────────────────────────────────────────────┐
│                   Threat Intel Module                  │
│   Feeds → Normalizer → Watchers → Viewer               │
└──────────────────────────┬─────────────────────────────┘
                           │ Watcher events / feed snapshots
                           ▼
┌────────────────────────────────────────────────────────┐
│               Threat Hunting Module                    │
│                                                        │
│  ┌─────────────┐   ┌──────────────────┐               │
│  │ Hunt Package │   │ Evidence Store   │               │
│  │  Wizard     │──▶│ (files, URLs,    │               │
│  │             │   │  feeds, notes)   │               │
│  └─────────────┘   └────────┬─────────┘               │
│                             │                          │
│                    ┌────────▼──────────┐               │
│                    │ Artifact Parser   │               │
│                    │ (Docling | Marker │               │
│                    │  + httpx/trafilat)│               │
│                    └────────┬──────────┘               │
│                             │                          │
│                    ┌────────▼──────────┐               │
│                    │ IOC Normalizer    │               │
│                    │ + Noise Scorer    │               │
│                    └────────┬──────────┘               │
│                             │                          │
│                    ┌────────▼──────────┐               │
│                    │  LangGraph Agent  │               │
│                    │  Pipeline         │               │
│                    │  (LangChain tools)│               │
│                    └────────┬──────────┘               │
│                             │                          │
│         ┌───────────────────┼────────────────────┐     │
│         ▼                   ▼                    ▼     │
│  ┌────────────┐  ┌──────────────────┐  ┌──────────────┐│
│  │  Hunting   │  │  Deep Retrohunt  │  │  Behavioral  ││
│  │  Package   │  │  Lead + IOC CSV  │  │  TTP / Query ││
│  │  Draft     │  │  Draft           │  │  Drafts      ││
│  └─────┬──────┘  └──────┬───────────┘  └──────┬───────┘│
│        │                │                      │        │
│        └────────────────┴──────────────────────┘        │
│                         │                               │
│               ┌─────────▼────────┐                      │
│               │ Operator Approval│                      │
│               └─────────┬────────┘                      │
│                         │                               │
│               ┌─────────▼────────┐                      │
│               │  SIEM Connector  │                      │
│               │  (Splunk first)  │                      │
│               └─────────┬────────┘                      │
│                         │                               │
│               ┌─────────▼────────┐                      │
│               │   Hunt Report    │                      │
│               └──────────────────┘                      │
└────────────────────────────────────────────────────────┘
```

---

## 4. Hunt Package Model

A **Hunt Package** is the central domain object. It aggregates evidence,
generated plans, execution tasks, and reports.

```
HuntPackage
├── id                    UUID
├── name                  str
├── description           str
├── status                draft | planning | approved | executing |
│                         completed | archived
├── created_by            user_id
├── created_at            datetime
├── updated_at            datetime
├── evidence[]            EvidenceItem (see §5)
├── threat_context        ThreatContext (LLM-generated)
├── hypotheses[]          Hypothesis
├── hunting_leads[]       HuntingLead
├── deep_retrohunt        DeepRetrohuntLead | null
├── ttp_analysis          BehavioralTTPAnalysis
├── query_drafts[]        QueryDraft
├── execution_results[]   TaskResult
└── report                HuntReport | null
```

---

## 5. Evidence Model

Every item added to a Hunt Package is stored as an `EvidenceItem`. All
retrieved content is retained permanently as part of the package.

```
EvidenceItem
├── id                    UUID
├── hunt_package_id       FK
├── item_type             file | url | watcher_feed | manual_text
├── label                 str (operator-provided name)
├── source_ref            str (original filename / URL / watcher_id)
├── original_bytes        blob | path    (stored on disk)
├── content_hash          sha256
├── mime_type             str
├── fetch_url             str | null     (if type=url)
├── final_url             str | null     (after redirects)
├── extracted_text        str            (markdown/plain from parser)
├── extracted_iocs[]      ExtractedIOC
├── parser_used           docling | marker | text | csv | none
├── parser_version        str
├── parse_status          ok | error | partial
├── parse_warnings[]      str[]
├── fetch_metadata        FetchMetadata | null
├── watcher_snapshot      WatcherSnapshot | null
├── created_at            datetime
└── provenance_notes      str
```

### ExtractedIOC

```
ExtractedIOC
├── ioc                   str
├── ioc_type              ip | domain | url | hash_md5 | hash_sha1 |
│                         hash_sha256 | email | cve | registry_key |
│                         filepath | mutex | asn | other
├── ioc_description       str
├── raw_text_offset       int | null
└── noise_score           float (0.0–1.0, higher = noisier)
```

---

## 6. Manual Hunt Package Wizard

The Threat Hunting module entry point is a multi-step **wizard** for creating a
Hunt Package. It supports an extensible `Add Hunt Package Item` flow.

### Wizard Steps

```
Step 1: Package Identity
  - Name (required)
  - Description
  - Tags

Step 2: Add Evidence (repeatable — "Add hunt package item")
  Item types:
  ┌────────────────────────────────────────────────────────┐
  │  FILE     │ PDF, DOC/DOCX, TXT, CSV, JSON, XML, NDJSON│
  │  URL      │ Fetch and extract article/page content     │
  │  WATCHER  │ Import events from a configured watcher    │
  │  MANUAL   │ Free-text note / pasted threat intel       │
  └────────────────────────────────────────────────────────┘
  Each item shows extraction status, IOC count, parse status.

Step 3: Review Evidence Summary
  - Total items, total IOCs, parser statuses
  - Flag noisy IOCs for review

Step 4: Generate Hunting Package (LLM)
  - Select LLM provider / model
  - Start generation
  - Poll progress per agent step

Step 5: Review and Approve
  - Review threat context
  - Review hypotheses
  - Review hunting leads
  - Review Deep Retrohunt plan
  - Review TTP analysis and query drafts
  - Approve / request revision / archive

Step 6: Execute (approved packages only)
  - Select SIEM connector
  - Configure time range (earliest / latest)
  - Start execution
  - Monitor progress
```

### Supported File Types

| Extension | Parser |
|---|---|
| `.pdf` | Docling or Marker (configurable, default `auto`) |
| `.doc` / `.docx` | Docling or python-docx |
| `.txt` | Direct text |
| `.md` | Direct text |
| `.csv` / `.tsv` | CSV parser → IOC extraction |
| `.json` | JSON parser |
| `.ndjson` | NDJSON parser |
| `.xml` | XML parser |
| `.gz` / `.zip` | Decompress then apply inner type parser |

---

## 7. URL Fetching and SSRF Baseline Policy

URL ingestion is enabled from Phase 1 with the following baseline SSRF controls:

### Blocked by Default

| Category | Examples |
|---|---|
| Loopback | `127.0.0.0/8`, `::1` |
| Link-local | `169.254.0.0/16`, `fe80::/10` |
| Private RFC1918 | `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` |
| Cloud metadata | `169.254.169.254`, `fd00:ec2::254` |
| Multicast | `224.0.0.0/4` |
| Reserved | `0.0.0.0/8`, `240.0.0.0/4` |

### Enforcement Steps

1. Parse and validate scheme: only `http` / `https` allowed.
2. Extract hostname and resolve all DNS `A` / `AAAA` records.
3. Validate every resolved IP against block lists above.
4. Follow redirects with re-validation of each intermediate URL/IP.
5. Cap redirect chain to 5 hops.
6. Enforce response size limit (default 20 MiB, configurable).
7. Enforce request timeout (default 30 s, configurable).
8. Restrict content types to `text/*`, `application/pdf`,
   `application/json`, `application/xml`, and common document MIME types.
9. Store `fetch_url`, `final_url`, resolved IPs, HTTP status, content type,
   and response size in `FetchMetadata`.

### Future Config

Operator-configurable allow/denylist in `config/threat-hunting.yaml`:

```yaml
url_fetch:
  enabled: true
  max_response_bytes: 20971520   # 20 MiB
  timeout_seconds: 30
  max_redirects: 5
  blocked_ranges:
    - "10.0.0.0/8"
    - "172.16.0.0/12"
    - "192.168.0.0/16"
    - "169.254.0.0/16"
    - "127.0.0.0/8"
    - "::1/128"
    - "fe80::/10"
  # additional_allowlist: []
  # additional_denylist: []
```

---

## 8. Agent Structure and LangGraph Pipeline

### Stack

| Layer | Technology |
|---|---|
| Workflow orchestration | **LangGraph** (stateful directed graph, approval gates) |
| Model/tool/prompt abstraction | **LangChain** |
| LLM providers | Existing `backend/llm/` registry (OpenAI, Anthropic, Ollama, OpenAI-compatible) |

### LangGraph Pipeline State

```python
class HuntPipelineState(TypedDict):
    hunt_package_id: str
    evidence_summary: EvidenceSummary
    threat_context: ThreatContext | None
    hypotheses: list[Hypothesis]
    hunting_leads: list[HuntingLead]
    deep_retrohunt: DeepRetrohuntLead | None
    ttp_analysis: BehavioralTTPAnalysis | None
    query_drafts: list[QueryDraft]
    errors: list[str]
    current_step: str
```

### Agent Nodes

| Agent Node | Input | Output | Notes |
|---|---|---|---|
| `intake_classifier` | raw evidence items | typed/routed artifact list | Determines how to parse each item |
| `artifact_parser` | artifact list | extracted text + IOC list per item | Dispatches to Docling / Marker / text |
| `ioc_normalizer` | raw IOC list | normalized, deduped, noise-scored IOC CSV | Strips http/https, dedupes, flags noisy IOCs |
| `threat_context_builder` | extracted text corpus | `ThreatContext` | LLM summarizes adversary/campaign/malware |
| `hypothesis_generator` | `ThreatContext` + IOCs | `Hypothesis[]` | LLM generates justified hypotheses |
| `hunting_lead_planner` | `Hypothesis[]` | `HuntingLead[]` with sub-tasks | LLM breaks hypotheses into leads |
| `deep_retrohunt_planner` | normalized IOC CSV | `DeepRetrohuntLead` | Always runs if atomic IOCs present |
| `ttp_analyst` | `ThreatContext` | `BehavioralTTPAnalysis` | ATT&CK-style behavioral analysis |
| `query_drafting_agent` | leads + TTPs | `QueryDraft[]` (SPL, KQL, ES, CQL) | LLM-generated, drafts only |
| `approval_gate` | full draft package | paused state, awaits operator | LangGraph interrupt node |
| `splunk_connector` | approved retrohunt + query | SIEM result set | Executes approved SPL search |
| `results_interpreter` | SIEM results + context | interpreted findings | LLM summarizes matches |
| `report_writer` | all results | `HuntReport` | Structured final report |

### Pipeline Graph

```
intake_classifier
      │
artifact_parser
      │
ioc_normalizer
      │
┌─────┴──────┐
▼            ▼
threat_context_builder   deep_retrohunt_planner (if IOCs exist)
      │
hypothesis_generator
      │
hunting_lead_planner ─── ttp_analyst ─── query_drafting_agent
      │
[aggregate draft package]
      │
APPROVAL GATE (operator)
      │
splunk_connector (per approved lead)
      │
results_interpreter
      │
report_writer
```

### Parser Selection Strategy

```
parser_mode: auto | docling | marker
```

Resolution in `artifact_parser` node:

1. If user explicitly set parser mode in wizard step, use it.
2. If `auto`:
   - Large structured docs with tables → Docling
   - Report/article PDFs where markdown quality matters → Marker
   - `.txt` / `.md` / `.csv` / `.json` → direct text handler
3. Store `parser_used`, `parser_version`, and `parse_status` in each
   `EvidenceItem`.

---

## 9. Deep Retrohunt Pipeline

The Deep Retrohunt lead is **always proposed** when the extracted IOC set
contains atomic IOCs (IPs, hashes, domains, CVEs, URLs, etc.).

### Canonical IOC CSV Schema

```csv
ioc,ioc_type,ioc_description
1.2.3.4,ip,C2 server identified in malware config
evil.example.com,domain,Phishing domain observed in campaign
d41d8cd98f00b204e9800998ecf8427e,hash_md5,Known ransomware dropper
```

### IOC Sanitization Steps (LLM-assisted + deterministic)

1. **Parse**: accept CSV input.
2. **Normalize casing**: lowercase domains, uppercase hex hashes.
3. **Strip protocols**: remove `http://`, `https://`, `ftp://` from URL-typed IOCs.
4. **Tokenize**: where applicable produce shortened search-ready tokens.
5. **Deduplicate**: remove exact duplicates after normalization.
6. **Remove redactions**: detect and strip `[.]`, `(.)`-style defanging where search-intent is clear.
7. **Noise scoring**: flag IOCs likely to produce excessive SIEM matches:
   - Known process names: `cmd.exe`, `powershell.exe`, `wscript.exe`, etc.
   - Known CDN/infrastructure: CloudFlare, Akamai, etc.
   - Common/benign hashes.
   - Single-character or very short tokens.
   - Private/RFC1918 IPs.
8. **Flag for review**: high-noise-score IOCs are surfaced to the operator before executing.

### Splunk Execution Contract

The retrohunt dispatches to the Splunk connector using:

```
function: retrohunt_search(csv_file, earliest, latest, hunt_id)
```

The implementation uses the Splunk REST API:

```
POST /services/search/jobs
  search=<macro with IOC list>
  earliest_time=<earliest>
  latest_time=<latest>
```

Results are polled until terminal, collected, and passed to `results_interpreter`.

---

## 10. Splunk Connector Design

### Connector Profile

```yaml
# config/siem-connectors.yaml (gitignored for real config)
connectors:
  - name: my-splunk
    kind: splunk
    base_url: https://splunk.example.com:8089
    auth_method: token          # token | username_password
    api_token: "***"            # write-only, stored on save
    verify_tls: true
    default_index: main
    default_earliest: -24h
    default_latest: now
    retrohunt_macro: threathunt_ioc_search
```

### Security Properties

- API tokens and passwords are write-only (returned as `"***"` on GET).
- TLS verification configurable (default on); `verify_tls: false` emits WARNING.
- Connection test available before saving.
- Admin-only access.

### Splunk REST API Flow

1. `GET /services/server/info` — test connection.
2. `POST /services/search/jobs` — submit search.
3. `GET /services/search/jobs/{sid}` — poll job status.
4. `GET /services/search/jobs/{sid}/results` — retrieve results.
5. Map results to `TaskResult` model.

---

## 11. Durable DB Schema (`data/threat_hunting.db`)

```sql
-- Schema version tracking
CREATE TABLE IF NOT EXISTS th_schema_version (version INTEGER PRIMARY KEY);

-- Hunt packages
CREATE TABLE IF NOT EXISTS hunt_packages (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    status TEXT NOT NULL DEFAULT 'draft',
    created_by TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- Evidence items
CREATE TABLE IF NOT EXISTS evidence_items (
    id TEXT PRIMARY KEY,
    hunt_package_id TEXT NOT NULL REFERENCES hunt_packages(id),
    item_type TEXT NOT NULL,
    label TEXT,
    source_ref TEXT,
    content_hash TEXT,
    mime_type TEXT,
    fetch_url TEXT,
    final_url TEXT,
    extracted_text TEXT,
    parser_used TEXT,
    parser_version TEXT,
    parse_status TEXT,
    parse_warnings TEXT,        -- JSON array
    fetch_metadata TEXT,        -- JSON object
    watcher_snapshot TEXT,      -- JSON object
    created_at TEXT NOT NULL,
    provenance_notes TEXT
);

-- Binary evidence blobs (stored separately to keep rows small)
CREATE TABLE IF NOT EXISTS evidence_blobs (
    evidence_item_id TEXT PRIMARY KEY REFERENCES evidence_items(id),
    data BLOB NOT NULL
);

-- Extracted IOCs
CREATE TABLE IF NOT EXISTS extracted_iocs (
    id TEXT PRIMARY KEY,
    evidence_item_id TEXT NOT NULL REFERENCES evidence_items(id),
    hunt_package_id TEXT NOT NULL REFERENCES hunt_packages(id),
    ioc TEXT NOT NULL,
    ioc_type TEXT NOT NULL,
    ioc_description TEXT,
    noise_score REAL DEFAULT 0.0,
    flagged_noisy INTEGER DEFAULT 0,
    created_at TEXT NOT NULL
);

-- LLM-generated hunting packages
CREATE TABLE IF NOT EXISTS hunting_packages (
    id TEXT PRIMARY KEY,
    hunt_package_id TEXT NOT NULL REFERENCES hunt_packages(id),
    threat_context TEXT,        -- JSON
    hypotheses TEXT,            -- JSON array
    hunting_leads TEXT,         -- JSON array
    deep_retrohunt TEXT,        -- JSON
    ttp_analysis TEXT,          -- JSON
    query_drafts TEXT,          -- JSON array
    llm_provider TEXT,
    llm_model TEXT,
    generation_status TEXT,
    generation_errors TEXT,     -- JSON array
    created_at TEXT NOT NULL
);

-- Task execution results
CREATE TABLE IF NOT EXISTS task_results (
    id TEXT PRIMARY KEY,
    hunt_package_id TEXT NOT NULL REFERENCES hunt_packages(id),
    task_type TEXT NOT NULL,
    siem_connector TEXT,
    query_text TEXT,
    earliest TEXT,
    latest TEXT,
    hunt_id TEXT,
    status TEXT NOT NULL,
    raw_result TEXT,            -- JSON
    interpreted_findings TEXT,
    confidence REAL,
    created_at TEXT NOT NULL,
    completed_at TEXT
);

-- Hunt reports
CREATE TABLE IF NOT EXISTS hunt_reports (
    id TEXT PRIMARY KEY,
    hunt_package_id TEXT NOT NULL REFERENCES hunt_packages(id),
    executive_summary TEXT,
    full_report TEXT,           -- JSON
    created_at TEXT NOT NULL,
    created_by TEXT
);

-- SIEM connector profiles
CREATE TABLE IF NOT EXISTS siem_connectors (
    id TEXT PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    kind TEXT NOT NULL,
    base_url TEXT NOT NULL,
    auth_method TEXT NOT NULL,
    api_token_hash TEXT,        -- stored as SHA-256 hash; plain token in keystore
    config_json TEXT,           -- other config (JSON, no secrets)
    verified INTEGER DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
```

---

## 12. Backend Module Structure

```
backend/threat_hunting/
  __init__.py
  db.py                   # DB init, migration, CRUD helpers
  models.py               # Pydantic models for API I/O
  artifacts.py            # EvidenceItem creation and storage
  extractors/
    __init__.py
    dispatcher.py         # auto/docling/marker routing
    docling_extractor.py
    marker_extractor.py
    text_extractor.py
    url_fetcher.py        # httpx + SSRF policy + trafilatura
    csv_ioc_extractor.py
  iocs.py                 # IOC normalization, dedup, noise scoring
  ssrf.py                 # SSRF IP block-list enforcement
  agents/
    __init__.py
    pipeline.py           # LangGraph graph definition
    nodes/
      intake_classifier.py
      artifact_parser.py
      ioc_normalizer.py
      threat_context_builder.py
      hypothesis_generator.py
      hunting_lead_planner.py
      deep_retrohunt_planner.py
      ttp_analyst.py
      query_drafting_agent.py
      results_interpreter.py
      report_writer.py
  siem/
    __init__.py
    base.py               # Abstract connector base
    splunk.py             # Splunk REST API connector
  reports.py              # Report assembly and formatting
  runner.py               # Job/task lifecycle management

backend/api/routes_threat_hunting.py
```

---

## 13. Frontend Module Structure

```
frontend/src/pages/
  ThreatHunting.tsx           # Top-level page: list hunt packages

frontend/src/pages/threat-hunting/
  HuntPackageWizard.tsx       # Multi-step creation wizard
  HuntDetail.tsx              # View/manage a hunt package
  EvidencePanel.tsx           # Evidence items list + upload
  ArtifactsPanel.tsx          # Extracted IOCs and parsed content
  HypothesesPanel.tsx         # Review hypotheses
  LeadsPanel.tsx              # Review hunting leads + tasks
  RetrohuntPanel.tsx          # Deep Retrohunt review + approval
  QueryDraftsPanel.tsx        # SPL/KQL/ES/CQL drafts
  ExecutionPanel.tsx          # SIEM execution + result monitoring
  ReportPanel.tsx             # Final hunt report

frontend/src/pages/configuration/
  SiemConnectorsTab.tsx       # SIEM connector management (new)
  LLMProvidersTab.tsx         # Moved from Normalizer to General config
```

---

## 14. API Route Map

All routes under `/api/threat-hunting/`, admin + threat-researcher only:

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/threat-hunting/packages` | List all hunt packages |
| `POST` | `/api/threat-hunting/packages` | Create new hunt package |
| `GET` | `/api/threat-hunting/packages/{id}` | Get package detail |
| `PUT` | `/api/threat-hunting/packages/{id}` | Update package metadata |
| `DELETE` | `/api/threat-hunting/packages/{id}` | Archive package |
| `POST` | `/api/threat-hunting/packages/{id}/evidence` | Add evidence item |
| `DELETE` | `/api/threat-hunting/packages/{id}/evidence/{eid}` | Remove evidence item |
| `POST` | `/api/threat-hunting/packages/{id}/generate` | Trigger LLM generation |
| `GET` | `/api/threat-hunting/packages/{id}/generate/status` | Poll generation status |
| `POST` | `/api/threat-hunting/packages/{id}/approve` | Approve package for execution |
| `POST` | `/api/threat-hunting/packages/{id}/execute` | Start SIEM execution |
| `GET` | `/api/threat-hunting/packages/{id}/results` | Get execution results |
| `GET` | `/api/threat-hunting/packages/{id}/report` | Get final report |
| `GET` | `/api/threat-hunting/connectors` | List SIEM connectors |
| `POST` | `/api/threat-hunting/connectors` | Add connector |
| `PUT` | `/api/threat-hunting/connectors/{id}` | Update connector |
| `DELETE` | `/api/threat-hunting/connectors/{id}` | Delete connector |
| `POST` | `/api/threat-hunting/connectors/{id}/test` | Test connector |

---

## 15. Security Considerations

| Risk | Mitigation |
|---|---|
| Malicious PDF/DOC uploads | Parse in subprocess isolation where possible; cap file size; validate MIME by magic bytes; store original but operate on extracted text only |
| SSRF via URL ingestion | Enforce `ssrf.py` block list on every fetch + each redirect hop; log fetch metadata |
| SIEM credential leakage | Write-only storage; API tokens stored hashed or in secure keystore; never logged |
| LLM prompt injection via evidence | Do not execute LLM-generated outputs as code; treat all LLM outputs as draft data requiring operator review |
| Noisy retrohunt searches | Noise scorer + operator review gate before SIEM execution; warn on estimated match count |
| Watcher public feed usage | Internal module imports from authenticated DB/API calls, not public `/feed/watcher/*` URLs |
| Role escalation | New role checks in backend middleware; frontend guards; test coverage required |
| Evidence retention | Blobs stored under `data/threat_hunting_blobs/`; access via authenticated API only; never served publicly |
| Excessive LLM token use | Per-hunt token budget config; LLM call step/context limits |
| Long-running pipeline durability | All state persisted to `threat_hunting.db` before each step; LangGraph checkpointing |

---

## 16. LLM Configuration Relocation

**Current:** LLM Providers tab lives under `Normalizer` page.

**Target:** Move `LLMProvidersTab` to `Configuration → General → LLM Providers`.

Impact:

- `Normalizer.tsx`: remove LLM Providers sub-tab.
- `Configuration.tsx` General group: add `LLM Providers` tab.
- No backend changes needed — routes are already at `/api/llm/`.
- Both Normalizer smart mode and Threat Hunting agents use the shared provider registry.

---

## 17. Implementation Roadmap

| Phase | Scope | Branch |
|---|---|---|
| **0** | This design document | `main` |
| **1** | Role model update + skeleton route/UI + `threat_hunting.db` schema | `feat/th-phase-1-skeleton` |
| **2** | Hunt Package wizard + evidence intake (upload, URL, watcher, text) | `feat/th-phase-2-intake` |
| **3** | LLM agent pipeline — threat context, hypotheses, leads, TTP, query drafts | `feat/th-phase-3-agents` |
| **4** | Deep Retrohunt IOC sanitization + SPL draft generation | `feat/th-phase-4-retrohunt` |
| **5** | Splunk connector — config, test, execute, result collection | `feat/th-phase-5-splunk` |
| **6** | Report assembly, review UI, full end-to-end hunt workflow | `feat/th-phase-6-reporting` |

---

## 18. Open Decisions (Deferred)

- Multi-SIEM (Sentinel KQL, Elastic, CrowdStrike CQL) — Phase 5+ after Splunk.
- Automated evidence ingestion from TAXII/STIX feeds.
- Hunt package sharing / export (STIX, PDF, JSON).
- Scheduled re-hunting against updated IOC sets.
- Collaboration features (comments, review assignments).
- Subprocess/sandbox isolation for document parsing.
