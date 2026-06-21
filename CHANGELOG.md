# Changelog

All notable changes to Mizton-ThreatBox are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added — Agent Tools Config, Expandable Phase Cards, Marker PDF Parser (issue-local-007)

- **Part 2A — Agent Tools Configuration**: global per-tool enable/disable toggles in Agents Configuration tab (Threat Hunting group); backend-driven catalog endpoint (`GET /api/app/agent-tools/catalog`) returns operator-facing labels, descriptions, per-tool agent assignments, implication-if-disabled text, and live runtime `available` flag; hard gate in all 4 tool-enabled nodes via new `get_enabled_tool_specs(names, enabled)` helper; disabled tools are never offered to the LLM; `deep_retrohunt_planner` inline tool tuple normalized to module-level `_TOOL_NAMES` constant; `load_agent_tools()`/`save_agent_tools()` in `loader.py` (YAML key `agent_tools`); `GET/PUT /api/app/agent-tools` routes; `ToolCatalogEntry` type in `client.ts`; `AgentsConfigTab` extended with pill-toggle rows per tool showing usage description, amber implication warning on disable, not-installed hint for Marker.
- **Part 2B — Expandable Phase Cards**: `list_hunt_packages` widens the `phases` projection to include `tools_used`, `decision`, `item_count`, `ioc_count`, `noisy_count` from step_logs (no schema migration); `THPhaseEntry` extended with these optional fields; `PhaseCard` in `ThreatHunting.tsx` is now an expandable button-card — collapsed shows label/status/elapsed, expanded shows tools-used pills (purple), decision text, and item/IOC counts; `ProcessArrow` uses `items-start` to accommodate expanded cards.
- **Part 2C — Docling PDF Parser**: switched from marker-pdf to Docling after dependency conflict assessment — marker-pdf hard-caps `pillow<11.0.0` reintroducing 3 High + 2 Medium Pillow CVEs; Docling requires `pillow<13.0.0,>=10.0.0` which is compatible with our `pillow>=12.2.0` security pin. Real `extract_pdf_docling()` implementation in `pdf_extractor.py` using Docling `DocumentConverter` + `DocumentStream` (no temp file) → `export_to_markdown()`; `is_docling_available()` runtime check; dispatcher routes `parser_mode='docling'` (and legacy `'marker'` as backward-compat alias) to Docling when available+enabled, `parser_mode='auto'` prefers Docling as default when available+enabled; `docling` key added to `agent_tools` config and catalog (category `document_parser`); `docling>=2.104.0` added to `requirements.txt` (note: pulls PyTorch ~2-3 GB; pillow-compatible); **startup script** (`mizton-threatbox`) gains an idempotent Docling model-prefetch block after the Playwright block — downloads DocLayNet/TableFormer/picture-classifier/RapidOCR models at startup, cached under `~/.cache/docling/`, non-fatal if network unavailable; `AddEvidenceModal` parser dropdown shows `(prefers Docling)` in auto-mode and disables Docling option with install hint when unavailable.

### Added — TH Tooling, Visualization, List UX, Hypotheses, Report, Re-run (issue-local-006)

- **Part A — URL Fetch Robustness**: browser-like headers (realistic UA/Accept), `raise_for_status` on 4xx/5xx (no more error-HTML extraction), `tenacity` retry with exponential backoff (3 attempts), extractor fallback chain (trafilatura → readability-lxml → raw utf-8), Playwright headless-Chromium fallback for JS-heavy pages; new `browser_fetcher.py` with SSRF validation + route interception + service-worker blocking; `mizton-threatbox` startup script idempotently installs Chromium.
- **Part B — Agent Tool-Calling**: `LLMClient.supports_tools` property (True for OpenAI/Anthropic/OpenAI-compatible, False for Ollama); `complete_with_tools()` on `OpenAIClient` (function-calling) and `AnthropicClient` (tool-use); `call_llm_with_tools()` in `llm_bridge.py` with non-capable provider fallback; `tools.py` with 6 tool wrappers (`extract_iocs`, `defang_ioc`, `noise_score`, `mitre_lookup`, `validate_spl`, `refetch_url`); `call_tool()` dispatcher with name + required-param validation + extra-kwarg stripping; 4 pipeline nodes (`intake_classifier`, `threat_context_builder`, `deep_retrohunt_planner`, `query_drafting_agent`) tool-enabled with `tools_used`/`decision`/`debug_lines` in step_logs.
- **Part C — Workflow Visualization**: 2-column layout in verbose/debug (task list LEFT, diagram RIGHT); `tools_used` pills per step in timeline view; `decision` sub-text per step; `THIntakeSource` interface and `intake_sources` in `THStepLog`; Mermaid: amber source nodes + edges above `intake_classifier`; ReactFlow: same with y=-120 source tier and dashed amber edges.
- **Part D — Hunt List Process-Arrow**: `list_hunt_packages` extended with latest-run phase summary (server-side subquery, no new migration); `THPhaseEntry`/`phases`/`total_elapsed_s`/`generation_status` on `THuntPackage`; `ProcessArrow` component in `ThreatHunting.tsx` (green=ok, red=error, blue-pulse=active, total elapsed time); `STATUS_COLORS.completed` → green.
- **Part E — Hypotheses Enrichment**: `suggested_actions: list[str]` added to `Hypothesis` TypedDict; prompt instructs model to provide 2–4 concrete detection steps per hypothesis (SIEM query, EDR artifact, MITRE T-ID, log source); `suggested_actions` rendered in `AnalysisTab` hypothesis cards; `ioc_basis` now rendered; both included in Markdown and PDF reports.
- **Part F — PDF Report Enrichment**: cover header block (styled H1 + thick colored rule + metadata row); page numbers via `onFirstPage`/`onLaterPages` callbacks; `Table`/`TableStyle` for Evidence Summary, TTP Techniques, and Execution Results; dark-blue `HRFlowable` rule above each H2 section header; all tables wrapped in try/except → paragraph fallback; no new dependencies.
- **Part G — Re-run Dialog**: Re-run button opens a modal with model selector (Configured default + provider·model dropdown) and effort pills (low/medium/high); `startGeneration` called with chosen `provider_name`/`model_name`/`research_effort`; providers lazy-loaded only when dialog opens.

### Security Fixes (issue-local-006 review)
- `python-multipart>=0.0.31` (was `>=0.0.9`; GHSA-wp53-j4wj-2cfg CVSS 8.7 at file-upload endpoints).
- `langsmith>=0.8.18` explicit pin (GHSA-f4xh-w4cj-qxq8 arbitrary file read via TracingMiddleware).
- `pillow>=12.2.0` explicit pin (GHSA-3f63-hfp8-52jq CVSS 9.3; transitive via pymupdf/reportlab).
- `ssrf.py`: RFC 6598 CGNAT `100.64.0.0/10` added to `_BLOCKED_NETWORKS`.
- `idna>=3.15` explicit pin (PYSEC-2026-215 ReDoS; hostname-length cap in `ssrf.py` is the advisory workaround).
- `browser_fetcher._ssrf_check_url` replaced with authoritative `ssrf.py` logic (eliminates divergence and CGNAT gap).

### Added — Threat Hunting Framework (issue-local-002, Phases 1–6)

- **Phase 1** — Role model (`admin`, `threat-researcher`, `threat-viewer`, `feed-sender`), `threat_hunting.db` SQLite schema, sidebar sections, TH route skeleton, LLM Providers moved to Configuration → General.
- **Phase 2** — Hunt Package wizard; evidence intake (file upload with PyMuPDF/DOCX/text parsers, URL fetch with SSRF enforcement, watcher event import, manual text); IOC extraction, normalization, noise scoring; evidence API.
- **Phase 3** — LangGraph + LangChain agent pipeline: `intake_classifier → threat_context_builder → hypothesis_generator → hunting_lead_planner → ttp_analyst → query_drafting_agent`; operator approval gate; generation status API; `AnalysisTab` frontend with step progress and draft review.
- **Phase 4** — `deep_retrohunt_planner` agent node (parallel with `threat_context_builder`): deterministic IOC sanitization, deduplication, noise scoring with human-readable reasons, canonical IOC CSV, LLM-generated SPL macro draft and analyst notes; `RetrohuntPanel` frontend with IOC review table, noise flags, and CSV download.
- **Phase 5** — Splunk REST API connector (Bearer token + basic auth, TLS, `test_connection` / `submit_search` / `poll_job` / `fetch_results`); connector CRUD API; background execution runner with LLM result interpretation; `SiemConnectorsTab` in Configuration; `ExecutionPanel` in HuntDetail.
- **Phase 6** — `report_writer`: deterministic report assembly (evidence stats, threat context, hypotheses, retrohunt summary, TTP analysis, execution results, recommendations) + LLM executive summary; auto-triggered after execution; manual `POST /report` endpoint; `ReportPanel` frontend with collapsible sections, Generate/Regenerate button, Markdown and JSON export.

### Added — Per-hunt Model Selection + Re-runnable Hunt Packages (issue-local-005)

- **Per-hunt model selector**: `AnalysisTab` Generate screen now shows a "Model" dropdown populated from `GET /api/llm/providers` (mirrors `SmartProposalConfirmModal`). Blank = configured default; otherwise a `provider · model` pair is sent as `provider_name`/`model_name` to the generate endpoint. The chosen model/provider is displayed in the running-status bar.
- **Re-run model** (DB schema v4 — `_TH_SCHEMA_VERSION = 4`):
  - Each call to `start_generation` creates a **new** `hunting_packages` row with its own `run_id` (UUID). Prior runs are never overwritten.
  - `_ACTIVE_JOBS` re-keyed by `run_id`; sequential guard prevents starting a run while another is active for the same package.
  - New columns: `run_id TEXT` on `hunt_reports` and `task_results`; v3→v4 migration runs ALTER + backfill.
- **New CRUD helpers** in `db.py`: `get_generation_run(run_id)`, `list_generation_runs(pkg_id)`, `list_task_results_by_run(run_id)`, `get_hunt_report_by_run(run_id)`. `create_task_result`/`create_hunt_report` accept optional `run_id`.
- **report_writer**: `write_report` accepts `run_id`; loads generation record and SIEM results scoped to that run; stores report with `run_id` linkage.
- **SIEM executor**: `start_execution` accepts `run_id`; persists it on `task_results`.
- **New API endpoints**: `GET /packages/{id}/runs`, `GET /runs/{run_id}/status`, `POST /runs/{run_id}/approve|reject`, `GET /runs/{run_id}/results`, `GET/POST /runs/{run_id}/report`, `GET /runs/{run_id}/report/markdown|pdf`. Legacy package-level routes remain and resolve to the latest run.
- **Frontend run picker** (`HuntDetail.tsx`): a run selector dropdown shows all runs (newest first, labeled by timestamp + model + status). Selected run is threaded into `AnalysisTab`, `ExecutionPanel`, `ReportPanel`.
- **Re-run button** in `HuntDetail.tsx`: visible when the package is finished and no run is active. Creates a new generation and auto-selects the new run.
- **`client.ts`**: new `THRunSummary` type; `run_id` on `THGenerationRecord`, `THTaskResult`, `THHuntReport`; new `listRuns`, `getRunStatus`, `approveRun`, `rejectRun`, `listRunResults`, `getRunReport`, `generateRunReport`, `downloadRunReportMarkdown/Pdf` methods.
- **ReportPanel**: PDF download link added; uses run-scoped URL when a `runId` is active.
- **Tests**: 11 new backend tests covering schema v4 migration, CRUD helpers, runner independence, sequential guard, model threading, and run-scoped API routes (1078 total pass). Existing v3 migration test updated to assert `version >= 3`.

### Added — Agents Configuration & TH Settings (issue-local-004)

- **Agents Configuration tab** (new, under Configuration → Threat Hunting group):
  - *Agentic Workflow Verbosity*: Info (clean step summary), Verbose (animated pipeline card with per-step status/timing/item counts), Debug (verbose + scoped backend log textbox).
  - *Visualization Style* (Verbose/Debug only): Timeline (built-in animated list), Mermaid (lazy-loaded flowchart), React Flow (lazy-loaded interactive node/edge graph).
- **Threat Hunting Settings tab** (new, under Configuration → Threat Hunting group):
  - *Research Effort*: High / Medium / Low — tunes hypothesis count, lead count, `max_tokens`, and IOC caps across all agent nodes; per-run override available at generation time.
  - *Report Format*: PDF and Markdown toggles (both default on).
- **Backend settings** persisted in `application.yaml` via `config/loader.py` + `GET/PUT /api/app/agent-verbosity|agent-visualization|th-research-effort|th-report-formats` routes.
- **Effort profile** (`backend/threat_hunting/agents/effort_profile.py`): canonical knob table for High/Medium/Low used by all agent nodes.
- **`research_effort`** threaded through `HuntPipelineState`, `build_initial_state`, `runner.start_generation`, and `POST /generate` (`GenerateBody.research_effort`).
- **Step telemetry** persisted to DB: schema v3 migration adds `current_step`, `completed_steps`, `step_logs`, `research_effort` columns to `hunting_packages`; runner persists after each node; status endpoint returns live data.
- **WorkflowVisualizer** (`frontend/src/pages/threat-hunting/WorkflowVisualizer.tsx`): reads verbosity + visualization settings and renders accordingly during a running generation.
- **Mermaid/ReactFlow visualizers** lazy-loaded so default bundle is unaffected.
- **Report formats** (`reportlab>=4.0` added to `backend/requirements.txt`):
  - `render_report_markdown(full_report)` — deterministic Markdown renderer.
  - `render_report_pdf(full_report)` — reportlab PDF renderer (no OS deps).
  - `GET /packages/{id}/report/markdown` → `text/markdown` download.
  - `GET /packages/{id}/report/pdf` → `application/pdf` download (generated on demand).
- **35 new backend tests** (`test_th_issue_local_004.py`) covering loader round-trips, route validation, effort profile ordering, schema v3 migration (fresh + from v2), and report format renderers.
- **8 new frontend tests** (`agentsConfigTabs.test.tsx`) covering tab rendering, verbosity toggle behavior, effort options, format toggles, and Configuration TH group tabs.

### Added — Other
- Initial project structure based on ThreatFeeds Lite fork.
- Renamed project identity to Mizton-ThreatBox across all manifests, docs, and tooling.
- Added `pyproject.toml` as the canonical Python project descriptor.
- Consolidated version string into `backend/__init__.py` (`__version__`).
- Added OCI image labels to `docker/build/Dockerfile`.
- Added `.dockerignore` at `docker/build/`.
- Added `CHANGELOG.md`, `CONTRIBUTING.md`, and `.github/workflows/ci.yml`.
- Updated `LICENSE` copyright holder to HoneyMex Lab (2025–2026).
- Updated `README.md` clone URL from placeholder to actual repository URL.

---

## [0.1.0] — 2026-06-20

### Added
- Initial import from ThreatFeeds Lite (fork base).
- Threat Intelligence feed ingestion: JSON, NDJSON, CSV/TSV, XML; `.gz` and `.zip` decompression.
- LLM-powered normalization engine with smart-mode field-mapping proposals.
- Watcher system: saved filters with public syndication feeds and optional webhook delivery.
- Web UI: Viewer, Normalizer, Smart Mappings, Configuration, Watchers, Account pages.
- Push listener endpoint (`POST /api/ingest/listener`).
- Optional authentication with role-based access (`admin`, `normal`, `sender`).
- SQLite-backed storage; no external database required.
- `./mizton-threatbox` shell launcher with `start`, `stop`, `restart`, `status` commands.
- Docker image and Compose file at `docker/`.
- API client script at `scripts/api_client.py`.
- Backend: FastAPI + uvicorn + APScheduler + aiosqlite.
- Frontend: React 18 + TypeScript + Vite + Tailwind CSS.

[Unreleased]: https://github.com/Mizton-Labs/Mizton-ThreatBox/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Mizton-Labs/Mizton-ThreatBox/releases/tag/v0.1.0
