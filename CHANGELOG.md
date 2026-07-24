# Changelog

All notable changes to Mizton-ThreatBox are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added — User Management relocation, admin password reset hardening, per-user themes (issue-local-016)

**User Management moved from Threat Intel to General Configuration.** It's an instance-wide
administration concern, not Threat-Intel-specific — a tab-group relocation only, no behavior
change (still admin-only, still the same component).

**Global Field Defaults moved from General Configuration to Threat Intel.** It configures
default field mappings for ingested Threat Intel data specifically, so it belongs alongside the
other Threat-Intel-scoped settings (General TI Settings, feed sources) rather than under general
platform settings — a tab-group relocation only, no behavior change.

**Admin password reset now generates a random password and forces a change on next login.**
Previously the admin typed the new password directly. The admin no longer supplies one at
all — the backend generates it (`secrets.token_urlsafe(18)`, the same pattern already used by
`--reset-admin-password`), flags the account `must_change_password`, and returns the generated
value once for the admin to hand off out-of-band (there's no email capability in this codebase).
The forced-change enforcement itself needed no new code — the existing `must_change_password`
middleware gate and forced-reset screen already covered it unconditionally. The reset UI requires
an explicit "Generate new password" click (not auto-generated on open) and shows the value
read-only with a copy-to-clipboard affordance and a one-time-only warning.

**New per-user theme system: "Classic" (the existing look, now a named theme) and "Energy" (new)
— an admin-configurable instance default, user-overridable from the Account page.** No theming
infrastructure existed before this (single hardcoded dark palette) — built from scratch:
- `gray`/`brand` Tailwind color scales now resolve through CSS custom properties, switched by a
  `data-theme` attribute on `<html>`, so every existing component's `bg-gray-950`,
  `border-brand-700`, `.tab-active`, `.toggle-on`, focus rings, etc. re-skins per theme with zero
  component-file changes. Severity badges and other status colors (red/green/orange) stay on
  Tailwind's stock palettes, untouched, so error/success meaning stays constant across themes.
  Classic's values are the literal pre-existing colors — visually unchanged.
- Energy: solid neutral dark grey/black surfaces (every `gray-*` stop is R=G=B — no warm/sepia
  tint) with a real solid yellow accent (`brand-*`) on buttons, active tab, toggles, and focus
  rings — same role a theme's accent color normally plays, just yellow instead of blue. (An
  earlier iteration tried a diffuse yellow box-shadow glow instead of a solid fill, to keep the
  accent more contained — but the glow bled into the surrounding dark background and read as
  sepia too, so it was dropped in favor of solid fills on discrete elements.) A muted brick-red
  decorative touch remains on the sidebar active item / card hover — unrelated to yellow, not a
  semantic color; danger/error stays on stock red in both themes.
- `users.theme` (schema v5, nullable — NULL means "follow the instance default"), a new
  `GET/PUT /api/app/theme` (public GET, admin-gated PUT, mirrors the existing `app/title`
  pattern), and a new self-service `PUT /api/auth/me/theme` (any authenticated user, own account
  only). Selectable in General Configuration (instance default) and the Account page (personal
  override, with a "use instance default" option to clear it).
- Fixed a related pre-existing bug found while wiring this up: `GET /api/app/title` claimed
  public (pre-login) access in its own docstring but had no matching middleware carve-out, so it
  actually 401'd for unauthenticated visitors — the sidebar/tab-title just silently fell back to
  the default, masking it. Fixed alongside the new `/api/app/theme` carve-out (same one-line
  pattern, needed for the login screen to theme correctly pre-login).

**About page now shows the build's git branch alongside its commit**, so the exact deployed
version is always unambiguous (e.g. a feature-branch build vs. `main`). Follows the exact same
build-time-injection pattern already used for the commit hash: the launcher (`mizton-threatbox`)
now also captures `git rev-parse --abbrev-ref HEAD` and passes it as `GIT_BRANCH` to the frontend
build, wired through Vite's `define` as `__GIT_BRANCH__`.

**Tests:** schema v4→v5 migration and `set_theme`/`VALID_THEMES` coverage, admin-reset
random-generation + forced-change + session-eviction + non-admin-403 coverage, self-service theme
endpoint (including a non-admin-role regression test for the new `_SELF_PATHS` entry),
`GET/PUT /api/app/theme` admin-gating + validation, a public-pre-login regression test for both
`/api/app/theme` and `/api/app/title`, `ThemeProvider`/`useTheme` fallback/apply/optimistic-
update/rollback coverage, and Configuration/Account UI coverage for the relocated tab and both new
theme pickers.

### Added — Threat Hunting analysis/IOC data-integrity improvements (issue-local-015 Part 1)

issue-local-015 spans five feature areas (progress stepper/run-scoping, per-run configuration
including Threat Intel enrichment, a creation-wizard redesign, hypothesis/IOC analysis UX, and
deeper verbose logging). This pass covers the analysis/IOC/data-integrity subset; the creation
wizard, Threat Intel enrichment toggle, "Recommendations" (behavioral IoA / detection-use-case
suggestions), and deeper verbose-logging work are deferred to a follow-up.

**Bug fixed: IOC data was not actually independent per run.** The run-selector dropdown already
correctly re-scoped hypotheses/hunting-leads/deep-retrohunt/report/execution-results per run, but
`extracted_iocs` had no `run_id` column at all, and `clear_extracted_iocs` wiped the package's
entire IOC set at the start of every run — so switching to an older run never showed that run's
actual IOCs, and re-running destroyed the previous run's IOC data outright. Fixed via DB schema
v5 (`run_id`/`action` columns on `extracted_iocs`, backfilled for existing data) and scoping every
read/write/clear to `(hunt_package_id, run_id)`.

**IOC active-cleaning config.** Each run can now choose `tagging_only` (default — flags noise but
never excludes anything, matching pre-015 behavior exactly) or `active_cleaning` with four
independent toggles: remove noisy IOCs, remove known legit domains, remove known CDN
ranges, remove known legit services. Removed IOCs are marked, not deleted — still visible/
auditable in the IOC table (now showing Result and Action columns), just excluded from what
feeds the LLM pipeline downstream. CDN-range coverage is domain-based (no real IP-range data
source exists in this codebase) — documented, not a silent gap.

**Hypothesis confidence + Discard.** Hypotheses now carry an LLM-assessed `confidence` score
(0-100, distinct from the existing coarse `relevance` bucket) and a `discarded` flag an analyst
can toggle to exclude a hypothesis from further consideration — persisted per run, never
overwritten by the LLM.

**Hypothesis ↔ Hunting Lead linking, now visible.** `HuntingLead.hypothesis_id` already flowed
end-to-end through the backend but was never rendered anywhere — hunting-lead cards now show
which hypothesis they were derived from.

**Evidence-source chips on hypothesis cards** — derived entirely client-side (no new backend
field): each hypothesis's `ioc_basis` values are looked up in the run's IOC list for their
`evidence_item_id`, then in the evidence list for a label.

**Progress-block header stepper** — horizontal, arrow-connected stepper in the hunt-package
header, visible regardless of active tab, tracking the five analyst-facing phases (Evidence,
Analysis, IOC, Execution, Report) rather than internal pipeline node names.

**Discard is a first-class action.** The Discard control on hypothesis cards is now a full-width,
clearly-labeled button card instead of a small inline link. Hunting leads gained the same discard
capability (previously only hypotheses could be discarded, with no way to exclude a lead).

**Fixed: a bad SIEM query draft could blank the whole Analysis page.** Some models occasionally
returned a structured object (e.g. a raw Elasticsearch DSL query, or `null`) in a query draft's
`query` field instead of a string. This crashed the query-viewer component (React error #31,
"objects are not valid as a React child") and, separately, crashed SPL tool-validation's
`str.join()` call, which silently discarded every draft for that step. Fixed at the source
(`query_drafting_agent` now normalizes non-string/`null` query values before returning) and
defensively in the viewer for already-stored data predating this fix.

**Fixed: the Sanitized IOCs table couldn't show what active cleaning removed.** `deep_retrohunt_
planner` read the already-filtered IOC list, so IOCs excluded by active cleaning were invisible to
it — no selector could ever surface them. Fixed by threading the full, unfiltered IOC list through
a new `all_extracted_iocs` state field; the deep-retrohunt SPL/CSV/LLM context still uses the kept
set only. The table's filter is now `All` / `Removed` (dropped the redundant `Noisy` tab, since
noise level is already shown per row), and a removed IOC's rationale — which active-cleaning rule
excluded it — is now surfaced and shown expanded by default instead of requiring a click.

**Fixed: truncated (but non-empty) LLM responses bypassed the retry-with-more-tokens logic.**
When a model ran out of output-token budget partway through a JSON response (`finish_reason=
length`), any already-emitted text was returned verbatim rather than treated as a failure — only
a genuinely *empty* response triggered the existing retry/backoff-with-higher-max-tokens path.
The result was intermittent parse failures in Analysis sections (raw JSON or unparsed text shown
instead of the rendered summary/technique list/query drafts) that a retry would usually have
avoided. Truncated non-empty content is now treated the same as empty content.

**Tests:** 23 new backend tests (`test_th_issue_local_015.py`) covering the schema v5 migration
(fresh DB and v4→v5 backfill), `compute_ioc_action` across all mode/toggle combinations, run-
scoped IOC independence, hypothesis discard round-trip, confidence normalization (clamping/
defaults for out-of-range or missing LLM values), and `/generate` `run_config` validation, plus
additional coverage for the query-draft normalization, kept/removed IOC visibility, and truncated-
content retry fixes above.

### Added — Threat Hunting reliability improvements (issue-local-014)

**1. Re-run available at any time.** The hunt-package re-run button and its backend endpoint no
longer block while a previous run is still active — `start_generation()` always creates a new,
independently-tracked run (`backend/threat_hunting/agents/runner.py`), and the frontend gate
(`HuntDetail.tsx`) no longer hides the button while a run is in progress. Lets an operator kick
off a second run (different model/effort) without waiting for the first to finish. The run
selector already listed/marked every run independently, so no further UI change was needed.
Known limitation: `hunt_packages.status` (one coarse value per package) can still race between
concurrent runs finishing at different times — per-run status (`hunting_packages.generation_status`)
is authoritative and unaffected.

**2. IOC parsing/verification consistency.** `backend/threat_hunting/iocs.py`:
- Defanging (`[.]`, `(.)`, `{.}`, `[dot]`/`(dot)`, `[at]`/`(at)`, `hxxp[://]`) now runs on the
  whole evidence text *before* IOC candidate matching, not only on an already-matched substring
  afterward — a redacted domain like `evil[.]com` previously never matched the extraction regex
  at all, so it was silently missed rather than merely mis-normalized.
- Consolidated three inconsistent noise-score thresholds (0.5 / 0.7 / 0.8, duplicated across
  `iocs.py` and `deep_retrohunt_planner.py`) into two shared constants, `NOISE_THRESHOLD` (0.7)
  and `HIGH_NOISE_THRESHOLD` (0.85); `deep_retrohunt_planner.py` now imports its noisy-domain/
  process/hash allowlists from `iocs.py` instead of maintaining copy-pasted duplicates.
- New LLM IOC-triage pass (`intake_classifier.py`) with a dedicated persona
  (`_IOC_TRIAGE_SYSTEM_PROMPT`) reviews IOCs the deterministic scorer didn't flag and catches
  what regex/allowlists can't — documentation/example domains, RFC 5737 test ranges, version-number
  false positives. Adjusts the in-memory IOC list feeding every downstream node (hypothesis,
  hunting-lead, deep-retrohunt); does not persist back to the `extracted_iocs` DB table.
  `llm_bridge.build_prompt()` gained an optional `system` override to support it (backward
  compatible — every other node keeps its existing default persona).

**3. LLM call retry/backoff resilience.** `backend/threat_hunting/agents/llm_bridge.py` gained a
retry loop around every agent LLM call, covering the failure mode that previously bypassed the
existing low-level HTTP retry entirely: a successful response whose content came back empty
because the output-token budget was exhausted (`finish_reason=length`). That case now retries
with `max_tokens` doubled each attempt (capped), while genuinely transient failures (timeouts,
5xx) retry unchanged and permanent ones (4xx) fail fast without wasting attempts. New configurable
settings `th_llm_max_retries` (default 3) and `th_llm_retry_backoff_seconds` (default 2.0),
exposed via `/api/app/th-llm-max-retries` / `/api/app/th-llm-retry-backoff-seconds` and a new
"LLM Call Resilience" section on the Agents Config tab.

**Tests:** 39 new backend tests across `test_th_llm_bridge_retry.py`, `test_th_iocs_014.py`,
`test_th_ioc_triage_014.py`, plus new coverage in `test_routes_app.py` and an updated
`test_th_issue_local_005.py` (the old "sequential guard returns the same run" test now asserts
the opposite — concurrent runs are allowed).

### Fixed — SSO users bypass forced password reset (issue-local-013)

**Bug:** Any user with `must_change_password=True` who authenticated via SSO was blocked by the
password-change gate — the middleware returned 403 on every API call and `ProtectedLayout` showed
a full-screen forced-reset screen. This affected: (a) existing local accounts (e.g. a bootstrap
admin after `--reset-admin-password`) that were later linked/authenticated via SSO, and (b) any
SSO-provisioned account where the flag was set after provisioning.

Three-layer fix:

- **Layer 1 — Clear flag at SSO login (`backend/auth/oidc.py`):** `_upsert_sso_user` now clears
  `must_change_password` in the matched-user branch — the `UPDATE users SET ... must_change_password = 0`
  SQL and the returned dict are both updated. Covers both existing local accounts logging in via SSO
  for the first time and returning SSO users. New SSO users were already created with the flag `False`
  (`oidc.py:398`) — that path is unchanged but now tested.

- **Layer 2 — Defense-in-depth middleware skip (`backend/main.py`):** The `must_change_password`
  gate at `main.py:329` now also checks `not user.get("idp")`. An SSO-linked account (`idp` set)
  is never blocked by the gate even if the flag somehow persists (e.g. set by an admin after
  the account was already linked). `resolve_session` already returns `idp` — no schema change needed.

- **Layer 3 — Frontend guard (`ProtectedLayout.tsx` + `client.ts`):** `_public_user` in
  `routes_auth.py` now exposes `idp`. `AuthUser` in `client.ts` has new optional field
  `idp?: string | null`. `ProtectedLayout.tsx` guards the forced-reset screen with
  `user.must_change_password && !user.idp` — SSO users (idp set) are never shown the screen,
  even before a `/me` refresh.

**Not changed:** Local login of a flagged non-SSO account still correctly forces the password
reset (existing behavior preserved). The `--reset-admin-password` workflow on pure-local accounts
continues to work as before.

**Tests:** 11 new backend tests (`test_auth_issue_local_013.py`) + 3 new frontend tests
(`auth.test.tsx`) covering all three layers and all scenarios (new SSO user, existing-user SSO
login, DB persistence, middleware pass/block, `_public_user` idp field, `/me` idp response,
frontend SSO bypass, frontend local-user still blocked).

### Added — Workflow viz, hunt creation, design, defaults, ownership, home page (issue-local-012)

- **Part 1a — Evidence nodes visually distinct**: Evidence source nodes now use a distinct **stadium shape** (`([...])`) in Mermaid and a **dashed capsule border** (`borderRadius: 20px, borderStyle: dashed`) in ReactFlow, differentiated from agent/task rectangular nodes. Teal/cyan base color (`#0e4f4f`/`#14b8a6`) for pending evidence — never used by agent nodes. Agent and evidence categories are now visually unambiguous.
- **Part 1b — Granular subtasks toggle**: New "Show subtasks" toggle above the diagram in Mermaid and ReactFlow visualizers. When on, derives child nodes client-side: one **subroutine node** per `tools_used[]` entry per agent step (violet: `#2d1b69`/`#7c3aed`), and explicit evidence-child connections under `intake_classifier`. Toggle state persisted server-side via new `GET/PUT /api/app/agent-show-subtasks` endpoint (default off). Also exposed in `AgentsConfigTab` as "Show granular subtasks by default". `classDef subtask` + `classDef evidence` added to Mermaid; dedicated sub-node rows added to ReactFlow graph. `client.ts`: `getAgentShowSubtasks`/`setAgentShowSubtasks` methods added.
- **Part 1c — In-progress node animation**: `@keyframes nodeGlow` CSS added to `index.css`; active ReactFlow nodes get `className="node-active"` for a pulsing blue glow. Mermaid injects a `<style>` element into the rendered SVG after render, applying a drop-shadow pulse animation to the active node via CSS class injection.
- **Part 2 — Drag-and-drop multiple files**: New `FileDropzone` component (`frontend/src/components/FileDropzone.tsx`) with drag-enter/over/leave/drop + click-to-browse, `multiple` files, drag-active highlight. Both `HuntPackageWizard` and `AddEvidenceModal` now use the dropzone; multiple files can be dropped at once and are uploaded sequentially with individual progress tracking.
- **Part 3a — Larger hunt card text**: Card name `text-sm` → `text-base font-semibold`; description `text-xs` → `text-sm text-gray-400`; meta line `text-[10px]` → `text-xs`. Applies to both Classic and Modern themes.
- **Part 3b — Clone hunt package**: New `POST /api/threat-hunting/packages/{id}/clone` endpoint (body: `{name}`). Backend `clone_hunt_package` DB helper copies all `evidence_items` rows + `evidence_blobs`, resets `parse_status='pending'`/`extracted_text=''`, preserves `fetch_metadata` (parser_mode) and watcher snapshots. Runs, reports, IOCs and generation state are NOT copied. Frontend: Clone button (Copy icon) on each hunt card → name dialog (prefilled "Copy of …") → `api.threatHunting.clonePackage` → navigates to new package.
- **Part 4 — New default values**: Backend `loader.py` default constants changed: research effort `medium` → **`high`**, verbosity `info` → **`debug`**, visualization `timeline` → **`reactflow`**. These apply app-wide until the user saves different values in Configuration. Frontend defaults updated to match (`AgentsConfigTab`, `ThreatHuntingSettingsTab`, `AnalysisTab`). Test assertions updated for the 7 affected tests.
- **Part 5 — Hunt package creator shown on card**: Each hunt card now shows the `created_by` username (with `UserCircle` icon) in the meta line when present. Backend already captured and returned this field; only the card UI was missing.
- **Part 6 — New Home landing page**: `frontend/src/pages/Home.tsx` — a centered landing page with two module cards: **Threat Intelligence Feeds** (icon `Radar`) → Viewer and **Threat Hunting** (icon `Crosshair`) → Threat Hunting. Post-login landing changed from `/viewer` to `/home`. `Home` added to `PAGE_COMPONENTS`, `KNOWN_ROUTES`, and as a sidebar nav section at the top. `navigation.test.tsx` KNOWN_ROUTES assertion updated.

### Added — Threat Hunting UX overhaul (issue-local-011)

- **Part 1 — Deferred file parsing**: File uploads are now instant. PDF/DOCX parsing (previously synchronous at upload time) is deferred to the analysis pipeline, exactly like URL fetching. `add_evidence_file` stores the raw blob with `parse_status='pending'`; `intake_classifier` parses pending files at analysis time using the user's chosen parser mode (stored in `fetch_metadata`). New `get_evidence_blob` DB helper. `intake_sources` extended with `sub_status` and `parser_used` per item. `parsed_file_count` added to step_log.
- **Part 2 — Upload progress bar**: File uploads now report real byte-level progress. `api.addEvidenceFile` switched from plain `fetch` to `uploadMultipartWithProgress` (XHR-based). Both `HuntPackageWizard` and `AddEvidenceModal` render a progress bar with percentage and KB uploaded/total. File name + size summary shown after selection. Parser options unified to Auto / PyMuPDF / Docling (removed stale "Marker" option from wizard).
- **Part 3 — Phase card sizing + 2-theme system**: Phase cards slightly reduced to ~1.25x from original (`px-3 py-2 text-[13px] min-w-[88px]`). New localStorage-backed theme selector (`sfi.th.cardTheme`): **Classic** (current look with solid fills, `border-2`, neon status colors) and **Modern** (softer fills, `border`, muted palette, lighter aesthetic). A segmented "Classic | Modern" toggle in the TH list header persists the preference. Theme applies only to the Threat Hunting item list and phase cards.
- **Part 4 — Delete confirmation**: Archive and evidence-delete actions now require confirmation. New reusable `ConfirmDialog` component. List-page archive shows a warning dialog before executing. Evidence delete in the detail view shows a confirmation before removing.
- **Part 5 — Routed TH views**: Threat Hunting navigation converted from internal component-state to React Router routes. New routes: `threat-hunting/new` (full-page clean wizard, `ThreatHuntingNew.tsx`) and `threat-hunting/:id` (detail view, `ThreatHuntingDetail.tsx`). "New Hunt Package" button navigates to `/threat-hunting/new` instead of opening a modal. Deep links and browser back-button now work. `beforeunload` event guard: if the wizard has a package name and evidence hasn't been saved yet, the browser warns on tab close / refresh.
- **Part 6 — Re-run any time**: Re-run is now available as soon as evidence is uploaded, not only after analysis completes. Changed gate from `isFinished` to `pkg.evidence_count > 0` (backend already allowed re-runs at any stage). Matches the backend's only real guards: "at least one evidence item" and "no concurrent run".
- **Part 7 — Live per-evidence nodes + IOC link**: Intake diagram now shows per-evidence sub-task status live. In the timeline view, a sub-list under `intake_classifier` renders each evidence item's `sub_status` (gray=pending, blue=running/ok, red=error), label, item type, text length, and parser used. When IOCs are present, a clickable "View N IOCs →" link switches directly to the IOC tab. Mermaid and ReactFlow visualizers now color each evidence source node by `sub_status` (green=ok, red=error, amber=partial, gray=pending). `THIntakeSource` type extended with `sub_status`, `parser_used`, `ioc_count`. `AnalysisTab` and `WorkflowVisualizer` wired with `onShowIocs` callback from `HuntDetail`.

### Added — SSO / OIDC authentication support (issue-local-010)

- **Generic OIDC Authorization Code + PKCE flow** via `authlib>=1.3.0`. Works with Microsoft Entra ID (Azure AD), Okta, Google Workspace, Keycloak, Auth0, and any OIDC provider with a discovery document. Provider is selected via `provider_preset`; Entra is just one named preset.
- **SSO coexists with local login**: the login page shows a configurable "Sign in with SSO" button above a divider and the existing username/password form. Local admin always works as a break-glass path.
- **Write-only-secret config** at `config/sso.yaml` (gitignored). Mirrors `llm-providers.yaml` hygiene: `client_secret` is always redacted to `"***"` on reads; sentinel round-trips preserve the stored value. `config/sso.yaml.example` committed with annotated Entra, Google, and generic OIDC templates. Env overrides: `MIZTON_THREATBOX_SSO_ENABLED`, `..._SSO_CLIENT_ID`, `..._SSO_CLIENT_SECRET`, `..._SSO_ISSUER`, `..._SSO_TENANT_ID`, `..._SSO_BUTTON_LABEL`, `..._SSO_DEFAULT_ROLE`.
- **Role mapping**: configurable `role_claim` (e.g. `roles` for Entra App Roles, `groups` for group GUIDs) with a `role_mapping` dict (claim value → app role). Most-privileged match wins when a user has multiple matching claims. Unmapped users get `default_role` (default `threat-viewer`).
- **Auto-provisioning**: on first SSO login, a Mizton-ThreatBox account is automatically created with an unusable local password. `auto_provision: false` requires manual account creation. Returning SSO users are matched by `(idp, sub)` first (stable across email renames), then by username.
- **DB schema v4 migration**: two nullable columns added to `users` (`idp`, `external_id`) for SSO account tracking; new `oidc_flows` table stores short-lived OIDC state/nonce/PKCE (10-min TTL, consumed atomically on callback to prevent replay). Migration is idempotent; existing local accounts are unaffected (both columns NULL).
- **New backend modules**: `backend/auth/oidc_config.py` (config load/save/validate/redact/map_claims), `backend/auth/oidc.py` (discovery cache, PKCE, authorization URL builder, callback handler, ID-token verification via joserfc/JWKS, user upsert).
- **New routes** (all under `/api/auth`):
  - `GET /api/auth/oidc/login` — public; redirects browser to IdP authorize endpoint.
  - `GET /api/auth/oidc/callback` — public; exchanges code, verifies ID token, mints `sf_session` cookie, 302-redirects to SPA; SSO errors redirected to `/login?sso_error=…`.
  - `GET /api/auth/sso/config` — admin; returns redacted SSO config.
  - `PUT /api/auth/sso/config` — admin; validates and persists SSO config.
  - `GET /api/auth/sso/callback-url` — admin; returns the computed redirect URI to copy into the IdP registration.
  - `GET /api/auth/status` extended: now publishes `sso_enabled` and `sso_button_label`.
  - Both OIDC paths added to `_PUBLIC_API_PATHS` in `main.py`.
- **Frontend**:
  - `client.ts`: new `SsoConfig` type; `AuthStatus` extended with `sso_enabled`/`sso_button_label`; `api.auth.getSsoConfig/updateSsoConfig/getSsoCallbackUrl`; `ssoLoginUrl()` helper.
  - `auth/context.ts` + `AuthContext.tsx`: `ssoEnabled`/`ssoButtonLabel` added to `AuthContextValue`, populated from `/status` on bootstrap.
  - `Login.tsx`: SSO button (`LogIn` icon + configurable label) rendered above a divider when `ssoEnabled`; `?sso_error=` query param decoded to human-readable messages; `autoFocus` moved to password form only when SSO is visible.
  - `SsoConfigTab.tsx`: new admin-only tab (Configuration → General → SSO / OIDC) — toggle, preset selector, issuer, client credentials (write-only masked secret), scopes, button label, username/role claim, role-mapping editor (dynamic rows), default-role selector, auto-provision toggle, read-only callback URL with copy button, setup guide.
  - `Configuration.tsx`: `sso-config` tab added to `GENERAL_TABS` and tab renderer.
- **Callback URL** (register this in your IdP): `https://<host>/api/auth/oidc/callback` (or `https://<host>/<base-prefix>/api/auth/oidc/callback` if using `app_base_prefix`). Exact URL shown in Configuration → SSO → Callback URL field.
- **36 new backend tests** in `test_auth_issue_local_010.py`: config validation, secret redaction/merge, env overrides, tenant-ID substitution, `map_claims_to_role` (6 cases), DB v4 migration idempotency, `oidc_flows` create/consume/expiry roundtrips, `get_user_by_external_id`, URL sanitization and callback-URL builder, public allowlist, SSO endpoint structural checks.
- **Breaking (existing tests)**: `test_auth_db.py::test_migration_adds_must_change_password_to_legacy_db` updated — schema version assertion changed from `3` → `4`.

### Added — Execution/report workflow visibility, report prose fix, ruff CI fix (issue-local-009)

- **Part 1 — Fine-grained workflow visibility for SIEM execution + report generation**:
  - New DB helpers `append_run_step_log(run_id, entry)` (last-write-wins merge) and `set_run_generation_status(run_id, status)` in `db.py`.
  - New `generation_status` values: `executing` (SIEM execution phase) and `reporting` (report generation phase).
  - `executor._run_execution` now writes 5 fine-grained step_logs: `siem_connect`, `siem_submit`, `siem_poll` (live progress %), `siem_fetch`, `siem_interpret`. Sets `generation_status="executing"` on the run row during execution. Passes `run_id` to `write_report` for scoped report.
  - `report_writer.write_report` now writes 4 fine-grained step_logs: `report_assemble`, `report_exec_summary`, `report_findings`, `report_render`. Sets `generation_status="reporting"` during generation, restores to `"completed"` when done. All step writes are soft-fail.
  - Frontend: `STEP_ORDER` and `STEP_SHORT_LABELS` in `ThreatHunting.tsx` extended with 9 new step IDs (5 siem\_\* + 4 report\_\*). Poll condition widened to also poll during `executing` and `reporting` statuses. Generation status badge has new amber (`executing`) and purple (`reporting`) color treatments. `ProcessArrow.isRunning` covers all three active statuses.
  - `WorkflowVisualizer.tsx`, `MermaidVisualizer.tsx`, `ReactFlowVisualizer.tsx` all updated with execution and report nodes/edges (+ approval gate node between pipeline and SIEM steps).
  - `client.ts`: `THGenerationRecord.generation_status` union extended with `executing`/`reporting`; `THStepLog.status` and `THPhaseEntry.status` extended with `running` for in-progress steps.

- **Part 2 — Fix: Executive Summary and Findings sections showed raw JSON**:
  - `build_prompt()` gains `json_output: bool = True` param. When `False`, the system prompt omits all JSON-only directives and instead instructs the model to write clear prose. User prompt also drops the "return ONLY the JSON" suffix.
  - `_generate_executive_summary` and `_generate_findings` in `report_writer.py` now call `build_prompt(..., json_output=False)`.
  - New `_clean_prose_response(text)` helper in `report_writer.py`: strips ` ```json ``` ` fences; unwraps single-value JSON dicts (e.g. `{"executive_summary": "…"}` → the inner string). Applied to both prose LLM returns.
  - `_interpret_results` in `executor.py` also updated to use `json_output=False` (SIEM interpretation always produces plain text).

- **Part 3 — Fix: Ruff CI failures in test_th_issue_local_008.py**: 12× I001 (unsorted per-function imports) and 1× F401 (unused `asyncio` import) fixed via `ruff check --fix` + `ruff format`. All 13 errors resolved; tests still pass.

- **21 new backend tests** in `test_th_issue_local_009.py`:
  - `append_run_step_log`: insert, last-write-wins merge, no-op when run missing.
  - `build_prompt(json_output=False)`: JSON directives absent; prose system prompt used.
  - `_clean_prose_response`: passthrough, fence stripping, single-key dict unwrap (5 variants), multi-key dict preserved.
  - Structural: executor `_step_log` helper + `run_id` param + step name coverage; report_writer `_report_step_log` + step name coverage.

### Added — Hunt-list process-arrow, IOC agent task, report findings, effort-aware tools (issue-local-008)

- **2A — Always-visible process-arrow rail**: phase rail now rendered on every hunt-list card regardless of run state (was null for draft/never-run); live ticking timer when running (from run_created_at); total elapsed when finished; per-step tools-used pills + item/IOC counts inline on done steps (no longer click-to-expand); `list_hunt_packages` fixed subquery to use `ORDER BY created_at DESC` + adds `run_created_at` to projection.
- **2B — IOC extraction + URL fetch become genuine agent tasks (Option B2)**: upload routes (`file`, `text`, `watcher`, `url`) no longer extract IOCs or fetch URL content. `add_evidence_url` stores a `parse_status='pending'` evidence item with SSRF pre-validation only. `intake_classifier` now: (1) fetches pending URL evidence via `fetch_url()` with effort-aware Playwright settings, (2) clears prior IOCs (`clear_extracted_iocs`) for idempotent re-runs, (3) runs deterministic `extract_iocs_from_text` over all evidence text + persists to DB. New db helpers: `clear_extracted_iocs`, `update_evidence_item`. IOC tab hidden until IOCs are present. Pending URL evidence shows "⟳ pending — fetched during analysis" in Evidence tab.
- **2C-A — Auto-report on pipeline completion**: `runner._run_pipeline` now auto-triggers a run-scoped `write_report()` (soft-fail) when the pipeline completes (`final_status='completed'`), so a report is available after analysis + approval without requiring a manual POST.
- **2C-B — Hypothesis detail parity**: `ReportPanel.tsx HypothesesSection` now renders `ioc_basis` chips and `suggested_actions` list, matching the Analysis tab. The frontend `reportToMarkdown` helper also includes them. (Backend renderers already included them.)
- **2C-C — Findings/Conclusion section (LLM-generated, placed last)**: new `findings` field in `assemble_report`, generated by a second LLM call in `write_report` (soft-fail with templated fallback). Rendered after Recommendations in `render_report_markdown`, `render_report_pdf`, and `ReportPanel.tsx`. More detailed than executive summary; synthesizes threat context, IOCs, TTPs, SIEM results, and a clear conclusion statement. Added to `THFullReport` TS type.
- **2D — High-effort tool forcing + Playwright-first URL fetch**: `effort_profile.py` gains `force_all_tools: bool` (high=True) and `url_fetch_strategy` (high="playwright_first"). `intake_classifier` reads effort profile and passes `prefer_playwright=True` to `fetch_url()` on high runs. `fetch_url()` gains `prefer_playwright: bool=False` param. `_should_force_playwright()` fires immediately when `prefer_playwright=True`. `tool_refetch_url` accepts and forwards `prefer_playwright`.
- **26 new backend tests** in `test_th_issue_local_008.py` covering all areas.

### Fixed — URL fetch Brotli decoding + Playwright fallback (issue-local-008)

Diagnosed on production server (`test-edr-1` hunt package, welivesecurity.com evidence):
URLs that serve `Content-Encoding: br` (Brotli) returned compressed binary bytes because
the `brotli` package was missing. The extractors produced mojibake, Playwright was never
triggered, and zero IOCs/info were extracted. Four fixes applied:

- **Fix 1 — Brotli package**: `brotli>=1.1.0` added to `requirements.txt` so httpx
  auto-decodes Brotli-encoded responses. Accept-Encoding header is now built
  dynamically: only advertises `br` when a brotli decoder is actually importable
  (`_BROTLI_AVAILABLE` flag), preventing servers from sending Brotli when httpx
  can't decode it.
- **Fix 2 — Binary content detection**: after streaming, raw bytes are checked with
  `_looks_like_binary()` (non-ASCII ratio >30% OR control-char ratio >5%). When
  binary content is detected on an HTML response, a descriptive `parse_warning` is
  recorded and the Playwright fallback is forced regardless of extracted-text length.
- **Fix 3 — Broader Playwright trigger**: `_should_force_playwright()` replaces the
  original length-only check and also fires when extracted text is binary/mojibake
  (the root cause of the welivesecurity failure: 31 KB of Brotli garbage was >200
  chars so the old trigger silently passed). Also fires on `utf8-fallback` on HTML,
  and when raw bytes are binary. Playwright result is accepted over static extraction
  when the static content is binary — no longer rejected just because mojibake is
  longer than the browser article.
- **Fix 4 — readability errors surfaced**: `readability-lxml` exceptions (e.g.
  `ValueError: All strings must be XML compatible: no NULL bytes`) are now captured
  and appended to `parse_warnings` instead of being silently swallowed.
- **21 new tests** covering all four fixes.

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
