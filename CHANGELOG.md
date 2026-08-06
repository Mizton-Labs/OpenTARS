# Changelog

All notable changes to OpenTARS are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added — Home branding, commit-stamped logs/reports, hunt package clone + Simple view, RedHunter theme, first-login wizard, user-management polish (issue-local-038)

- **Home**: subtitle "Threat Agentic Research System" under the OpenTARS title, with spacing before "Choose a module to get started". The title is slightly larger with a two-tone "Open"/"TARS" treatment, and the subtitle's T-A-R-S initials are highlighted and enlarged so the acronym reads clearly.
- **Logging**: the `opentars` launcher now exports `GIT_COMMIT` to the backend process itself (previously only to the frontend build step), so the startup log line includes the running commit.
- **Hunt packages**:
  - A Clone button in the package detail page's action bar (previously only on the list page), reusing the same clone route/dialog.
  - Each generated report — data, markdown export, and PDF — is stamped with the app version/commit it was generated with.
  - A new "Simple" density (leftmost in the switcher): like Compact, but the per-run chip row collapses to a one-line run count.
  - The list's default density is now **Table** (was Detailed) when the user has no saved preference.
  - The HuntID prefix may now contain `strftime` directives (e.g. `TH-%Y%m%d` → `TH-20260805`), resolved from each package's own creation date — not "now" — so a date-based prefix never drifts as time passes. Fixed a real bug found along the way: the prefix input forced every keystroke to uppercase, silently corrupting case-sensitive directives (`%m` month → `%M` minutes).
- **Themes**: Light's page background and card surface were inverted — previously the page was a light grey and cards read as near-white; now the page is near-white and cards carry the grey contrast, as intended. Added **RedHunter**, a near-black dark theme with an intense ruby/crimson accent (Tailwind's `rose` scale, deliberately distinct from the app's stock red danger color so error states stay legible). A first-login onboarding wizard (backend-driven `onboarded` flag, grandfathering every pre-existing account so nobody is retroactively interrupted) lets a new user pick a theme and hunt-package view style, with a live preview, before entering the app. An admin can also force the wizard to show again for any user via a "First-login wizard" action in User Management.
- **User management**:
  - Role and Organization changes are now staged and applied via an explicit "Save" button that appears once either is dirty (the Enabled toggle stays instant, since disabling a compromised account shouldn't wait on a confirm step).
  - Creating a user no longer takes an admin-supplied password — the backend always generates one (same as the existing Reset Password flow), shown once for the admin to hand off.
  - The Reset Password button now shows its label ("Reset password"), not just the key icon.

### Fixed — SSO login silently reverted admin-assigned roles; Account page role hidden behind a long username

- **Fixed: SSO login could silently overwrite an admin-assigned role.** On every SSO login,
  `_upsert_sso_user` unconditionally wrote the role computed from the IdP's claims — falling back to
  the SSO config's `default_role` whenever no claim matched — over the existing user's role. An admin
  who manually promoted or demoted a user via User Management would have that change reverted back to
  `default_role` on the user's very next SSO login. Role is now treated as admin-owned, the same as
  username: only ever set at Create or via the role dropdown, never touched by a login. The mapped
  role is still applied when auto-provisioning a brand-new account, where no admin assignment exists
  yet to protect.
- **Fixed: the Account page's Role value could be visually hidden behind Username.** With org-derived
  full-email usernames (`local-part@org-domain`, issue-local-037) the two-column layout at the page's
  previous `max-w-md` width let a long username overflow into the Role column. The page is now wider
  (`max-w-xl`) and both cells truncate instead of overflowing.

### Fixed — SSO sign-ins missing from the audit log; post-login redirect broke out of a reverse-proxy alias

- **Fixed: SSO sign-ins were invisible in the audit log.** Only the local-password `/login` route
  ever recorded a "Signed in" / "Failed sign-in attempt" event — the OIDC callback route never did,
  so every SSO-authenticated session (success or failure) left no trail. The callback now records
  the same events the local login path always has, including the IdP name.
- **Fixed: after SSO login, the browser could land in a different application.** The callback's
  post-login and error redirects (`Location: /viewer`, `Location: /login?sso_error=...`) were plain
  root-relative paths, which the browser resolves against the domain ROOT — behind a reverse-proxy
  alias (`callback_base_url`, issue-local-036) that is a *different* upstream application, not this
  one. Every redirect issued from the callback now carries the same alias prefix already used to
  build the `redirect_uri` sent to the IdP, so it lands back inside the app.

### Added — User Organizations and org-derived usernames (issue-local-037)

- **New: Organizations.** A "Org Management" tab (Configuration → General) lets admins add, list,
  edit, and delete Organizations — each a `(name, email domain)` pair. Deleting an organization that
  still has users assigned is rejected (409) rather than silently orphaning them.
- **New: per-user Organization on Create/Change.** Creating a user now offers an Organization
  dropdown ("Local user" if none selected) and a checkbox, enabled by default, to make the stored
  username the full email (`local-part@org-domain`) rather than the bare local part. The final
  username is always built server-side from the admin-typed local part plus the organization's own
  trusted email domain — never from a client-supplied string — so a stored username can never drift
  from what's actually configured for that org. Existing users can be moved between organizations
  from their row in User Management, which recomputes the username from their current local part; a
  notice always confirms the actual resulting username after any add or change.
- **New: SSO auto-match by email domain.** On every SSO login, a user's organization is best-effort
  resynced (like their role already was) by matching their IdP-supplied username against configured
  organizations' email domains — but unlike the admin-driven change flow, the username itself is
  never touched by an SSO login.

### Added — Configurable SSO callback URL for reverse-proxy-alias deployments (issue-local-036)

- **New: "Callback Base URL Override" field on Configuration → SSO.** The OIDC redirect_uri sent to
  the identity provider used to always be derived from the current request's own base URL, which
  never includes a reverse-proxy alias segment (e.g. `/tars`) unless `app_base_prefix` is explicitly
  configured — and setting `app_base_prefix` can itself break static asset routing under some proxy
  setups (see the issue-local-035 follow-up). This was a functional bug, not cosmetic: without the
  alias, the IdP either rejects the redirect_uri outright (exact-match requirement) or redirects the
  browser to a URL the proxy doesn't route back to the app, breaking login on the affected browsers
  entirely, not just the one that saved the config.
  The new field is independent of `app_base_prefix`, prefilled (as a placeholder, not silently
  auto-saved) with the alias this app's own client-side detection infers from the admin's browser —
  a "Use detected" button copies it into the field for review before saving. Left blank, behavior is
  unchanged from before this issue.

### Added — Data Explorer fixes, hunt package/run delete & archive, configurable pipeline timeout (issue-local-034)

- **Fixed: Data Explorer search didn't actually filter most categories.** Previously, search only
  ever matched a hunt package's own name/description/stored analysis — a package matching anywhere
  returned *every* row of that package unfiltered. Evidence, SIEM Searches, Hunting Leads, and
  Queries Drafted were a complete no-op; Runs, IOCs, and Hypotheses were coarse (a package match let
  every one of its rows through, not just the matching one). Every hunt-scoped category now matches
  its own displayed field(s) — a label, an IOC value, a model name, a hypothesis title — so search
  shows only the rows that themselves match.
- **New: a "Run" column** on Runs, Hypotheses, Hunting Leads, Queries Drafted, IOCs Extracted, and
  SIEM Searches, linking to the exact run a row came from (not just the hunt package, which used to
  land on its newest run regardless). Deep-links via `/threat-hunting/{id}?run={runId}`.
- **New: evidence rows are now expandable**, previewing inline with the same viewer (PDF / extracted
  text / "not processed") the Evidence tab's own detail pane already uses — no more switching to
  the hunt package just to see what an evidence item actually contains.
- **Rebuilt: "Feed Sources"** used to show unrelated Threat-Intel ingestion-pipeline stats. It now
  aggregates where hunt evidence actually came from — the domain for URL evidence (parsed
  deterministically), or a best-effort identified vendor/organization for file/text/watcher evidence
  (one LLM call at evidence-add time, soft-fail, never computed live) — with the same Hunts-badge
  drill-through the Threat Actor/Campaign/Malware Family tabs already have.
- **Archived hunts and runs are visible again in Data Explorer and global Search/Assistant**,
  tagged "Archived" — they still disappear from the main Hunt Package list and Dashboard, unchanged.
- **New: Archive/Unarchive and permanent Delete** for both individual runs (in the all-runs table)
  and whole hunt packages (next to Re-run). Archive is reversible and available to the same
  researcher+admin roles as every other Threat Hunting action. Delete is permanent and cascades
  through every IOC, task result, report, comment, and threat-intel analysis tied to what's
  deleted — **admin-only**, with a strong confirmation dialog, since nothing else in this app
  destroys data outright.
- **Fixed: some hunt runs (e.g. TH67) were failing on a plain timeout, not a hang.** Diagnosed a
  genuine `query_drafting_agent` LLM slowdown (provider retries + transport timeouts on both
  configured providers) pushing past the previous hardcoded 600-second per-node budget. The
  timeout is now configurable in Configuration → Agents, default raised to 900 seconds.
- **Design: the search-drawer trigger now shows a magnifier and a bot icon together**, so it reads
  as "search and assistant" at a glance, not just search.
- **Data Explorer's category tabs now render in two rows** — Threat Hunting categories (Hunt
  Packages, Runs, Evidence, Hypotheses, Hunting Leads, Queries Drafted, IOCs Extracted, SIEM
  Searches, Feed Sources) on the first row, Threat Intel tracking's global categories (Threat
  Actors, Campaigns, Malware Families, MITRE Techniques) on the second — instead of one long
  wrapping list.

### Added — Audit section; fixed unreadable removed-IOC text (issue-local-033)

- **New: an "Audit" sidebar entry**, visible to every signed-in user. Four tabs — Application, User,
  Agent, System — each backed by `GET /api/audit/events?category=...`, with search and
  page-size-selectable pagination (25/50/100/200, matching Data Explorer's pattern).
  - **User** — authentication and account activity: sign-in/sign-out (including failed attempts),
    password/theme changes, SSO configuration, and user/API-key management. Category is a pure
    function of the route (`/api/auth/*`), computed once and shared by the generic audit middleware
    and every other interpretation below — no per-route instrumentation needed.
  - **Application** — everything else the application does: hunt package/evidence/IOC-verdict/
    connector/report changes, LLM provider and configuration changes, source/watcher management, plus
    the existing ingestion-pull and watcher-trigger events. Every action gets a short, consistent,
    human-readable label (e.g. "Created hunt package", "Updated IOC verdicts") rather than the raw
    method/path or log line — a curated table covers ~110 routes and the ingestion log shape, with an
    algorithmic fallback so a future route is never shown fully raw.
  - **Agent** — AI/pipeline activity (hypothesis generation, TTP analysis, query drafting, SIEM
    execution, report/threat-intel steps, ...), each with an interpreted label reflecting what
    happened and whether it succeeded ("Generated hunting hypotheses" / "Hypothesis generation
    failed"). Fed from the two places that persist pipeline step logs — the LangGraph node loop
    itself (`_save_generation_state`, the actual per-node choke point; previously missed, which is
    why this category showed almost nothing despite hunts actively running) and
    `append_run_step_log` for the post-approval steps that run outside the graph — attributed to the
    run's own creator.
  - **System** — operational health: a dedicated startup/shutdown lifecycle logger, plus a bridge that
    captures any WARNING+ log record anywhere in the app (failed DB inits, degraded providers, ...)
    regardless of which module logged it, labeled by the originating module.
  - **Permissions**: an admin sees every category and every actor. A normal user sees Application,
    User, and Agent — their own everyday activity, their own authentication activity, and their own
    agent-triggered runs — always scoped server-side to the caller's own session (`routes_audit.py`
    never trusts a client-supplied identity, the same rule Assistant chat sessions already follow).
    Only System (not a per-user concept) stays admin-only.
  - Retention is bounded automatically: checked probabilistically (not on every write) and trimmed
    back down well before an unbounded table could become a problem.
- **Fixed: a removed IOC in the Hunt Detail and Retrohunt IOC tables was hard to read.** Removed IOCs
  no longer get a strikethrough or dimmed row — every cell reads at full brightness like a kept IOC.
  The red "Removed" badge and background/border tint are the sole removal indicator.

### Added — Dashboard charts, pagination (issue-local-034)

- **New: two timeline charts lead the Dashboard** — Hunts per Day and IOCs per Day, both respecting
  the page's search/time-range filter the same way every other hunt-scoped figure does.
- **Evidence by Type and Packages by Status are now pie charts** instead of bar breakdowns, each
  slice labeled with its count and share; still link through to their Data Explorer category.
- **Runs by Model and Hunt Packages by Model are now paginated at 10 rows per page** — an
  installation with many models no longer turns those two panels into a very long scroll.
- **New: pagination in the Data Explorer**, with a page-size dropdown (25/50/100/200, default 25).
- **The Data Explorer's category tabs now wrap onto a second row** instead of scrolling
  horizontally — 13 categories never fit one row at any reasonable width.
- No new charting dependency: the timeline charts are hand-rolled SVG and the pie charts are a CSS
  `conic-gradient`, consistent with the rest of the app's no-charting-library approach.

### Added — Data Explorer, and Dashboard fixes/reordering (issue-local-033)

- **New: "Data Explorer" sidebar entry**, below Threat Intel Tracking — the row-level data behind
  every Dashboard panel/stat card, one tab per category (Hunt Packages, Runs, Evidence, Hypotheses,
  Hunting Leads, Queries Drafted, IOCs Extracted, SIEM Searches, and the five Threat Intel
  categories), with its own search box. Every panel and stat card on the Dashboard now links here
  with the matching tab pre-selected, so "what does this number actually consist of" is always one
  click away.
- **Dashboard reordering**: the Threat Intel summary now leads the page (previously last), and
  within the remaining breakdown panels, Evidence by Type and Packages by Status now come before
  the two model breakdowns (Runs by Model, Hunt Packages by Model).
- **Fixed: "View Hunt Packages" on the Dashboard led to a blank page.** The Dashboard is mounted at
  the bare `threat-hunting` route (a single path segment); a relative `../packages` navigation from
  a single-segment route resolves by climbing to the root and appending "packages" — landing on the
  nonexistent `/packages`, not `/threat-hunting/packages`. Fixed by navigating to the absolute path.

### Added — Assistant chat sessions (issue-local-032)

- **The Assistant/SmartSearch chatbot now remembers conversations.** Every conversation is a
  session, auto-created under a timestamped name (`TARS-assistant-YYYYMMDD-HHMMSS`) the first time
  you ask a question, and auto-saved after every completed turn — nothing to remember to do
  yourself. A top bar (New session, Save session — set a name, Export, Delete, and a picker over
  your saved sessions) is available in **both** places the chat lives: the full-page Assistant view
  and the search drawer's Smart tab. They are the same top bar and, more importantly, the same
  live conversation — asking a question in one and switching to the other continues it, rather than
  finding two independent chats that happen to share code.
- **A new session starts whenever you navigate to a different section of the app** (e.g. Viewer →
  Threat Hunting, or Assistant → Configuration) — the conversation you were having is not lost, it
  was already saved turn-by-turn and stays in your session list. Moving between pages *within* the
  same section (e.g. the Threat Hunting Dashboard → Hunt Packages) does not start a new one.
- **Export as Markdown, JSON, or PDF.** Markdown and PDF download directly from the server; JSON is
  built client-side from the already-fetched session, the same pattern the Threat Hunting report
  downloads already use. The PDF export reuses the report renderer's print-friendly palette.
- **New: an emphasized "Open in Assistant" button in the search drawer's Smart tab** — jumps to the
  full-page Assistant view without losing the conversation (it's the same session, not a handoff).
- Sessions are private to the signed-in user (or, in open/no-auth mode, shared the same way
  everything else is when there's no signed-in identity to separate them) — every read, update, and
  delete is filtered by owner at the database level, so a session id alone is never enough to reach
  someone else's conversation. Session content is sanitized the same way a live answer already is,
  and every field (name, message count, per-message length, sessions kept per person) is bounded.

### Added — Threat Hunting Dashboard (issue-local-032)

- **New: a "Dashboard" section in the Threat Hunting sidebar group, now the module's default
  view.** The bare Threat Hunting entry point (`/threat-hunting`) now shows a metrics overview
  instead of the hunt-package list: hunt package / run counts (with a status breakdown), evidence
  items (by type), hypotheses, hunting leads, queries drafted, IOCs extracted (and how many were
  kept after sanitization), SIEM searches executed and events retrieved, runs and hunts broken
  down by model, and a Threat Intel summary (threat actors, campaigns, malware families, MITRE
  techniques, feed sources processed) aggregated across every hunt.
- The hunt-package list itself is unchanged — it moved to its own sidebar entry, "Hunt Packages"
  (`/threat-hunting/packages`), and gained no new behavior. The Dashboard shares its search box and
  time-range filter (same debounce, same `HuntTimeFilter` component), so the hunt-scoped figures
  always describe the same set that filter would show in the list.
- The Threat Intel summary panel is deliberately **not** filtered by the search/date controls —
  it's a cross-hunt aggregate keyed by deduplicated entity name, the same global-scope convention
  the Threat Intel Tracking dashboard already uses, not a per-package figure a date range could
  meaningfully narrow.
- No new charting dependency: the breakdowns are proportional-width bar rows built from the app's
  own card/theme tokens, consistent with how every other dashboard-style page in this app already
  renders without one.

### Fixed — Search drawer contrast in dark themes (issue-local-032)

- The search/SmartSearch drawer's surface (`bg-gray-950`) matched the page background exactly in
  every dark theme (Classic, Energy, Ocean), so the panel barely read as its own layer over
  whatever page it was overlaying. Its base surface is now one step lighter in those three themes
  specifically; Light is unchanged, since its inverted color ramp already separates the two
  surfaces.

### Added — Global search and SmartSearch chatbot (issue-local-031)

- **New: a search button flush in the top-right corner of every page**, opening a right-hand
  drawer that stays fully collapsed until you ask for it. The shell reserves a gutter for it, so it
  never covers a page's own controls. Search spans the whole application — hunt packages; the
  Threat Intel module (both the raw and normalized stores, which are independent, plus the
  configured feeds); the Threat Intel Tracking submodule (correlated IOCs and CVEs, and the threat
  actors, campaigns, malware families and MITRE techniques aggregated across hunts, each linked
  back to the hunts it was seen in); watchers; pages; settings; and documentation. Each hit names
  the section it was found in with a short context snippet, and opens the exact place it lives —
  including the right Viewer store, since a raw match and a normalized match are different things.
- **Categories are searchable by name, not just by value.** Asking for *hashes*, *sha256*, *domains*,
  *ips*, *CVEs*, *malware families*, *threat actors*, *campaigns* or *techniques* lists what exists,
  rather than looking for an entry whose text happens to contain that word — a hash is hex and never
  contains the word "hash", and the malware families are called `msaRAT` and `Chaos ransomware`, so
  the obvious way of asking previously returned nothing. Results are spread across the types and
  categories present, so the commonest one cannot crowd out the rest.
- **New: SmartSearch**, a chatbot over the same results, behind a switch that is always visible.
  When no LLM provider is configured the Smart side is greyed out and its tooltip names the setting
  that enables it (Configuration → General → LLM Providers) rather than failing silently.
- **Answers are grounded in this installation.** SmartSearch is retrieval-augmented rather than a
  model with tools: the question is reduced to search terms, the ordinary search retrieves matching
  snippets, and the model answers from those plus a short description of the product. It cites the
  sections it used, and says so when it does not know instead of inventing hunts or indicators.
- **The guardrails are structural, not prompt-deep.** Retrieval runs as the calling user's role, so
  the model is only ever shown content that user could already fetch themselves — no phrasing of a
  question can widen it. There is no tool calling, no query generation and no write path, so no
  input can execute code or change data. Settings are indexed as names and locations only, never
  values, so no credential is reachable in the first place. Hunt evidence is adversary-authored by
  definition (fetched pages, uploaded threat reports), so retrieved text is fenced and the model is
  told it is data and never instructions. Question length, history depth, snippet count, output
  tokens and timeout are all bounded. Answers are formatted as Markdown — lists, tables, `code`
  for indicators and queries — rendered with no raw HTML, no images, and no clickable links: a URL
  in this product is frequently the malicious indicator under investigation, so it is shown as code
  rather than as something to click.
- Search results are stripped of invisible and directional characters before display. A
  right-to-left override inside an attacker-supplied hostname would otherwise make a result read
  differently from the indicator it actually matched — the wrong failure mode for a tool whose
  output analysts act on.
- **New: an "Assistant" section in the sidebar**, above Account, giving SmartSearch a permanent,
  full-height home instead of only living behind the drawer. It is the same chat — same request,
  history and Markdown-rendering logic as the drawer's Smart tab — both are built on one shared
  `useSmartChat`/`SmartChatPanel` implementation, so there is a single place that logic can drift.

### Added — About page tabs, in-app API documentation, Swagger UI (issue-local-030)

- **New: a tab bar on the About page** — General (the existing version/license content, now topped by
  a prominent, medium-sized OpenTARS logo header), API Docs, and API Swagger.
- **New: API Docs tab.** Renders the Threat Hunting API reference
  (`docs/api-threat-hunting.md`) as real formatted HTML — headings, tables, code blocks — styled with
  the app's own theme tokens rather than a generic typography plugin, so it matches every theme
  (Classic/Energy/Light/Ocean) instead of a mismatched hardcoded palette.
  The reference is split on its topic headings into one card per topic — Authentication,
  Hunt Packages, Evidence, Reports, and so on — behind a table of contents that jumps straight to
  any of them, so a 470-line document is navigable instead of one long scroll. Splitting happens at
  render time, so the committed Markdown stays a normal document that still reads correctly on
  GitHub.
- **New: API Swagger tab.** FastAPI's own interactive Swagger UI, embedded via an iframe (plus an
  "open in a new tab" link), generated live from the running server's OpenAPI schema. It defaults to
  the endpoints a scoped **API access key** can actually call (29 operations) rather than the whole
  application (220), since a reader on this tab is usually integrating with a key and most endpoints
  can never be reached with one; a *Show all endpoints* checkbox switches to the complete API. The
  subset is derived from `backend/auth/api_scopes.py` — the same source the auth middleware enforces
  against — so the documentation cannot drift from what is actually permitted.
- Both API tabs use the full page width, so the reference's endpoint tables and the Swagger schemas
  are readable without horizontal scrolling; General keeps its narrower reading column.
- **Fixed: the OpenAPI description still described the pre-rebrand product** ("Lightweight Threat
  Intelligence feed receiver, normaliser, and viewer"), which was the first thing anyone opening the
  API docs read. It now describes OpenTARS and summarises the two authentication modes.
- **Fixed: the embedded Swagger showed a *different application's* endpoints** when OpenTARS ran
  behind a reverse-proxy alias. FastAPI's stock docs pages hardcode a root-anchored
  `/openapi.json`, and the usual alias block (`location /alias/ { proxy_pass http://host:port/; }` —
  the trailing slash strips the prefix) leaves the backend unable to learn its external mount point
  from the path. The browser therefore resolved the schema URL against the proxy *root* and loaded
  whatever application was mounted there — in the observed deployment, the parent app manager's
  schema. `/docs` and `/redoc` are now served with a document-relative `openapi.json`, the same
  strategy the SPA already uses (`<base href="./">` and a relative `api` base), so the schema always
  resolves inside the alias. Correct with or without `app_base_prefix` set, and with no cooperation
  required from the proxy — the `X-Script-Name` header it sends is deliberately not trusted, since
  it is client-controllable and relative URLs make it unnecessary.
- **Fixed: the API documentation now works fully offline.** FastAPI's stock docs pages load Swagger
  UI and ReDoc from `cdn.jsdelivr.net` (ReDoc additionally pulls Google Fonts), so on the isolated
  and air-gapped networks this platform is built for, the page rendered blank. Both bundles are now
  vendored under `backend/static/api-docs/` and served from `/docs-assets`; the pages reference no
  external host at all, which also removes a third-party runtime dependency from an authenticated
  page. Versions are pinned and attributed in `THIRD-PARTY-NOTICES.md`, with upstream license texts
  alongside the files, and the asset URLs are relative for the same reverse-proxy reason as above.
- **Fixed (security): FastAPI's `/docs`, `/redoc`, and `/openapi.json` were completely
  unauthenticated**, even with auth enabled — they're auto-registered outside `/api/`, so the
  existing "only guard `/api/`" bypass left the entire route/schema surface (including admin,
  configuration, and user-management routes, not just Threat Hunting) reachable by anyone who
  requested the URL directly. They now require the same valid session as everything else once auth
  is enabled — any authenticated role, matching the About page's own accessibility.
- Both the Swagger UI and the new `GET /api/app/docs/{doc_id}` endpoint that feeds the rendered
  reference resolve correctly under a configured reverse-proxy base prefix, same as the existing
  branding-logo/base-prefix handling. `doc_id` is allowlisted server-side (a fixed dict lookup, never
  concatenated into a filesystem path), so it can't become an arbitrary-file-read primitive.

### Added — Programmatic API access with scoped keys (issue-local-029)

- **New: API access keys**, configurable from Configuration → General → API Access. A master
  "Programmatic API access" toggle (`api_access_enabled`, off by default) controls whether keys are
  accepted at all — independent of the existing session-cookie auth, and off by default so it never
  changes behavior for deployments that don't opt in.
- **New: a guided create wizard.** Enter a name, choose which capabilities the key can use from a
  curated list of named scopes (or apply the "Create hunt package / add evidence / download
  report+IOCs+threat-intel / query threat-intel tracking" default profile, or select every scope at
  once), and a client ID + secret are generated. The combined `Authorization: Bearer <client_id>.
  <secret>` value, client ID, and endpoint are shown exactly once in a copyable, downloadable
  summary card — the secret is never retrievable again afterward, only its hash is stored.
  Existing keys can be enabled/disabled, deleted, or test-probed from the same tab.
- **Scoped by design, not by convention**: every scope resolves to an explicit, hardcoded
  `(HTTP method, path pattern)` allowlist confined to `/api/threat-hunting/*`. A request-level hard
  cap in the auth middleware independently rejects any API-key request outside that prefix, so a
  key — even one granted every scope — can never reach configuration, user-management, or LLM
  provider endpoints. The management routes for creating/listing/editing keys are session-auth-only
  and structurally cannot be reached by an API key at all.
- **New: edit an existing key's scopes.** Each key row now has an "Edit scopes" action (the same
  checkbox list as the create wizard, including the default-profile/select-all quick-picks)
  instead of scopes being fixed for the lifetime of a key.
- **New: `docs/api-threat-hunting.md`** — a full endpoint reference for every `/api/threat-hunting/*`
  route (packages, evidence, IOCs, generation/runs, connectors, execution, reports, Threat
  Intelligence, comparison, run comments, tracking), the session-role vs. API-key-scope access table
  for each, and the `/api/auth/api-keys/*` management routes.
- **New: a standalone Threat Hunting API client**, `scripts/client_tests_demo/threat_hunting/
  api_client_threat_hunting.py` — dependency-free (stdlib only), with a subcommand for every route in
  the new doc, supporting both session-cookie login and `--api-key` Bearer auth. A `run_tests.sh`
  demo runner (mirroring the existing Threat Intel one) exercises a full non-destructive hunt
  lifecycle end to end.
- **Changed: `scripts/client_tests_demo/`** now nests the existing Threat Intel client demo under a
  `threat_intel/` subdirectory (was directly in `client_tests_demo/`), alongside the new
  `threat_hunting/` one — see the updated `README.md` for the new paths.

### Changed — Configuration section now lands on General, not Threat Intel (issue-local-029)

Opening Configuration from the sidebar now defaults to the General tab group (previously Threat
Intel's Open Threat Feeds tab), matching where the most commonly changed settings — including the
new API Access tab — live.

### Fixed / Added — Azure AI Foundry Claude provider, manual model entry (issue-local-027)

- **Fixed: "Discover Models" showed a scary, crash-looking error for Azure AI Foundry's Anthropic
  passthrough** (`api_style: anthropic`, used for Claude models via Azure). Root cause: the test
  runner's Anthropic-protocol detection only recognized the native `anthropic` provider kind, not
  `azure_ai_foundry` configured for the passthrough — even though both have exactly the same "no
  public model-list endpoint" limitation. It fell through to the generic path and got treated as a
  hard failure (`"client.list_models() returned None"`) instead of the same graceful, expected
  "no discovery endpoint" outcome native Anthropic already gets.
- **Fixed: a base URL change on this provider type could never be saved.** The provider card's Save
  button ran model discovery whenever the base URL changed and refused to persist if it came back
  empty — but an Anthropic-protocol provider's discovery *always* comes back empty by design, so
  this made it permanently impossible to save a base URL edit for one. Save now persists directly
  for this provider type, skipping the discovery gate that could never succeed.
- **New: manually add models to a provider's card.** Providers with no model-discovery endpoint
  (or where discovery simply hasn't found a model yet) can now have model ids typed in directly —
  they show as removable chips and feed the same `available_models` list "Discover Models" would
  have populated, including the Threat Hunting per-run model-selector dropdown. "Discover Models"
  on an Anthropic-protocol provider now shows an informational note pointing at this instead of a
  red error.

### Fixed — PDF report generation failing on ~half of real hunts

Root-caused via a live check of the last 25 generated reports on the test server: 12 (48%)
failed with a fatal `reportlab.platypus.doctemplate.LayoutError`. Each evidence item's extracted
text was wrapped in a single-row, single-column `Table` for its bordered-box look — but a 1-row
table has no row boundary to paginate at, so any evidence item whose text ran past one page's
usable height (long articles routinely did) crashed the *entire* PDF, not just that section. This
is what "PDF generation randomly fails" actually was: deterministic per report, driven by evidence
length, not random. The border/background now live on the paragraph's own style instead of a
wrapping table, so it paginates like normal document text. Also: `download_run_report_pdf` (the
per-run PDF route, the one actually used from the Runs table) never logged its exceptions, unlike
its two sibling PDF routes — a failure there was invisible in `app.log`, which is why nothing
showed up when first grepping the logs for this issue.

### Changed — Table view title-bar contrast

The per-hunt title bar's background (added for issue-local-026) reads more clearly against the
card body across the dark themes (Classic, Energy, Ocean).

### Added / Fixed — Threat Hunting IOC totals, URL->domain IOCs, RBAC, run attribution (issue-local-026)

- **IOC totals now shown explicitly and can no longer read inconsistent.** A run's "IOCs (N)"
  tab label previously counted the raw `extracted_iocs` table (populated by intake) while the
  tab body (once Deep Retrohunt has run) displayed a separately, independently-deduped
  `sanitized_iocs` list — two different dedup passes over the same extraction, so the two numbers
  could legitimately disagree. The tab label now counts the exact same list the tab body renders.
  The per-run IOC summary (Retrohunt panel) and the Comparison tab's diff table both gained an
  explicit "Total IOCs" figure, always computed as sanitized + removed in the same place they're
  shown — never a separately-stored number that could drift. The Comparison Markdown/PDF reports
  gained the same Total IOCs column.
- **New "Overall IOCs" table in the Comparison tab**: every IOC found across the compared runs,
  which run/model extracted it, a confidence figure (derived from the existing noise score, since
  this schema has no separate per-IOC confidence field), its verdict (kept/removed), and which
  hypotheses/hunting leads referenced it.
- **URLs now also add their domain as a separate IOC** before verdict/noise analysis runs — the
  original URL IOC is kept unchanged; the derived domain is what SIEM/EDR/DNS-log pivots
  typically need and previously only existed embedded inside the URL string.
- **Fixed: Threat Researcher role couldn't use the model selector.** `GET /api/llm/providers` and
  `GET /api/llm/config` were missing from that role's allowed read paths, so the model-selector
  dropdown (which a Threat Researcher is explicitly meant to use) silently came back empty for
  anyone who wasn't an admin. Both routes already redact API keys server-side, so opening them to
  Researcher carries no secret-exposure risk.
- **Hunt runs now record who started them.** New `hunting_packages.created_by` column (schema
  v10) — the Runs table gained a "Created by" column, and the hunt-package list's Table density
  view now shows the owner (Card/Compact views already did).
- **Fixed: a run made with "Configured default" showed no model at all.** `hunting_packages.llm_provider`/
  `llm_model` stayed `NULL` forever for a "Default" run — nothing was ever persisted to show. The
  pipeline now resolves the actual default provider/model once, at run-start time, and persists
  those resolved values on the run itself, so it reflects what was genuinely used for that specific
  run rather than being reconstructed later from whatever the default happens to be *today* (which
  would silently drift if an admin changes the default afterward). The Runs table still falls back
  to resolving today's default for runs created before this fix, whose columns are still `NULL`.
- **Table view styling**: each hunt's title bar now has its own background and slightly larger
  text so it reads clearly as a header, and the run owner is shown as a highlighted pill instead of
  small muted text.
- **Fixed: the same IOC could appear as multiple duplicate rows**, most visibly as repeated
  entries in the Threat Intelligence tab's cross-package "Correlated IOCs" table. Root cause:
  `extracted_iocs` had no uniqueness constraint at all — the table's only key was a fresh UUID per
  row, so the existing `INSERT OR IGNORE` never actually ignored anything, and every evidence item
  mentioning the same IOC inserted its own duplicate row. New schema migration cleans up any
  duplicates already on disk and adds a real unique index (scoped per run, so the same IOC found
  again in a later, independent run is correctly kept separate) so future inserts dedupe as the
  code already assumed they did. The cross-package correlation query also now collapses an IOC
  found across several runs of the *same* other hunt package into one row, since the Threat
  Intelligence tab only ever displays which hunt an IOC came from, not which run.

### Fixed — Anthropic responses truncated by output-token budget went undetected (issue-local-025)

Every Threat Hunting run against an Anthropic-protocol provider (native `anthropic` kind, and
`azure_ai_foundry` with `api_style: anthropic`) that got cut off by the output-token budget
(`stop_reason: max_tokens`) was silently treated as a successful completion — the truncated,
unparseable JSON fragment was handed straight to each pipeline node's JSON parser, which then
logged `unexpected LLM response type` and fell back to an empty result. Confirmed live against
both `claude-sonnet-5` and `claude-opus-4-8`: replaying a real hunt's prompt at its actual token
budget reproduced `stop_reason: max_tokens` on every call, and `claude-sonnet-5` additionally
spent part of that budget on an implicit `thinking` content block before ever reaching a
`text` block. The OpenAI protocol path already had this covered
(`finish_reason: length` raises `LLMEmptyContentError`, which triggers the existing
raise-max_tokens-and-retry loop in `llm_bridge._call_with_retry`); the Anthropic path had no
equivalent check. `_anthropic_extract_text` / `_anthropic_extract_tool_calls` now raise the same
`LLMEmptyContentError` whenever `stop_reason == "max_tokens"` or no `text`/`tool_use` content was
produced at all, so the existing generic retry logic now applies uniformly across both protocols.

### Changed — Rebrand to OpenTARS (issue-local-024)

Project renamed from Mizton-ThreatBox to **OpenTARS** ("Threat Agentic Research System"). New logo
and favicon throughout the app (login screen, sidebar, About page, browser tab); every user-visible
string across the frontend and backend (credential prompts, watcher envelope naming, SSO copy,
report/PDF headers) now reads OpenTARS. README.md rewritten with a hero banner, a proper Quick Start,
and expanded Features subsections covering everything shipped since the last full README pass
(Threat Intel Tracking, Comparison Module, Evidence content viewer, Azure AI Foundry provider,
config-drift notice). All other docs (`architecture.md`, `agent-architecture.md`,
`platform-overview.md`, `threat-hunting-framework-design.md`, `CONTRIBUTING.md`,
`THIRD-PARTY-NOTICES.md`) retitled to match, while historical CHANGELOG entries were left untouched
for factual accuracy. The GitHub repository has since been transferred and renamed to
[`Mizton-Labs/OpenTARS`](https://github.com/Mizton-Labs/OpenTARS); every repo URL in this project
(clone instructions, `pyproject.toml` project links, the About page's repo link, Docker build
defaults) has been updated to match. The maintaining entity itself also renamed: `LICENSE`'s
copyright holder and `pyproject.toml`'s author are now Mizton Labs (previously HoneyMex Lab).

**Follow-up:** the internal code references initially deferred (see the original risk analysis this
paragraph used to link to, since removed) have now been renamed too. The launcher script is now
`./opentars`; the old `./mizton-threatbox` name still works as a deprecated forwarding shim (prints a
warning, execs the new script) so already-deployed automation doesn't break outright. Every
`MIZTON_THREATBOX_*` env var (`_BASE_PREFIX`, `_ENABLE_AUTH`, `_COOKIE_SECURE`, and the seven
`_SSO_*` SSO overrides) is now `OPENTARS_*`; the old names still work too, via a shared
`env_with_legacy_fallback()` helper that reads the new name first and falls back to the old one with
a deprecation warning — so an already-configured deployment's override never silently stops applying
just because the variable was renamed. `pyproject.toml`'s and `frontend/package.json`'s package
identifiers are now `opentars` / `opentars-frontend`. The Docker build artifacts
(`docker/mizton-threatbox-docker/` → `docker/opentars-docker/`, image tag, container/service name,
OCI labels) were renamed to match.

**Follow-up 2:** the remaining bare `threatbox` references (not just `mizton-threatbox`) have been
swept from the Docker image, Compose file, and config examples: the container's Linux user/group/home
is now `opentars` (was `threatbox`), `config/sso.yaml.example`'s sample role-mapping claim values are
now `OpenTARS-Admin/Researcher/Viewer`, and stray example URLs (README, `scripts/client_tests_demo/`)
now use `/opentars` instead of `/threatbox`. The Docker image's minimal system-package list also
gained two entries it was silently missing: `libgomp1` (the OpenMP runtime PyTorch/onnxruntime need,
pulled in by the `docling` PDF parser) and, at build time, Chromium's OS-level shared libraries for
Playwright's headless-Chromium JS-page fallback — both previously worked only on hosts whose base
image happened to already carry them, since the app installs its Python dependencies at runtime as an
unprivileged user with no `apt`/`sudo` access to fix a missing system library itself.

### Added — Config-drift notice for admins

Every setting in the gitignored instance-config files (`application.yaml`, `sources.yaml`,
`normalizer-config.yaml`) already self-heals when a new one is introduced in code — each loader
merges the live file over a coded-in default. The one gap was `feed-fields.yaml`'s `core_fields`
list, which has no coded default to merge new entries against, so a deployment bootstrapped before
a new built-in field shipped had no way to notice or receive it. Admins now see a top-bar notice
(new `GET /api/app/config-drift`) whenever a newer release's shipped `.example` templates introduce
core fields or top-level settings the live files don't have yet, with a review screen listing
exactly what's new — nothing is added until the admin selects it and clicks Apply
(`POST /api/app/config-drift/apply`); anything they've customized or deliberately removed is never
touched or re-added.

### Fixed — Live instance config no longer tracked in git

`config/application.yaml`, `config/sources.yaml`, `config/feed-fields.yaml`, and
`config/normalizer-config.yaml` were tracked in git despite being written to at runtime by the app
itself (branding, ingestion sources, custom fields, normalizer mappings). Any deployment where an
operator changed one of these settings via the UI permanently diverged that deployment's git HEAD
from upstream — most visibly, the About page's build-time-baked commit hash would never match the
actual released commit again, since every future `git pull`/checkout needed a merge to reconcile
the local edit. Fixed by gitignoring all four (matching the existing `llm-providers.yaml`/
`sso.yaml` pattern) and shipping a `config/<name>.yaml.example` template for each; the real file is
now bootstrapped from its `.example` automatically on first read if absent, so a fresh clone/deploy
still starts with working defaults. Audited the full git history of all four paths — confirmed no
real/live configuration was ever committed to any of them.

### Fixed — Anthropic `temperature` rejection, Azure AI Foundry provider consistency

Newer Claude models (confirmed: `claude-sonnet-5` via Azure AI Foundry's Anthropic passthrough)
reject the `temperature` request field outright with HTTP 400 (`` `temperature` is deprecated for
this model``), which broke every Test/complete call against such a provider. Both `AnthropicClient`
and `AzureAIFoundryClient` now retry once without `temperature` specifically when the provider
reports that exact deprecation — any other 400 still fails immediately, and models that still expect
`temperature` for deterministic output are unaffected.

While fixing this, folded in the Azure AI Foundry Anthropic-passthrough mode documented in
issue-local-023 as a proper `api_style: anthropic` option on the `azure_ai_foundry` provider kind
itself, rather than the previous guidance of configuring an `anthropic` kind provider with an Azure
base_url — same protocol, but a different kind was confusing for operators to reason about. The
`anthropic` kind is now pinned to the native `api.anthropic.com` API only; both the Add Provider
wizard and the persisted-provider edit form expose the deployment-mode choice directly under
`azure_ai_foundry`.

### Added — Evidence content viewer (issue-local-023)

The Evidence tab is now a two-pane view — a sidebar list of evidence items on the left, and a
content card on the right rendering the selected one: PDFs preview inline via the browser's native
viewer, plaintext/extracted content renders in full, and a "Download original" link is always
available. Binary files with no extracted text show a clear "not processed" placeholder instead of
silently having no content at all, which was the previous behavior for every evidence type.

New backend routes serve this safely: the PDF-preview route always responds with a hardcoded
`application/pdf` content type and independently verifies the file's magic bytes server-side before
serving it (regardless of what the uploader's browser claimed the file was), and the download route
always forces `application/octet-stream` + an attachment disposition — neither ever trusts the
stored, client-supplied `mime_type` for the response, closing a stored-content-type risk that a
naive "just serve the file" implementation would have had.

### Fixed — preliminary Threat Intel timing, Azure AI Foundry deployment modes (issue-local-023)

The preliminary-phase Threat Intel analysis was gated on the pipeline reaching `"completed"`, which
only happens on the *resumed* run once a human approves it — i.e. it ran after approval, not before,
contradicting its own "preliminary" naming and the pipeline diagrams. Fixed to run at the point the
pipeline first reaches the approval gate, so analysts reviewing a draft for approval already have
threat intel context. The Hypothesis/Lead/IOC relationship chart also moved below the Analysis tab's
main summary, collapsed by default behind an emphasized toggle.

Confirmed against a real Azure AI Foundry resource that not every deployment uses the unified Model
Inference API the `azure_ai_foundry` provider kind implements — some models (Anthropic Claude,
confirmed 2026-07-26) are instead exposed as a native passthrough answering the model vendor's own
API shape, for which the existing `anthropic` kind already works unmodified. Documented both modes
in the provider wizard and config example so this doesn't need rediscovering.

### Added — Azure AI Foundry LLM provider, Analysis relationship chart, run-config consistency (issue-local-022)

**New `azure_ai_foundry` LLM provider kind** covers OpenAI, Anthropic Claude, and other model
families deployed through Azure AI Foundry — they all answer Foundry's unified Model Inference API.
Previously there was no way to connect a Foundry-hosted endpoint at all: the closest existing kinds
(`anthropic`, `openai_compatible`) each sent the wrong path/auth-header/query-parameter shape,
which is why Foundry connections consistently failed.

**A new relationship chart on the Analysis tab** shows Hypotheses, Hunting Leads, and IOCs as a
three-tier graph, so an analyst can see at a glance whether a hypothesis has one or multiple hunting
leads, and which IOCs aren't cited by any hypothesis ("coverage"). It sits above the existing flat
detail lists as a navigational overview, not a replacement. A "Deep view" toggle overlays this run's
Threat Intel analysis (threat actors, malware families, campaigns, MITRE techniques) as an aggregate
cluster, plus precise per-IOC edges for any IOC also seen in another hunt package.

**Threat Intel workflow visibility and consistency.** Both Threat Intel Analyst phases (preliminary
and post-execution) now log under distinct step ids so both appear in the workflow chart/list
instead of the final phase silently overwriting the preliminary one. New Run and Re-run now share
one `RunConfigForm` (previously two independently-drifting copies of the same form) with Threat
Intel included by default on both. A new `threat_intel_status` field gates Re-run and report
generation while an analysis is in flight, so they can no longer race it. Track Workflow now
defaults on.

**Run/tab UI polish.** The Execution/Threat-Intel/Report tabs now gate on the *active run's* own
status rather than the package's (a stale `pkg.status` from a prior run no longer leaves them wrongly
enabled while a new run is mid-pipeline). Tabs render as connected arrow/chevron segments. The
Comparison Assessment trigger is a distinct purple button-card. The enriched Sanitized-IOC table
(All/Sanitized/Removed filter, verdict toggles) now lives in the IOCs tab, replacing the old flat
list, with better Keep/Remove contrast and deduplicated removal-reason text. The Threat Intel
Tracking dashboard's Exclude/Delete actions are now gated on the researcher/admin role, matching
every other mutating action in that feature.

### Fixed — PDF generation, IOC step ordering (issue-local-022)

PDF report downloads crashed inconsistently on runs whose LLM output had explicit-`null`
hypothesis/lead/TTP fields (rather than merely absent ones), plus a Findings-section double-escape
bug that corrupted `&`/`<`/`>` in generated text — both fixed at the source (`_esc()` made
defensive; the double-escape removed).

Both the header progress rail and the tab bar showed the IOC phase before Analysis, ahead of when
IOCs are actually reviewed. Reordered to Evidence → Analysis → IOC → Execution.

---

### Added — Threat Intel Tracking dashboard, two-phase Threat Intel Analyst, run picker, agent consistency (issue-local-021)

**A new "Threat Intel Tracking" sidebar subsection aggregates data across every hunt package** —
IOCs, CVEs, threat actors, campaigns, malware families, and MITRE ATT&CK techniques, each showing
which hunt package(s) it came from. A Dashboard tab has a deep-search box and six panels; a Hunts
tab lets an analyst Include/Exclude a hunt from all cross-hunt aggregation (reversible) or
permanently delete it. This is a pure read/aggregate layer over data that already existed per-hunt
— no new agent runs.

**The Threat Hunt Intelligence Analyst now runs in two phases.** A new "preliminary" phase fires
right after the generation pipeline completes (before SIEM execution), and the existing
post-execution phase now additionally ingests this run's SIEM findings to confirm or refine the
preliminary assessment — previously the analyst never read execution results at all. Both phases
are gated by a new "Include Threat Intel analysis" run option (default on), alongside a new
default of active IOC cleaning (all four noise-reduction toggles on, including the one that
previously defaulted off).

**Assess & Compare now lets you pick which runs to include and which model to use**, via a dialog
(all runs selected by default) rather than always comparing every run immediately. The trigger
also moved off the per-run tab bar onto the "All runs" row, signaling it's a package-level view;
the comparison itself now lives inside its own self-contained action (mirroring how the Threat
Intelligence tab already worked), so re-running a comparison doesn't require leaving the tab.

**Every hunt-detail tab is now always visible** (Execution/Threat Intelligence/Report grey out
instead of disappearing until the package finishes; IOCs no longer wait for the Analysis tab to be
visited first), the currently-open run is now highlighted in the all-runs table, and HuntID/RunID
badges are a size larger.

**Agent consistency**: five pipeline nodes (TTP Analyst, Hypothesis Generator, Hunting Lead
Planner, Report Writer, Threat Intel Analyst) previously emitted no debug detail at all, leaving
half the pipeline invisible in the run's Pipeline Log console. All five now record what they asked
the LLM, what came back, and why a step fell back to a deterministic default. That console is also
no longer debug-only — Verbose mode now shows a filtered view (errors and fallbacks only), with
the full raw trace still reserved for Debug.

### Added — Search/time filter, Threat Intelligence Analyst, Comparison Module (issue-local-020)

**The hunt package list now supports server-side deep search and a time-range filter.** The search
box reaches past name/description into each package's stored per-run JSON (threat context,
hypotheses, TTP analysis, deep retrohunt) and extracted IOCs via `list_hunt_packages(search=...)`,
with LIKE-wildcard escaping so literal `%`/`_` in a search term aren't treated as wildcards. A new
`HuntTimeFilter` component adds three sub-modes — Relative ("Last N days"), Time Range (native
`<input type="date">` pair), and Presets (Last 1d/7d/15d/30d/3m/6m, Year to Date, Last Year) — with
the search input debounced ~350ms before hitting the API.

**A new Threat Hunt Intelligence Analyst runs automatically after every SIEM execution**, correlating
the run's threat context, hypotheses, and kept IOCs against every other hunt package in the system.
It persists threat actors, attribution, malware families, campaigns, related vendor reporting, and
cross-package IOC correlations (`extracted_iocs` shares one DB across all packages, so this is a
plain cross-package query) to a new `threat_intel_analysis` table (schema v7). Results surface in a
new **Threat Intelligence** tab, shown before Report. Since it lives entirely in
`siem/executor.py` — SIEM execution is outside the LangGraph pipeline, same as `report_writer.py` —
packages that never execute don't get it automatically; a manual
`POST /packages/{id}/runs/{run_id}/threat-intel` route covers that gap.

**A new Comparison Module lets analysts assess all runs of a hunt package side by side.** The
"Assess & Compare" button (next to Re-run, available regardless of any run's status) triggers a
comparison agent that builds a deterministic per-run diff table (model, effort, status, hypothesis/
IOC/technique/event counts) plus an LLM narrative (key differences, gaps, enrichment opportunities,
a recommended combination). Full run detail is only sent to the LLM for the 3 most recent runs —
older runs get a one-line summary — to keep prompt size bounded on packages with many runs.
Comparison reports reuse the existing `hunt_reports` table via a `report_kind: "comparison"`
discriminator instead of a new table; `get_hunt_report()` was updated to filter these out so a
comparison report can never shadow a package's real report. Results show in a new **Comparison
Assessment** tab (before Report), downloadable as Markdown/PDF/JSON.

### Added — Run cancellation, traceable logging, report identifiers/IOC table (issue-local-019)

**Operators can now cancel a currently-running hunt generation run** — a new Cancel button on
HuntDetail (shown only while the active run is `running`) calls a new
`POST /packages/{id}/runs/{run_id}/cancel` route. Since every await point in a run (an LLM call, a
tool call, a URL/Playwright fetch) lives inside one tracked asyncio task, cancelling that task
interrupts whatever is currently in flight — no separate subtask bookkeeping needed. If the app
restarted since the run started (the in-process task registry doesn't survive that), there's
nothing left to actually stop; the stale "running" status is corrected directly instead.

**Stalled runs now time out instead of hanging forever.** A single LangGraph node could previously
block indefinitely — an unresponsive LLM backend, a stuck fetch — with zero step_logs or errors
ever recorded, since nothing bounded how long any one node was allowed to run. Every node now has a
10-minute wall-clock ceiling; on timeout the run is marked `error` with a clear reason instead of
staying `running` forever.

**Pipeline logging is now traceable to a specific hunt package/run.** Every log line emitted while
processing a hunt package previously had inconsistent (or no) identifying context. A new
`get_run_logger()` helper prefixes every message with `[hunt=<id> run=<id>]`, applied across the
pipeline runner and all 9 node files — `grep 'run=1a2b3c4d' logs/app.log` now finds every log line
for one specific run in one shot.

**Reports show the human-readable HuntID/RunID** (e.g. `TH55` / `TH55-X02`) alongside the internal
UUID (kept for reference), and now include the full IOC table (the same All/Sanitized/Removed data
the app's own review table shows — LLM description and noise/removal rationale in full, not just
aggregate counts) in both the Markdown and PDF report.

**Fixed IOC review table text getting cut off**: the Description column (the LLM's per-IOC
assessment) was truncated with an ellipsis and no way to see the rest — it now wraps in full.
Report download links (MD/PDF/JSON) gained small colored format badges so they're distinguishable
without relying on a hover tooltip. Light theme's surfaces are a bit darker (previously read as
washed-out white).

### Added — Track workflow, full evidence in reports, professional branded PDF (issue-local-018 follow-up)

**New "Track workflow" checkbox** next to "Show subtasks" in the workflow graph toolbar — when
enabled, the React Flow chart re-centers on whichever agent/task node is currently active every
time it changes (smooth animated pan, generous padding for a readable zoom), instead of staying at
its initial fit for the rest of the run.

**Reports now include the full extracted/parsed evidence**, not just an aggregate count. Every
evidence item's label, type, parser, status, and full parsed text now appears as its own section in
both the Markdown and PDF reports, consistent with how thoroughly every other section (hypotheses,
leads, TTPs) is already documented.

**Overhauled PDF report generation** — replaced the dark-UI color scheme (near-invisible light-gray
headings and dark table fills on a printed white page) with a professional light palette: dark
slate headings, a brand-blue accent rule, light indigo table headers with dark text, alternating
rows, consistent borders, and header rows that repeat across page breaks. The configured branding
logo and app title (when set in Configuration) now appear on the cover and in a running footer.

### Changed — IOC apply placement, run header dedup, graph focus/colors, Ocean re-hue (issue-local-018 follow-up)

**"Apply changes" for staged IOC verdicts moved next to the filter it affects** — instead of a
page-wide banner detached from context, it now sits directly beside the All/Sanitized/Removed
filter (Analysis tab) and the IOC counts row (IOCs tab), with a visible amber staged-count + Apply
button and a brief green "Applied" confirmation after saving.

**Removed the duplicated "currently viewing" run info** in HuntDetail — the standalone "Viewing
`TH01` / `TH01-X01`" indicator card is gone; the active run's RunID now appears alongside the
HuntID directly in the main title (next to the back arrow and re-run button) instead of being
shown twice.

**The workflow graph now focuses on where an analysis starts**: on mount, both the ReactFlow and
Mermaid visualizers center tightly on the Evidence nodes + the root `intake_classifier` node,
instead of fitting the entire ~1800px-tall pipeline (which zoomed out so far the starting point was
barely visible). Evidence nodes' "ok" state also no longer reuses the exact green Agent nodes use
for "completed" — it's now a distinct teal, consistent with Evidence's other states, so a completed
Evidence node never reads as a completed Agent node at a glance.

**Ocean theme re-hued** — previously a darkened copy of Classic's indigo-blue accent, it now uses a
cyan/sky-blue accent with a teal-tinted gray ramp, so it reads as a genuinely different blue tone
rather than just a dimmer Classic.

### Added — HuntID emphasis, run indicator, pagination, IOC approval gate, Ocean theme (issue-local-018 follow-up)

**HuntID now renders as an emphasized badge** (bordered, brand-accented) everywhere it appears —
the package list (all density modes) and the HuntDetail header — instead of a plain gray label,
since it's the primary way analysts refer to a package. **HuntDetail also shows a "Viewing `TH01` /
`TH01-X02`" indicator** above the run selector, so which run is currently open is unambiguous at a
glance.

**Fixed Light theme's plain-white cards**: `.card` had no Light override at all and fell through to
a near-white background on a near-white page; it now gets a subtle slate-blue tint, matching the
mechanism already used for Energy's card bump. Also extended the earlier Light-theme color-contrast
fix to cover gaps it missed: the app's own `brand-900` accent idiom (re-run/IOC-mode selectors,
SmartMappings/Configuration filter toggles), a `text-blue-200` case, and the workflow phase chips'
one-shade-darker `-800` tier.

**The hunt-package list gained pagination** — a "Show 10/20/50/100" page-size dropdown (persisted,
default 20) plus Prev/Next controls, applied uniformly across Compact/Detailed/Table density modes.

**Approve is now gated on unsaved IOC verdict changes**: if there are staged-but-unapplied IOC
keep/remove overrides for a run, the Approve button is disabled with an explanatory message,
preventing a package from moving into Execution using stale IOC data.

**New "Ocean" theme** — a fourth UI theme, a slightly darker and more blue-biased variant of
Classic's ramp (same accent, same construction method as Light's ramp-mirror), selectable
everywhere Classic/Energy/Light already were (Account's personal override, Configuration's instance
default).

### Added — HuntID/RunID, run-table polish, theme fixes, per-run comments (issue-local-018)

**Every Hunt Package now gets an automatic HuntID** (e.g. `TH01`, `TH02`) — a configurable prefix
(default `TH`, editable in Threat Hunting settings) plus a monotonic sequence, shown to the left of
the package title everywhere it appears. **Runs get a matching Run ID** (e.g. `TH01-X01`), shown as
the leftmost column of the run summary tables. Both IDs are computed dynamically from the current
prefix at read time (not baked into stored strings), so changing the prefix relabels everything
consistently. The 44 pre-existing hunt packages/runs were backfilled by creation order (oldest =
01) via a v6 schema migration.

**The run summary table gained a Duration column**, and its Run ID/Model cells are now clickable —
opening that exact run's detail view (previously only the newest run could be reached without
manually switching the run selector).

**The Classic/Modern card-color toggle was removed** — only the Classic card design remains, and
the hunt-package list's Table density mode now gets the same card chrome (border/background) as
Compact/Detailed mode, closing a visual gap where Table mode rendered with no card styling at all.

**Fixed Light theme contrast**: badges, chips, and buttons using Tailwind's stock
`{color}-900/NN` + `{color}-300`/`-400` pairing (severity badges, status pills, the IOC Keep/Remove
toggle, workflow phase chips) previously stayed dark-tinted with pastel text even in Light mode,
since those literal color classes never participated in Light's CSS-variable ramp-mirroring — a
scoped `[data-theme='light']` CSS override flips the idiom to light-background/dark-text for
green/red/blue/amber/yellow, without touching any component. The sidebar's Threat Intel/Threat
Hunting section titles are also now visually emphasized (brand-colored, bold) to separate them from
Home and the utility items.

**New Comments tab** on each run in `HuntDetail` — free-text analyst notes with author/timestamp,
gated by role (post: researcher, delete: researcher/admin). Previously the closest thing,
`approval_notes`, was accepted by the API but silently discarded — there was no durable place to
record analyst commentary on a specific run.

### Added — Table density mode, Light theme, run-summary IOC counts and report links (issue-local-017)

**New "Table" density mode for the hunt-package list**, alongside the existing Compact/Detailed
toggle — renders each package's runs via the same all-runs status table `HuntDetail` already
shows, under a clickable package-name heading that opens the detail view. Packages with no runs
yet show a "No runs yet" placeholder instead of an empty table.

**The all-runs status table gained two columns.** "IOCs" shows each run's sanitized/removed
counts, parsed server-side from the `deep_retrohunt` blob (`list_generation_runs()`/
`list_hunt_packages()` now return `sanitized_ioc_count`/`removed_ioc_count` per run). "Report"
shows MD/PDF/JSON download links once a report exists for that run (`has_report`, bulk-checked
against `hunt_reports` — no per-run extra fetch). MD/PDF link directly to the existing download
routes; JSON fetches the report on click and builds the download client-side, mirroring
`ReportPanel.tsx`'s existing export pattern (no server-side JSON route exists).

**New "Light" theme**, alongside Classic/Energy — a professional light mode built by mirroring
Classic's gray ramp (gray-950↔gray-50, gray-900↔gray-100, ...) rather than a hand-picked scale,
so every existing component flips from dark-surface/light-text to light-surface/dark-text while
keeping every contrast relationship already tuned for Classic — the same mechanism Energy already
uses, zero component changes needed. The blue accent (`brand-*`) is reused verbatim from Classic.
Threaded through backend validation (`auth/db.py` and `config/loader.py`, both now generating
their error messages dynamically from the valid-theme set instead of a hardcoded string) and both
frontend theme pickers (Account page personal override, General Configuration instance default).

**Energy theme cards are now visibly lighter, not just outlined.** Cards previously only got a
colored ring on `:hover`, with no difference in their resting state — `.card` now gets its own
slightly lighter background in Energy (independent of the shared `gray-900` variable used by 30+
other elements), so cards read as distinct from the page at rest.

**Fixed: the per-run tab row on the hunt-package list only showed for packages with more than one
run.** A single-run package now shows its tab too, so its model/status is visible without opening
the detail view.

**Fixed the GitHub Actions ruff format check** — two files (`backend/auth/oidc.py`,
`backend/tests/test_th_issue_local_004.py`) needed reformatting.

**Tests:** coverage for the Table density mode (toggle presence, per-package table rendering,
zero-runs fallback, click-to-open); `list_generation_runs()`/`list_hunt_packages()` IOC-count and
`has_report` projections; `RunsStatusTable`'s new columns including the JSON-download fetch path;
`"light"` accepted end-to-end at every validation/persistence layer (DB round-trip, both API
routes, `ThemeProvider`, both pickers); and the single-run tab-row regression.

### Fixed — Run-tab clarity, larger Threat Hunting text, all-runs status table, LLM array-field crash (issue-local-017 follow-up)

**Fixed a live page-crash bug (minified React error #31).** Confirmed on the test deployment: the
"issue-015 bugfix2 verification" package's Mistral-Large-3 run has
`threat_context.key_observations` entries shaped as `{observation, confidence, evidence}` objects
instead of the plain strings the schema asks for — rendering an object directly as a React child
blanks the whole page. The same risk existed for hypothesis `suggested_actions` and
`ttp_analysis.detection_opportunities`. Fixed at both ends: backend nodes
(`threat_context_builder`, `hypothesis_generator`, `ttp_analyst`) now normalize these arrays to
strings at the source via a new `coerce_string_list()` helper in `llm_bridge.py`, so future runs
are clean; the frontend also gained a defensive `asDisplayText()` coercion at every render site in
`AnalysisTab.tsx`/`ReportPanel.tsx` (mirroring the existing `asQueryText` pattern for the same
failure class), since a backend-only fix can't repair already-persisted historical runs without a
re-run — this is what actually makes the Mistral run viewable again.

**Run tabs on the hunt-package list now read as actual tabs.** The previous pass gave inactive
tabs a transparent border (invisible until active) and only a faint ring to mark selection — hard
to tell which run was selected or that the row was clickable at all. Inactive tabs now get a
visible border, the active tab uses a stronger fill plus a brand-colored border, and a small
"Runs" label identifies the row without hovering.

**Larger text across the whole Threat Hunting module.** Bumped the smallest text a step each
(9px→10px, 10px→11px, 11px→12px, `text-xs`→`text-sm`) across all `ThreatHunting.tsx` and
`threat-hunting/` components — left `text-sm` and larger alone to limit layout-breakage risk
without a visual QA pass.

**New compact all-runs status table in HuntDetail**, shown below the run-selector dropdown: one
row per run showing the model used, its status, and the same coarse workflow-with-arrows
visualization (Evidence → IOC → Analysis → Execution → Report) `PipelineStepper` shows for the
single selected run — so the whole run history's progress is visible at a glance without
switching the selector back and forth. `list_generation_runs()` now returns each run's
`phases`/`total_elapsed_s` (the same `_parse_step_logs` projection `list_hunt_packages()` already
uses), so this needs no per-run extra fetch.

**Tests:** `coerce_string_list()` unit coverage plus per-node coercion tests (object-shaped items
flattened to strings, missing fields default to an empty list); a frontend regression test
rendering the exact live-observed `{observation, confidence, evidence}` shape end-to-end through
`AnalysisTab`; DB-layer coverage for `list_generation_runs()`'s new phase/elapsed projection; and
`RunsStatusTable` coverage (model/effort display, provider fallback, status text, coarse-phase
done/error states, one row per run).

### Added — Sidebar module grouping, forced password change, multi-run indicators, manual IOC verdict overrides (issue-local-017)

**Sidebar now visually separates the Threat Intel and Threat Hunting modules from Home and the
utility items.** Both sections are wrapped in one bordered/tinted container (`.nav-module-group`,
subtle inset accent in the Energy theme, no-op in Classic), distinguishing the app's two product
modules from everything else in the nav — a pure layout/CSS change, no navigation behavior change.

**Admin-created users are now forced to change their password on first login, not just after an
admin reset.** `POST /api/auth/users` now sets `must_change_password=True` unconditionally — the
existing forced-change middleware gate and reset screen needed no new code, since the flag is read
generically off any user row regardless of how it was set.

**Hunt-package cards now show every run, not just the latest, with a compact/detailed density
toggle.** `list_hunt_packages()` bulk-fetches every non-archived package's full run history
(phases, status, model/effort, elapsed time) in one extra query — no N+1 — and each card renders a
tab strip of its runs when there's more than one. Runs default to the newest; clicking a tab
switches that card's 16-step stage rail to the selected run's data. A new Compact/Detailed toggle
(sibling to the existing Classic/Modern control, `sfi.th.cardDensity` in localStorage) hides the
heavy stage rail in Compact mode — the run tabs themselves stay visible in both modes, since
they're the actual payoff of the multi-run feature. The run tabs read as real tabs (bigger font,
a status-color dot, model/effort-or-date label, and the status word itself — not just a color —
so the active tab and each run's identity are both unambiguous at a glance, addressing feedback
that the first pass only showed a bare status pill with a barely-visible selection ring).

**Manual per-IOC keep/remove verdict overrides**, closing a gap against the original issue-local-015
ask: IOC review previously only supported the *automated* active-cleaning decision, with no way for
an analyst to override an individual IOC. A new `PATCH /packages/{pkg_id}/runs/{run_id}/iocs` route
updates both IOC data stores in one call — `extracted_iocs` (the real table backing the IOCs tab)
and the `deep_retrohunt` JSON blob's `sanitized_iocs` (backing the Sanitized IOCs table and its
CSV/count summary, matched by `(ioc, ioc_type)` since it has no independent id) — recomputing the
canonical CSV and noise counts from the updated kept set. The Sanitized IOCs table gained a true
three-way All/Sanitized/Removed filter (previously "all" silently meant "kept only"), and both IOC
tables gained a Keep/Remove segmented toggle per row. Changes are staged locally (mirroring
`AgentsConfigTab.tsx`'s dirty-gated Save pattern) and only sent on an explicit "Apply changes"
click, shared across the IOCs tab and the Analysis tab's embedded Sanitized IOCs table so a change
survives switching tabs. A manually-removed IOC is visually flagged (struck through, not hidden)
everywhere it's cited as a hypothesis's evidence basis — no auto-discard of the hypothesis itself.

**About page now also shows the build's commit date**, alongside the existing commit hash and
branch — same build-time-injection pattern (`GIT_COMMIT_DATE` from `git log -1 --format=%cI`,
wired through Vite's `define` as `__GIT_COMMIT_DATE__`), so it's obvious at a glance how stale a
running deployment is.

**Tests:** sidebar module-group grouping/collapse coverage; forced-change-on-creation coverage
plus fixes for three pre-existing tests whose freshly-created accounts were newly blocked by the
gate; real-SQLite coverage for `list_hunt_packages()`'s per-run bulk fetch across 0/1/N-run
packages; `useHuntDensity` persistence and the run-tab strip's default-newest-selection/click-to-
switch/compact-mode-survival behavior; DB- and route-level coverage for the new IOC verdict route
(both stores updated together, invalid-action rejection, unknown-package 404, run-scoping); staged-
edit hook coverage (stage/unstage-on-match/dirty-count/apply-clears-pending); the three-way
Sanitized-IOCs filter; and the evidence-chip strike-through flag.

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
build-time-injection pattern already used for the commit hash: the launcher (`opentars`)
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
- **Write-only-secret config** at `config/sso.yaml` (gitignored). Mirrors `llm-providers.yaml` hygiene: `client_secret` is always redacted to `"***"` on reads; sentinel round-trips preserve the stored value. `config/sso.yaml.example` committed with annotated Entra, Google, and generic OIDC templates. Env overrides: `OPENTARS_SSO_ENABLED`, `..._SSO_CLIENT_ID`, `..._SSO_CLIENT_SECRET`, `..._SSO_ISSUER`, `..._SSO_TENANT_ID`, `..._SSO_BUTTON_LABEL`, `..._SSO_DEFAULT_ROLE`.
- **Role mapping**: configurable `role_claim` (e.g. `roles` for Entra App Roles, `groups` for group GUIDs) with a `role_mapping` dict (claim value → app role). Most-privileged match wins when a user has multiple matching claims. Unmapped users get `default_role` (default `threat-viewer`).
- **Auto-provisioning**: on first SSO login, an OpenTARS account is automatically created with an unusable local password. `auto_provision: false` requires manual account creation. Returning SSO users are matched by `(idp, sub)` first (stable across email renames), then by username.
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
- **Part 2C — Docling PDF Parser**: switched from marker-pdf to Docling after dependency conflict assessment — marker-pdf hard-caps `pillow<11.0.0` reintroducing 3 High + 2 Medium Pillow CVEs; Docling requires `pillow<13.0.0,>=10.0.0` which is compatible with our `pillow>=12.2.0` security pin. Real `extract_pdf_docling()` implementation in `pdf_extractor.py` using Docling `DocumentConverter` + `DocumentStream` (no temp file) → `export_to_markdown()`; `is_docling_available()` runtime check; dispatcher routes `parser_mode='docling'` (and legacy `'marker'` as backward-compat alias) to Docling when available+enabled, `parser_mode='auto'` prefers Docling as default when available+enabled; `docling` key added to `agent_tools` config and catalog (category `document_parser`); `docling>=2.104.0` added to `requirements.txt` (note: pulls PyTorch ~2-3 GB; pillow-compatible); **startup script** (`opentars`) gains an idempotent Docling model-prefetch block after the Playwright block — downloads DocLayNet/TableFormer/picture-classifier/RapidOCR models at startup, cached under `~/.cache/docling/`, non-fatal if network unavailable; `AddEvidenceModal` parser dropdown shows `(prefers Docling)` in auto-mode and disables Docling option with install hint when unavailable.

### Added — TH Tooling, Visualization, List UX, Hypotheses, Report, Re-run (issue-local-006)

- **Part A — URL Fetch Robustness**: browser-like headers (realistic UA/Accept), `raise_for_status` on 4xx/5xx (no more error-HTML extraction), `tenacity` retry with exponential backoff (3 attempts), extractor fallback chain (trafilatura → readability-lxml → raw utf-8), Playwright headless-Chromium fallback for JS-heavy pages; new `browser_fetcher.py` with SSRF validation + route interception + service-worker blocking; `opentars` startup script idempotently installs Chromium.
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

[Unreleased]: https://github.com/Mizton-Labs/OpenTARS/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Mizton-Labs/OpenTARS/releases/tag/v0.1.0
