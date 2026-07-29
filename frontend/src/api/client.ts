/**
 * Typed API client — all fetch calls go through here.
 *
 * URL contract (prompts-019):
 *   - When the application has NO base prefix configured (the default), all
 *     URLs produced by this client are DOCUMENT-RELATIVE: BASE is the bare
 *     string "api" and fetch() resolves it against the document's <base href>.
 *   - When a non-empty prefix is configured, BASE becomes "<prefix>/api"
 *     (root-anchored). This is the forcing path used only when relative URLs
 *     cannot work (e.g. proxy environments that demand absolute paths).
 *
 * The runtime prefix is read from <meta name="app-base-prefix">, which the
 * backend injects only when a non-empty prefix is configured. See
 * frontend/src/utils/basePrefix.ts.
 */
import { getAppBasePrefix } from '../utils/basePrefix'

const _prefix = getAppBasePrefix()
const BASE = _prefix ? `${_prefix}/api` : 'api'

/**
 * Build the SSO/OIDC login initiation URL (issue-local-010).
 * Navigating to this URL starts the Authorization Code flow.
 * @param next  SPA path to return to after successful login (same-origin).
 */
export function ssoLoginUrl(next: string = '/viewer'): string {
  const base = _prefix ? `${_prefix}/api/auth/oidc/login` : '/api/auth/oidc/login'
  return `${base}?next=${encodeURIComponent(next)}`
}

/**
 * URL for the branding logo image (prompts-045). Uses the same relative BASE
 * as the API client so it resolves under any reverse-proxy prefix. Pass a
 * cache-buster (e.g. a counter bumped after upload/delete) to force the
 * browser to refetch.
 */
export function logoSrc(cacheBust?: number | string): string {
  const suffix = cacheBust != null ? `?v=${cacheBust}` : ''
  return `${BASE}/app/logo${suffix}`
}

/**
 * URL for FastAPI's own interactive Swagger UI (issue-local-030's About ->
 * API Swagger tab). Lives OUTSIDE /api/ (auto-registered by FastAPI), so it
 * can't reuse BASE — same relative-vs-prefixed resolution as logoSrc above,
 * just rooted at the bare prefix instead of "<prefix>/api".
 *
 * `apiKeysOnly` narrows the rendered schema to the endpoints a scoped API
 * access key can actually call (backend/main.py's _api_key_openapi), which is
 * what the About tab shows by default.
 */
export function swaggerUiSrc(opts?: { apiKeysOnly?: boolean }): string {
  const base = _prefix ? `${_prefix}/docs` : 'docs'
  return opts?.apiKeysOnly ? `${base}?api_keys_only=1` : base
}

// prompts-045: global 401 handler. The AuthProvider registers a callback so a
// 401 from ANY request (e.g. an expired session) drops the cached user and
// bounces the SPA to /login. Kept module-level so the plain `request` helper
// and the XHR upload helper share one hook.
let onUnauthorized: (() => void) | null = null
export function setUnauthorizedHandler(fn: (() => void) | null): void {
  onUnauthorized = fn
}
function _notifyUnauthorized(): void {
  if (onUnauthorized) onUnauthorized()
}

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: { 'Content-Type': 'application/json', ...options?.headers },
    // Always send the session cookie (same-origin in prod; CORS allows
    // credentials for the dev server, see backend CORS config).
    credentials: 'include',
    ...options,
  })
  if (!res.ok) {
    if (res.status === 401) _notifyUnauthorized()
    const text = await res.text()
    throw new Error(`${res.status} ${res.statusText}: ${text}`)
  }
  // 204 No Content: empty body, return undefined cast to T so callers
  // using request<void> (e.g. DELETE endpoints) don't choke on json().
  if (res.status === 204) return undefined as T
  return res.json() as Promise<T>
}

// ── Multipart upload with progress (prompts-021A item 2) ─────────────────────

export interface UploadProgress {
  loaded: number
  total: number
  /** Integer 0–100. 0 when total is unknown. */
  pct: number
}

/**
 * POST a multipart/form-data body and report upload-byte progress.
 *
 * Built on XMLHttpRequest because the Fetch API does not expose
 * request-body upload progress in any current browser (the Streams
 * spec for request bodies is still partial and not portable). This
 * helper is intentionally scoped to multipart uploads only — every
 * other endpoint continues to use the `fetch`-based `request` helper.
 *
 * Resolves with the parsed JSON response on 2xx, rejects with an Error
 * carrying status code and response body on any other outcome (including
 * network failure and timeout).
 */
export function uploadMultipartWithProgress<T>(
  path: string,
  form: FormData,
  onProgress?: (p: UploadProgress) => void,
): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const xhr = new XMLHttpRequest()
    xhr.open('POST', `${BASE}${path}`, true)
    // Send the session cookie with the multipart upload (prompts-045).
    xhr.withCredentials = true

    if (onProgress) {
      xhr.upload.addEventListener('progress', (ev: ProgressEvent) => {
        if (ev.lengthComputable) {
          const loaded = ev.loaded
          const total = ev.total
          const pct = total > 0 ? Math.min(100, Math.round((loaded / total) * 100)) : 0
          onProgress({ loaded, total, pct })
        } else {
          onProgress({ loaded: ev.loaded, total: 0, pct: 0 })
        }
      })
    }

    xhr.addEventListener('load', () => {
      const ok = xhr.status >= 200 && xhr.status < 300
      if (!ok) {
        if (xhr.status === 401) _notifyUnauthorized()
        reject(new Error(`${xhr.status} ${xhr.statusText}: ${xhr.responseText}`))
        return
      }
      try {
        const parsed = JSON.parse(xhr.responseText) as T
        resolve(parsed)
      } catch (e) {
        reject(new Error(`Failed to parse response body: ${String(e)}`))
      }
    })
    xhr.addEventListener('error', () => reject(new Error('Network error during upload')))
    xhr.addEventListener('abort', () => reject(new Error('Upload aborted')))

    xhr.send(form)
  })
}

// ── Types ──────────────────────────────────────────────────────────────────

export interface Entry {
  id?: number
  source: string
  ingested_at: string
  indicator?: string
  indicator_type?: string
  threat_type?: string
  severity?: string
  confidence?: number
  title?: string
  description?: string
  tags?: string
  tlp?: string
  published_at?: string
  cve_id?: string
  cvss_score?: number
  mitre_attack_id?: string
  malware_family?: string
  actor?: string
  country?: string
  ingest_mode?: string
  [key: string]: unknown
}

export interface ActiveJobInfo {
  job_id: string
  kind: string
  step: JobStep
  processed: number
  total: number
}

export interface SummaryItem {
  source: string
  count: number
  last_ingested_at?: string | null
  last_total_read?: number | null
  last_inserted?: number | null
  last_duplicates?: number | null
  last_discarded?: number | null
  last_job_state?: 'done' | 'error' | null
  active_jobs?: ActiveJobInfo[]
}

// prompts-039: one normalizer run-history row from GET /normalizer/runs.
export interface RunHistoryRow {
  id: number
  started_at: string
  trigger: 'manual' | 'schedule' | 'reapply'
  mode: string | null
  proposal_id: number | null
  proposal_name: string | null
  sources: string[]
  status: string
  processed: number
  inserted: number
  errors: number
  warning: string | null
}

export interface IngestResponse {
  inserted: number
  skipped: number
  errors: string[]
  total_read?: number
  duplicates?: number
  discarded?: number
}

export interface RefreshAllItem {
  name: string
  ok: boolean
  inserted?: number
  duplicates?: number
  skipped?: number
  errors?: string[]
  error?: string
}

export interface RefreshAllResult {
  kind: string
  total: number
  succeeded: number
  failed: number
  results: RefreshAllItem[]
}

export interface PreviewResponse {
  preview_id: string
  source_name: string
  format: string
  total: number
  sample: Record<string, unknown>[]
  expires_in_seconds: number
}

// ── Background job tracking ────────────────────────────────────────────────

export type JobState = 'queued' | 'running' | 'done' | 'error'
export type JobStep = 'fetching' | 'parsing' | 'normalising' | 'inserting' | 'done'

export interface Job {
  id: string
  source: string
  kind: string
  state: JobState
  step: JobStep
  processed: number
  total: number
  counters: {
    total_read?: number
    inserted?: number
    duplicates?: number
    discarded?: number
  }
  first_ingest: boolean
  started_at: number
  finished_at: number | null
  error_msg: string | null
}

export interface JobHandle {
  job_id: string
}

export function isJobHandle(x: unknown): x is JobHandle {
  return !!x && typeof x === 'object' && 'job_id' in (x as Record<string, unknown>)
}

export interface FieldDef {
  name: string
  description?: string
  enabled?: boolean
}

export interface FieldsConfig {
  core_fields: FieldDef[]
  custom_fields: FieldDef[]
}

export interface SourceDef {
  name: string
  enabled: boolean
  url: string
  interval_minutes?: number
  headers?: Record<string, string>
  fields?: Record<string, unknown>
}

export interface RemoteJsonSourceDef {
  name: string
  enabled: boolean
  url: string
  continuous: boolean
  interval_minutes?: number
  fields?: Record<string, unknown>
}

// Alias for renamed source type
export type RemoteFeedSourceDef = RemoteJsonSourceDef

// Threat-intel catalogue (prompts-042) — a curated default feed plus live state
export interface ThreatIntelCatalogItem {
  name: string
  title: string
  kind: 'rss_pull' | 'remote_json_pull'
  url: string
  info: string
  default_interval_minutes: number
  enabled: boolean
  continuous: boolean
  interval_minutes: number
}

// Payload sent to bulk-apply catalogue toggles
export interface ThreatIntelToggle {
  name: string
  enabled: boolean
  continuous: boolean
  interval_minutes?: number
}

export interface ListenerConfig {
  enabled: boolean
  fields?: Record<string, unknown>
}

// ── Viewer ─────────────────────────────────────────────────────────────────

export interface EntriesParams {
  source?: string
  search?: string
  severity?: string
  indicator_type?: string
  threat_type?: string
  ingest_mode?: string
  limit?: number
  offset?: number
}

// ── Auth (prompts-045) ───────────────────────────────────────────────────────

// issue-local-002: expanded role model for Threat Hunting module.
// 'normal' → 'threat-viewer', 'sender' → 'feed-sender'
export type UserRole = 'admin' | 'threat-researcher' | 'threat-viewer' | 'feed-sender'

export interface AuthUser {
  id: number
  username: string
  role: UserRole
  enabled: boolean
  created_at?: string
  /**
   * True when the password is a generated default (first-run bootstrap or
   * --reset-admin-password) that must be changed before any other action
   * (prompts-047).
   */
  must_change_password?: boolean
  /**
   * IdP identifier for SSO-authenticated accounts (e.g. 'entra', 'google').
   * Null/undefined for purely local accounts.
   * issue-local-013: used by ProtectedLayout to exempt SSO users from the
   * forced-password-reset screen.
   */
  idp?: string | null
  /**
   * Per-user theme override (issue-local-016). `null`/`undefined` means "use
   * the instance default" (see `getDefaultTheme`/`setDefaultTheme`).
   */
  theme?: 'classic' | 'energy' | 'light' | 'ocean' | null
}

export interface CreateUserPayload {
  username: string
  password: string
  role: UserRole
}

/** A defined API-key scope (issue-local-029) — the wizard's toggle list
 *  source, from GET /api/auth/api-keys/scopes. */
export interface ApiScope {
  id: string
  label: string
  description: string
}

/** A persisted API key as returned by list/update — never includes the
 *  secret (redacted server-side; the secret only ever appears once, in
 *  createApiKey's response). */
export interface ApiKey {
  id: number
  client_id: string
  name: string
  scopes: string[]
  enabled: boolean
  created_by: string | null
  created_at: string
  last_used_at: string | null
}

/** POST /api/auth/api-keys's response — the ONLY time `secret`/`api_key`
 *  are ever available; the caller must show/copy/download them immediately,
 *  they cannot be retrieved again afterward. */
export interface CreatedApiKey extends ApiKey {
  secret: string
  /** The combined `<client_id>.<secret>` bearer value to send as
   *  `Authorization: Bearer <api_key>`. */
  api_key: string
  /** Base URL for the scoped Threat Hunting API, resolved from the request
   *  that created the key (host + any configured base prefix). */
  endpoint: string
}

// ── Global search + SmartSearch (issue-local-031) ────────────────────────────

/** One match, in the section of the app it was found in. */
export interface SearchHit {
  section: string
  title: string
  snippet: string
  /** SPA route that opens the match. */
  route: string
  ref: string | null
}

export interface SearchSection {
  section: string
  hits: SearchHit[]
}

export interface SearchResults {
  query: string
  total: number
  sections: SearchSection[]
}

/** Drives the always-visible Normal/Smart switch: when `available` is false the
 *  Smart side is disabled and `reason` is shown on hover, naming the setting
 *  that turns it on. */
export interface SmartSearchStatus {
  available: boolean
  reason: string | null
  provider: string | null
}

export interface SmartTurn {
  role: 'user' | 'assistant'
  content: string
}

export interface SmartAnswer {
  /** Plain prose. Rendered as text, never HTML. */
  answer: string
  sources: SearchHit[]
  used_context: number
}

/**
 * Password policy published by GET /api/auth/status (prompts-046).
 * The backend (_validate_password) is the source of truth; the SPA mirrors
 * these rules for inline validation only.
 */
export interface PasswordPolicy {
  min_length: number
  required_classes: number
  max_bytes: number
}

export interface AuthStatus {
  auth_enabled: boolean
  password_policy?: PasswordPolicy
  /** issue-local-010: SSO availability published by /api/auth/status */
  sso_enabled?: boolean
  sso_button_label?: string
}

/** SSO / OIDC configuration (issue-local-010). client_secret is always redacted. */
export interface SsoConfig {
  enabled: boolean
  provider_preset: 'entra' | 'okta' | 'google' | 'keycloak' | 'generic'
  issuer: string
  client_id: string
  /** Always "***" on reads — write-only field. */
  client_secret: string
  scopes: string
  button_label: string
  username_claim: string
  role_claim: string
  role_mapping: Record<string, string>
  default_role: string
  auto_provision: boolean
}

export const api = {
  // Health
  health: () => request<{ status: string; version: string }>('/health'),

  // Auth (prompts-045)
  auth: {
    status: () => request<AuthStatus>('/auth/status'),
    me: () => request<{ user: AuthUser }>('/auth/me'),
    login: (username: string, password: string) =>
      request<{ user: AuthUser }>('/auth/login', {
        method: 'POST',
        body: JSON.stringify({ username, password }),
      }),
    logout: () => request<{ status: string }>('/auth/logout', { method: 'POST' }),
    changePassword: (current_password: string, new_password: string) =>
      request<{ status: string }>('/auth/password', {
        method: 'PUT',
        body: JSON.stringify({ current_password, new_password }),
      }),
    // issue-local-016: any authenticated user may set their own theme
    // override. `theme: null` clears the override (falls back to the
    // instance default set via setDefaultTheme).
    setOwnTheme: (theme: 'classic' | 'energy' | 'light' | 'ocean' | null) =>
      request<AuthUser>('/auth/me/theme', {
        method: 'PUT',
        body: JSON.stringify({ theme }),
      }),
    // Admin: user management
    listUsers: () => request<AuthUser[]>('/auth/users'),
    createUser: (payload: CreateUserPayload) =>
      request<AuthUser>('/auth/users', { method: 'POST', body: JSON.stringify(payload) }),
    setUserRole: (id: number, role: UserRole) =>
      request<AuthUser>(`/auth/users/${id}/role`, {
        method: 'PUT',
        body: JSON.stringify({ role }),
      }),
    setUserEnabled: (id: number, enabled: boolean) =>
      request<AuthUser>(`/auth/users/${id}/enabled`, {
        method: 'PUT',
        body: JSON.stringify({ enabled }),
      }),
    // issue-local-016: admin no longer supplies the new password — the
    // backend generates one and returns it once for the admin to hand off
    // out-of-band; the target is forced to change it on next login.
    resetUserPassword: (id: number) =>
      request<{ status: string; username: string; generated_password: string }>(
        `/auth/users/${id}/password`,
        { method: 'PUT' },
      ),
    deleteUser: (id: number) =>
      request<{ status: string; id: number }>(`/auth/users/${id}`, { method: 'DELETE' }),
    // SSO config (issue-local-010) — admin only
    getSsoConfig: () => request<SsoConfig>('/auth/sso/config'),
    updateSsoConfig: (cfg: Partial<SsoConfig>) =>
      request<SsoConfig>('/auth/sso/config', {
        method: 'PUT',
        body: JSON.stringify(cfg),
      }),
    getSsoCallbackUrl: () => request<{ callback_url: string }>('/auth/sso/callback-url'),
    // API access keys (issue-local-029) — admin only
    getApiAccessConfig: () => request<{ enabled: boolean }>('/auth/api-keys/config'),
    setApiAccessConfig: (enabled: boolean) =>
      request<{ enabled: boolean }>('/auth/api-keys/config', {
        method: 'PUT',
        body: JSON.stringify({ enabled }),
      }),
    listApiKeyScopes: () =>
      request<{ scopes: ApiScope[]; default_profile: string[] }>('/auth/api-keys/scopes'),
    listApiKeys: () => request<ApiKey[]>('/auth/api-keys'),
    createApiKey: (name: string, scopes: string[]) =>
      request<CreatedApiKey>('/auth/api-keys', {
        method: 'POST',
        body: JSON.stringify({ name, scopes }),
      }),
    updateApiKey: (
      clientId: string,
      patch: { name?: string; scopes?: string[]; enabled?: boolean },
    ) =>
      request<ApiKey>(`/auth/api-keys/${encodeURIComponent(clientId)}`, {
        method: 'PUT',
        body: JSON.stringify(patch),
      }),
    deleteApiKey: (clientId: string) =>
      request<{ status: string; client_id: string }>(
        `/auth/api-keys/${encodeURIComponent(clientId)}`,
        { method: 'DELETE' },
      ),
    testApiKey: (clientId: string) =>
      request<{ status: 'ok' | 'warning' | 'error'; detail: string; scopes: string[] }>(
        `/auth/api-keys/${encodeURIComponent(clientId)}/test`,
        { method: 'POST' },
      ),
  },

  // Viewer
  getEntries: (params: EntriesParams = {}) => {
    const q = new URLSearchParams()
    Object.entries(params).forEach(([k, v]) => {
      if (v !== undefined && v !== null && v !== '') q.set(k, String(v))
    })
    return request<Entry[]>(`/viewer/entries?${q}`)
  },
  getSummary: (opts: { includeActive?: boolean } = {}) =>
    request<SummaryItem[]>(`/viewer/summary${opts.includeActive ? '?include_active=true' : ''}`),

  // issue_local_009: field names seen populated by ingestion, most-relevant
  // first. Used by the Raw Feeds table to pick its default visible columns.
  getFieldPresence: () =>
    request<{ fields: string[] }>('/viewer/field-presence').then(r => r.fields),

  // Fields
  getFields: () => request<FieldsConfig>('/fields'),
  toggleCoreField: (name: string, enabled: boolean) =>
    request<FieldDef>(`/fields/core/${name}/enabled`, {
      method: 'PUT',
      body: JSON.stringify({ enabled }),
    }),
  addCustomField: (field: FieldDef) =>
    request<FieldDef>('/fields/custom', { method: 'POST', body: JSON.stringify(field) }),
  updateCustomField: (name: string, field: FieldDef) =>
    request<FieldDef>(`/fields/custom/${name}`, { method: 'PUT', body: JSON.stringify(field) }),
  deleteCustomField: (name: string) =>
    request<{ deleted: string }>(`/fields/custom/${name}`, { method: 'DELETE' }),

  // Sources — listener
  getListener: () => request<ListenerConfig>('/sources/listener'),
  updateListener: (body: ListenerConfig) =>
    request<ListenerConfig>('/sources/listener', { method: 'PUT', body: JSON.stringify(body) }),

  // Sources — API pull
  getApiPull: () => request<SourceDef[]>('/sources/api-pull'),
  addApiPull: (source: SourceDef) =>
    request<SourceDef>('/sources/api-pull', { method: 'POST', body: JSON.stringify(source) }),
  updateApiPull: (name: string, source: SourceDef) =>
    request<SourceDef>(`/sources/api-pull/${name}`, { method: 'PUT', body: JSON.stringify(source) }),
  deleteApiPull: (name: string) =>
    request<{ deleted: string }>(`/sources/api-pull/${name}`, { method: 'DELETE' }),

  // Sources — RSS pull
  getRssPull: () => request<SourceDef[]>('/sources/rss-pull'),
  addRssPull: (source: SourceDef) =>
    request<SourceDef>('/sources/rss-pull', { method: 'POST', body: JSON.stringify(source) }),
  updateRssPull: (name: string, source: SourceDef) =>
    request<SourceDef>(`/sources/rss-pull/${name}`, { method: 'PUT', body: JSON.stringify(source) }),
  deleteRssPull: (name: string) =>
    request<{ deleted: string }>(`/sources/rss-pull/${name}`, { method: 'DELETE' }),

  // Sources — Remote JSON pull
  getRemoteJsonPull: () => request<RemoteJsonSourceDef[]>('/sources/remote-json-pull'),
  addRemoteJsonPull: (source: RemoteJsonSourceDef) =>
    request<RemoteJsonSourceDef>('/sources/remote-json-pull', { method: 'POST', body: JSON.stringify(source) }),
  updateRemoteJsonPull: (name: string, source: RemoteJsonSourceDef) =>
    request<RemoteJsonSourceDef>(`/sources/remote-json-pull/${name}`, { method: 'PUT', body: JSON.stringify(source) }),
  deleteRemoteJsonPull: (name: string) =>
    request<{ deleted: string }>(`/sources/remote-json-pull/${name}`, { method: 'DELETE' }),

  // Threat-intel catalogue (prompts-042)
  getThreatIntelCatalog: () =>
    request<ThreatIntelCatalogItem[]>('/sources/threat-intel-catalog'),
  saveThreatIntelSources: (toggles: ThreatIntelToggle[]) =>
    request<ThreatIntelCatalogItem[]>('/sources/threat-intel', {
      method: 'PUT',
      body: JSON.stringify(toggles),
    }),

  // Per-source field config
  getSourceFields: (sourceType: string, name: string) =>
    request<FieldsConfig>(`/sources/${sourceType}/${name}/fields`),
  putSourceFields: (sourceType: string, name: string, config: FieldsConfig) =>
    request<FieldsConfig>(`/sources/${sourceType}/${name}/fields`, { method: 'PUT', body: JSON.stringify(config) }),
  getListenerFields: () => request<FieldsConfig>('/sources/listener/fields'),
  putListenerFields: (config: FieldsConfig) =>
    request<FieldsConfig>('/sources/listener/fields', { method: 'PUT', body: JSON.stringify(config) }),

  // Control
  resetDb: () => request<{ reset: string[]; message: string }>('/control/reset-db', { method: 'POST' }),
  resetSource: (name: string) =>
    request<{ reset: string[]; message: string }>(`/control/reset-source/${name}`, { method: 'POST' }),
  refreshApiPull: (name: string) =>
    request<IngestResponse>(`/control/refresh/api-pull/${name}`, { method: 'POST' }),
  refreshRssPull: (name: string) =>
    request<IngestResponse>(`/control/refresh/rss-pull/${name}`, { method: 'POST' }),
  refreshRemoteJsonPull: (name: string) =>
    request<IngestResponse>(`/control/refresh/remote-json-pull/${name}`, { method: 'POST' }),
  // Alias for renamed remote feed
  refreshRemoteFeedPull: (name: string) =>
    request<IngestResponse>(`/control/refresh/remote-json-pull/${name}`, { method: 'POST' }),
  // Per-section "refresh all" — refresh every configured source of one kind.
  refreshAllApiPull: () =>
    request<RefreshAllResult>('/control/refresh/api-pull', { method: 'POST' }),
  refreshAllRssPull: () =>
    request<RefreshAllResult>('/control/refresh/rss-pull', { method: 'POST' }),
  refreshAllRemoteJsonPull: () =>
    request<RefreshAllResult>('/control/refresh/remote-json-pull', { method: 'POST' }),

  // Scheduler reload
  reloadScheduler: () => request<{ status: string }>('/scheduler/reload', { method: 'POST' }),

  // Ingest — local file upload (multipart) — supports JSON, NDJSON, CSV, XML
  uploadLocalFeed: async (sourceName: string, file: File): Promise<IngestResponse> => {
    const form = new FormData()
    form.append('file', file)
    const res = await fetch(`${BASE}/ingest/local/${sourceName}`, { method: 'POST', body: form, credentials: 'include' })
    if (!res.ok) {
      if (res.status === 401) _notifyUnauthorized()
      throw new Error(`${res.status} ${res.statusText}`)
    }
    return res.json()
  },
  // Back-compat alias
  uploadLocalJson: async (sourceName: string, file: File): Promise<IngestResponse> => {
    const form = new FormData()
    form.append('file', file)
    const res = await fetch(`${BASE}/ingest/local/${sourceName}`, { method: 'POST', body: form, credentials: 'include' })
    if (!res.ok) {
      if (res.status === 401) _notifyUnauthorized()
      throw new Error(`${res.status} ${res.statusText}`)
    }
    return res.json()
  },

  // Preview — two-step local ingest.
  // Accepts an optional onProgress callback (prompts-021A item 2) so the
  // FE can render a real upload-bytes progress bar during the multipart
  // POST. When omitted, behaviour is unchanged from prompts-019.
  previewLocalFeed: async (
    sourceName: string,
    file: File,
    onProgress?: (p: UploadProgress) => void,
  ): Promise<PreviewResponse> => {
    const form = new FormData()
    form.append('file', file)
    return uploadMultipartWithProgress<PreviewResponse>(
      `/ingest/preview/local/${sourceName}`,
      form,
      onProgress,
    )
  },
  confirmPreview: (previewId: string, background: boolean = false) =>
    request<IngestResponse | JobHandle>(
      `/ingest/preview/confirm/${previewId}${background ? '?background=true' : ''}`,
      { method: 'POST' },
    ),

  // Source-preview (pull sources only) — fetch+parse without persisting
  previewApiPullSource: (source: SourceDef) =>
    request<PreviewResponse>('/sources/preview/api-pull', { method: 'POST', body: JSON.stringify(source) }),
  previewRssPullSource: (source: SourceDef) =>
    request<PreviewResponse>('/sources/preview/rss-pull', { method: 'POST', body: JSON.stringify(source) }),
  previewRemoteJsonPullSource: (source: RemoteJsonSourceDef) =>
    request<PreviewResponse>('/sources/preview/remote-json-pull', { method: 'POST', body: JSON.stringify(source) }),
  confirmSourcePreview: (previewId: string, background: boolean = false) =>
    request<IngestResponse | JobHandle>(
      `/sources/preview/confirm/${previewId}${background ? '?background=true' : ''}`,
      { method: 'POST' },
    ),
  cancelSourcePreview: (previewId: string) =>
    request<{ cancelled: boolean }>(`/sources/preview/cancel/${previewId}`, { method: 'POST' }),

  // Ingest — remote URL
  ingestRemote: (sourceName: string, url: string) =>
    request<IngestResponse>(`/ingest/remote/${sourceName}`, {
      method: 'POST',
      body: JSON.stringify({ url }),
    }),

  // Fields — ingest-all toggle
  getIngestAllFields: () => request<{ ingest_all_fields: boolean }>('/fields/ingest-all'),
  setIngestAllFields: (value: boolean) =>
    request<{ ingest_all_fields: boolean }>('/fields/ingest-all', {
      method: 'PUT',
      body: JSON.stringify({ ingest_all_fields: value }),
    }),

  // Fields — flatten depth (prompts-015)
  getFlattenDepth: () => request<{ flatten_max_depth: number }>('/fields/flatten-depth'),
  setFlattenDepth: (value: number) =>
    request<{ flatten_max_depth: number }>('/fields/flatten-depth', {
      method: 'PUT',
      body: JSON.stringify({ flatten_max_depth: value }),
    }),

  // Application — base URL prefix (prompts-017)
  getAppBasePrefix: () => request<{ app_base_prefix: string }>('/app/base-prefix'),
  setAppBasePrefix: (value: string) =>
    request<{ app_base_prefix: string; restart_required: boolean }>('/app/base-prefix', {
      method: 'PUT',
      body: JSON.stringify({ app_base_prefix: value }),
    }),

  // Application — Normalized viewer pagination cap (prompts-043)
  getPaginationMax: () => request<{ pagination_max: number }>('/app/pagination-max'),
  setPaginationMax: (value: number) =>
    request<{ pagination_max: number }>('/app/pagination-max', {
      method: 'PUT',
      body: JSON.stringify({ pagination_max: value }),
    }),

  // Application — per-watcher stored/feed event cap (issue_local_006)
  getWatcherMaxEvents: () => request<{ watcher_max_events: number }>('/app/watcher-max-events'),
  setWatcherMaxEvents: (value: number) =>
    request<{ watcher_max_events: number }>('/app/watcher-max-events', {
      method: 'PUT',
      body: JSON.stringify({ watcher_max_events: value }),
    }),

  // Application — operator display title (issue-local-001-rev1)
  getAppTitle: () => request<{ app_title: string }>('/app/title'),
  setAppTitle: (value: string) =>
    request<{ app_title: string }>('/app/title', {
      method: 'PUT',
      body: JSON.stringify({ app_title: value }),
    }),

  // Application — allowlisted project docs (About page's API Docs tab, issue-local-030)
  getDoc: (docId: string) =>
    request<{ doc_id: string; content: string }>(`/app/docs/${encodeURIComponent(docId)}`),

  // Global search + SmartSearch (issue-local-031). All read-only; the server
  // scopes every result to the caller's role.
  search: {
    query: (q: string) => request<SearchResults>(`/search?q=${encodeURIComponent(q)}`),
    status: () => request<SmartSearchStatus>('/search/status'),
    smart: (question: string, history: SmartTurn[] = []) =>
      request<SmartAnswer>('/search/smart', {
        method: 'POST',
        body: JSON.stringify({ question, history }),
      }),
  },

  // Application — instance-wide default UI theme (issue-local-016). Public
  // GET (needed so the login screen, pre-auth, can apply it); admin-gated PUT.
  getDefaultTheme: () => request<{ theme: string }>('/app/theme'),
  setDefaultTheme: (theme: 'classic' | 'energy' | 'light' | 'ocean') =>
    request<{ theme: string }>('/app/theme', {
      method: 'PUT',
      body: JSON.stringify({ theme }),
    }),

  // Application — branding logo (prompts-045)
  getLogoInfo: () => request<{ has_logo: boolean }>('/app/logo-info'),
  uploadLogo: async (file: File): Promise<{ logo_path: string; has_logo: boolean }> => {
    const form = new FormData()
    form.append('file', file)
    const res = await fetch(`${BASE}/app/logo`, {
      method: 'POST',
      body: form,
      credentials: 'include',
    })
    if (!res.ok) {
      if (res.status === 401) _notifyUnauthorized()
      throw new Error(`${res.status} ${res.statusText}: ${await res.text()}`)
    }
    return res.json()
  },
  deleteLogo: () => request<{ has_logo: boolean }>('/app/logo', { method: 'DELETE' }),

  // Agent workflow settings (issue-local-004)
  getAgentVerbosity: () => request<{ agent_workflow_verbosity: string }>('/app/agent-verbosity'),
  setAgentVerbosity: (value: string) =>
    request<{ agent_workflow_verbosity: string }>('/app/agent-verbosity', {
      method: 'PUT',
      body: JSON.stringify({ agent_workflow_verbosity: value }),
    }),
  getAgentVisualization: () => request<{ agent_workflow_visualization: string }>('/app/agent-visualization'),
  setAgentVisualization: (value: string) =>
    request<{ agent_workflow_visualization: string }>('/app/agent-visualization', {
      method: 'PUT',
      body: JSON.stringify({ agent_workflow_visualization: value }),
    }),
  getAgentShowSubtasks: () => request<{ agent_workflow_show_subtasks: boolean }>('/app/agent-show-subtasks'),
  setAgentShowSubtasks: (value: boolean) =>
    request<{ agent_workflow_show_subtasks: boolean }>('/app/agent-show-subtasks', {
      method: 'PUT',
      body: JSON.stringify({ agent_workflow_show_subtasks: value }),
    }),
  getThLlmMaxRetries: () => request<{ th_llm_max_retries: number }>('/app/th-llm-max-retries'),
  setThLlmMaxRetries: (value: number) =>
    request<{ th_llm_max_retries: number }>('/app/th-llm-max-retries', {
      method: 'PUT',
      body: JSON.stringify({ th_llm_max_retries: value }),
    }),
  getThLlmRetryBackoffSeconds: () =>
    request<{ th_llm_retry_backoff_seconds: number }>('/app/th-llm-retry-backoff-seconds'),
  setThLlmRetryBackoffSeconds: (value: number) =>
    request<{ th_llm_retry_backoff_seconds: number }>('/app/th-llm-retry-backoff-seconds', {
      method: 'PUT',
      body: JSON.stringify({ th_llm_retry_backoff_seconds: value }),
    }),
  getThResearchEffort: () => request<{ th_research_effort: string }>('/app/th-research-effort'),
  setThResearchEffort: (value: string) =>
    request<{ th_research_effort: string }>('/app/th-research-effort', {
      method: 'PUT',
      body: JSON.stringify({ th_research_effort: value }),
    }),
  getThReportFormats: () => request<{ th_report_formats: { pdf: boolean; markdown: boolean } }>('/app/th-report-formats'),
  setThReportFormats: (value: { pdf: boolean; markdown: boolean }) =>
    request<{ th_report_formats: { pdf: boolean; markdown: boolean } }>('/app/th-report-formats', {
      method: 'PUT',
      body: JSON.stringify({ th_report_formats: value }),
    }),
  // issue-local-018: HuntID prefix (e.g. "TH" -> "TH01")
  getHuntIdPrefix: () => request<{ hunt_id_prefix: string }>('/app/hunt-id-prefix'),
  setHuntIdPrefix: (value: string) =>
    request<{ hunt_id_prefix: string }>('/app/hunt-id-prefix', {
      method: 'PUT',
      body: JSON.stringify({ hunt_id_prefix: value }),
    }),

  // Agent tools + document parsers toggles (issue-007)
  getAgentTools: () => request<{ agent_tools: Record<string, boolean> }>('/app/agent-tools'),
  setAgentTools: (value: Record<string, boolean>) =>
    request<{ agent_tools: Record<string, boolean> }>('/app/agent-tools', {
      method: 'PUT',
      body: JSON.stringify({ agent_tools: value }),
    }),
  getAgentToolsCatalog: () => request<{ catalog: ToolCatalogEntry[] }>('/app/agent-tools/catalog'),

  // Config drift (issue-local-024 follow-up): application.yaml/sources.yaml/
  // feed-fields.yaml/normalizer-config.yaml are gitignored instance state
  // bootstrapped from a .example template on first run. This detects the one
  // gap that doesn't self-heal on upgrade (feed-fields.yaml's core_fields
  // list) plus any brand-new top-level key a future .example introduces.
  getConfigDrift: () => request<{ reports: ConfigDriftReport[] }>('/app/config-drift'),
  applyConfigDriftFix: (file: string, patch: { keys?: string[]; core_field_names?: string[] }) =>
    request<{ reports: ConfigDriftReport[] }>('/app/config-drift/apply', {
      method: 'POST',
      body: JSON.stringify({ file, ...patch }),
    }),

  // Normalizer
  getNormalizerConfig: () => request<Record<string, unknown>>('/normalizer/config'),
  updateNormalizerConfig: (cfg: Record<string, unknown>) =>
    request<Record<string, unknown>>('/normalizer/config', {
      method: 'PUT',
      body: JSON.stringify(cfg),
    }),
  runNormalizer: () => request<Record<string, unknown>>('/normalizer/run', { method: 'POST' }),
  getNormalizedEntries: (params: { source?: string; search?: string; limit?: number; offset?: number; mapping_version_id?: number } = {}) => {
    const q = new URLSearchParams()
    Object.entries(params).forEach(([k, v]) => {
      if (v !== undefined && v !== null && v !== '') q.set(k, String(v))
    })
    return request<Record<string, unknown>[]>(`/normalizer/entries?${q}`)
  },
  getNormalizerSummary: () => request<SummaryItem[]>('/normalizer/summary'),
  // prompts-039: normalizer run history (manual / schedule / reapply runs).
  getRunHistory: (limit = 200) =>
    request<RunHistoryRow[]>(`/normalizer/runs?limit=${limit}`),

  // Jobs
  getJob: (id: string) => request<Job>(`/jobs/${id}`),
  listActiveJobs: () => request<Job[]>('/jobs?active=true'),

  // Smart mappings (prompts-021E)
  smartMappings: {
    dryRun: (body: SmartDryRunRequest) =>
      request<SmartDryRunResponse>('/smart-mappings/dry-run', {
        method: 'POST',
        body: JSON.stringify(body),
      }),
    createJob: (body: SmartJobRequest) =>
      request<SmartJobHandle>('/smart-mappings/jobs', {
        method: 'POST',
        body: JSON.stringify(body),
      }),
    getJob: (id: string) => request<Job>(`/smart-mappings/jobs/${id}`),
    listProposals: (params: {
      source?: string
      status?: SmartProposalStatus
      // prompts-021E-4: when omitted, backend defaults to outcome='pending_review'.
      // Pass 'all' to bypass the filter, or a specific outcome value.
      outcome?: SmartProposalOutcome | 'all'
      limit?: number
      // prompts-034: archive filter. 'active' (default) hides archived rows,
      // 'all' shows both, 'only' shows archived rows only.
      archived?: 'active' | 'all' | 'only'
    } = {}) => {
      const q = new URLSearchParams()
      Object.entries(params).forEach(([k, v]) => {
        if (v !== undefined && v !== null && v !== '') q.set(k, String(v))
      })
      const qs = q.toString()
      return request<SmartProposal[]>(`/smart-mappings/proposals${qs ? `?${qs}` : ''}`)
    },
    getProposal: (id: number) => request<SmartProposal>(`/smart-mappings/proposals/${id}`),
    approve: (id: number, body: SmartApproveRequest = {}) =>
      request<SmartApproveResponse>(`/smart-mappings/proposals/${id}/approve`, {
        method: 'POST',
        body: JSON.stringify(body),
      }),
    reject: (id: number, body: SmartRejectRequest = {}) =>
      request<{ proposal_id: number; status: 'rejected' }>(`/smart-mappings/proposals/${id}/reject`, {
        method: 'POST',
        body: JSON.stringify(body),
      }),
    // prompts-032 Phase D: return an operator-rejected proposal to the review
    // queue. 409 when the proposal is not 'rejected' or was auto-discarded.
    reenable: (id: number, body: SmartRejectRequest = {}) =>
      request<{ proposal_id: number; status: 'pending' }>(`/smart-mappings/proposals/${id}/reenable`, {
        method: 'POST',
        body: JSON.stringify(body),
      }),
    // prompts-032 Phase D: the active consolidated mapping summary (or null)
    // backing the active-mapping card above the proposal list.
    getActive: () => request<{ active: ActiveConsolidatedMapping | null }>('/smart-mappings/active'),
    // prompts-038: re-apply the active consolidated mapping on demand — clears
    // and re-normalizes the mapping's feeds, then runs the normalizer. Returns
    // the run counters (processed/inserted/errors) plus reset_rows.
    runActive: () =>
      request<{ reset_rows: number; processed?: number; inserted?: number; errors?: number }>(
        '/smart-mappings/active/run',
        { method: 'POST' },
      ),
    // prompts-034: archive a proposal (any status). Hides it from default
    // views without deleting it. Optional note recorded for provenance.
    archive: (id: number, body: { note?: string } = {}) =>
      request<{ proposal_id: number; archived: true }>(`/smart-mappings/proposals/${id}/archive`, {
        method: 'POST',
        body: JSON.stringify(body),
      }),
  },

  // LLM providers (prompts-021D-2, expanded in 022 step 5)
  llm: {
    getConfig: () => request<LLMConfig>('/llm/config'),
    /**
     * Update the top-level LLM toggles only.
     *
     * 022 step 4 narrowed the backend: PUT /api/llm/config now accepts
     * ONLY {enabled, default_provider}; the providers list is managed via
     * addProvider / updateProvider / deleteProvider below. Sending any
     * other key (including the historical 'providers') returns 400.
     *
     * The parameter type accepts the legacy full :type:`LLMConfig` shape
     * as well so call sites that still build the wide payload keep
     * compiling until Step 7 swaps them over; the backend will reject
     * any extra keys at runtime.
     */
    setConfig: (cfg: LLMConfigUpdate | LLMConfig) =>
      request<LLMConfig>('/llm/config', {
        method: 'PUT',
        body: JSON.stringify(cfg),
      }),
    listProviders: () => request<LLMProviderSummary[]>('/llm/providers'),
    /**
     * Append a new provider to llm-providers.yaml. Backend enforces the
     * identifier regex (^[A-Za-z0-9_-]{1,40}$) and uniqueness against
     * existing names. 400 on validation error.
     */
    addProvider: (provider: LLMProviderConfig) =>
      request<LLMProviderSummary>('/llm/providers', {
        method: 'POST',
        body: JSON.stringify(provider),
      }),
    /**
     * Replace one provider in-place. The path name is authoritative; a
     * body name that differs is ignored. Write-only api_key semantics
     * still apply: send "***" (or omit) to retain the stored key.
     */
    updateProvider: (name: string, provider: LLMProviderConfig) =>
      request<LLMProviderSummary>(
        `/llm/providers/${encodeURIComponent(name)}`,
        { method: 'PUT', body: JSON.stringify(provider) },
      ),
    /** Delete a provider; clears default_provider when it pointed here. */
    deleteProvider: (name: string) =>
      request<void>(`/llm/providers/${encodeURIComponent(name)}`, {
        method: 'DELETE',
      }),
    /**
     * Test an already-persisted provider. Returns the canonical
     * run_provider_test transcript (status + details[] + models + sample).
     * Provider/transport errors are captured into details[] with
     * aggregate status='error' (NOT raised as HTTP 502).
     */
    testProvider: (name: string) =>
      request<LLMTestRunResult>(
        `/llm/providers/${encodeURIComponent(name)}/test`,
        { method: 'POST' },
      ),
    /**
     * Test a *draft* provider that has not been persisted yet. Used by
     * the Add LLM wizard so the operator can validate config before
     * clicking 'Add LLM'. The YAML file is never touched. Same canonical
     * transcript shape as testProvider.
     */
    testProviderDraft: (provider: LLMProviderConfig) =>
      request<LLMTestRunResult>('/llm/providers/test', {
        method: 'POST',
        body: JSON.stringify(provider),
      }),
    /**
     * prompts-027: Discover models ONLY against a draft provider (no
     * probe). Returns LLMDiscoverResult. Used by the Add Provider
     * wizard's "Connect to provider" button (stage 2).
     */
    discoverDraft: (provider: LLMProviderConfig) =>
      request<LLMDiscoverResult>('/llm/providers/discover', {
        method: 'POST',
        body: JSON.stringify(provider),
      }),
    /**
     * prompts-027: Discover models ONLY against an already-persisted
     * provider. Used by the persisted ProviderCard's "Discover Models"
     * button to refresh the per-provider list. The caller is responsible
     * for persisting the returned ``models`` to ``available_models``
     * via :func:`updateProvider`.
     */
    discoverProvider: (name: string) =>
      request<LLMDiscoverResult>(
        `/llm/providers/${encodeURIComponent(name)}/discover`,
        { method: 'POST' },
      ),
  },

  // Mapping versions (prompts-021F)
  mappings: {
    listVersions: (source?: string) => {
      const q = source ? `?source=${encodeURIComponent(source)}` : ''
      return request<MappingVersion[]>(`/normalizer/mappings/versions${q}`)
    },
    getVersion: (id: number) =>
      request<MappingVersionDetail>(`/normalizer/mappings/versions/${id}`),
    activate: (id: number) =>
      request<MappingVersionActivateResponse>(
        `/normalizer/mappings/versions/${id}/activate`,
        { method: 'POST' },
      ),
    diff: (fromId: number, toId: number) =>
      request<MappingVersionDiffResponse>(
        `/normalizer/mappings/diff?from=${fromId}&to=${toId}`,
      ),
  },

  // Watchers (issue_local_006) — admin CRUD + triggered-event reader.
  watchers: {
    list: () => request<Watcher[]>('/watchers'),
    get: (id: string) => request<Watcher>(`/watchers/${encodeURIComponent(id)}`),
    create: (body: WatcherInput) =>
      request<Watcher>('/watchers', { method: 'POST', body: JSON.stringify(body) }),
    update: (id: string, body: WatcherInput) =>
      request<Watcher>(`/watchers/${encodeURIComponent(id)}`, {
        method: 'PUT',
        body: JSON.stringify(body),
      }),
    setEnabled: (id: string, enabled: boolean) =>
      request<Watcher>(`/watchers/${encodeURIComponent(id)}/enabled`, {
        method: 'PUT',
        body: JSON.stringify({ enabled }),
      }),
    remove: (id: string) =>
      request<void>(`/watchers/${encodeURIComponent(id)}`, { method: 'DELETE' }),
    trigger: (id: string) =>
      request<WatcherTriggerResult>(
        `/watchers/${encodeURIComponent(id)}/trigger`,
        { method: 'POST' },
      ),
    events: (id: string, params: { limit?: number; offset?: number } = {}) => {
      const q = new URLSearchParams()
      Object.entries(params).forEach(([k, v]) => {
        if (v !== undefined && v !== null) q.set(k, String(v))
      })
      const qs = q.toString()
      return request<WatcherEventsPage>(
        `/watchers/${encodeURIComponent(id)}/events${qs ? `?${qs}` : ''}`,
      )
    },
    metaFeeds: () => request<{ feeds: string[] }>('/watchers/meta/feeds'),
    metaFields: (dataset: WatcherDataset = 'all', feeds: string[] = []) => {
      const q = new URLSearchParams()
      q.set('dataset', dataset)
      feeds.forEach((f) => {
        if (f) q.append('feeds', f)
      })
      return request<{ fields: string[] }>(`/watchers/meta/fields?${q.toString()}`)
    },
  },

  // Threat Hunting (issue-local-002, Phase 2)
  threatHunting: {
    // Hunt Packages
    // issue-local-020: optional deep search (name/description + per-run
    // stored analysis JSON + extracted IOCs) and created_at date-range filter.
    listPackages: (params: { search?: string; date_from?: string; date_to?: string } = {}) => {
      const q = new URLSearchParams()
      if (params.search) q.set('search', params.search)
      if (params.date_from) q.set('date_from', params.date_from)
      if (params.date_to) q.set('date_to', params.date_to)
      const qs = q.toString()
      return request<THuntPackage[]>(`/threat-hunting/packages${qs ? `?${qs}` : ''}`)
    },
    createPackage: (body: { name: string; description?: string }) =>
      request<THuntPackage>('/threat-hunting/packages', {
        method: 'POST',
        body: JSON.stringify(body),
      }),
    getPackage: (id: string) =>
      request<THuntPackage>(`/threat-hunting/packages/${encodeURIComponent(id)}`),
    updatePackage: (id: string, body: { name?: string; description?: string; status?: string }) =>
      request<THuntPackage>(`/threat-hunting/packages/${encodeURIComponent(id)}`, {
        method: 'PUT',
        body: JSON.stringify(body),
      }),
    archivePackage: (id: string) =>
      request<void>(`/threat-hunting/packages/${encodeURIComponent(id)}`, {
        method: 'DELETE',
      }),
    clonePackage: (pkgId: string, name: string) =>
      request<THuntPackage>(`/threat-hunting/packages/${encodeURIComponent(pkgId)}/clone`, {
        method: 'POST',
        body: JSON.stringify({ name }),
      }),

    // Evidence — file upload (multipart, with XHR progress reporting)
    // issue-local-011: switched to uploadMultipartWithProgress so callers can
    // render a real upload-byte progress bar instead of just a spinner.
    addEvidenceFile: (
      pkgId: string,
      file: File,
      parserMode = 'auto',
      onProgress?: (p: UploadProgress) => void,
    ): Promise<THEvidenceItem> => {
      const form = new FormData()
      form.append('file', file)
      return uploadMultipartWithProgress<THEvidenceItem>(
        `/threat-hunting/packages/${encodeURIComponent(pkgId)}/evidence/file?parser_mode=${parserMode}`,
        form,
        onProgress,
      )
    },
    // Evidence — URL
    addEvidenceUrl: (pkgId: string, body: { url: string; label?: string }) =>
      request<THEvidenceItem>(
        `/threat-hunting/packages/${encodeURIComponent(pkgId)}/evidence/url`,
        { method: 'POST', body: JSON.stringify(body) },
      ),
    // Evidence — manual text
    addEvidenceText: (pkgId: string, body: { text: string; label?: string; source_ref?: string }) =>
      request<THEvidenceItem>(
        `/threat-hunting/packages/${encodeURIComponent(pkgId)}/evidence/text`,
        { method: 'POST', body: JSON.stringify(body) },
      ),
    // Evidence — watcher import
    addEvidenceWatcher: (pkgId: string, body: { watcher_id: string; label?: string; max_events?: number }) =>
      request<THEvidenceItem>(
        `/threat-hunting/packages/${encodeURIComponent(pkgId)}/evidence/watcher`,
        { method: 'POST', body: JSON.stringify(body) },
      ),
    listEvidence: (pkgId: string) =>
      request<THEvidenceItem[]>(
        `/threat-hunting/packages/${encodeURIComponent(pkgId)}/evidence`,
      ),
    deleteEvidence: (pkgId: string, itemId: string) =>
      request<void>(
        `/threat-hunting/packages/${encodeURIComponent(pkgId)}/evidence/${encodeURIComponent(itemId)}`,
        { method: 'DELETE' },
      ),
    // issue-local-023: URL-string methods (not fetch calls) — same pattern
    // as downloadReportPdf, for direct use in an <iframe src> / <a href>.
    getEvidencePdfUrl: (pkgId: string, itemId: string) =>
      `${BASE}/threat-hunting/packages/${encodeURIComponent(pkgId)}/evidence/${encodeURIComponent(itemId)}/pdf`,
    getEvidenceDownloadUrl: (pkgId: string, itemId: string) =>
      `${BASE}/threat-hunting/packages/${encodeURIComponent(pkgId)}/evidence/${encodeURIComponent(itemId)}/download`,
    listIocs: (pkgId: string, runId?: string) =>
      request<THExtractedIOC[]>(
        `/threat-hunting/packages/${encodeURIComponent(pkgId)}/iocs${runId ? `?run_id=${encodeURIComponent(runId)}` : ''}`,
      ),
    discardHypothesis: (pkgId: string, runId: string, hypothesisId: string, discarded: boolean) =>
      request<THHypothesis>(
        `/threat-hunting/packages/${encodeURIComponent(pkgId)}/runs/${encodeURIComponent(runId)}/hypotheses/${encodeURIComponent(hypothesisId)}`,
        { method: 'PATCH', body: JSON.stringify({ discarded }) },
      ),
    discardHuntingLead: (pkgId: string, runId: string, leadId: string, discarded: boolean) =>
      request<THHuntingLead>(
        `/threat-hunting/packages/${encodeURIComponent(pkgId)}/runs/${encodeURIComponent(runId)}/hunting-leads/${encodeURIComponent(leadId)}`,
        { method: 'PATCH', body: JSON.stringify({ discarded }) },
      ),
    // issue-local-016: batch-apply manual keep/remove verdict overrides for
    // this run's IOCs. Updates both extracted_iocs and the deep_retrohunt
    // blob's sanitized_iocs server-side — the response's `deep_retrohunt`
    // field is the updated lead, ready to swap into the run-record cache
    // without a second fetch.
    updateIocVerdicts: (
      pkgId: string,
      runId: string,
      updates: { ioc: string; ioc_type: string; action: 'keep' | 'remove' }[],
    ) =>
      request<{ status: string; updated_count: number; deep_retrohunt: THDeepRetrohuntLead | null }>(
        `/threat-hunting/packages/${encodeURIComponent(pkgId)}/runs/${encodeURIComponent(runId)}/iocs`,
        { method: 'PATCH', body: JSON.stringify({ updates }) },
      ),

    // Generation (Phase 3)
    startGeneration: (pkgId: string, body: { provider_name?: string; model_name?: string; research_effort?: string; run_config?: THIocRunConfig } = {}) =>
      request<THGenerationRecord>(
        `/threat-hunting/packages/${encodeURIComponent(pkgId)}/generate`,
        { method: 'POST', body: JSON.stringify(body) },
      ),
    getGenerationStatus: (pkgId: string) =>
      request<THGenerationRecord>(
        `/threat-hunting/packages/${encodeURIComponent(pkgId)}/generate/status`,
      ),
    approveGeneration: (pkgId: string, notes = '') =>
      request<{ generation_status: string }>(
        `/threat-hunting/packages/${encodeURIComponent(pkgId)}/approve`,
        { method: 'POST', body: JSON.stringify({ notes }) },
      ),
    rejectGeneration: (pkgId: string, notes = '') =>
      request<{ generation_status: string }>(
        `/threat-hunting/packages/${encodeURIComponent(pkgId)}/reject`,
        { method: 'POST', body: JSON.stringify({ notes }) },
      ),
    // ── Phase 5: SIEM connectors ────────────────────────────────────────────
    listConnectors: () =>
      request<THSiemConnector[]>('/threat-hunting/connectors'),
    createConnector: (body: THConnectorCreateBody) =>
      request<THSiemConnector>('/threat-hunting/connectors', {
        method: 'POST',
        body: JSON.stringify(body),
      }),
    getConnector: (connId: string) =>
      request<THSiemConnector>(`/threat-hunting/connectors/${encodeURIComponent(connId)}`),
    updateConnector: (connId: string, body: Partial<THConnectorCreateBody>) =>
      request<THSiemConnector>(`/threat-hunting/connectors/${encodeURIComponent(connId)}`, {
        method: 'PUT',
        body: JSON.stringify(body),
      }),
    deleteConnector: (connId: string) =>
      request<void>(`/threat-hunting/connectors/${encodeURIComponent(connId)}`, {
        method: 'DELETE',
      }),
    testConnector: (connId: string) =>
      request<THConnectorTestResult>(`/threat-hunting/connectors/${encodeURIComponent(connId)}/test`, {
        method: 'POST',
      }),
    // ── Phase 5: Execution ──────────────────────────────────────────────────
    executeHunt: (pkgId: string, body: THExecuteBody) =>
      request<THTaskResult>(
        `/threat-hunting/packages/${encodeURIComponent(pkgId)}/execute`,
        { method: 'POST', body: JSON.stringify(body) },
      ),
    listResults: (pkgId: string) =>
      request<THTaskResult[]>(`/threat-hunting/packages/${encodeURIComponent(pkgId)}/results`),
    getResult: (pkgId: string, resultId: string) =>
      request<THTaskResult>(
        `/threat-hunting/packages/${encodeURIComponent(pkgId)}/results/${encodeURIComponent(resultId)}`,
      ),
    // ── Phase 6: Reports ────────────────────────────────────────────────────
    getReport: (pkgId: string) =>
      request<THHuntReport>(`/threat-hunting/packages/${encodeURIComponent(pkgId)}/report`),
    generateReport: (pkgId: string, body: { provider_name?: string | null; model_name?: string | null; report_formats?: { pdf: boolean; markdown: boolean } } = {}) =>
      request<THHuntReport>(`/threat-hunting/packages/${encodeURIComponent(pkgId)}/report`, {
        method: 'POST',
        body: JSON.stringify(body),
      }),
    listReports: (pkgId: string) =>
      request<THHuntReport[]>(`/threat-hunting/packages/${encodeURIComponent(pkgId)}/report/list`),
    downloadReportMarkdown: (pkgId: string) =>
      `${BASE}/threat-hunting/packages/${encodeURIComponent(pkgId)}/report/markdown`,
    downloadReportPdf: (pkgId: string) =>
      `${BASE}/threat-hunting/packages/${encodeURIComponent(pkgId)}/report/pdf`,
    // ── issue-local-005: Run-scoped methods ─────────────────────────────────
    // issue-local-017: returns THuntPackageRun[] (THRunSummary + each run's
    // phases/total_elapsed_s), needed for HuntDetail's compact all-runs
    // status table without a per-run extra fetch.
    listRuns: (pkgId: string) =>
      request<THuntPackageRun[]>(`/threat-hunting/packages/${encodeURIComponent(pkgId)}/runs`),
    getRunStatus: (pkgId: string, runId: string) =>
      request<THGenerationRecord>(
        `/threat-hunting/packages/${encodeURIComponent(pkgId)}/runs/${encodeURIComponent(runId)}/status`,
      ),
    approveRun: (pkgId: string, runId: string, notes = '') =>
      request<{ generation_status: string }>(
        `/threat-hunting/packages/${encodeURIComponent(pkgId)}/runs/${encodeURIComponent(runId)}/approve`,
        { method: 'POST', body: JSON.stringify({ notes }) },
      ),
    rejectRun: (pkgId: string, runId: string, notes = '') =>
      request<{ generation_status: string }>(
        `/threat-hunting/packages/${encodeURIComponent(pkgId)}/runs/${encodeURIComponent(runId)}/reject`,
        { method: 'POST', body: JSON.stringify({ notes }) },
      ),
    // issue-local-019: cancel a currently-running generation run.
    cancelRun: (pkgId: string, runId: string) =>
      request<{ generation_status: string }>(
        `/threat-hunting/packages/${encodeURIComponent(pkgId)}/runs/${encodeURIComponent(runId)}/cancel`,
        { method: 'POST' },
      ),
    listRunResults: (pkgId: string, runId: string) =>
      request<THTaskResult[]>(
        `/threat-hunting/packages/${encodeURIComponent(pkgId)}/runs/${encodeURIComponent(runId)}/results`,
      ),
    getRunReport: (pkgId: string, runId: string) =>
      request<THHuntReport>(
        `/threat-hunting/packages/${encodeURIComponent(pkgId)}/runs/${encodeURIComponent(runId)}/report`,
      ),
    generateRunReport: (pkgId: string, runId: string, body: { provider_name?: string | null; model_name?: string | null; report_formats?: { pdf: boolean; markdown: boolean } } = {}) =>
      request<THHuntReport>(
        `/threat-hunting/packages/${encodeURIComponent(pkgId)}/runs/${encodeURIComponent(runId)}/report`,
        { method: 'POST', body: JSON.stringify(body) },
      ),
    downloadRunReportMarkdown: (pkgId: string, runId: string) =>
      `${BASE}/threat-hunting/packages/${encodeURIComponent(pkgId)}/runs/${encodeURIComponent(runId)}/report/markdown`,
    downloadRunReportPdf: (pkgId: string, runId: string) =>
      `${BASE}/threat-hunting/packages/${encodeURIComponent(pkgId)}/runs/${encodeURIComponent(runId)}/report/pdf`,
    // issue-local-018: analyst comments on a specific run
    listRunComments: (pkgId: string, runId: string) =>
      request<THRunComment[]>(
        `/threat-hunting/packages/${encodeURIComponent(pkgId)}/runs/${encodeURIComponent(runId)}/comments`,
      ),
    createRunComment: (pkgId: string, runId: string, body: string) =>
      request<THRunComment>(
        `/threat-hunting/packages/${encodeURIComponent(pkgId)}/runs/${encodeURIComponent(runId)}/comments`,
        { method: 'POST', body: JSON.stringify({ body }) },
      ),
    deleteRunComment: (pkgId: string, runId: string, commentId: string) =>
      request<void>(
        `/threat-hunting/packages/${encodeURIComponent(pkgId)}/runs/${encodeURIComponent(runId)}/comments/${encodeURIComponent(commentId)}`,
        { method: 'DELETE' },
      ),

    // ── Threat Intelligence (issue-local-020) ────────────────────────────────
    getRunThreatIntel: (pkgId: string, runId: string) =>
      request<THThreatIntel>(
        `/threat-hunting/packages/${encodeURIComponent(pkgId)}/runs/${encodeURIComponent(runId)}/threat-intel`,
      ),
    getThreatIntel: (pkgId: string) =>
      request<THThreatIntel>(`/threat-hunting/packages/${encodeURIComponent(pkgId)}/threat-intel`),
    triggerRunThreatIntel: (pkgId: string, runId: string) =>
      request<THThreatIntel>(
        `/threat-hunting/packages/${encodeURIComponent(pkgId)}/runs/${encodeURIComponent(runId)}/threat-intel`,
        { method: 'POST' },
      ),

    // ── Comparison Module (issue-local-020) ──────────────────────────────────
    compareRuns: (
      pkgId: string,
      body: { provider_name?: string | null; model_name?: string | null; run_ids?: string[] } = {},
    ) =>
      request<THComparisonReport>(`/threat-hunting/packages/${encodeURIComponent(pkgId)}/compare`, {
        method: 'POST',
        body: JSON.stringify(body),
      }),
    getComparison: (pkgId: string) =>
      request<THComparisonReport>(`/threat-hunting/packages/${encodeURIComponent(pkgId)}/comparison`),
    downloadComparisonMarkdown: (pkgId: string) =>
      `${BASE}/threat-hunting/packages/${encodeURIComponent(pkgId)}/comparison/markdown`,
    downloadComparisonPdf: (pkgId: string) =>
      `${BASE}/threat-hunting/packages/${encodeURIComponent(pkgId)}/comparison/pdf`,

    // ── Threat Intel Tracking dashboard (issue-local-021) ────────────────────
    tracking: {
      getDashboard: (search?: string) => {
        const q = new URLSearchParams()
        if (search) q.set('search', search)
        const qs = q.toString()
        return request<THTrackingDashboard>(`/threat-hunting/tracking/dashboard${qs ? `?${qs}` : ''}`)
      },
      listHunts: () => request<THTrackingHunt[]>('/threat-hunting/tracking/hunts'),
      setHuntExcluded: (pkgId: string, excluded: boolean) =>
        request<THuntPackage>(
          `/threat-hunting/tracking/hunts/${encodeURIComponent(pkgId)}/exclude`,
          { method: 'POST', body: JSON.stringify({ excluded }) },
        ),
      deleteHunt: (pkgId: string) =>
        request<void>(`/threat-hunting/tracking/hunts/${encodeURIComponent(pkgId)}`, {
          method: 'DELETE',
        }),
    },
  },
}

// ── Smart mappings types ───────────────────────────────────────────────────

export type SmartProposalStatus = 'pending' | 'approved' | 'rejected' | 'error'

export type SmartProposalOutcome =
  | 'pending_review'
  | 'auto_applied'
  | 'discarded_below_threshold'
  | 'approved'
  | 'rejected'
  | 'error'

export type SmartTriggerReason = 'manual' | 'schedule' | 'on_new_feed'

// prompts-032: scope of raw fields presented to the LLM for a consolidated
// request. 'configured' = only fields enabled in feed-fields.yaml.
export type SmartFieldScope = 'all' | 'configured'

export interface SmartScoreBreakdown {
  coverage_before: number
  coverage_after: number
  coverage_delta: number
  raw_field_population?: Record<string, number>
}

export interface SmartDryRunRequest {
  source: string
  sample_size?: number
}

export interface SmartDryRunResponse {
  source: string
  sample_size: number
  raw_fields: string[]
  canonical_fields: string[]
  prompt_system: string
  prompt_user: string
}

export interface SmartJobRequest {
  // prompts-032: consolidated/global manual flow. One request → one proposal
  // spanning the selected feeds.
  sources: string[]
  provider?: string
  // prompts-034: optional per-proposal model override. When omitted the
  // provider's configured default model is used. prompts-036: the UI offers
  // each provider's DISCOVERED models (provider.available_models) — a green
  // Test Connection is no longer required.
  model?: string
  sample_size?: number
  field_scope?: SmartFieldScope
}

export interface SmartJobHandle {
  job_id: string
  sources: string[]
  field_scope: SmartFieldScope
  // prompts-034: echoes the chosen provider (null = configured default).
  provider?: string | null
  // prompts-034: echoes the clamped sample size used for the job.
  sample_size?: number
  // prompts-034: echoes the chosen model override (null = provider default).
  model?: string | null
  state: string
}

export interface SmartProposal {
  id: number
  source_name: string
  provider_name: string | null
  model: string | null
  sample_size: number
  raw_fields: string[]
  mapping: Record<string, string>
  prompt_system: string
  prompt_user: string
  llm_response_raw: string
  // prompts-037: raw LLM HTTP exchange for the error/detail card.
  // `llm_request_raw` is the full request (method/url/redacted headers/body);
  // `llm_response_json` is the WHOLE HTTP response envelope (not just the
  // extracted `llm_response_raw` content). Absent on pre-v6 rows.
  llm_request_raw?: string
  llm_response_json?: string
  status: SmartProposalStatus
  created_at: string
  decided_at: string | null
  decided_by_note: string | null
  // prompts-021E-3 / 021E-4 fields
  trigger_reason?: SmartTriggerReason
  score?: number | null
  score_breakdown?: SmartScoreBreakdown | null
  outcome?: SmartProposalOutcome
  auto_applied?: boolean
  // prompts-021G follow-up: id of the mapping_versions row produced by
  // approve / auto-apply. NULL/undefined for pending/rejected/discarded
  // proposals; the Activity tab uses this to deep-link to Mapping versions.
  mapping_version_id?: number | null
  // prompts-032: consolidated (multi-feed) proposals. source_name is the
  // sentinel "__consolidated__"; the real feed list lives in `sources`.
  sources?: string[]
  field_scope?: SmartFieldScope
  consolidated_version_id?: number | null
  // prompts-034: proposal lifecycle. `proposal_name` is a stable human-facing
  // label ("Proposal-<UTC timestamp>"); absent on pre-v5 rows (fall back to
  // a synthesised label). `archived` hides the row from default views.
  proposal_name?: string
  archived?: boolean
}

export interface SmartApproveRequest {
  note?: string
  set_mode_manual?: boolean
}

// prompts-032 Phase D: summary of the single active consolidated mapping,
// surfaced by GET /api/smart-mappings/active and rendered as the active card.
export interface ActiveConsolidatedMapping {
  id: number
  sources: string[]
  field_count: number
  field_scope: SmartFieldScope | null
  proposal_id: number | null
  proposal_name?: string | null
  created_at: string
  note: string | null
  // prompts-039: the full {raw_field: canonical} map, for the expanded card.
  mapping?: Record<string, string>
}

export interface SmartApproveResponse {
  proposal_id: number
  source: string
  added: Array<{ raw_field: string; canonical: string }>
  skipped_conflicts: Array<{
    raw_field: string
    existing_canonical: string
    proposal_canonical: string
  }>
  mode: string
  mode_changed: boolean
  hint?: string
  // prompts-021F additions
  mapping_version_id?: number
  reset_rows?: number
  auto_applied?: boolean
  outcome?: SmartProposalOutcome
}

export interface SmartRejectRequest {
  note?: string
}

// ── LLM provider types (prompts-021D-2, expanded in 022 step 5) ────────────

export type LLMProviderKind = 'openai' | 'anthropic' | 'ollama' | 'openai_compatible' | 'azure_ai_foundry'

/** Single entry from GET /api/app/agent-tools/catalog (issue-007). */
export interface ToolCatalogEntry {
  name: string
  label: string
  category: 'agent_tool' | 'document_parser'
  description: string
  used_by: string[]
  used_by_description: string
  implication_if_disabled: string
  /** Runtime availability (always true for agent tools; reflects pip install for marker). */
  available: boolean
}

/** issue-local-024 follow-up: one gitignored instance-config file's detected
 *  drift against its shipped .example template. Omitted entirely from the
 *  GET /api/app/config-drift response when it has none. */
export interface ConfigDriftReport {
  file: string
  missing_keys: string[]
  missing_core_fields: { name: string; description: string }[]
}

export interface LLMProvider {
  name: string
  kind: LLMProviderKind
  base_url?: string
  /**
   * Write-only. GET responses return "***" when a key is set, "" otherwise.
   * On PUT, send "***" to retain the stored key; any other string replaces it.
   * Never bind this directly to a visible input value.
   */
  api_key?: string
  model?: string
  timeout_seconds?: number
  max_retries?: number
  skip_tls_verify?: boolean
  /**
   * issue-local-022 follow-up: only meaningful when kind === 'azure_ai_foundry'.
   * 'unified' (default) is Azure's OpenAI-compatible Model Inference API;
   * 'anthropic' is the Anthropic-native passthrough mode for Claude models.
   * See AzureAIFoundryClient's docstring in backend/llm/client.py.
   */
  api_style?: 'unified' | 'anthropic'
  /**
   * prompts-027: persisted list of models last returned by the
   * "Discover Models" button on the persisted ProviderCard. Lets the
   * default-model dropdown render on first paint without forcing the
   * operator to click Discover every time the page loads. Not a secret;
   * never redacted. Absent / [] on legacy records.
   */
  available_models?: string[]
}

/**
 * Shape of the body accepted by POST /api/llm/providers and
 * PUT /api/llm/providers/{name} (022 step 4). Same fields as
 * :type:`LLMProvider`; named separately so call-sites can be explicit
 * about whether they hold a redacted-from-disk record or a
 * to-be-persisted request body.
 */
export type LLMProviderConfig = LLMProvider

export interface LLMConfig {
  enabled: boolean
  default_provider: string | null
  providers: LLMProvider[]
}

/**
 * Subset of LLMConfig accepted by PUT /api/llm/config after 022 step 4.
 * The providers list moved to dedicated CRUD endpoints; sending it here
 * is rejected by the backend with 400.
 */
export interface LLMConfigUpdate {
  enabled?: boolean
  default_provider?: string | null
}

export interface LLMProviderSummary {
  name: string
  kind: LLMProviderKind
  model: string | null
  has_api_key: boolean
  skip_tls_verify: boolean
  // prompts-034: models that have a successful Test Connection on record for
  // this provider. Still recorded on a green probe but, as of prompts-036, no
  // longer the proposal-dropdown source. Default [] on legacy records.
  tested_models?: string[]
  // prompts-036: discovered model catalog for this provider. Drives the
  // per-proposal model dropdown in Smart Mappings (a green Test is no longer
  // required — bad models surface at proposal request/response time). Default
  // [] on providers that have not been discovered yet.
  available_models?: string[]
}

/**
 * One row of the Test Connection transcript produced by
 * backend/llm/test_runner.run_provider_test. Rendered by the Test
 * Details modal (022 step 6). Every field is best-effort: a step that
 * never made it to the wire still has its label, error, and
 * duration_ms populated, but url/status_code may be null.
 */
export interface LLMTestStepDetail {
  step: string
  method: string | null
  url: string | null
  headers_redacted: Record<string, string> | null
  request_body: string | null
  status_code: number | null
  response_body: string | null
  duration_ms: number
  error: string | null
  // prompts-061: non-blocking advisory for a step that otherwise succeeded
  // (error === null). e.g. the model catalog was empty but the completion
  // probe passed. Optional for backward compatibility with older payloads.
  warning?: string | null
}

/**
 * Canonical Test Connection response shape returned by both
 * POST /api/llm/providers/{name}/test and POST /api/llm/providers/test
 * (022 step 4). Always 200 OK from the HTTP layer; aggregate failure
 * is signalled by `status === 'error'` and surfaced through `details[]`.
 */
export interface LLMTestRunResult {
  status: 'ok' | 'error'
  details: LLMTestStepDetail[]
  models: string[] | null
  sample: string | null
}

/**
 * prompts-027: response shape of POST /api/llm/providers/discover and
 * POST /api/llm/providers/{name}/discover. Same as
 * :type:`LLMTestRunResult` minus the ``sample`` field — discover does
 * NOT run the ``complete`` smoke probe.
 */
export interface LLMDiscoverResult {
  status: 'ok' | 'error'
  details: LLMTestStepDetail[]
  models: string[] | null
}

/**
 * issue_local_02: build a minimal LLMTestRunResult from a thrown error string
 * (network/4xx/5xx that never produced a structured payload) so the
 * "View test details" link + TestDetailsModal can open on error-only paths,
 * not just when the server returned a transcript. A single synthetic step
 * carries the error message.
 */
export function synthesizeErrorTestResult(
  error: string,
  step = 'test',
): LLMTestRunResult {
  return {
    status: 'error',
    details: [
      {
        step,
        method: null,
        url: null,
        headers_redacted: null,
        request_body: null,
        status_code: null,
        response_body: null,
        duration_ms: 0,
        error,
        warning: null,
      },
    ],
    models: null,
    sample: null,
  }
}

/**
 * Legacy Test Connection shape kept ONLY so existing call sites in
 * LLMProvidersTab + its tests keep compiling until Steps 6+7 swap them
 * over to :type:`LLMTestRunResult`. Do NOT use in new code.
 *
 * @deprecated 022 step 5 — replaced by LLMTestRunResult; will be
 * removed once the tab refactor in step 7 lands.
 */
export interface LLMTestResult {
  status: 'ok'
  method: 'list_models' | 'complete'
  models?: string[]
  sample?: string
}

// ── Mapping versions (prompts-021F) ────────────────────────────────────────

export type MappingVersionOrigin = 'migration' | 'proposal' | 'manual'

export interface MappingVersion {
  id: number
  source_name: string
  origin: MappingVersionOrigin
  source_proposal_id: number | null
  active: number | boolean
  created_at: string
  note: string | null
  mapping: Record<string, string>
}

export interface MappingVersionDiff {
  added: Array<{ raw_field: string; canonical: string }>
  removed: Array<{ raw_field: string; canonical: string }>
  changed: Array<{ raw_field: string; from: string; to: string }>
}

export interface MappingVersionDetail {
  version: MappingVersion
  active: MappingVersion | null
  diff: MappingVersionDiff
}

export interface MappingVersionActivateResponse {
  version_id: number
  source: string
  reset_rows: number
}

export interface MappingVersionDiffResponse {
  from: { id: number; source_name: string }
  to: { id: number; source_name: string }
  diff: MappingVersionDiff
}

// ── Watchers (issue_local_006) ─────────────────────────────────────────────

export type WatcherSeverity = 'low' | 'medium' | 'high' | 'critical'
export type WatcherDataset = 'all' | 'raw' | 'normalized'
export type WatcherMode = 'realtime' | 'scheduled'
export type WatcherFormat = 'json' | 'csv' | 'xml'
export type WatcherMatchType = 'exact' | 'wildcard' | 'regex' | 'gte' | 'lte' | 'contains'
export type WatcherPublishTarget = 'local' | 'webhook' | 'http'
export type WatcherWebhookFormat = 'generic' | 'discord' | 'slack' | 'teams'

export interface WatcherCondition {
  field: string
  value: string
  match_type: WatcherMatchType
  case_sensitive?: boolean
}

export interface DeliveryDetail {
  url?: string
  error_type?: string
  message?: string
  status?: number | null
  reason?: string | null
  headers?: Record<string, string> | null
  body?: string
}

export interface WatcherInput {
  name: string
  severity: WatcherSeverity
  dataset: WatcherDataset
  feeds: string[]
  conditions: WatcherCondition[]
  mode: WatcherMode
  interval_sec: number
  format: WatcherFormat
  max_feed_events: number
  cleanup_interval_sec: number
  enabled: boolean
  publish_target: WatcherPublishTarget
  webhook_url: string | null
  webhook_format: WatcherWebhookFormat
  auth_header: string | null
  auth_value: string | null
}

export interface Watcher extends WatcherInput {
  id: string
  trigger_count: number
  created_at: string
  updated_at: string
  last_triggered_at: string | null
  delivery_error_count: number
  last_delivery_error: string | null
  last_delivery_detail: DeliveryDetail | null
}

export interface WatcherEvent {
  id: number
  watcher_id: string
  dataset: string
  source_entry_id: number
  source_name: string | null
  triggered_at: string
  event: Record<string, unknown>
  delivery_status: 'ok' | 'error' | null
  delivery_error: string | null
  delivery_detail: DeliveryDetail | null
  delivered_at: string | null
}

export interface WatcherEventsPage {
  events: WatcherEvent[]
  total: number
}

export interface WatcherTriggerResult {
  evaluated: number
  triggered: number
  delivery: { delivered: number; failed: number }
}

// ── Threat Hunting (issue-local-002) ──────────────────────────────────────

export type THuntPackageStatus =
  | 'draft'
  | 'planning'
  | 'approved'
  | 'executing'
  | 'completed'
  | 'archived'

/** Phase summary entry (issue-006-D, widened in issue-007, issue-local-009). */
export interface THPhaseEntry {
  step: string
  /** issue-local-009: 'running' added for in-progress execution/report steps */
  status: 'ok' | 'error' | 'partial' | 'skipped' | 'unknown' | 'running'
  elapsed_s: number | null
  /** Tools the model invoked during this step (issue-007). */
  tools_used?: string[]
  /** Model's brief rationale / decision text (issue-007). */
  decision?: string
  /** Count of items produced (hypotheses, leads, queries, etc.) (issue-007). */
  item_count?: number
  /** IOC count (deep_retrohunt_planner) (issue-007). */
  ioc_count?: number
  /** Noisy IOC count (deep_retrohunt_planner) (issue-007). */
  noisy_count?: number
}

export interface THuntPackage {
  id: string
  name: string
  description: string
  status: THuntPackageStatus
  created_by: string | null
  created_at: string
  updated_at: string
  evidence_count: number
  /** Latest-run generation_status (issue-006-D). */
  generation_status?: string | null
  /** Per-step phase summary from the latest run (issue-006-D). */
  phases?: THPhaseEntry[] | null
  /** Total elapsed time across all steps of the latest run in seconds (issue-006-D). */
  total_elapsed_s?: number | null
  /** ISO timestamp when the latest run started — used for the live timer (issue-008-2A). */
  run_created_at?: string | null
  /** Every generation run for this package, newest first (issue-local-016). */
  runs?: THuntPackageRun[]
  /** Convenience count of `runs`. */
  run_count?: number
  /** issue-local-018: human-readable HuntID (e.g. "TH01"), computed
   *  dynamically from the configured prefix. Empty string if not yet backfilled. */
  hunt_id_display?: string
}

export interface THEvidenceItem {
  id: string
  hunt_package_id: string
  item_type: 'file' | 'url' | 'manual_text' | 'watcher_feed'
  label: string
  source_ref: string
  content_hash: string
  mime_type: string
  fetch_url: string
  final_url: string
  extracted_text: string
  parser_used: string
  parser_version: string
  /** issue-008-2B: 'pending' = URL registered but not yet fetched (fetch deferred to pipeline) */
  parse_status: 'ok' | 'partial' | 'error' | 'pending'
  parse_warnings: string[]
  fetch_metadata: Record<string, unknown>
  created_at: string
  provenance_notes: string
}

export interface THExtractedIOC {
  id: string
  evidence_item_id: string
  hunt_package_id: string
  /** issue-local-015: which run this IOC belongs to — each run's set is independent. */
  run_id?: string | null
  ioc: string
  ioc_type: string
  ioc_description: string
  noise_score: number
  flagged_noisy: boolean
  /** issue-local-015: keep/remove decision from this run's IOC active-cleaning config. */
  action?: 'keep' | 'remove'
  created_at: string
}

/** issue-local-015: per-run IOC handling config, sent when starting a run. */
export interface THIocRunConfig {
  ioc_mode: 'tagging_only' | 'active_cleaning'
  ioc_cleaning_options?: {
    remove_noisy?: boolean
    remove_legit_domains?: boolean
    remove_cdn_ranges?: boolean
    remove_legit_services?: boolean
  }
  /** issue-local-021: include the Threat Hunt Intelligence Analyst (both the
   *  preliminary and post-execution phases) in this run's workflow. */
  include_threat_intel?: boolean
}

/** Per-source intake metadata emitted by intake_classifier (issue-006-C / issue-local-011). */
export interface THIntakeSource {
  label: string
  item_type: string
  text_length: number
  /** Sub-status of this evidence source after file-parse in Part 1 (issue-local-011). */
  sub_status?: 'ok' | 'partial' | 'error' | 'pending'
  /** Which parser was used for this source (issue-local-011). */
  parser_used?: string
  /** Number of IOCs extracted from this source. */
  ioc_count?: number
}

export interface THStepLog {
  step: string
  /** issue-local-009: 'running' added for in-progress execution/report steps */
  status: 'ok' | 'error' | 'partial' | 'skipped' | 'running'
  elapsed_s: number
  item_count?: number
  ioc_count?: number
  noisy_count?: number
  effort?: string
  error?: string
  /** Debug log lines captured during this step. */
  debug_lines?: string[]
  /** Names of tools called during this step (issue-006-B/C). */
  tools_used?: string[]
  /** Brief decision/rationale string from the model (issue-006-B/C). */
  decision?: string
  /** Per-source intake metadata from intake_classifier (issue-006-C). */
  intake_sources?: THIntakeSource[]
}

/** Lightweight run summary returned by GET /packages/{id}/runs */
export interface THRunSummary {
  id: string
  hunt_package_id: string
  generation_status: string
  llm_provider?: string | null
  llm_model?: string | null
  research_effort?: string | null
  created_at: string
  /** issue-local-022 (item 3): 'running' while either Threat Intel Analyst
   *  phase (preliminary/final) is active for this run, else null/undefined —
   *  used to gate Re-run/report-generation so they don't race the analysis. */
  threat_intel_status?: string | null
  /** issue-local-026: username that triggered this specific run (null when
   *  auth is disabled, or for runs created before this field existed). */
  created_by?: string | null
}

/**
 * A run summary as returned inline on the hunt-package LIST endpoint
 * (issue-local-016) — extends THRunSummary with the phase data needed to
 * drive that run's stage rail when selected via a run chip. HuntDetail's
 * own lightweight run-selector dropdown keeps using plain THRunSummary
 * (it doesn't need per-run phases).
 */
export interface THuntPackageRun extends THRunSummary {
  phases?: THPhaseEntry[] | null
  total_elapsed_s?: number | null
  /** issue-local-017: post-action-filter IOC split (deep_retrohunt.sanitized_iocs),
   *  null when the run has no deep_retrohunt lead yet. */
  sanitized_ioc_count?: number | null
  removed_ioc_count?: number | null
  /** issue-local-017: whether a hunt_reports row exists for this run — drives
   *  the report-download links in the all-runs status table. */
  has_report?: boolean
  /** issue-local-018: human-readable Run ID (e.g. "TH01-X02"), prefixed by
   *  the owning package's HuntID. Named *_display (not run_id) to avoid
   *  colliding with THGenerationRecord.run_id, which carries the internal UUID. */
  run_id_display?: string
}

/** issue-local-018: an analyst's free-text note on a specific run. */
export interface THRunComment {
  id: string
  hunt_package_id: string
  run_id: string
  body: string
  created_by: string | null
  created_at: string
}

export interface THGenerationRecord {
  id?: string
  /** run_id — the hunting_packages row id for this specific run */
  run_id?: string
  hunt_package_id: string
  generation_status:
    | 'running'
    | 'awaiting_approval'
    | 'approved'
    | 'rejected'
    /** issue-local-009: SIEM execution phase */
    | 'executing'
    /** issue-local-009: report generation phase */
    | 'reporting'
    | 'completed'
    | 'error'
  is_running?: boolean
  provider_name?: string | null
  model_name?: string | null
  research_effort?: string | null
  /** Agent pipeline step currently executing (Phase 3 progress tracking). */
  current_step?: string | null
  /** Agent pipeline steps already completed (Phase 3 progress tracking). */
  completed_steps?: string[] | null
  /** Per-step telemetry (Phase 4+ verbosity). */
  step_logs?: THStepLog[] | null
  threat_context?: Record<string, unknown> | null
  hypotheses?: THHypothesis[] | null
  hunting_leads?: THHuntingLead[] | null
  /** Phase 4: Deep Retrohunt lead — IOC sanitization + SPL draft. */
  deep_retrohunt?: THDeepRetrohuntLead | null
  ttp_analysis?: THBehavioralTTPAnalysis | null
  query_drafts?: THQueryDraft[] | null
  generation_errors?: string[] | null
  created_at?: string
}

export interface THHypothesis {
  id: string
  title: string
  description: string
  justification: string
  relevance: 'high' | 'medium' | 'low'
  ioc_basis: string[]
  /** Specific detection tools/artifacts/query fragments (issue-006-E). */
  suggested_actions?: string[]
  /** issue-local-015: LLM-assessed confidence (0-100) this hypothesis is correct. */
  confidence?: number
  /** issue-local-015: analyst-set — excluded from further consideration/execution. */
  discarded?: boolean
}

export interface THHuntTask {
  id: string
  title: string
  description: string
  datasource: string
  query_hint: string
}

export interface THHuntingLead {
  id: string
  hypothesis_id: string
  title: string
  description: string
  priority: 'high' | 'medium' | 'low'
  tasks: THHuntTask[]
  /** issue-local-015: analyst-set — excluded from further consideration/execution. */
  discarded?: boolean
}

export interface THTTPTechnique {
  technique_id: string
  technique_name: string
  tactic: string
  description: string
  evidence_basis: string
}

export interface THBehavioralTTPAnalysis {
  summary: string
  techniques: THTTPTechnique[]
  detection_opportunities: string[]
}

export interface THQueryDraft {
  id: string
  language: 'spl' | 'kql' | 'eql' | 'cql' | 'es_dsl'
  title: string
  description: string
  query: string
  data_sources: string[]
  lead_id: string | null
}

// ── Phase 4: Deep Retrohunt types ────────────────────────────────────────────

export interface THSanitizedIOC {
  ioc: string
  ioc_type: string
  ioc_description: string
  noise_score: number       // 0.0–1.0; higher = noisier
  noise_reasons: string[]   // human-readable noise reasons
  search_token: string      // shortest SIEM-ready search token
  /** issue-local-015: this run's IOC active-cleaning decision. 'remove' items
   * are excluded from the SPL/CSV but stay visible here for audit. */
  action?: 'keep' | 'remove'
}

export interface THDeepRetrohuntLead {
  sanitized_iocs: THSanitizedIOC[]
  ioc_csv: string           // canonical CSV (ioc,ioc_type,ioc_description)
  total_ioc_count: number
  noisy_ioc_count: number   // noise_score >= 0.5
  high_noise_ioc_count: number  // noise_score >= 0.8
  spl_draft: string         // Splunk SPL macro draft
  spl_macro_name: string    // suggested macro name
  search_hint: string       // plain-language hunt scope
  analyst_notes: string     // LLM notes on sanitization
  llm_parse_error: boolean  // true if LLM enrichment failed
}

// ── Phase 5: SIEM connector + execution types ─────────────────────────────────

export interface THSiemConnector {
  id: string
  name: string
  kind: 'splunk'
  base_url: string
  auth_method: 'token' | 'username_password'
  config_json: string         // JSON — credentials masked as '***' on read
  verified: number            // 0 or 1
  created_at: string
  updated_at: string
}

export interface THConnectorCreateBody {
  name: string
  kind?: string
  base_url: string
  auth_method?: 'token' | 'username_password'
  api_token?: string | null
  username?: string | null
  password?: string | null
  verify_tls?: boolean
  default_index?: string
  retrohunt_macro?: string
}

export interface THConnectorTestResult {
  ok: boolean
  message: string
  server_info?: {
    version: string
    build: string
    server_name: string
    os_name: string
  } | null
}

export interface THTaskResult {
  id: string
  hunt_package_id: string
  run_id?: string | null
  task_type: string
  siem_connector: string
  query_text: string
  earliest: string
  latest: string
  hunt_id: string
  status: 'pending' | 'running' | 'completed' | 'failed'
  raw_result?: Record<string, unknown>[] | null
  interpreted_findings?: string | null
  confidence?: number | null
  created_at: string
  completed_at?: string | null
  is_running?: boolean
}

export interface THExecuteBody {
  connector_id: string
  spl: string
  earliest?: string
  latest?: string
  provider_name?: string | null
  model_name?: string | null
  run_id?: string | null
}

// ── Phase 6: Report types ─────────────────────────────────────────────────────

export interface THReportEvidenceSummary {
  total_items: number
  ioc_count: number
  item_types: string[]
}

export interface THReportRetrohuntSummary {
  total_iocs: number
  noisy_iocs: number
  high_noise_iocs: number
  spl_macro_name: string
  search_hint: string
}

export interface THReportExecutionResult {
  id: string
  status: string
  earliest: string
  latest: string
  event_count: number
  interpreted_findings: string
  completed_at: string
}

export interface THFullReport {
  executive_summary: string
  hunt_name: string
  hunt_id: string
  generated_at: string
  generated_by: string | null
  package_status: string
  evidence_summary: THReportEvidenceSummary
  threat_context: Record<string, unknown> | null
  hypotheses: THHypothesis[]
  hunting_leads: THHuntingLead[]
  deep_retrohunt_summary: THReportRetrohuntSummary | null
  ttp_analysis: THBehavioralTTPAnalysis | null
  query_drafts_count: number
  execution_results: THReportExecutionResult[]
  recommendations: string[]
  /** LLM-generated Findings/Conclusion section (issue-008-2C-C).
   *  More detailed than executive_summary; synthesizes key facts from the full hunt.
   *  Placed last in the report. null when generation failed or LLM is disabled. */
  findings?: string | null
}

export interface THHuntReport {
  id: string
  hunt_package_id: string
  run_id?: string | null
  executive_summary: string
  full_report: THFullReport
  created_at: string
  created_by: string | null
}

// ── Threat Intelligence (issue-local-020) ─────────────────────────────────────

export interface THThreatActor {
  name: string
  confidence: string
  rationale?: string
}

export interface THAttribution {
  assessment: string
  confidence: string
  rationale?: string
}

export interface THCampaign {
  name: string
  description?: string
}

export interface THRelatedVendorReport {
  vendor: string
  report?: string
  campaign?: string
}

export interface THCorrelatedIoc {
  ioc: string
  ioc_type: string
  hunt_package_id: string
  run_id?: string | null
  hunt_name: string
}

export interface THThreatIntel {
  id: string
  hunt_package_id: string
  run_id: string | null
  threat_actors: THThreatActor[]
  attribution: THAttribution | null
  malware_families: string[]
  campaigns: THCampaign[]
  related_vendors: THRelatedVendorReport[]
  correlated_iocs: THCorrelatedIoc[]
  summary: string
  full_analysis: Record<string, unknown>
  created_at: string
  created_by: string | null
}

// ── Comparison Module (issue-local-020) ────────────────────────────────────────
// Reuses THHuntReport's envelope shape; `full_report` here is a
// THComparisonFullReport rather than THFullReport (report_kind: "comparison").

export interface THComparisonDiffRow {
  run_id: string
  run_id_display: string
  model: string
  effort: string
  status: string
  hypothesis_count: number
  sanitized_ioc_count: number
  removed_ioc_count: number
  /** issue-local-026: sanitized_ioc_count + removed_ioc_count, computed
   *  server-side so it can't drift from the two counts it's derived from. */
  total_ioc_count: number
  technique_count: number
  event_count: number
  created_at: string
}

/** issue-local-026: one row per IOC per run that extracted it — the
 *  cross-run overview table in the Comparison tab. */
export interface THComparisonIocRow {
  ioc: string
  ioc_type: string
  run_id: string
  run_id_display: string
  model: string
  /** Derived from (1 - noise_score); null when unavailable. Not a
   *  model-reported confidence — see comparison_analyst.py docstring. */
  confidence_pct: number | null
  verdict: 'keep' | 'remove' | string
  hypotheses: string[]
}

export interface THComparisonFullReport {
  hunt_name: string
  hunt_id: string
  hunt_id_display: string
  compared_run_ids: string[]
  generated_at: string
  diff_table: THComparisonDiffRow[]
  ioc_overview: THComparisonIocRow[]
  summary: string
  key_differences: string[]
  gaps: string[]
  enrichment_opportunities: string[]
  recommended_combination: string
  report_kind?: string
}

export interface THComparisonReport {
  id: string
  hunt_package_id: string
  run_id: string | null
  executive_summary: string
  full_report: THComparisonFullReport
  created_at: string
  created_by: string | null
}

// ── Threat Intel Tracking dashboard (issue-local-021) ───────────────────────

/** A hunt package as an aggregated item's data-provenance source. */
export interface THTrackingSource {
  id: string
  name: string
  hunt_id_display: string
}

export interface THTrackingIoc {
  ioc: string
  ioc_type: string
  hunt_count: number
  hunt_packages: THTrackingSource[]
}

export interface THTrackingThreatActor {
  name: string
  confidence?: string
  rationale?: string
  sources: THTrackingSource[]
}

export interface THTrackingCampaign {
  name: string
  description?: string
  sources: THTrackingSource[]
}

export interface THTrackingMalwareFamily {
  name: string
  sources: THTrackingSource[]
}

export interface THTrackingTtp {
  technique_id: string
  technique_name: string
  tactic: string
  sources: THTrackingSource[]
}

export interface THTrackingDashboard {
  iocs: THTrackingIoc[]
  cves: THTrackingIoc[]
  threat_actors: THTrackingThreatActor[]
  campaigns: THTrackingCampaign[]
  malware_families: THTrackingMalwareFamily[]
  ttps: THTrackingTtp[]
}

export interface THTrackingHunt {
  id: string
  name: string
  hunt_id_display: string
  status: string
  excluded_from_correlation: boolean
  ioc_count: number
  has_threat_intel: boolean
}
