/**
 * SSO / OIDC Configuration tab (issue-local-010).
 *
 * Admin-only tab in Configuration → General → SSO.
 *
 * Provides:
 *  - Enable/disable SSO toggle
 *  - Provider preset selector (Entra, Okta, Google, Keycloak, Generic)
 *  - Issuer URL (with Entra tenant-ID shortcut field)
 *  - Client ID + Client Secret (write-only masked input)
 *  - Scopes, button label, username/role claim
 *  - Role mapping editor (claim value → app role rows)
 *  - Default role selector
 *  - Auto-provision toggle
 *  - Read-only Callback URL with copy-to-clipboard button
 */
import { useState, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Copy, Check, Plus, Trash2, Loader2, Wand2 } from 'lucide-react'
import { clsx } from 'clsx'
import { api, type SsoConfig } from '../../api/client'
import { getAppBasePrefix } from '../../utils/basePrefix'

type UserRole = 'admin' | 'threat-researcher' | 'threat-viewer' | 'feed-sender'

const ROLE_OPTIONS: { value: UserRole; label: string }[] = [
  { value: 'admin',             label: 'Admin' },
  { value: 'threat-researcher', label: 'Threat Researcher' },
  { value: 'threat-viewer',     label: 'Threat Viewer' },
  { value: 'feed-sender',       label: 'Feed Sender' },
]

const PRESET_OPTIONS = [
  { value: 'entra',    label: 'Microsoft Entra ID (Azure AD)' },
  { value: 'okta',     label: 'Okta' },
  { value: 'google',   label: 'Google Workspace' },
  { value: 'keycloak', label: 'Keycloak' },
  { value: 'generic',  label: 'Generic OIDC' },
] as const

const PRESET_ISSUER_HINTS: Partial<Record<string, string>> = {
  entra:    'https://login.microsoftonline.com/<your-tenant-id>/v2.0',
  okta:     'https://your-org.okta.com',
  google:   'https://accounts.google.com',
  keycloak: 'https://your-keycloak/realms/your-realm',
  generic:  'https://your-idp.example.com',
}

const _EMPTY: SsoConfig = {
  enabled: false,
  provider_preset: 'generic',
  issuer: '',
  client_id: '',
  client_secret: '',
  scopes: 'openid profile email',
  button_label: 'Sign in with SSO',
  username_claim: 'preferred_username',
  role_claim: 'roles',
  role_mapping: {},
  default_role: 'threat-viewer',
  auto_provision: true,
  callback_base_url: '',
}

/** issue-local-036: same client-side alias-detection already used for the
 *  Push Listener endpoint display (Configuration.tsx's ListenerTab) — the
 *  browser's own URL is the only place this can be reliably inferred from
 *  when app_base_prefix isn't set. */
function detectedCallbackBaseUrl(): string {
  return `${window.location.origin}${getAppBasePrefix()}`
}

export default function SsoConfigTab() {
  const qc = useQueryClient()

  const { data: savedCfg, isLoading } = useQuery({
    queryKey: ['sso-config'],
    queryFn: api.auth.getSsoConfig,
  })

  const { data: callbackData } = useQuery({
    queryKey: ['sso-callback-url'],
    queryFn: api.auth.getSsoCallbackUrl,
  })

  const [form, setForm] = useState<SsoConfig>(_EMPTY)
  const [roleRows, setRoleRows] = useState<{ claim: string; role: string }[]>([])
  const [saved, setSaved] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)
  const [secretDirty, setSecretDirty] = useState(false)

  // Populate form from fetched config
  useEffect(() => {
    if (!savedCfg) return
    setForm(savedCfg)
    setRoleRows(
      Object.entries(savedCfg.role_mapping ?? {}).map(([claim, role]) => ({ claim, role }))
    )
    setSecretDirty(false)
  }, [savedCfg])

  const saveMut = useMutation({
    mutationFn: (cfg: Partial<SsoConfig>) => api.auth.updateSsoConfig(cfg),
    onSuccess: (updated) => {
      qc.setQueryData(['sso-config'], updated)
      setSaved(true)
      setError(null)
      setSecretDirty(false)
      setTimeout(() => setSaved(false), 2500)
    },
    onError: (err) => {
      setError(err instanceof Error ? err.message : 'Save failed')
    },
  })

  function handleSave() {
    const role_mapping: Record<string, string> = {}
    for (const row of roleRows) {
      if (row.claim.trim() && row.role) {
        role_mapping[row.claim.trim()] = row.role
      }
    }
    const payload: Partial<SsoConfig> = {
      ...form,
      role_mapping,
      // If secret field not touched, send sentinel to preserve existing
      client_secret: secretDirty ? form.client_secret : '***',
    }
    saveMut.mutate(payload)
  }

  function setField<K extends keyof SsoConfig>(key: K, val: SsoConfig[K]) {
    setForm((f) => ({ ...f, [key]: val }))
    setSaved(false)
    setError(null)
  }

  function handlePresetChange(preset: string) {
    const hint = PRESET_ISSUER_HINTS[preset] ?? ''
    setForm((f) => ({
      ...f,
      provider_preset: preset as SsoConfig['provider_preset'],
      issuer: f.issuer || hint,
      button_label:
        preset === 'entra' ? 'Sign in with Microsoft'
        : preset === 'google' ? 'Sign in with Google'
        : preset === 'okta' ? 'Sign in with Okta'
        : preset === 'keycloak' ? 'Sign in with Keycloak'
        : 'Sign in with SSO',
    }))
  }

  function handleCopyCallback() {
    if (!callbackData?.callback_url) return
    navigator.clipboard.writeText(callbackData.callback_url).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    })
  }

  if (isLoading) {
    return <p className="text-sm text-gray-500">Loading SSO configuration…</p>
  }

  const callbackUrl = callbackData?.callback_url ?? ''

  return (
    <div className="space-y-8">
      {/* ── Callback URL (top — most important for setup) ── */}
      <div className="card space-y-3">
        <h2 className="text-sm font-semibold text-gray-200">Redirect / Callback URL</h2>
        <p className="text-xs text-gray-500">
          Register this URL as a <strong>Web Redirect URI</strong> in your identity provider
          (Entra app registration, Okta application, etc.).
        </p>
        <div className="flex items-center gap-2">
          <code className="flex-1 text-xs font-mono bg-gray-800 text-brand-300 px-3 py-2 rounded border border-gray-700 break-all">
            {callbackUrl || '(save config to compute URL)'}
          </code>
          {callbackUrl && (
            <button
              type="button"
              className="btn-ghost p-2 shrink-0"
              title="Copy callback URL"
              onClick={handleCopyCallback}
            >
              {copied ? (
                <Check className="w-4 h-4 text-green-400" />
              ) : (
                <Copy className="w-4 h-4 text-gray-400" />
              )}
            </button>
          )}
        </div>

        {/* issue-local-036: override for reverse-proxy-alias deployments —
            the URL above is derived from the CURRENT request and won't
            include an alias segment (e.g. /tars) unless either this field
            or app_base_prefix is set; app_base_prefix isn't always safe to
            set (can affect static asset routing under some proxy setups),
            so this is independent of it. */}
        <div className="pt-2 border-t border-gray-800 space-y-1.5">
          <label className="block text-xs text-gray-400">
            Callback Base URL Override <span className="text-gray-600">(optional)</span>
          </label>
          <p className="text-xs text-gray-500">
            Set this if the app is reachable through a reverse-proxy alias (e.g.{' '}
            <code className="text-gray-400">https://host/tars</code>) — the callback URL above
            won't include the alias otherwise, and the IdP will reject the login redirect.
          </p>
          <div className="flex items-center gap-2">
            <input
              type="text"
              className="input flex-1 text-xs font-mono"
              placeholder={detectedCallbackBaseUrl()}
              value={form.callback_base_url}
              onChange={(e) => setField('callback_base_url', e.target.value.trim())}
            />
            <button
              type="button"
              className="btn-ghost p-2 shrink-0 flex items-center gap-1 text-xs text-gray-400 hover:text-gray-200"
              title="Fill with the alias detected from this browser's own URL"
              onClick={() => setField('callback_base_url', detectedCallbackBaseUrl())}
            >
              <Wand2 className="w-3.5 h-3.5" />
              Use detected
            </button>
          </div>
          <p className="text-[11px] text-gray-600">
            Detected from this browser: <code>{detectedCallbackBaseUrl()}</code>. Leave blank to
            keep deriving the callback URL from each request (correct if there's no alias).
          </p>
        </div>
      </div>

      {/* ── Enable + preset ── */}
      <div className="card space-y-4">
        <h2 className="text-sm font-semibold text-gray-200">SSO Provider</h2>

        <div className="flex items-center justify-between">
          <div>
            <p className="text-sm text-gray-300">Enable SSO</p>
            <p className="text-xs text-gray-500">Show the SSO button on the login page.</p>
          </div>
          <button
            type="button"
            onClick={() => setField('enabled', !form.enabled)}
            className={clsx(
              'relative inline-flex h-6 w-11 items-center rounded-full transition-colors',
              form.enabled ? 'bg-brand-600' : 'bg-gray-700',
            )}
          >
            <span
              className={clsx(
                'inline-block h-4 w-4 transform rounded-full bg-white transition-transform',
                form.enabled ? 'translate-x-6' : 'translate-x-1',
              )}
            />
          </button>
        </div>

        <div>
          <label className="label">Provider</label>
          <select
            className="input"
            value={form.provider_preset}
            onChange={(e) => handlePresetChange(e.target.value)}
          >
            {PRESET_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>{o.label}</option>
            ))}
          </select>
        </div>

        <div>
          <label className="label">
            Issuer URL
            {form.provider_preset === 'entra' && (
              <span className="text-gray-500 font-normal ml-1">
                — replace &lt;your-tenant-id&gt; with your Directory (tenant) ID
              </span>
            )}
          </label>
          <input
            className="input font-mono text-xs"
            type="url"
            placeholder={PRESET_ISSUER_HINTS[form.provider_preset] ?? 'https://'}
            value={form.issuer}
            onChange={(e) => setField('issuer', e.target.value)}
          />
          <p className="text-[11px] text-gray-600 mt-0.5">
            Must point to an OIDC provider with a{' '}
            <code className="text-gray-500">/.well-known/openid-configuration</code> endpoint.
          </p>
        </div>
      </div>

      {/* ── Credentials ── */}
      <div className="card space-y-4">
        <h2 className="text-sm font-semibold text-gray-200">Client Credentials</h2>

        <div>
          <label className="label">Client ID</label>
          <input
            className="input font-mono text-xs"
            type="text"
            placeholder="e.g. 12345678-abcd-efgh-ijkl-000000000000"
            value={form.client_id}
            onChange={(e) => setField('client_id', e.target.value)}
          />
        </div>

        <div>
          <label className="label">
            Client Secret
            <span className="text-gray-500 font-normal ml-1">(write-only — masked after save)</span>
          </label>
          <input
            className="input font-mono text-xs"
            type="password"
            autoComplete="new-password"
            placeholder={secretDirty ? '' : '••••••••  (unchanged)'}
            value={secretDirty ? form.client_secret : ''}
            onChange={(e) => {
              setSecretDirty(true)
              setField('client_secret', e.target.value)
            }}
          />
        </div>

        <div>
          <label className="label">Scopes</label>
          <input
            className="input"
            type="text"
            value={form.scopes}
            onChange={(e) => setField('scopes', e.target.value)}
          />
        </div>

        <div>
          <label className="label">Login Button Label</label>
          <input
            className="input"
            type="text"
            placeholder="Sign in with SSO"
            value={form.button_label}
            onChange={(e) => setField('button_label', e.target.value)}
          />
        </div>
      </div>

      {/* ── Claims + role mapping ── */}
      <div className="card space-y-4">
        <h2 className="text-sm font-semibold text-gray-200">Claims & Role Mapping</h2>

        <div>
          <label className="label">Username Claim</label>
          <input
            className="input"
            type="text"
            placeholder="preferred_username"
            value={form.username_claim}
            onChange={(e) => setField('username_claim', e.target.value)}
          />
          <p className="text-[11px] text-gray-600 mt-0.5">
            JWT claim used as the OpenTARS username. Common values:{' '}
            <code className="text-gray-500">preferred_username</code>,{' '}
            <code className="text-gray-500">email</code>,{' '}
            <code className="text-gray-500">upn</code>.
          </p>
        </div>

        <div>
          <label className="label">Role Claim</label>
          <input
            className="input"
            type="text"
            placeholder="roles"
            value={form.role_claim}
            onChange={(e) => setField('role_claim', e.target.value)}
          />
          <p className="text-[11px] text-gray-600 mt-0.5">
            JWT claim that carries group/role names. Entra App Roles: <code className="text-gray-500">roles</code>.
            Entra group claims: <code className="text-gray-500">groups</code> (returns GUIDs).
          </p>
        </div>

        <div>
          <label className="label">Role Mapping</label>
          <p className="text-[11px] text-gray-500 mb-2">
            Map claim values to OpenTARS roles. Unmapped users get the default role below.
          </p>
          <div className="space-y-2">
            {roleRows.map((row, i) => (
              <div key={i} className="flex items-center gap-2">
                <input
                  className="input flex-1 text-xs font-mono"
                  type="text"
                  placeholder="Claim value (e.g. OpenTARS-Admin)"
                  value={row.claim}
                  onChange={(e) => {
                    const next = [...roleRows]
                    next[i] = { ...next[i], claim: e.target.value }
                    setRoleRows(next)
                    setSaved(false)
                  }}
                />
                <span className="text-gray-600 text-xs shrink-0">→</span>
                <select
                  className="input text-xs w-44 shrink-0"
                  value={row.role}
                  onChange={(e) => {
                    const next = [...roleRows]
                    next[i] = { ...next[i], role: e.target.value }
                    setRoleRows(next)
                    setSaved(false)
                  }}
                >
                  {ROLE_OPTIONS.map((o) => (
                    <option key={o.value} value={o.value}>{o.label}</option>
                  ))}
                </select>
                <button
                  type="button"
                  className="btn-ghost p-1.5 text-gray-600 hover:text-red-400 shrink-0"
                  onClick={() => setRoleRows(roleRows.filter((_, j) => j !== i))}
                >
                  <Trash2 className="w-3.5 h-3.5" />
                </button>
              </div>
            ))}
          </div>
          <button
            type="button"
            className="btn-ghost text-xs mt-2 flex items-center gap-1 text-gray-400"
            onClick={() => setRoleRows([...roleRows, { claim: '', role: 'threat-viewer' }])}
          >
            <Plus className="w-3.5 h-3.5" /> Add mapping
          </button>
        </div>

        <div>
          <label className="label">Default Role</label>
          <select
            className="input"
            value={form.default_role}
            onChange={(e) => setField('default_role', e.target.value)}
          >
            {ROLE_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>{o.label}</option>
            ))}
          </select>
          <p className="text-[11px] text-gray-600 mt-0.5">
            Applied when a user's claims don't match any mapping row above.
          </p>
        </div>

        <div className="flex items-center justify-between">
          <div>
            <p className="text-sm text-gray-300">Auto-provision accounts</p>
            <p className="text-xs text-gray-500">
              Create an OpenTARS account on first SSO login. Disable to require
              manual account creation before SSO login is allowed.
            </p>
          </div>
          <button
            type="button"
            onClick={() => setField('auto_provision', !form.auto_provision)}
            className={clsx(
              'relative inline-flex h-6 w-11 items-center rounded-full transition-colors',
              form.auto_provision ? 'bg-brand-600' : 'bg-gray-700',
            )}
          >
            <span
              className={clsx(
                'inline-block h-4 w-4 transform rounded-full bg-white transition-transform',
                form.auto_provision ? 'translate-x-6' : 'translate-x-1',
              )}
            />
          </button>
        </div>
      </div>

      {/* ── Save ── */}
      <div className="flex items-center gap-3">
        <button
          type="button"
          className="btn-primary flex items-center gap-2"
          onClick={handleSave}
          disabled={saveMut.isPending}
        >
          {saveMut.isPending && <Loader2 className="w-4 h-4 animate-spin" />}
          {saved ? <Check className="w-4 h-4" /> : null}
          {saveMut.isPending ? 'Saving…' : saved ? 'Saved' : 'Save SSO Configuration'}
        </button>
        {error && <p className="text-xs text-red-400">{error}</p>}
      </div>

      {/* ── Help ── */}
      <div className="card bg-gray-900/30 space-y-2 text-xs text-gray-500">
        <p className="font-semibold text-gray-400">Quick setup guide</p>
        <ol className="list-decimal list-inside space-y-1">
          <li>Register the Callback URL above as a <strong>Web Redirect URI</strong> in your IdP.</li>
          <li>Enter your Issuer URL, Client ID, and Client Secret (SPN secret).</li>
          <li>Configure role mapping so users get the right permissions on login.</li>
          <li>Enable SSO and save — the login page will show the SSO button immediately.</li>
        </ol>
        <p className="pt-1">
          The local admin account always works as a break-glass path regardless of SSO status.
        </p>
      </div>
    </div>
  )
}
