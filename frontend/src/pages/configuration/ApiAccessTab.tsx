/**
 * API Access tab (issue-local-029) — admin only.
 *
 * Lists existing API keys and provides a Create wizard: name -> scope
 * toggles (with "Use default profile" and "Select all" quick-picks) -> a
 * one-time reveal card (client ID, secret, endpoint) with copy-to-clipboard
 * and download-as-file. Also owns the "Programmatic API access" master
 * toggle (api_access_enabled) — deliberately its own narrower toggle, not
 * the main auth_enabled switch, since it only ever ADDS an alternative
 * credential type on top of whatever session/role auth already applies.
 *
 * Configuration only mounts this tab when authEnabled && isAdmin, the same
 * gating as User Management.
 */
import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { clsx } from 'clsx'
import {
  Trash2,
  Plus,
  X,
  Copy,
  Check,
  AlertTriangle,
  Download,
  FlaskConical,
} from 'lucide-react'
import { api, type ApiScope, type CreatedApiKey } from '../../api/client'
import Toggle from '../../components/Toggle'

const KEYS_QUERY = ['api-keys'] as const
const SCOPES_QUERY = ['api-key-scopes'] as const
const CONFIG_QUERY = ['api-access-config'] as const

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err)
}

export default function ApiAccessTab() {
  const qc = useQueryClient()
  const [actionError, setActionError] = useState<string | null>(null)
  const [showCreate, setShowCreate] = useState(false)
  const [confirmDeleteId, setConfirmDeleteId] = useState<string | null>(null)
  const [testResult, setTestResult] = useState<
    { clientId: string; status: string; detail: string } | null
  >(null)

  const { data: config } = useQuery({ queryKey: CONFIG_QUERY, queryFn: api.auth.getApiAccessConfig })
  const { data: keys = [], isLoading } = useQuery({ queryKey: KEYS_QUERY, queryFn: api.auth.listApiKeys })
  const { data: scopesData } = useQuery({ queryKey: SCOPES_QUERY, queryFn: api.auth.listApiKeyScopes })

  const invalidateKeys = () => qc.invalidateQueries({ queryKey: KEYS_QUERY })

  const configMut = useMutation({
    mutationFn: (enabled: boolean) => api.auth.setApiAccessConfig(enabled),
    onSuccess: () => qc.invalidateQueries({ queryKey: CONFIG_QUERY }),
  })
  const enabledMut = useMutation({
    mutationFn: ({ clientId, enabled }: { clientId: string; enabled: boolean }) =>
      api.auth.updateApiKey(clientId, { enabled }),
    onSuccess: () => { setActionError(null); invalidateKeys() },
    onError: (e) => setActionError(errorMessage(e)),
  })
  const deleteMut = useMutation({
    mutationFn: (clientId: string) => api.auth.deleteApiKey(clientId),
    onSuccess: () => { setActionError(null); setConfirmDeleteId(null); invalidateKeys() },
    onError: (e) => { setConfirmDeleteId(null); setActionError(errorMessage(e)) },
  })
  const testMut = useMutation({
    mutationFn: (clientId: string) => api.auth.testApiKey(clientId),
    onSuccess: (r, clientId) => setTestResult({ clientId, status: r.status, detail: r.detail }),
    onError: (e, clientId) => setTestResult({ clientId, status: 'error', detail: errorMessage(e) }),
  })

  if (isLoading) return <div className="text-sm text-gray-500">Loading…</div>

  return (
    <div className="card space-y-5">
      <div>
        <h3 className="text-sm font-semibold text-gray-200">API Access</h3>
        <p className="text-xs text-gray-500 mt-1">
          Generate API keys for programmatic access to the Threat Hunting API, each scoped to
          only the capabilities it's granted. Keys never reach configuration or user-management
          endpoints, regardless of scope.
        </p>
      </div>

      <div className="flex items-center justify-between rounded-lg border border-gray-700 bg-gray-800/50 px-3 py-2.5">
        <div>
          <p className="text-sm text-gray-200">Programmatic API access</p>
          <p className="text-xs text-gray-500">
            When off, API keys are never accepted — only the session cookie authenticates,
            regardless of any keys below.
          </p>
        </div>
        <Toggle
          checked={config?.enabled ?? false}
          disabled={configMut.isPending}
          onChange={(enabled) => configMut.mutate(enabled)}
        />
      </div>

      {actionError !== null && (
        <p role="alert" className="text-xs text-red-400">{actionError}</p>
      )}

      <div className="space-y-2">
        {keys.length === 0 && (
          <p className="text-xs text-gray-500 italic">No API keys yet.</p>
        )}
        {keys.map((k) => {
          const armed = confirmDeleteId === k.client_id
          const testing = testMut.isPending && testMut.variables === k.client_id
          const result = testResult?.clientId === k.client_id ? testResult : null
          return (
            <div key={k.client_id} className="rounded-lg border border-gray-700 bg-gray-800/50">
              <div className="flex items-center gap-3 px-3 py-2.5">
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-gray-200 truncate">{k.name}</p>
                  <p className="text-xs text-gray-500 font-mono truncate">{k.client_id}</p>
                  <p className="text-[10px] text-gray-600 mt-0.5">
                    {k.scopes.length} scope{k.scopes.length === 1 ? '' : 's'} ·{' '}
                    {k.last_used_at
                      ? `last used ${k.last_used_at.slice(0, 19).replace('T', ' ')}`
                      : 'never used'}
                  </p>
                </div>
                <Toggle
                  checked={k.enabled}
                  disabled={enabledMut.isPending}
                  onChange={(enabled) => enabledMut.mutate({ clientId: k.client_id, enabled })}
                />
                <button
                  className="btn-ghost p-1"
                  title="Test key"
                  disabled={testing}
                  onClick={() => testMut.mutate(k.client_id)}
                >
                  <FlaskConical className="w-3.5 h-3.5" />
                </button>
                <button
                  className="btn-ghost p-1 text-red-400 hover:text-red-300"
                  title="Delete key"
                  onClick={() => { setActionError(null); setConfirmDeleteId(k.client_id) }}
                >
                  <Trash2 className="w-3.5 h-3.5" />
                </button>
              </div>

              {result && (
                <div
                  className={clsx(
                    'border-t px-3 py-2 text-xs',
                    result.status === 'ok' && 'border-green-800/40 text-green-400',
                    result.status === 'warning' && 'border-amber-800/40 text-amber-400',
                    result.status === 'error' && 'border-red-800/40 text-red-400',
                  )}
                >
                  {result.detail}
                </div>
              )}

              {armed && (
                <div
                  className="border-t border-red-500/40 bg-red-500/5 rounded-b-lg px-3 py-2.5 space-y-2"
                  role="alertdialog"
                  aria-label={`Confirm delete ${k.name}`}
                >
                  <p className="text-xs text-gray-200">
                    Delete API key "<span className="font-mono">{k.name}</span>"? Any client using
                    it will immediately stop working. This cannot be undone.
                  </p>
                  <div className="flex items-center gap-2">
                    <button
                      className="btn-danger flex items-center gap-1.5"
                      onClick={() => deleteMut.mutate(k.client_id)}
                      disabled={deleteMut.isPending}
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                      {deleteMut.isPending ? 'Deleting…' : 'Confirm delete'}
                    </button>
                    <button
                      className="btn-secondary"
                      onClick={() => setConfirmDeleteId(null)}
                      disabled={deleteMut.isPending}
                    >
                      Cancel
                    </button>
                  </div>
                </div>
              )}
            </div>
          )
        })}
      </div>

      {!showCreate ? (
        <button className="btn-secondary w-full justify-center" onClick={() => setShowCreate(true)}>
          <Plus className="w-3.5 h-3.5" /> Create API Key
        </button>
      ) : (
        <CreateApiKeyWizard
          scopes={scopesData?.scopes ?? []}
          defaultProfile={scopesData?.default_profile ?? []}
          onClose={() => setShowCreate(false)}
          onCreated={invalidateKeys}
        />
      )}
    </div>
  )
}

// ── Create wizard ────────────────────────────────────────────────────────────

function CreateApiKeyWizard({
  scopes,
  defaultProfile,
  onClose,
  onCreated,
}: {
  scopes: ApiScope[]
  defaultProfile: string[]
  onClose: () => void
  onCreated: () => void
}) {
  const [name, setName] = useState('')
  const [selected, setSelected] = useState<Set<string>>(new Set())

  const mutation = useMutation({
    mutationFn: () => api.auth.createApiKey(name.trim(), Array.from(selected)),
    onSuccess: () => onCreated(),
  })

  const allSelected = scopes.length > 0 && scopes.every((s) => selected.has(s.id))

  function toggleScope(id: string) {
    setSelected((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  function selectAll() {
    setSelected(allSelected ? new Set() : new Set(scopes.map((s) => s.id)))
  }

  function useDefaultProfile() {
    setSelected(new Set(defaultProfile))
  }

  // Result card — the ONLY time client_id/secret/endpoint are shown together.
  if (mutation.data !== undefined) {
    return <CreatedApiKeyCard created={mutation.data} onDone={onClose} />
  }

  const canSubmit = name.trim() !== '' && selected.size > 0 && !mutation.isPending

  return (
    <div className="rounded-lg border border-brand-700/40 bg-brand-900/10 p-3 space-y-3">
      <div className="flex items-center justify-between">
        <p className="text-sm font-medium text-gray-300">New API key</p>
        <button className="btn-ghost p-1" onClick={onClose}>
          <X className="w-3.5 h-3.5" />
        </button>
      </div>

      <div>
        <label htmlFor="new-api-key-name" className="label">Name</label>
        <input
          id="new-api-key-name"
          className="input"
          placeholder="CI pipeline"
          value={name}
          onChange={(e) => setName(e.target.value)}
        />
      </div>

      <div className="flex items-center justify-between">
        <label className="label !mb-0">Endpoint access</label>
        <div className="flex items-center gap-2">
          <button type="button" className="text-xs text-brand-400 hover:underline" onClick={useDefaultProfile}>
            Use default profile
          </button>
          <span className="text-gray-700">·</span>
          <button type="button" className="text-xs text-brand-400 hover:underline" onClick={selectAll}>
            {allSelected ? 'Deselect all' : 'Select all'}
          </button>
        </div>
      </div>

      <div className="space-y-1.5 max-h-64 overflow-y-auto pr-1">
        {scopes.map((s) => (
          <label
            key={s.id}
            className="flex items-start gap-2 rounded border border-gray-700/60 bg-gray-900/40 px-2.5 py-1.5 cursor-pointer hover:border-gray-600"
          >
            <input
              type="checkbox"
              className="mt-0.5"
              checked={selected.has(s.id)}
              onChange={() => toggleScope(s.id)}
            />
            <span>
              <span className="block text-xs font-medium text-gray-200">{s.label}</span>
              <span className="block text-[11px] text-gray-500">{s.description}</span>
            </span>
          </label>
        ))}
      </div>

      {mutation.isError && (
        <p role="alert" className="text-xs text-red-400">{errorMessage(mutation.error)}</p>
      )}

      <div className="flex justify-end gap-2">
        <button className="btn-ghost" onClick={onClose}>
          <X className="w-3.5 h-3.5" /> Cancel
        </button>
        <button className="btn-primary" disabled={!canSubmit} onClick={() => mutation.mutate()}>
          <Plus className="w-3.5 h-3.5" />
          {mutation.isPending ? 'Creating…' : 'Create'}
        </button>
      </div>
    </div>
  )
}

// ── One-time secret reveal card ─────────────────────────────────────────────

function CreatedApiKeyCard({ created, onDone }: { created: CreatedApiKey; onDone: () => void }) {
  const [copied, setCopied] = useState<string | null>(null)

  async function copy(label: string, value: string) {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(value)
      setCopied(label)
      setTimeout(() => setCopied((c) => (c === label ? null : c)), 2000)
    }
  }

  function downloadAsFile() {
    const content = [
      `Client ID: ${created.client_id}`,
      `API Key:   ${created.api_key}`,
      `Endpoint:  ${created.endpoint}`,
      '',
      `Send as:   Authorization: Bearer ${created.api_key}`,
      '',
      `Scopes:    ${created.scopes.join(', ') || '(none)'}`,
    ].join('\n')
    const blob = new Blob([content], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `api-${created.client_id}.txt`
    a.click()
    URL.revokeObjectURL(url)
  }

  const fields: { label: string; value: string }[] = [
    { label: 'Client ID', value: created.client_id },
    { label: 'API Key', value: created.api_key },
    { label: 'Endpoint', value: created.endpoint },
  ]

  return (
    <div className="rounded-lg border border-brand-700/40 bg-brand-900/10 p-3 space-y-3">
      <p className="text-sm font-medium text-gray-300">
        API key created — <span className="font-mono">{created.name}</span>
      </p>

      <div className="rounded-lg border border-amber-700/40 bg-amber-900/10 p-2.5 flex gap-2">
        <AlertTriangle className="w-3.5 h-3.5 text-amber-400 shrink-0 mt-0.5" />
        <p className="text-xs text-amber-300">
          The API key is shown only once — copy or download it now. It cannot be retrieved again;
          if it's lost, delete this key and create a new one.
        </p>
      </div>

      <div className="space-y-2">
        {fields.map((f) => (
          <div key={f.label}>
            <label className="label">{f.label}</label>
            <div className="flex items-center gap-2">
              <input
                readOnly
                aria-label={f.label}
                className="input font-mono flex-1 text-xs"
                value={f.value}
                onFocus={(e) => e.currentTarget.select()}
              />
              <button
                className="btn-secondary p-2"
                title={`Copy ${f.label}`}
                onClick={() => copy(f.label, f.value)}
              >
                {copied === f.label ? (
                  <Check className="w-3.5 h-3.5 text-green-400" />
                ) : (
                  <Copy className="w-3.5 h-3.5" />
                )}
              </button>
            </div>
          </div>
        ))}
      </div>

      <p className="text-xs text-gray-500">
        Granted: {created.scopes.length > 0 ? created.scopes.join(', ') : '(no scopes — this key cannot access anything)'}
      </p>

      <div className="flex justify-between items-center">
        <button className="btn-secondary text-xs" onClick={downloadAsFile}>
          <Download className="w-3.5 h-3.5" /> Download as file
        </button>
        <button className="btn-primary text-xs" onClick={onDone}>Done</button>
      </div>
    </div>
  )
}
