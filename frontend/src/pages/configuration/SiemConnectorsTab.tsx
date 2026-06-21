/**
 * SiemConnectorsTab — Phase 5 SIEM connector management (General config group)
 *
 * Allows admins to:
 *   - List configured SIEM connectors
 *   - Add a new Splunk connector (token or username/password auth)
 *   - Edit existing connectors (partial update — leave token empty to keep existing)
 *   - Test a connector (live connection check)
 *   - Delete a connector
 *
 * Security notes:
 *   - API tokens / passwords are write-only: displayed as '***' once saved.
 *   - TLS verification can be disabled (emits a visible warning).
 */

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { clsx } from 'clsx'
import {
  Plus, Trash2, Pencil, X, CheckCircle, AlertTriangle, Loader2, Zap,
} from 'lucide-react'
import { api, type THSiemConnector, type THConnectorCreateBody } from '../../api/client'

// ── Empty form state ──────────────────────────────────────────────────────────

const EMPTY_FORM: THConnectorCreateBody = {
  name: '',
  kind: 'splunk',
  base_url: '',
  auth_method: 'token',
  api_token: '',
  username: '',
  password: '',
  verify_tls: true,
  default_index: 'main',
  retrohunt_macro: 'threathunt_ioc_search',
}

// ── Connector form ────────────────────────────────────────────────────────────

function ConnectorForm({
  initial,
  onSave,
  onCancel,
  saving,
}: {
  initial: THConnectorCreateBody
  onSave: (v: THConnectorCreateBody) => void
  onCancel: () => void
  saving: boolean
}) {
  const [form, setForm] = useState<THConnectorCreateBody>(initial)
  const set = (k: keyof THConnectorCreateBody, v: unknown) =>
    setForm((f) => ({ ...f, [k]: v }))

  const valid = form.name.trim() !== '' && form.base_url.trim() !== ''

  return (
    <div className="card space-y-4">
      <h4 className="text-sm font-semibold text-gray-200">
        {initial.name ? 'Edit Connector' : 'New SIEM Connector'}
      </h4>

      <div className="grid grid-cols-2 gap-3">
        {/* Name */}
        <div className="col-span-2">
          <label className="label">Connector Name</label>
          <input
            className="input w-full"
            placeholder="e.g. prod-splunk"
            value={form.name}
            onChange={(e) => set('name', e.target.value)}
          />
        </div>

        {/* Base URL */}
        <div className="col-span-2">
          <label className="label">Splunk Base URL</label>
          <input
            className="input w-full font-mono"
            placeholder="https://splunk.example.com:8089"
            value={form.base_url}
            onChange={(e) => set('base_url', e.target.value)}
          />
        </div>

        {/* Auth method */}
        <div>
          <label className="label">Auth Method</label>
          <select
            className="input w-full"
            value={form.auth_method}
            onChange={(e) => set('auth_method', e.target.value as 'token' | 'username_password')}
          >
            <option value="token">Bearer Token</option>
            <option value="username_password">Username / Password</option>
          </select>
        </div>

        {/* Token or credentials */}
        {form.auth_method === 'token' ? (
          <div>
            <label className="label">API Token</label>
            <input
              className="input w-full font-mono"
              type="password"
              placeholder={initial.name ? '(unchanged — leave empty)' : 'Splunk API token'}
              value={form.api_token ?? ''}
              onChange={(e) => set('api_token', e.target.value)}
              autoComplete="new-password"
            />
          </div>
        ) : (
          <>
            <div>
              <label className="label">Username</label>
              <input
                className="input w-full"
                placeholder="admin"
                value={form.username ?? ''}
                onChange={(e) => set('username', e.target.value)}
              />
            </div>
            <div>
              <label className="label">Password</label>
              <input
                className="input w-full font-mono"
                type="password"
                placeholder={initial.name ? '(unchanged — leave empty)' : 'Password'}
                value={form.password ?? ''}
                onChange={(e) => set('password', e.target.value)}
                autoComplete="new-password"
              />
            </div>
          </>
        )}

        {/* Default index */}
        <div>
          <label className="label">Default Index</label>
          <input
            className="input w-full font-mono"
            placeholder="main"
            value={form.default_index ?? 'main'}
            onChange={(e) => set('default_index', e.target.value)}
          />
        </div>

        {/* Retrohunt macro */}
        <div>
          <label className="label">Retrohunt Macro Name</label>
          <input
            className="input w-full font-mono"
            placeholder="threathunt_ioc_search"
            value={form.retrohunt_macro ?? ''}
            onChange={(e) => set('retrohunt_macro', e.target.value)}
          />
        </div>

        {/* TLS verification */}
        <div className="col-span-2 flex items-center gap-2">
          <input
            id="verify-tls"
            type="checkbox"
            className="w-4 h-4 accent-brand-500"
            checked={form.verify_tls !== false}
            onChange={(e) => set('verify_tls', e.target.checked)}
          />
          <label htmlFor="verify-tls" className="text-sm text-gray-300 cursor-pointer">
            Verify TLS certificate
          </label>
          {!form.verify_tls && (
            <span className="text-[10px] text-amber-400 flex items-center gap-1">
              <AlertTriangle className="w-3 h-3" /> Insecure — use only for development
            </span>
          )}
        </div>
      </div>

      <div className="flex gap-2 pt-1">
        <button
          className="btn-primary text-xs"
          disabled={!valid || saving}
          onClick={() => onSave(form)}
        >
          {saving ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : 'Save'}
        </button>
        <button className="btn-secondary text-xs" onClick={onCancel}>
          Cancel
        </button>
      </div>
    </div>
  )
}

// ── Connector row ─────────────────────────────────────────────────────────────

function ConnectorRow({
  conn,
  onEdit,
  onDelete,
  onTest,
}: {
  conn: THSiemConnector
  onEdit: () => void
  onDelete: () => void
  onTest: () => void
}) {
  let cfg: Record<string, unknown> = {}
  try { cfg = JSON.parse(conn.config_json) } catch { /* ignore */ }

  return (
    <div className="border border-gray-700 rounded-lg p-3 space-y-1.5">
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <span className="text-sm font-medium text-gray-200 truncate">{conn.name}</span>
            <span className="text-[10px] px-1.5 py-0.5 rounded bg-gray-800 text-gray-400 font-mono">{conn.kind}</span>
            {conn.verified ? (
              <span className="text-[10px] flex items-center gap-1 text-green-400">
                <CheckCircle className="w-3 h-3" /> Verified
              </span>
            ) : (
              <span className="text-[10px] text-gray-600">Unverified</span>
            )}
          </div>
          <p className="text-[11px] text-gray-500 font-mono truncate mt-0.5">{conn.base_url}</p>
          <p className="text-[10px] text-gray-600 mt-0.5">
            Auth: {conn.auth_method === 'token' ? 'Bearer token' : 'Username/password'}
            {' · '}Index: <span className="font-mono">{String(cfg.default_index || 'main')}</span>
            {' · '}TLS: {cfg.verify_tls !== false ? 'verified' : <span className="text-amber-500">disabled</span>}
          </p>
        </div>
        <div className="flex gap-1 shrink-0">
          <button
            className="btn-ghost p-1.5"
            title="Test connection"
            onClick={onTest}
          >
            <Zap className="w-4 h-4" />
          </button>
          <button
            className="btn-ghost p-1.5"
            title="Edit"
            onClick={onEdit}
          >
            <Pencil className="w-4 h-4" />
          </button>
          <button
            className="btn-ghost p-1.5 text-red-400 hover:text-red-300"
            title="Delete"
            onClick={onDelete}
          >
            <Trash2 className="w-4 h-4" />
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Main tab ──────────────────────────────────────────────────────────────────

export default function SiemConnectorsTab() {
  const qc = useQueryClient()
  const [showForm, setShowForm] = useState(false)
  const [editingId, setEditingId] = useState<string | null>(null)
  const [testResult, setTestResult] = useState<{ id: string; ok: boolean; message: string } | null>(null)

  const { data: connectors = [], isLoading } = useQuery({
    queryKey: ['siem-connectors'],
    queryFn: () => api.threatHunting.listConnectors(),
  })

  const createMut = useMutation({
    mutationFn: (body: THConnectorCreateBody) => api.threatHunting.createConnector(body),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['siem-connectors'] }); setShowForm(false) },
  })

  const updateMut = useMutation({
    mutationFn: ({ id, body }: { id: string; body: Partial<THConnectorCreateBody> }) =>
      api.threatHunting.updateConnector(id, body),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['siem-connectors'] }); setEditingId(null) },
  })

  const deleteMut = useMutation({
    mutationFn: (id: string) => api.threatHunting.deleteConnector(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['siem-connectors'] }),
  })

  const testMut = useMutation({
    mutationFn: (id: string) => api.threatHunting.testConnector(id),
    onSuccess: (data, id) => {
      setTestResult({ id, ok: data.ok, message: data.message })
      qc.invalidateQueries({ queryKey: ['siem-connectors'] })
    },
  })

  const editingConn = editingId ? connectors.find((c) => c.id === editingId) : null

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-sm font-semibold text-gray-200">SIEM Connectors</h3>
          <p className="text-xs text-gray-500 mt-0.5">
            Configure Splunk connections for retrohunt execution.
          </p>
        </div>
        {!showForm && !editingId && (
          <button
            className="btn-primary text-xs flex items-center gap-1.5"
            onClick={() => setShowForm(true)}
          >
            <Plus className="w-3.5 h-3.5" /> Add Connector
          </button>
        )}
      </div>

      {/* Test result banner */}
      {testResult && (
        <div
          className={clsx(
            'flex items-start gap-2 p-3 rounded-lg text-xs border',
            testResult.ok
              ? 'bg-green-900/20 border-green-800/40 text-green-300'
              : 'bg-red-900/20 border-red-800/40 text-red-300',
          )}
        >
          {testResult.ok ? <CheckCircle className="w-4 h-4 shrink-0" /> : <AlertTriangle className="w-4 h-4 shrink-0" />}
          <span>{testResult.message}</span>
          <button className="ml-auto" onClick={() => setTestResult(null)}>
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      {/* Create form */}
      {showForm && (
        <ConnectorForm
          initial={EMPTY_FORM}
          onSave={(body) => createMut.mutate(body)}
          onCancel={() => setShowForm(false)}
          saving={createMut.isPending}
        />
      )}

      {/* List */}
      {isLoading ? (
        <div className="flex items-center gap-2 text-sm text-gray-500">
          <Loader2 className="w-4 h-4 animate-spin" /> Loading…
        </div>
      ) : connectors.length === 0 && !showForm ? (
        <p className="text-sm text-gray-600 italic">No SIEM connectors configured.</p>
      ) : (
        <div className="space-y-2">
          {connectors.map((conn) =>
            editingId === conn.id && editingConn ? (
              <ConnectorForm
                key={conn.id}
                initial={{
                  name: editingConn.name,
                  kind: editingConn.kind,
                  base_url: editingConn.base_url,
                  auth_method: editingConn.auth_method,
                  api_token: '',
                  username: '',
                  password: '',
                  verify_tls: true,
                  default_index: 'main',
                  retrohunt_macro: 'threathunt_ioc_search',
                }}
                onSave={(body) => updateMut.mutate({ id: conn.id, body })}
                onCancel={() => setEditingId(null)}
                saving={updateMut.isPending}
              />
            ) : (
              <ConnectorRow
                key={conn.id}
                conn={conn}
                onEdit={() => { setShowForm(false); setEditingId(conn.id) }}
                onDelete={() => {
                  if (window.confirm(`Delete connector "${conn.name}"?`)) {
                    deleteMut.mutate(conn.id)
                  }
                }}
                onTest={() => { setTestResult(null); testMut.mutate(conn.id) }}
              />
            ),
          )}
        </div>
      )}

      {createMut.isError && (
        <p className="text-xs text-red-400">
          {createMut.error instanceof Error ? createMut.error.message : 'Create failed'}
        </p>
      )}
      {updateMut.isError && (
        <p className="text-xs text-red-400">
          {updateMut.error instanceof Error ? updateMut.error.message : 'Update failed'}
        </p>
      )}
    </div>
  )
}
