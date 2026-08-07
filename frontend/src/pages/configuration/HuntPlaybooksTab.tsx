/**
 * HuntPlaybooksTab — issue-local-040
 *
 * Hunt Playbooks define an automated set of hunt-generation runs (one per
 * enabled model) plus which of the normally-manual gates proceed
 * automatically: analysis approval, comparison assessment (Preliminary
 * and/or Full), a recommendation-synthesis run, and a consolidated report
 * of the Full assessment.
 *
 * Mirrors SiemConnectorsTab's card-list + inline create/edit form pattern —
 * the closest existing template for a global, DB-backed config-object CRUD
 * with edit/clone/delete.
 */

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Plus, Trash2, Pencil, Copy, Loader2 } from 'lucide-react'
import { api, type THPlaybook, type THPlaybookInput, type THPlaybookModelEntry } from '../../api/client'
import { modelOptionsFromProviders } from '../threat-hunting/runConfigUtils'

const EMPTY_FORM: THPlaybookInput = {
  name: '',
  models: [],
  auto_approve_analysis: false,
  auto_run_comparison: false,
  auto_compare_preliminary: false,
  auto_compare_full: false,
  auto_create_run_from_recommendations: false,
  auto_generate_full_report: false,
}

function modelKey(m: THPlaybookModelEntry): string {
  return `${m.provider_name ?? ''}\x00${m.model_name}`
}

// ── Playbook form ─────────────────────────────────────────────────────────────

function PlaybookForm({
  initial,
  onSave,
  onCancel,
  saving,
}: {
  initial: THPlaybookInput
  onSave: (v: THPlaybookInput) => void
  onCancel: () => void
  saving: boolean
}) {
  const [form, setForm] = useState<THPlaybookInput>(initial)
  const set = <K extends keyof THPlaybookInput>(k: K, v: THPlaybookInput[K]) =>
    setForm((f) => ({ ...f, [k]: v }))

  const { data: providers = [] } = useQuery({
    queryKey: ['llm-providers'],
    queryFn: () => api.llm.listProviders(),
  })
  const modelOptions = modelOptionsFromProviders(providers)

  const selectedKeys = new Set(form.models.map(modelKey))
  const toggleModel = (provider: string, model: string) => {
    const entry: THPlaybookModelEntry = { provider_name: provider, model_name: model }
    const key = modelKey(entry)
    setForm((f) => ({
      ...f,
      models: selectedKeys.has(key)
        ? f.models.filter((m) => modelKey(m) !== key)
        : [...f.models, entry],
    }))
  }

  const valid = form.name.trim() !== '' && form.models.length > 0

  return (
    <div className="card space-y-4">
      <h4 className="text-sm font-semibold text-gray-200">
        {initial.name ? 'Edit Playbook' : 'New Hunt Playbook'}
      </h4>

      <div>
        <label className="label">Playbook Name</label>
        <input
          className="input w-full"
          placeholder="e.g. Multi-model triage"
          value={form.name}
          onChange={(e) => set('name', e.target.value)}
        />
      </div>

      <div>
        <label className="label">Models to run</label>
        <p className="text-[11px] text-gray-500 mb-1.5">
          One generation run is fired per enabled model when this playbook runs.
        </p>
        {modelOptions.length === 0 ? (
          <p className="text-xs text-gray-600 italic">
            No models discovered yet — configure and test an LLM provider first.
          </p>
        ) : (
          <div className="space-y-1 max-h-48 overflow-y-auto border border-gray-800 rounded-lg p-2">
            {modelOptions.map((opt) => {
              const key = modelKey({ provider_name: opt.provider, model_name: opt.model })
              return (
                <label
                  key={key}
                  className="flex items-center gap-2 text-sm text-gray-300 cursor-pointer py-0.5"
                >
                  <input
                    type="checkbox"
                    className="w-4 h-4 accent-brand-500"
                    checked={selectedKeys.has(key)}
                    onChange={() => toggleModel(opt.provider, opt.model)}
                  />
                  <span className="font-mono text-xs">{opt.provider} · {opt.model}</span>
                </label>
              )
            })}
          </div>
        )}
      </div>

      <div className="space-y-2 border-t border-gray-800 pt-3">
        <label className="flex items-center gap-2 text-sm text-gray-300 cursor-pointer">
          <input
            type="checkbox"
            className="w-4 h-4 accent-brand-500"
            checked={form.auto_approve_analysis}
            onChange={(e) => set('auto_approve_analysis', e.target.checked)}
          />
          Automatically approve the Analysis phase
        </label>

        <label className="flex items-center gap-2 text-sm text-gray-300 cursor-pointer">
          <input
            type="checkbox"
            className="w-4 h-4 accent-brand-500"
            checked={form.auto_run_comparison}
            onChange={(e) => {
              const checked = e.target.checked
              setForm((f) => ({
                ...f,
                auto_run_comparison: checked,
                auto_compare_preliminary: checked ? f.auto_compare_preliminary : false,
                auto_compare_full: checked ? f.auto_compare_full : false,
                auto_create_run_from_recommendations: checked
                  ? f.auto_create_run_from_recommendations
                  : false,
                auto_generate_full_report: checked ? f.auto_generate_full_report : false,
              }))
            }}
          />
          Automatically run Comparison assessment (once every fired run finishes analysis)
        </label>

        {form.auto_run_comparison && (
          <div className="ml-6 space-y-2 border-l border-gray-800 pl-3">
            <label className="flex items-center gap-2 text-sm text-gray-300 cursor-pointer">
              <input
                type="checkbox"
                className="w-4 h-4 accent-brand-500"
                checked={form.auto_compare_preliminary}
                onChange={(e) => set('auto_compare_preliminary', e.target.checked)}
              />
              Preliminary Analysis
            </label>
            <label className="flex items-center gap-2 text-sm text-gray-300 cursor-pointer">
              <input
                type="checkbox"
                className="w-4 h-4 accent-brand-500"
                checked={form.auto_compare_full}
                onChange={(e) => set('auto_compare_full', e.target.checked)}
              />
              Full Assessment
            </label>

            <label
              className="flex items-center gap-2 text-sm text-gray-300 cursor-pointer"
              title={
                form.auto_compare_preliminary
                  ? undefined
                  : 'Requires Preliminary Analysis above — the new run is synthesized from it'
              }
            >
              <input
                type="checkbox"
                className="w-4 h-4 accent-brand-500"
                checked={form.auto_create_run_from_recommendations}
                disabled={!form.auto_compare_preliminary}
                onChange={(e) => set('auto_create_run_from_recommendations', e.target.checked)}
              />
              Automatically create a new run from the Preliminary Analysis recommendations
            </label>

            <label
              className="flex items-center gap-2 text-sm text-gray-300 cursor-pointer"
              title={
                form.auto_compare_full
                  ? undefined
                  : 'Requires Full Assessment above'
              }
            >
              <input
                type="checkbox"
                className="w-4 h-4 accent-brand-500"
                checked={form.auto_generate_full_report}
                disabled={!form.auto_compare_full}
                onChange={(e) => set('auto_generate_full_report', e.target.checked)}
              />
              Automatically generate a consolidated report of the Full Assessment
            </label>
          </div>
        )}
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

// ── Playbook row ──────────────────────────────────────────────────────────────

function PlaybookRow({
  playbook,
  onEdit,
  onClone,
  onDelete,
}: {
  playbook: THPlaybook
  onEdit: () => void
  onClone: () => void
  onDelete: () => void
}) {
  const autoBits: string[] = []
  if (playbook.auto_approve_analysis) autoBits.push('auto-approve analysis')
  if (playbook.auto_compare_preliminary) autoBits.push('auto preliminary compare')
  if (playbook.auto_compare_full) autoBits.push('auto full compare')
  if (playbook.auto_create_run_from_recommendations) autoBits.push('auto recommendation run')
  if (playbook.auto_generate_full_report) autoBits.push('auto consolidated report')

  return (
    <div className="border border-gray-700 rounded-lg p-3 space-y-1.5">
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <span className="text-sm font-medium text-gray-200 truncate">{playbook.name}</span>
            <span className="text-[10px] px-1.5 py-0.5 rounded bg-gray-800 text-gray-400">
              {playbook.models.length} model{playbook.models.length === 1 ? '' : 's'}
            </span>
          </div>
          <p className="text-[11px] text-gray-500 font-mono truncate mt-0.5">
            {playbook.models.map((m) => m.model_name).join(', ')}
          </p>
          <p className="text-[10px] text-gray-600 mt-0.5">
            {autoBits.length > 0 ? autoBits.join(' · ') : 'No automation beyond firing the runs'}
          </p>
        </div>
        <div className="flex gap-1 shrink-0">
          <button className="btn-ghost p-1.5" title="Clone" onClick={onClone}>
            <Copy className="w-4 h-4" />
          </button>
          <button className="btn-ghost p-1.5" title="Edit" onClick={onEdit}>
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

export default function HuntPlaybooksTab() {
  const qc = useQueryClient()
  const [showForm, setShowForm] = useState(false)
  const [editingId, setEditingId] = useState<string | null>(null)

  const { data: playbooks = [], isLoading } = useQuery({
    queryKey: ['hunt-playbooks'],
    queryFn: () => api.threatHunting.playbooks.list(),
  })

  const createMut = useMutation({
    mutationFn: (body: THPlaybookInput) => api.threatHunting.playbooks.create(body),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['hunt-playbooks'] }); setShowForm(false) },
  })

  const updateMut = useMutation({
    mutationFn: ({ id, body }: { id: string; body: Partial<THPlaybookInput> }) =>
      api.threatHunting.playbooks.update(id, body),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['hunt-playbooks'] }); setEditingId(null) },
  })

  const deleteMut = useMutation({
    mutationFn: (id: string) => api.threatHunting.playbooks.delete(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['hunt-playbooks'] }),
  })

  const cloneMut = useMutation({
    mutationFn: ({ id, name }: { id: string; name: string }) =>
      api.threatHunting.playbooks.clone(id, name),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['hunt-playbooks'] }),
  })

  const editingPlaybook = editingId ? playbooks.find((p) => p.id === editingId) : null

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-sm font-semibold text-gray-200">Hunt Playbooks</h3>
          <p className="text-xs text-gray-500 mt-0.5">
            Automate a set of hunt-generation runs — one per enabled model — plus, optionally,
            the analysis-approval, comparison-assessment, recommendation-run and
            consolidated-report steps that normally require a human. SIEM execution always
            stays a manual step.
          </p>
        </div>
        {!showForm && !editingId && (
          <button
            className="btn-primary text-xs flex items-center gap-1.5"
            onClick={() => setShowForm(true)}
          >
            <Plus className="w-3.5 h-3.5" /> New Playbook
          </button>
        )}
      </div>

      {showForm && (
        <PlaybookForm
          initial={EMPTY_FORM}
          onSave={(body) => createMut.mutate(body)}
          onCancel={() => setShowForm(false)}
          saving={createMut.isPending}
        />
      )}

      {isLoading ? (
        <div className="flex items-center gap-2 text-sm text-gray-500">
          <Loader2 className="w-4 h-4 animate-spin" /> Loading…
        </div>
      ) : playbooks.length === 0 && !showForm ? (
        <p className="text-sm text-gray-600 italic">No Hunt Playbooks configured.</p>
      ) : (
        <div className="space-y-2">
          {playbooks.map((playbook) =>
            editingId === playbook.id && editingPlaybook ? (
              <PlaybookForm
                key={playbook.id}
                initial={{
                  name: editingPlaybook.name,
                  models: editingPlaybook.models,
                  auto_approve_analysis: editingPlaybook.auto_approve_analysis,
                  auto_run_comparison: editingPlaybook.auto_run_comparison,
                  auto_compare_preliminary: editingPlaybook.auto_compare_preliminary,
                  auto_compare_full: editingPlaybook.auto_compare_full,
                  auto_create_run_from_recommendations:
                    editingPlaybook.auto_create_run_from_recommendations,
                  auto_generate_full_report: editingPlaybook.auto_generate_full_report,
                }}
                onSave={(body) => updateMut.mutate({ id: playbook.id, body })}
                onCancel={() => setEditingId(null)}
                saving={updateMut.isPending}
              />
            ) : (
              <PlaybookRow
                key={playbook.id}
                playbook={playbook}
                onEdit={() => { setShowForm(false); setEditingId(playbook.id) }}
                onClone={() => {
                  const name = window.prompt('Name for the cloned playbook:', `Copy of ${playbook.name}`)
                  if (name && name.trim()) cloneMut.mutate({ id: playbook.id, name: name.trim() })
                }}
                onDelete={() => {
                  if (window.confirm(`Delete playbook "${playbook.name}"?`)) {
                    deleteMut.mutate(playbook.id)
                  }
                }}
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
