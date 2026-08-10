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
import { clsx } from 'clsx'
import {
  api,
  type THPlaybook,
  type THPlaybookInput,
  type THPlaybookModelEntry,
  type THIocCleaningOptions,
} from '../../api/client'
import {
  modelOptionsFromProviders,
  EFFORT_OPTIONS,
  DEFAULT_IOC_MODE,
  DEFAULT_IOC_CLEANING_OPTIONS,
} from '../threat-hunting/runConfigUtils'
import Toggle from '../../components/Toggle'

const EMPTY_FORM: THPlaybookInput = {
  name: '',
  models: [],
  auto_approve_analysis: false,
  auto_run_comparison: false,
  auto_compare_preliminary: false,
  auto_compare_full: false,
  auto_create_run_from_recommendations: false,
  auto_generate_full_report: false,
  // issue-local-042: disabled by default — a fresh/never-touched playbook
  // keeps run_config={} on its fired runs, exactly the pre-existing default.
  ioc_cleaning_enabled: false,
  ioc_cleaning_scope: null,
  ioc_mode: null,
  ioc_cleaning_options: null,
}

// issue-local-042: IOC mode/cleaning-toggle mini-form, reused for both the
// playbook-level ("General") config and each model row's own ("Per model")
// override — same fields RunConfigForm.tsx's IOC Handling section shows for
// a manual run, just laid out compactly for a form/table row.
function IocModeEditor({
  mode,
  onModeChange,
  options,
  onOptionsChange,
}: {
  mode: 'tagging_only' | 'active_cleaning'
  onModeChange: (mode: 'tagging_only' | 'active_cleaning') => void
  options: THIocCleaningOptions
  onOptionsChange: (updater: (prev: THIocCleaningOptions) => THIocCleaningOptions) => void
}) {
  return (
    <div className="space-y-1.5">
      <div className="flex items-center gap-1.5">
        {(['tagging_only', 'active_cleaning'] as const).map((m) => (
          <button
            key={m}
            type="button"
            onClick={() => onModeChange(m)}
            className={clsx(
              'text-[11px] px-2 py-1 rounded border transition-colors',
              mode === m
                ? 'border-brand-500 bg-brand-900/20 text-brand-300'
                : 'border-gray-700 text-gray-500 hover:border-gray-500',
            )}
          >
            {m === 'tagging_only' ? 'Tagging only' : 'Active cleaning'}
          </button>
        ))}
      </div>
      {mode === 'active_cleaning' && (
        <div className="flex flex-wrap gap-x-3 gap-y-1 pl-1">
          {(
            [
              ['remove_noisy', 'Noisy'],
              ['remove_legit_domains', 'Legit domains'],
              ['remove_cdn_ranges', 'CDN ranges'],
              ['remove_legit_services', 'Legit services'],
            ] as const
          ).map(([key, label]) => (
            <label key={key} className="flex items-center gap-1 text-[11px] text-gray-400">
              <input
                type="checkbox"
                checked={options[key]}
                onChange={(e) => {
                  const checked = e.target.checked
                  onOptionsChange((prev) => ({ ...prev, [key]: checked }))
                }}
                className="accent-brand-500"
              />
              {label}
            </label>
          ))}
        </div>
      )}
    </div>
  )
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
  // issue-local-042: per-model research-effort override — a null/undefined
  // 'effort' means "use the configured default" when the playbook fires.
  const setModelEffort = (provider: string, model: string, effort: string | null) => {
    const key = modelKey({ provider_name: provider, model_name: model })
    setForm((f) => ({
      ...f,
      models: f.models.map((m) => (modelKey(m) === key ? { ...m, effort } : m)),
    }))
  }
  // issue-local-042: per-model IOC cleaning override — only meaningful (and
  // only shown) when ioc_cleaning_scope is 'per_model'.
  const setModelIoc = (
    provider: string,
    model: string,
    updater: (prev: { ioc_mode: 'tagging_only' | 'active_cleaning'; ioc_cleaning_options: THIocCleaningOptions }) => {
      ioc_mode: 'tagging_only' | 'active_cleaning'
      ioc_cleaning_options: THIocCleaningOptions
    },
  ) => {
    const key = modelKey({ provider_name: provider, model_name: model })
    setForm((f) => ({
      ...f,
      models: f.models.map((m) => {
        if (modelKey(m) !== key) return m
        const next = updater({
          ioc_mode: m.ioc_mode ?? DEFAULT_IOC_MODE,
          ioc_cleaning_options: m.ioc_cleaning_options ?? DEFAULT_IOC_CLEANING_OPTIONS,
        })
        return { ...m, ...next }
      }),
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
          <div className="space-y-1 max-h-64 overflow-y-auto border border-gray-800 rounded-lg p-2">
            {modelOptions.map((opt) => {
              const key = modelKey({ provider_name: opt.provider, model_name: opt.model })
              const selected = selectedKeys.has(key)
              const entry = form.models.find((m) => modelKey(m) === key)
              return (
                <div key={key} className="py-0.5 space-y-1.5">
                  <div className="flex items-center gap-2">
                    <Toggle checked={selected} onChange={() => toggleModel(opt.provider, opt.model)} />
                    <span className="font-mono text-xs text-gray-300 flex-1">{opt.provider} · {opt.model}</span>
                    {/* issue-local-042: per-model effort override — reuses the
                        same low/medium/high options as a manual run's Research
                        effort picker. Unset = configured default at run time. */}
                    {selected && (
                      <div className="flex items-center gap-1 shrink-0">
                        {EFFORT_OPTIONS.map((e) => (
                          <button
                            key={e}
                            type="button"
                            onClick={() => setModelEffort(opt.provider, opt.model, entry?.effort === e ? null : e)}
                            className={clsx(
                              'text-[10px] px-1.5 py-0.5 rounded border capitalize transition-colors',
                              entry?.effort === e
                                ? 'bg-brand-900/40 border-brand-600 text-brand-200'
                                : 'bg-transparent border-gray-700 text-gray-500 hover:text-gray-300',
                            )}
                            title={entry?.effort === e ? `Click to unset — use the configured default` : `Use ${e} effort for this model`}
                          >
                            {e}
                          </button>
                        ))}
                      </div>
                    )}
                  </div>
                  {/* issue-local-042: per-model IOC cleaning override — only
                      shown once IOC Cleaning below is enabled with the
                      Per-model scope. */}
                  {selected && form.ioc_cleaning_enabled && form.ioc_cleaning_scope === 'per_model' && (
                    <div className="ml-6 pl-2 border-l border-gray-800">
                      <IocModeEditor
                        mode={entry?.ioc_mode ?? DEFAULT_IOC_MODE}
                        onModeChange={(mode) =>
                          setModelIoc(opt.provider, opt.model, (prev) => ({ ...prev, ioc_mode: mode }))
                        }
                        options={entry?.ioc_cleaning_options ?? DEFAULT_IOC_CLEANING_OPTIONS}
                        onOptionsChange={(updater) =>
                          setModelIoc(opt.provider, opt.model, (prev) => ({
                            ...prev,
                            ioc_cleaning_options: updater(prev.ioc_cleaning_options),
                          }))
                        }
                      />
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        )}
      </div>

      <div className="space-y-2 border-t border-gray-800 pt-3">
        <div className="flex items-center gap-2 text-sm text-gray-300">
          <Toggle
            checked={form.auto_approve_analysis ?? false}
            onChange={(v) => set('auto_approve_analysis', v)}
          />
          <span>Automatically approve the Analysis phase</span>
        </div>

        <div className="flex items-center gap-2 text-sm text-gray-300">
          <Toggle
            checked={form.auto_run_comparison ?? false}
            onChange={(checked) => {
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
          <span>Automatically run Comparison assessment (once every fired run finishes analysis)</span>
        </div>

        {form.auto_run_comparison && (
          <div className="ml-6 space-y-2 border-l border-gray-800 pl-3">
            <div className="flex items-center gap-2 text-sm text-gray-300">
              <Toggle
                checked={form.auto_compare_preliminary ?? false}
                onChange={(v) => set('auto_compare_preliminary', v)}
              />
              <span>Preliminary Analysis</span>
            </div>
            <div className="flex items-center gap-2 text-sm text-gray-300">
              <Toggle checked={form.auto_compare_full ?? false} onChange={(v) => set('auto_compare_full', v)} />
              <span>Full Assessment</span>
            </div>

            <div
              className="flex items-center gap-2 text-sm text-gray-300"
              title={
                form.auto_compare_preliminary
                  ? undefined
                  : 'Requires Preliminary Analysis above — the new run is synthesized from it'
              }
            >
              <Toggle
                checked={form.auto_create_run_from_recommendations ?? false}
                disabled={!form.auto_compare_preliminary}
                onChange={(v) => set('auto_create_run_from_recommendations', v)}
              />
              <span>Automatically create a new run from the Preliminary Analysis recommendations</span>
            </div>

            <div
              className="flex items-center gap-2 text-sm text-gray-300"
              title={
                form.auto_compare_full
                  ? undefined
                  : 'Requires Full Assessment above'
              }
            >
              <Toggle
                checked={form.auto_generate_full_report ?? false}
                disabled={!form.auto_compare_full}
                onChange={(v) => set('auto_generate_full_report', v)}
              />
              <span>Automatically generate a consolidated report of the Full Assessment</span>
            </div>
          </div>
        )}
      </div>

      {/* issue-local-042 (item 20): IOC cleaning config for this playbook's
          fired runs — previously every playbook run always used
          run_config={}, silently ignoring the app-wide default with no way
          for a playbook to say otherwise. Disabled by default, so an
          untouched playbook keeps that exact prior behavior. */}
      <div className="space-y-2 border-t border-gray-800 pt-3">
        <div className="flex items-center gap-2 text-sm text-gray-300">
          <Toggle
            checked={form.ioc_cleaning_enabled ?? false}
            onChange={(v) =>
              setForm((f) => ({
                ...f,
                ioc_cleaning_enabled: v,
                ioc_cleaning_scope: v ? (f.ioc_cleaning_scope ?? 'general') : null,
              }))
            }
          />
          <span>Configure IOC cleaning for this playbook's runs</span>
        </div>
        <p className="text-[11px] text-gray-500 pl-6">
          Off (default): each fired run uses the app-wide configured default, same as before this existed.
        </p>

        {form.ioc_cleaning_enabled && (
          <div className="ml-6 space-y-2 border-l border-gray-800 pl-3">
            <div className="flex items-center gap-1.5">
              {(['general', 'per_model'] as const).map((scope) => (
                <button
                  key={scope}
                  type="button"
                  onClick={() => set('ioc_cleaning_scope', scope)}
                  className={clsx(
                    'text-[11px] px-2 py-1 rounded border transition-colors',
                    form.ioc_cleaning_scope === scope
                      ? 'border-brand-500 bg-brand-900/20 text-brand-300'
                      : 'border-gray-700 text-gray-500 hover:border-gray-500',
                  )}
                >
                  {scope === 'general' ? 'General (whole playbook)' : 'Per model'}
                </button>
              ))}
            </div>
            {form.ioc_cleaning_scope === 'general' && (
              <IocModeEditor
                mode={form.ioc_mode ?? DEFAULT_IOC_MODE}
                onModeChange={(mode) => set('ioc_mode', mode)}
                options={form.ioc_cleaning_options ?? DEFAULT_IOC_CLEANING_OPTIONS}
                onOptionsChange={(updater) =>
                  setForm((f) => ({
                    ...f,
                    ioc_cleaning_options: updater(f.ioc_cleaning_options ?? DEFAULT_IOC_CLEANING_OPTIONS),
                  }))
                }
              />
            )}
            {form.ioc_cleaning_scope === 'per_model' && (
              <p className="text-[11px] text-gray-500">
                Set per model above, in the Models to run list.
              </p>
            )}
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
  if (playbook.ioc_cleaning_enabled) {
    autoBits.push(`IOC cleaning: ${playbook.ioc_cleaning_scope === 'per_model' ? 'per model' : 'general'}`)
  }

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
                  ioc_cleaning_enabled: editingPlaybook.ioc_cleaning_enabled,
                  ioc_cleaning_scope: editingPlaybook.ioc_cleaning_scope,
                  ioc_mode: editingPlaybook.ioc_mode,
                  ioc_cleaning_options: editingPlaybook.ioc_cleaning_options,
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
