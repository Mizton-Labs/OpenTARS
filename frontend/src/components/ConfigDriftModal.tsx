/**
 * ConfigDriftModal (issue-local-024 follow-up).
 *
 * Lets an admin review exactly what a newer release's shipped config
 * templates introduced that this deployment's live, gitignored config files
 * (application.yaml/sources.yaml/feed-fields.yaml/normalizer-config.yaml)
 * don't have yet — a missing core field, or a brand-new top-level setting —
 * and choose which to add. Nothing is ever changed without an explicit
 * "Apply selected" click; unselected items stay exactly as-is.
 */
import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { X, AlertTriangle } from 'lucide-react'
import { api, type ConfigDriftReport } from '../api/client'

interface ConfigDriftModalProps {
  reports: ConfigDriftReport[]
  onClose: () => void
}

/** Selection keyed by "file::kind::identifier" -> selected. */
type SelectionKey = string
const keyOf = (file: string, kind: 'key' | 'core_field', id: string): SelectionKey =>
  `${file}::${kind}::${id}`

export default function ConfigDriftModal({ reports, onClose }: ConfigDriftModalProps) {
  const qc = useQueryClient()
  const [selected, setSelected] = useState<Set<SelectionKey>>(() => {
    // Default to everything selected — reviewing is still required (the
    // admin must click Apply), but starting fully-checked matches "these
    // are new upstream defaults, not something to second-guess per item".
    const all = new Set<SelectionKey>()
    for (const r of reports) {
      for (const key of r.missing_keys) all.add(keyOf(r.file, 'key', key))
      for (const f of r.missing_core_fields) all.add(keyOf(r.file, 'core_field', f.name))
    }
    return all
  })
  const [applyError, setApplyError] = useState<string | null>(null)

  const toggle = (k: SelectionKey) => {
    setSelected(prev => {
      const next = new Set(prev)
      if (next.has(k)) next.delete(k)
      else next.add(k)
      return next
    })
  }

  const applyMutation = useMutation({
    mutationFn: async () => {
      // Apply per-file (the endpoint takes one file per call).
      for (const r of reports) {
        const keys = r.missing_keys.filter(k => selected.has(keyOf(r.file, 'key', k)))
        const core_field_names = r.missing_core_fields
          .map(f => f.name)
          .filter(name => selected.has(keyOf(r.file, 'core_field', name)))
        if (keys.length === 0 && core_field_names.length === 0) continue
        await api.applyConfigDriftFix(r.file, { keys, core_field_names })
      }
    },
    onSuccess: () => {
      setApplyError(null)
      qc.invalidateQueries({ queryKey: ['config-drift'] })
      onClose()
    },
    onError: (e: unknown) => setApplyError(e instanceof Error ? e.message : String(e)),
  })

  const selectedCount = selected.size
  const totalCount = reports.reduce(
    (n, r) => n + r.missing_keys.length + r.missing_core_fields.length,
    0,
  )

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
      <div className="bg-gray-900 border border-gray-700 rounded-xl shadow-xl w-full max-w-xl max-h-[85vh] overflow-y-auto mx-4 p-5 space-y-4">
        <div className="flex items-start justify-between">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />
            <h3 className="text-sm font-semibold text-gray-100">
              New configuration available
            </h3>
          </div>
          <button
            className="btn-ghost p-1.5 text-gray-500 hover:text-gray-300"
            onClick={onClose}
            aria-label="Close"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <p className="text-xs text-gray-400">
          A newer release shipped configuration this instance's files don't have yet. Nothing is
          changed until you click Apply — uncheck anything you don't want added.
        </p>

        <div className="space-y-4">
          {reports.map(r => (
            <div key={r.file} className="space-y-2">
              <p className="text-xs font-semibold text-gray-300 font-mono">{r.file}</p>

              {r.missing_core_fields.map(f => {
                const k = keyOf(r.file, 'core_field', f.name)
                return (
                  <label
                    key={k}
                    className="flex items-start gap-2 text-xs text-gray-300 pl-2 cursor-pointer"
                  >
                    <input
                      type="checkbox"
                      className="mt-0.5"
                      checked={selected.has(k)}
                      onChange={() => toggle(k)}
                    />
                    <span>
                      <span className="font-mono text-gray-200">{f.name}</span>
                      {f.description && <span className="text-gray-500"> — {f.description}</span>}
                      <span className="text-gray-600"> (new core field)</span>
                    </span>
                  </label>
                )
              })}

              {r.missing_keys.map(key => {
                const k = keyOf(r.file, 'key', key)
                return (
                  <label
                    key={k}
                    className="flex items-start gap-2 text-xs text-gray-300 pl-2 cursor-pointer"
                  >
                    <input
                      type="checkbox"
                      className="mt-0.5"
                      checked={selected.has(k)}
                      onChange={() => toggle(k)}
                    />
                    <span>
                      <span className="font-mono text-gray-200">{key}</span>
                      <span className="text-gray-600"> (new setting)</span>
                    </span>
                  </label>
                )
              })}
            </div>
          ))}
        </div>

        {applyError && (
          <p className="text-xs text-red-400" role="alert">
            {applyError}
          </p>
        )}

        <div className="flex items-center justify-between gap-2 pt-1 border-t border-gray-800">
          <span className="text-[11px] text-gray-500">
            {selectedCount} of {totalCount} selected
          </span>
          <div className="flex gap-2">
            <button className="btn-ghost text-xs" onClick={onClose}>
              Cancel
            </button>
            <button
              className="px-3 py-1.5 text-xs rounded bg-brand-700 hover:bg-brand-600 text-white font-medium transition-colors disabled:opacity-50"
              onClick={() => applyMutation.mutate()}
              disabled={selectedCount === 0 || applyMutation.isPending}
            >
              {applyMutation.isPending ? 'Applying…' : 'Apply selected'}
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
