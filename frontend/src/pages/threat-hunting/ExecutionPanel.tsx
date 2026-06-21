/**
 * ExecutionPanel — Phase 5 SIEM execution UI
 *
 * Shown on approved hunt packages. Allows a threat-researcher or admin to:
 *   1. Select a configured SIEM connector
 *   2. Review/edit the SPL query (pre-filled from deep_retrohunt.spl_draft)
 *   3. Set time range (earliest / latest)
 *   4. Submit execution and monitor progress
 *   5. View results: event count, interpreted findings, raw result sample
 *
 * The panel is read-only for threat-viewers.
 */

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { clsx } from 'clsx'
import {
  Play,
  Loader2,
  AlertTriangle,
  ChevronDown,
  ChevronRight,
  Database,
  Search,
} from 'lucide-react'
import {
  api,
  type THSiemConnector,
  type THTaskResult,
  type THDeepRetrohuntLead,
} from '../../api/client'
import { useAuth } from '../../auth/useAuth'

// ── Helpers ───────────────────────────────────────────────────────────────────

function StatusBadge({ status }: { status: THTaskResult['status'] }) {
  const map: Record<string, { label: string; cls: string }> = {
    pending:   { label: 'Pending',   cls: 'bg-gray-800 text-gray-400' },
    running:   { label: 'Running',   cls: 'bg-blue-900/40 text-blue-300' },
    completed: { label: 'Completed', cls: 'bg-green-900/30 text-green-400' },
    failed:    { label: 'Failed',    cls: 'bg-red-900/30 text-red-400' },
  }
  const s = map[status] ?? map.pending
  return (
    <span className={clsx('text-[10px] px-2 py-0.5 rounded font-medium', s.cls)}>
      {s.label}
    </span>
  )
}

function ResultCard({ result }: { result: THTaskResult }) {
  const [showRaw, setShowRaw] = useState(false)
  const rawRows = Array.isArray(result.raw_result) ? result.raw_result : []

  return (
    <div className="border border-gray-700 rounded-lg overflow-hidden">
      {/* Header */}
      <div className="flex items-center gap-3 px-4 py-3 bg-gray-800/40">
        <Database className="w-4 h-4 text-brand-400 shrink-0" />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-sm font-medium text-gray-200">Execution</span>
            <StatusBadge status={result.status} />
            {result.is_running && (
              <Loader2 className="w-3.5 h-3.5 text-blue-400 animate-spin" />
            )}
          </div>
          <p className="text-[10px] text-gray-500 mt-0.5 font-mono truncate">
            {result.earliest} → {result.latest}
            {rawRows.length > 0 && ` · ${rawRows.length} events`}
          </p>
        </div>
        <span className="text-[10px] text-gray-600">{result.created_at?.slice(0, 19).replace('T', ' ')}</span>
      </div>

      {/* Findings */}
      {result.interpreted_findings && (
        <div className="px-4 py-3 border-t border-gray-800/60">
          <p className="text-[10px] text-gray-500 font-semibold uppercase tracking-wider mb-1">
            Interpreted Findings
          </p>
          <p className="text-xs text-gray-300 leading-relaxed">{result.interpreted_findings}</p>
        </div>
      )}

      {/* Raw results (collapsible) */}
      {rawRows.length > 0 && (
        <div className="border-t border-gray-800/60">
          <button
            className="w-full flex items-center gap-2 px-4 py-2 hover:bg-gray-800/30 transition-colors"
            onClick={() => setShowRaw((v) => !v)}
          >
            {showRaw ? (
              <ChevronDown className="w-3.5 h-3.5 text-gray-500" />
            ) : (
              <ChevronRight className="w-3.5 h-3.5 text-gray-500" />
            )}
            <span className="text-[11px] text-gray-500">
              Raw results ({rawRows.length} rows)
            </span>
          </button>
          {showRaw && (
            <div className="px-4 pb-3 overflow-x-auto">
              <pre className="bg-gray-950 rounded p-2 text-[10px] text-gray-400 font-mono whitespace-pre-wrap max-h-64 overflow-y-auto">
                {JSON.stringify(rawRows.slice(0, 20), null, 2)}
                {rawRows.length > 20 && `\n… (${rawRows.length - 20} more rows)`}
              </pre>
            </div>
          )}
        </div>
      )}

      {result.status === 'failed' && !result.interpreted_findings && (
        <div className="px-4 py-3 border-t border-gray-800/60">
          <p className="text-xs text-red-400">Execution failed. Check connector configuration and SPL syntax.</p>
        </div>
      )}
    </div>
  )
}

// ── Main panel ────────────────────────────────────────────────────────────────

export default function ExecutionPanel({
  pkgId,
  runId,
  retrohunt,
}: {
  pkgId: string
  runId?: string
  retrohunt?: THDeepRetrohuntLead | null
}) {
  const { isResearcher } = useAuth()
  const qc = useQueryClient()

  const [selectedConnector, setSelectedConnector] = useState('')
  const [spl, setSpl] = useState(retrohunt?.spl_draft ?? '')
  const [earliest, setEarliest] = useState('-24h')
  const [latest, setLatest] = useState('now')

  // Load connectors
  const { data: connectors = [] } = useQuery({
    queryKey: ['siem-connectors'],
    queryFn: () => api.threatHunting.listConnectors(),
  })

  // Poll results — scoped to run when runId is provided
  const { data: results = [] } = useQuery({
    queryKey: ['th-results', pkgId, runId],
    queryFn: () => {
      if (runId) return api.threatHunting.listRunResults(pkgId, runId)
      return api.threatHunting.listResults(pkgId)
    },
    refetchInterval: (query) => {
      const rows = query.state.data as THTaskResult[] | undefined
      return rows?.some((r) => r.status === 'running' || r.is_running) ? 3000 : false
    },
  })

  const executeMut = useMutation({
    mutationFn: () =>
      api.threatHunting.executeHunt(pkgId, {
        connector_id: selectedConnector,
        spl,
        earliest,
        latest,
        run_id: runId ?? null,
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['th-results', pkgId, runId] }),
  })

  const hasRunning = results.some((r) => r.status === 'running' || r.is_running)
  const canExecute = isResearcher && selectedConnector && spl.trim() && !hasRunning

  return (
    <div className="space-y-5">
      {/* Execution form */}
      {isResearcher && (
        <div className="card space-y-4">
          <h3 className="text-sm font-semibold text-gray-200">Start SIEM Execution</h3>

          {connectors.length === 0 ? (
            <div className="flex items-start gap-2 p-3 rounded-lg bg-amber-900/10 border border-amber-800/30">
              <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
              <p className="text-xs text-amber-300">
                No SIEM connectors configured. Add a connector in{' '}
                <span className="font-semibold">Configuration → General → SIEM Connectors</span>.
              </p>
            </div>
          ) : (
            <>
              {/* Connector selector */}
              <div>
                <label className="label">SIEM Connector</label>
                <select
                  className="input w-full"
                  value={selectedConnector}
                  onChange={(e) => setSelectedConnector(e.target.value)}
                >
                  <option value="">— Select connector —</option>
                  {connectors.map((c: THSiemConnector) => (
                    <option key={c.id} value={c.id}>
                      {c.name} ({c.base_url})
                      {c.verified ? ' ✓' : ''}
                    </option>
                  ))}
                </select>
              </div>

              {/* Time range */}
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="label">Earliest</label>
                  <input
                    className="input w-full font-mono"
                    value={earliest}
                    onChange={(e) => setEarliest(e.target.value)}
                    placeholder="-24h"
                  />
                </div>
                <div>
                  <label className="label">Latest</label>
                  <input
                    className="input w-full font-mono"
                    value={latest}
                    onChange={(e) => setLatest(e.target.value)}
                    placeholder="now"
                  />
                </div>
              </div>

              {/* SPL editor */}
              <div>
                <label className="label">
                  SPL Query
                  {retrohunt?.spl_draft && (
                    <button
                      className="ml-2 text-[10px] text-brand-400 hover:text-brand-300"
                      onClick={() => setSpl(retrohunt.spl_draft)}
                    >
                      Reset to generated draft
                    </button>
                  )}
                </label>
                <textarea
                  className="input w-full font-mono text-[11px] leading-relaxed resize-y"
                  rows={8}
                  value={spl}
                  onChange={(e) => setSpl(e.target.value)}
                  placeholder="| search index=main ..."
                  spellCheck={false}
                />
                {!spl.trim() && (
                  <p className="text-[10px] text-amber-400 mt-1">SPL query is required.</p>
                )}
              </div>

              {/* Submit */}
              <div className="flex items-center gap-3">
                <button
                  className="btn-primary flex items-center gap-2 text-xs"
                  disabled={!canExecute || executeMut.isPending}
                  onClick={() => executeMut.mutate()}
                >
                  {executeMut.isPending ? (
                    <Loader2 className="w-3.5 h-3.5 animate-spin" />
                  ) : (
                    <Play className="w-3.5 h-3.5" />
                  )}
                  {hasRunning ? 'Execution running…' : 'Execute Hunt'}
                </button>
                {executeMut.isError && (
                  <p className="text-xs text-red-400">
                    {executeMut.error instanceof Error
                      ? executeMut.error.message
                      : 'Execution failed'}
                  </p>
                )}
              </div>
            </>
          )}
        </div>
      )}

      {/* Results */}
      <div className="space-y-3">
        <div className="flex items-center gap-2">
          <Search className="w-4 h-4 text-gray-500" />
          <h4 className="text-xs font-semibold text-gray-400 uppercase tracking-wider">
            Execution Results
            {results.length > 0 && (
              <span className="ml-2 text-gray-600 normal-case font-normal">
                ({results.length})
              </span>
            )}
          </h4>
        </div>

        {results.length === 0 ? (
          <p className="text-sm text-gray-600 italic">No executions yet.</p>
        ) : (
          results.map((r) => (
            <ResultCard key={r.id} result={r} />
          ))
        )}
      </div>
    </div>
  )
}
