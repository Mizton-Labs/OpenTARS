/**
 * RunsStatusTable (issue-local-017) — compact overview of every run for a
 * hunt package, shown below the run-selector dropdown in HuntDetail.tsx:
 * one row per run with the model used, its status, and the same coarse
 * workflow-with-arrows visualization PipelineStepper.tsx shows for the
 * single selected run (Evidence → IOC → Analysis → Execution → Report),
 * so the whole run history's progress is visible at a glance without
 * switching the run selector back and forth.
 *
 * Derives phase state purely from each run's persisted `phases` (the
 * step_logs projection already returned by list_generation_runs — no
 * per-run extra fetches), unlike PipelineStepper's header usage which
 * reads a live `THGenerationRecord` for the single active run.
 */
import { CheckCircle, XCircle, Loader2, ArrowRight, FileText, FileCode2, FileJson } from 'lucide-react'
import { clsx } from 'clsx'
import { useQuery } from '@tanstack/react-query'
import { api, type THuntPackageRun } from '../../api/client'
import { runStatusClass } from './runStatusUtils'

type PhaseState = 'done' | 'active' | 'error' | 'pending'

const ANALYSIS_STEPS = [
  'threat_context_builder',
  'deep_retrohunt_planner',
  'hypothesis_generator',
  'hunting_lead_planner',
  'ttp_analyst',
  'query_drafting_agent',
]

function deriveCoarsePhases(run: THuntPackageRun): { label: string; state: PhaseState }[] {
  const stepStatus = new Map((run.phases ?? []).map((p) => [p.step, p.status]))
  const has = (step: string) => stepStatus.has(step)
  const isErr = (step: string) => stepStatus.get(step) === 'error'
  const status = run.generation_status
  const running = status === 'running'
  const analysisDone = status === 'awaiting_approval' || status === 'approved' || status === 'completed'

  return [
    { label: 'Evidence', state: 'done' as PhaseState },
    {
      label: 'IOC',
      state: has('intake_classifier')
        ? isErr('intake_classifier')
          ? 'error'
          : 'done'
        : running
          ? 'active'
          : 'pending',
    },
    {
      label: 'Analysis',
      state: analysisDone
        ? 'done'
        : ANALYSIS_STEPS.some(isErr)
          ? 'error'
          : running && ANALYSIS_STEPS.some(has)
            ? 'active'
            : 'pending',
    },
    {
      label: 'Execution',
      state: has('siem_interpret')
        ? isErr('siem_interpret')
          ? 'error'
          : 'done'
        : status === 'executing'
          ? 'active'
          : 'pending',
    },
    {
      label: 'Report',
      state: has('report_render')
        ? isErr('report_render')
          ? 'error'
          : 'done'
        : status === 'reporting'
          ? 'active'
          : 'pending',
    },
  ]
}

function MiniPhaseTrack({ run }: { run: THuntPackageRun }) {
  const phases = deriveCoarsePhases(run)
  return (
    <div className="flex items-center gap-0.5 flex-wrap">
      {phases.map((phase, idx) => (
        <div key={phase.label} className="flex items-center shrink-0">
          <div
            className={clsx(
              'flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-medium whitespace-nowrap',
              phase.state === 'done' && 'bg-green-900/20 text-green-400',
              phase.state === 'error' && 'bg-red-900/20 text-red-400',
              phase.state === 'active' && 'bg-blue-900/20 text-blue-300',
              phase.state === 'pending' && 'bg-gray-800/30 text-gray-600',
            )}
          >
            {phase.state === 'done' && <CheckCircle className="w-2.5 h-2.5 shrink-0" />}
            {phase.state === 'error' && <XCircle className="w-2.5 h-2.5 shrink-0" />}
            {phase.state === 'active' && <Loader2 className="w-2.5 h-2.5 shrink-0 animate-spin" />}
            {phase.label}
          </div>
          {idx < phases.length - 1 && <ArrowRight className="w-2.5 h-2.5 mx-0.5 text-gray-700 shrink-0" />}
        </div>
      ))}
    </div>
  )
}

// issue-local-018: no seconds -> "Xm Ys" formatter existed anywhere in the
// frontend yet (total_elapsed_s was only ever shown raw, e.g. "12s total").
function formatDuration(seconds: number | null | undefined): string {
  if (seconds == null) return '—'
  const total = Math.round(seconds)
  if (total < 60) return `${total}s`
  const minutes = Math.floor(total / 60)
  const rest = total % 60
  return `${minutes}m ${rest}s`
}

function IocCounts({ run }: { run: THuntPackageRun }) {
  if (run.sanitized_ioc_count == null && run.removed_ioc_count == null) {
    return <span className="text-[10px] text-gray-600">—</span>
  }
  const sanitized = run.sanitized_ioc_count ?? 0
  const removed = run.removed_ioc_count ?? 0
  return (
    <span className="text-[10px] whitespace-nowrap">
      <span className="text-green-400">{sanitized} sanitized</span>
      <span className="text-gray-600"> · </span>
      <span className="text-red-400">{removed} removed</span>
      {/* issue-local-026: explicit total, always the sum shown alongside it —
          never a separately-computed number that could drift from these two. */}
      <span className="text-gray-500"> · {sanitized + removed} total</span>
    </span>
  )
}

// issue-local-026: runner.py now resolves "Configured default" to the
// actual provider/model at run-start time and persists that on the run row,
// so llm_model is populated for every NEW run going forward. This fallback
// only matters for runs created before that backend fix, whose
// llm_provider/llm_model are still NULL — resolve what the CURRENT default
// is via the LLM config so those legacy rows don't show a bare "—" either
// (best-effort only: for a legacy row this reflects today's default, which
// may differ from what was actually used back when that run ran). Shared
// queryKey across every RunsStatusTable instance on a page, so react-query
// dedupes this to a single fetch regardless of how many run tables render.
function useDefaultModelLabel(): string | null {
  const { data } = useQuery({
    queryKey: ['llm-config-default-model'],
    queryFn: () => api.llm.getConfig(),
    staleTime: 60_000,
  })
  if (!data?.default_provider) return null
  const provider = data.providers.find((p) => p.name === data.default_provider)
  if (!provider) return `Default (${data.default_provider})`
  return provider.model ? `Default (${provider.model})` : `Default (${data.default_provider})`
}

// issue-local-017: MD/PDF download directly via <a href> (the backend
// serves those formats from GET routes); JSON has no server-side download
// route (ReportPanel.tsx's exportJson builds it client-side from the
// already-fetched report object) — so this fetches on click, mirroring
// that same client-side Blob/URL.createObjectURL pattern.
function ReportLinks({ pkgId, run }: { pkgId: string; run: THuntPackageRun }) {
  if (!run.has_report) {
    return <span className="text-[10px] text-gray-600">—</span>
  }

  async function downloadJson() {
    const report = await api.threatHunting.getRunReport(pkgId, run.id)
    const blob = new Blob([JSON.stringify(report.full_report, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `hunt-report-${run.id.slice(0, 8)}.json`
    a.click()
    URL.revokeObjectURL(url)
  }

  const linkClass = 'flex items-center gap-1 text-gray-500 hover:text-brand-400 transition-colors'
  const badgeClass = 'text-[9px] font-bold px-1 py-0.5 rounded leading-none tracking-wide'
  return (
    <span className="flex items-center gap-2">
      <a
        href={api.threatHunting.downloadRunReportMarkdown(pkgId, run.id)}
        className={linkClass}
        title="Download report as Markdown"
      >
        <FileText className="w-3.5 h-3.5" />
        <span className={clsx(badgeClass, 'bg-blue-900/40 text-blue-300')}>MD</span>
      </a>
      <a
        href={api.threatHunting.downloadRunReportPdf(pkgId, run.id)}
        className={linkClass}
        title="Download report as PDF"
      >
        <FileCode2 className="w-3.5 h-3.5" />
        <span className={clsx(badgeClass, 'bg-red-900/40 text-red-300')}>PDF</span>
      </a>
      <button type="button" onClick={() => void downloadJson()} className={linkClass} title="Download report as JSON">
        <FileJson className="w-3.5 h-3.5" />
        <span className={clsx(badgeClass, 'bg-amber-900/40 text-amber-300')}>JSON</span>
      </button>
    </span>
  )
}

export default function RunsStatusTable({
  pkgId,
  runs,
  onSelectRun,
  activeRunId,
}: {
  pkgId: string
  runs: THuntPackageRun[]
  /** issue-local-018: when provided, the Run ID and Model cells render as
   *  clickable buttons that open this specific run (rather than the
   *  package's newest run). Omitted call sites stay plain text. */
  onSelectRun?: (runId: string) => void
  /** issue-local-021: when provided, highlights the row matching this run id
   *  as the currently-open/selected run. */
  activeRunId?: string
}) {
  const defaultModelLabel = useDefaultModelLabel()
  if (runs.length === 0) return null
  const cellLinkClass = 'hover:text-brand-400 hover:underline transition-colors text-left'
  return (
    <div className="overflow-x-auto rounded-lg border border-gray-800">
      <table className="w-full min-w-[900px]">
        <thead>
          <tr className="bg-gray-800/50 text-[10px] uppercase tracking-wider text-gray-500">
            <th className="text-left py-1.5 px-2">Run ID</th>
            <th className="text-left py-1.5 px-2">Model</th>
            <th className="text-left py-1.5 px-2">Status</th>
            <th className="text-left py-1.5 px-2">Workflow</th>
            <th className="text-left py-1.5 px-2">Duration</th>
            <th className="text-left py-1.5 px-2">IOCs</th>
            <th className="text-left py-1.5 px-2">Report</th>
            <th className="text-left py-1.5 px-2">Created</th>
            <th className="text-left py-1.5 px-2">Created by</th>
          </tr>
        </thead>
        <tbody>
          {runs.map((run) => (
            <tr
              key={run.id}
              className={clsx(
                'border-t border-gray-800/60',
                run.id === activeRunId && 'bg-brand-900/20 border-l-2 border-l-brand-500',
              )}
            >
              <td className="py-1.5 px-2 text-[11px] text-gray-300 font-mono whitespace-nowrap">
                {onSelectRun ? (
                  <button type="button" onClick={() => onSelectRun(run.id)} className={cellLinkClass}>
                    {run.run_id_display || '—'}
                  </button>
                ) : (
                  run.run_id_display || '—'
                )}
              </td>
              <td className="py-1.5 px-2 text-[11px] text-gray-200 font-mono whitespace-nowrap">
                {onSelectRun ? (
                  <button type="button" onClick={() => onSelectRun(run.id)} className={cellLinkClass}>
                    {run.llm_model ?? run.llm_provider ?? defaultModelLabel ?? '—'}
                  </button>
                ) : (
                  run.llm_model ?? run.llm_provider ?? defaultModelLabel ?? '—'
                )}
                {run.research_effort && <span className="text-gray-600"> · {run.research_effort}</span>}
              </td>
              <td className="py-1.5 px-2">
                <span className={clsx('text-[10px] px-1.5 py-0.5 rounded whitespace-nowrap', runStatusClass(run.generation_status))}>
                  {run.generation_status}
                </span>
              </td>
              <td className="py-1.5 px-2">
                <MiniPhaseTrack run={run} />
              </td>
              <td className="py-1.5 px-2 text-[10px] text-gray-400 whitespace-nowrap">
                {formatDuration(run.total_elapsed_s)}
              </td>
              <td className="py-1.5 px-2">
                <IocCounts run={run} />
              </td>
              <td className="py-1.5 px-2">
                <ReportLinks pkgId={pkgId} run={run} />
              </td>
              <td className="py-1.5 px-2 text-[10px] text-gray-500 whitespace-nowrap">
                {run.created_at.slice(0, 19).replace('T', ' ')}
              </td>
              <td className="py-1.5 px-2 text-[10px] text-gray-500 whitespace-nowrap">
                {run.created_by ?? '—'}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
