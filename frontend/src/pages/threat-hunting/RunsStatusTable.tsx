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
  return (
    <span className="text-[10px] whitespace-nowrap">
      <span className="text-green-400">{run.sanitized_ioc_count ?? 0} sanitized</span>
      <span className="text-gray-600"> · </span>
      <span className="text-red-400">{run.removed_ioc_count ?? 0} removed</span>
    </span>
  )
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

  const linkClass = 'text-gray-500 hover:text-brand-400 transition-colors'
  return (
    <span className="flex items-center gap-2">
      <a
        href={api.threatHunting.downloadRunReportMarkdown(pkgId, run.id)}
        className={linkClass}
        title="Download report as Markdown"
      >
        <FileText className="w-3.5 h-3.5" />
      </a>
      <a
        href={api.threatHunting.downloadRunReportPdf(pkgId, run.id)}
        className={linkClass}
        title="Download report as PDF"
      >
        <FileCode2 className="w-3.5 h-3.5" />
      </a>
      <button type="button" onClick={() => void downloadJson()} className={linkClass} title="Download report as JSON">
        <FileJson className="w-3.5 h-3.5" />
      </button>
    </span>
  )
}

export default function RunsStatusTable({
  pkgId,
  runs,
  onSelectRun,
}: {
  pkgId: string
  runs: THuntPackageRun[]
  /** issue-local-018: when provided, the Run ID and Model cells render as
   *  clickable buttons that open this specific run (rather than the
   *  package's newest run). Omitted call sites stay plain text. */
  onSelectRun?: (runId: string) => void
}) {
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
          </tr>
        </thead>
        <tbody>
          {runs.map((run) => (
            <tr key={run.id} className="border-t border-gray-800/60">
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
                    {run.llm_model ?? run.llm_provider ?? '—'}
                  </button>
                ) : (
                  run.llm_model ?? run.llm_provider ?? '—'
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
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
