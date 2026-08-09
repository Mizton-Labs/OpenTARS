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
import { useEffect, useState } from 'react'
import {
  CheckCircle,
  XCircle,
  Loader2,
  ArrowRight,
  FileText,
  FileCode2,
  FileJson,
  Archive,
  ArchiveRestore,
  Trash2,
  ChevronLeft,
  ChevronRight,
} from 'lucide-react'
import { clsx } from 'clsx'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api, type THuntPackageRun } from '../../api/client'
import { runStatusClass } from './runStatusUtils'
import ConfirmDialog from '../../components/ConfirmDialog'

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
    // issue-local-041: the ONE column that must stay single-line ("so that
    // the progress is seen clearly from left to right") while every other
    // cell in this table now wraps — flex-nowrap (was flex-wrap, which had
    // this backwards: the phase track wrapped while text cells forced
    // horizontal scroll instead).
    <div className="flex items-center gap-0.5 flex-nowrap whitespace-nowrap">
      {phases.map((phase, idx) => (
        <div key={phase.label} className="flex items-center shrink-0">
          <div
            className={clsx(
              'flex items-center gap-1 px-1.5 py-0.5 rounded text-[11px] font-medium whitespace-nowrap',
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
    return <span className="text-[11px] text-gray-600">—</span>
  }
  const sanitized = run.sanitized_ioc_count ?? 0
  const removed = run.removed_ioc_count ?? 0
  return (
    // issue-local-026: explicit total, always the sum shown alongside it —
    // never a separately-computed number that could drift from these two.
    // issue-local-042 (item 26): sanitized/removed/total must always stay
    // on one line (superseding item 11's separate-row total) — whitespace-
    // nowrap here, matched by the same class on the parent <td>, keeps the
    // column growing to fit this text rather than letting it wrap.
    <span className="text-[11px] whitespace-nowrap">
      <span className="text-green-400">{sanitized} sanitized</span>
      <span className="text-gray-600"> · </span>
      <span className="text-red-400">{removed} removed</span>
      <span className="text-gray-600"> · </span>
      <span className="text-gray-500">{sanitized + removed} total</span>
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

// issue-local-042 (item 27): configured page size for this table — same
// setting whether it's embedded per-package in the Hunt Packages list
// (Table view) or shown for a single open package, so it's read here once
// rather than threaded through as a prop by every call site. Shared
// queryKey across instances, same dedupe reasoning as useDefaultModelLabel.
function useRunsTablePageSize(): number {
  const { data } = useQuery({
    queryKey: ['th-runs-table-page-size'],
    queryFn: () => api.getThRunsTablePageSize(),
    staleTime: 60_000,
  })
  return data?.th_runs_table_page_size ?? 10
}

// issue-local-017: MD/PDF download directly via <a href> (the backend
// serves those formats from GET routes); JSON has no server-side download
// route (ReportPanel.tsx's exportJson builds it client-side from the
// already-fetched report object) — so this fetches on click, mirroring
// that same client-side Blob/URL.createObjectURL pattern.
function ReportLinks({ pkgId, run }: { pkgId: string; run: THuntPackageRun }) {
  if (!run.has_report) {
    return <span className="text-[11px] text-gray-600">—</span>
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
  const badgeClass = 'text-[10px] font-bold px-1 py-0.5 rounded leading-none tracking-wide'
  // issue-local-042 (item 25): one download format per row (was all three
  // packed onto a single line) — narrower and easier to scan, and lets the
  // Report column itself shrink to fit instead of stretching the table.
  return (
    <span className="flex flex-col items-start gap-1">
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

// issue-local-034: archived runs are excluded from nothing today (this table
// always lists every run of the package) — the badge is the only indicator.
function ArchivedBadge() {
  return (
    <span className="text-[11px] px-1.5 py-0.5 rounded bg-gray-800 text-gray-400 border border-gray-700 whitespace-nowrap">
      Archived
    </span>
  )
}

// issue-local-034: Archive/Unarchive (researcher+, reversible) and hard
// Delete (admin-only, irreversible — cascades through every table that
// references this run) actions for a single run row.
function RunActions({
  pkgId,
  run,
  isResearcher,
  isAdmin,
}: {
  pkgId: string
  run: THuntPackageRun
  isResearcher: boolean
  isAdmin: boolean
}) {
  const qc = useQueryClient()
  const [confirmDelete, setConfirmDelete] = useState(false)
  const [confirmCancel, setConfirmCancel] = useState(false)

  const archiveMut = useMutation({
    mutationFn: () => api.threatHunting.setRunArchived(pkgId, run.id, !run.archived),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['th-runs', pkgId] }),
  })
  const deleteMut = useMutation({
    mutationFn: () => api.threatHunting.hardDeleteRun(pkgId, run.id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['th-runs', pkgId] })
      qc.invalidateQueries({ queryKey: ['th-package', pkgId] })
      setConfirmDelete(false)
    },
  })
  // issue-local-042 (item 8): cancel used to be a single header button tied
  // to whichever run the run-selector happened to have active — moved here
  // so it's scoped to the specific row's run, and reachable for any running
  // run without first switching the selector to it.
  const cancelMut = useMutation({
    mutationFn: () => api.threatHunting.cancelRun(pkgId, run.id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['th-runs', pkgId] })
      qc.invalidateQueries({ queryKey: ['th-generation', pkgId, run.id] })
      setConfirmCancel(false)
    },
  })

  if (!isResearcher && !isAdmin) return null

  return (
    <span className="flex items-center gap-2">
      {isResearcher && run.generation_status === 'running' && (
        <button
          type="button"
          onClick={() => setConfirmCancel(true)}
          disabled={cancelMut.isPending}
          className="text-gray-500 hover:text-red-400 transition-colors disabled:opacity-50"
          title="Cancel this run"
        >
          <XCircle className="w-3.5 h-3.5" />
        </button>
      )}
      {isResearcher && (
        <button
          type="button"
          onClick={() => archiveMut.mutate()}
          disabled={archiveMut.isPending}
          className="text-gray-500 hover:text-gray-300 transition-colors disabled:opacity-50"
          title={run.archived ? 'Unarchive run' : 'Archive run'}
        >
          {run.archived ? <ArchiveRestore className="w-3.5 h-3.5" /> : <Archive className="w-3.5 h-3.5" />}
        </button>
      )}
      {isAdmin && (
        <button
          type="button"
          onClick={() => setConfirmDelete(true)}
          className="text-gray-500 hover:text-red-400 transition-colors"
          title="Permanently delete run"
        >
          <Trash2 className="w-3.5 h-3.5" />
        </button>
      )}
      {confirmCancel && (
        <ConfirmDialog
          title="Cancel this run?"
          message={`This stops ${run.run_id_display || 'this run'} in place — progress made so far is kept, but the run will not continue.`}
          confirmLabel="Cancel run"
          onConfirm={() => cancelMut.mutate()}
          onCancel={() => setConfirmCancel(false)}
        />
      )}
      {confirmDelete && (
        <ConfirmDialog
          title="Permanently Delete Run?"
          message={`This permanently deletes ${run.run_id_display || 'this run'} and every IOC, task result, report, comment, and threat-intel analysis tied to it. This cannot be undone — use Archive instead if you just want to hide it.`}
          confirmLabel="Delete Permanently"
          onConfirm={() => deleteMut.mutate()}
          onCancel={() => setConfirmDelete(false)}
        />
      )}
    </span>
  )
}

// issue-local-040: which sub-tab a run belongs to. Undefined/missing
// run_origin (runs created before this field existed) counts as 'manual'.
export type RunSubTab = 'runs' | 'playbook' | 'consolidated'

const SUB_TABS: { id: RunSubTab; label: string }[] = [
  { id: 'runs', label: 'Runs' },
  { id: 'playbook', label: 'Playbook Runs' },
  { id: 'consolidated', label: 'Consolidated Runs' },
]

export function subTabOf(run: THuntPackageRun): RunSubTab {
  return run.run_origin === 'playbook' ? 'playbook' : run.run_origin === 'consolidated' ? 'consolidated' : 'runs'
}

export default function RunsStatusTable({
  pkgId,
  runs,
  onSelectRun,
  activeRunId,
  isResearcher = false,
  isAdmin = false,
  subTab: subTabProp,
  onSubTabChange,
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
  /** issue-local-034: gates the Actions column — Archive/Unarchive needs
   *  researcher+, permanent Delete needs admin. Both default to false
   *  (hidden) for read-only call sites that don't pass them. */
  isResearcher?: boolean
  isAdmin?: boolean
  /** issue-local-041: when provided (with onSubTabChange), the sub-tab
   *  becomes controlled by the parent — used by HuntDetail so switching to
   *  "Consolidated Runs"/"Playbook Runs" can also drive which run's content
   *  the tabs below show, instead of only filtering this table's rows.
   *  Omitted call sites (e.g. the dashboard) keep the previous
   *  self-contained/uncontrolled behavior. */
  subTab?: RunSubTab
  onSubTabChange?: (tab: RunSubTab) => void
}) {
  const defaultModelLabel = useDefaultModelLabel()
  const runsPageSize = useRunsTablePageSize()
  const [internalSubTab, setInternalSubTab] = useState<RunSubTab>('runs')
  const subTab = subTabProp ?? internalSubTab
  // issue-local-042 (item 27): page within the current sub-tab's runs.
  const [runsPage, setRunsPage] = useState(1)
  useEffect(() => {
    setRunsPage(1)
  }, [subTab])
  function handleSubTabChange(tab: RunSubTab) {
    setInternalSubTab(tab)
    onSubTabChange?.(tab)
  }
  if (runs.length === 0) return null
  const cellLinkClass = 'hover:text-brand-400 hover:underline transition-colors text-left'
  const showActions = isResearcher || isAdmin
  const counts: Record<RunSubTab, number> = { runs: 0, playbook: 0, consolidated: 0 }
  for (const run of runs) counts[subTabOf(run)] += 1
  const visibleRuns = runs.filter((run) => subTabOf(run) === subTab)
  const totalRunsPages = Math.max(1, Math.ceil(visibleRuns.length / runsPageSize))
  const clampedRunsPage = Math.min(runsPage, totalRunsPages)
  const pagedVisibleRuns = visibleRuns.slice(
    (clampedRunsPage - 1) * runsPageSize,
    clampedRunsPage * runsPageSize,
  )
  // issue-local-041: "a sum for the whole Hunt package" — every run in the
  // package, regardless of which sub-tab is currently selected.
  const packageTokenTotal = runs.reduce(
    (sum, run) => sum + (run.token_usage_total?.total_tokens ?? 0),
    0,
  )
  const packageHasTokenData = runs.some((run) => run.token_usage_total?.total_tokens != null)
  return (
    <div className="space-y-1.5">
      <nav className="flex gap-1 text-[12px]">
        {SUB_TABS.map((tab) => (
          <button
            key={tab.id}
            type="button"
            onClick={() => handleSubTabChange(tab.id)}
            className={clsx(
              'px-2 py-1 rounded transition-colors font-medium',
              subTab === tab.id
                ? 'bg-brand-900/30 text-brand-300'
                : 'text-gray-500 hover:text-gray-300',
            )}
          >
            {tab.label} <span className="text-gray-600">({counts[tab.id]})</span>
          </button>
        ))}
      </nav>
      {visibleRuns.length === 0 ? (
        <p className="text-xs text-gray-600 italic py-2">
          No {SUB_TABS.find((t) => t.id === subTab)?.label.toLowerCase()} yet.
        </p>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-gray-800">
          {/* issue-local-041: no forced min-width — most columns below wrap
              their text content so rows grow taller instead of forcing a
              fixed table width + horizontal scroll for normal viewing.
              issue-local-042 (item 10): Run ID joins Workflow/phases as a
              column that stays single-line instead — Model/IOCs/Created
              deliberately split their content across two fixed rows within
              the cell (items 11-13) rather than wrapping freely. */}
          <table className="w-full">
            <thead>
              <tr className="bg-gray-800/50 text-[11px] uppercase tracking-wider text-gray-500">
                <th className="text-left py-1.5 px-2">Run ID</th>
                <th className="text-left py-1.5 px-2">Model</th>
                <th className="text-left py-1.5 px-2">Status</th>
                <th className="text-left py-1.5 px-2">Workflow</th>
                <th className="text-left py-1.5 px-2">Duration</th>
                <th className="text-left py-1.5 px-2">IOCs</th>
                <th className="text-left py-1.5 px-2 w-px whitespace-nowrap">Report</th>
                <th className="text-left py-1.5 px-2">Created</th>
                <th className="text-left py-1.5 px-2">Created by</th>
                {showActions && <th className="text-left py-1.5 px-2">Actions</th>}
              </tr>
            </thead>
            <tbody>
              {pagedVisibleRuns.map((run) => (
                <tr
                  key={run.id}
                  className={clsx(
                    'border-t border-gray-800/60',
                    run.id === activeRunId && 'bg-brand-900/20 border-l-2 border-l-brand-500',
                  )}
                >
                  {/* issue-local-042 (item 10): run ID never wraps to a
                      second row, unlike most other cells in this table. */}
                  <td className="py-1.5 px-2 text-[12px] text-gray-300 font-mono whitespace-nowrap">
                    <span className="flex items-center gap-1.5">
                      {onSelectRun ? (
                        <button type="button" onClick={() => onSelectRun(run.id)} className={cellLinkClass}>
                          {run.run_id_display || '—'}
                        </button>
                      ) : (
                        run.run_id_display || '—'
                      )}
                      {run.archived && <ArchivedBadge />}
                    </span>
                  </td>
                  {/* issue-local-042 (item 13): model name and effort on
                      their own rows within the cell. */}
                  <td className="py-1.5 px-2 text-[12px] text-gray-200 font-mono break-words">
                    <span className="block">
                      {onSelectRun ? (
                        <button type="button" onClick={() => onSelectRun(run.id)} className={cellLinkClass}>
                          {run.llm_model ?? run.llm_provider ?? defaultModelLabel ?? '—'}
                        </button>
                      ) : (
                        run.llm_model ?? run.llm_provider ?? defaultModelLabel ?? '—'
                      )}
                    </span>
                    {run.research_effort && (
                      <span className="block text-[11px] text-gray-600">{run.research_effort}</span>
                    )}
                    {/* issue-local-040: playbook provenance — a consolidated
                        (recommendation-synthesis) run started from inside a
                        playbook still carries its playbook_id/name. */}
                    {run.playbook_name && (
                      <span className="block mt-0.5 text-[10px] px-1 py-0.5 rounded bg-purple-900/30 text-purple-300 whitespace-nowrap w-fit">
                        {run.run_origin === 'consolidated' ? 'consolidated · ' : 'playbook · '}
                        {run.playbook_name}
                      </span>
                    )}
                  </td>
                  <td className="py-1.5 px-2">
                    <span className={clsx('text-[11px] px-1.5 py-0.5 rounded whitespace-nowrap', runStatusClass(run.generation_status))}>
                      {run.generation_status}
                    </span>
                  </td>
                  <td className="py-1.5 px-2 whitespace-nowrap">
                    <MiniPhaseTrack run={run} />
                  </td>
                  <td className="py-1.5 px-2 text-[11px] text-gray-400 break-words">
                    {formatDuration(run.total_elapsed_s)}
                    {/* issue-local-041: per-run token total, alongside the
                        other run-level stat (duration) — applies at every
                        logging level, not just debug. */}
                    {run.token_usage_total?.total_tokens != null && (
                      <span className="block text-amber-600">
                        {run.token_usage_total.total_tokens.toLocaleString()} tok
                      </span>
                    )}
                  </td>
                  <td className="py-1.5 px-2 whitespace-nowrap">
                    <IocCounts run={run} />
                  </td>
                  <td className="py-1.5 px-2 w-px">
                    <ReportLinks pkgId={pkgId} run={run} />
                  </td>
                  {/* issue-local-042 (item 12): date on its own row, time on
                      the next, within the cell. */}
                  <td className="py-1.5 px-2 text-[11px] text-gray-500 whitespace-nowrap">
                    <span className="block">{run.created_at.slice(0, 10)}</span>
                    <span className="block text-gray-600">{run.created_at.slice(11, 19)}</span>
                  </td>
                  <td className="py-1.5 px-2 text-[11px] text-gray-500 break-words">
                    {run.created_by ?? '—'}
                  </td>
                  {showActions && (
                    <td className="py-1.5 px-2">
                      <RunActions pkgId={pkgId} run={run} isResearcher={isResearcher} isAdmin={isAdmin} />
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {/* issue-local-042 (item 27): pagination footer for the current
          sub-tab's runs — only shown once there's more than one page. */}
      {totalRunsPages > 1 && (
        <div className="flex items-center justify-center gap-3 text-[11px] text-gray-500">
          <button
            type="button"
            className="btn btn-secondary px-1.5 py-0.5"
            disabled={clampedRunsPage <= 1}
            onClick={() => setRunsPage((p) => Math.max(1, p - 1))}
            aria-label="Previous runs page"
          >
            <ChevronLeft className="w-3.5 h-3.5" />
          </button>
          <span>
            Page {clampedRunsPage} of {totalRunsPages} · {visibleRuns.length} run
            {visibleRuns.length === 1 ? '' : 's'}
          </span>
          <button
            type="button"
            className="btn btn-secondary px-1.5 py-0.5"
            disabled={clampedRunsPage >= totalRunsPages}
            onClick={() => setRunsPage((p) => Math.min(totalRunsPages, p + 1))}
            aria-label="Next runs page"
          >
            <ChevronRight className="w-3.5 h-3.5" />
          </button>
        </div>
      )}
      {/* issue-local-041: package-wide token total, across every run
          regardless of the selected sub-tab. */}
      {packageHasTokenData && (
        <p className="text-[11px] text-amber-600 text-right pr-1">
          Hunt package total: {packageTokenTotal.toLocaleString()} tokens across {runs.length} run
          {runs.length === 1 ? '' : 's'}
        </p>
      )}
    </div>
  )
}
