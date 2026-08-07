/**
 * ComparisonAssessmentTab — "Comparison Assessment" tab (issue-local-020).
 *
 * Read-only display of the latest comparison report for a hunt package, plus
 * (issue-local-021) a self-contained "Assess & Compare" action — mirroring
 * ThreatIntelTab.tsx's pattern of owning its own primary CTA + dialog rather
 * than relying on a page-level header button. Opens a run-picker + model
 * dropdown (all runs selected by default) before triggering
 * backend.threat_hunting.agents.nodes.comparison_analyst.
 *
 * Shows a deterministic per-run diff table (visual grammar matching
 * RunsStatusTable.tsx) plus the LLM-generated narrative sections, with
 * MD/PDF/JSON download links mirroring RunsStatusTable.tsx's ReportLinks
 * icon+badge pattern (issue-local-019).
 */
import { useState, useMemo, useEffect, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { clsx } from 'clsx'
import {
  GitCompare,
  Loader2,
  FileText,
  FileCode2,
  FileJson,
  AlertTriangle,
  Lightbulb,
  Sparkles,
  X,
  ChevronDown,
  Layers,
  RefreshCw,
  ListChecks,
  CheckCircle2,
  Wand2,
} from 'lucide-react'
import {
  api,
  type THComparisonReport,
  type THComparisonJob,
  type THuntPackageRun,
  type LLMProviderSummary,
} from '../../api/client'
import { useAuth } from '../../auth/useAuth'
import { runLabel } from './runStatusUtils'
import ComparisonProgress from './ComparisonProgress'

function downloadJson(report: THComparisonReport) {
  const blob = new Blob([JSON.stringify(report.full_report, null, 2)], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `hunt-comparison-${report.hunt_package_id.slice(0, 8)}.json`
  a.click()
  URL.revokeObjectURL(url)
}

function ComparisonDownloadLinks({
  pkgId,
  report,
  phase,
}: {
  pkgId: string
  report: THComparisonReport
  phase: 'preliminary' | 'full'
}) {
  const linkClass = 'flex items-center gap-1 text-gray-500 hover:text-brand-400 transition-colors'
  const badgeClass = 'text-[9px] font-bold px-1 py-0.5 rounded leading-none tracking-wide'
  return (
    <span className="flex items-center gap-3">
      <a
        href={api.threatHunting.downloadComparisonMarkdown(pkgId, phase)}
        className={linkClass}
        title="Download comparison as Markdown"
      >
        <FileText className="w-3.5 h-3.5" />
        <span className={clsx(badgeClass, 'bg-blue-900/40 text-blue-300')}>MD</span>
      </a>
      <a
        href={api.threatHunting.downloadComparisonPdf(pkgId, phase)}
        className={linkClass}
        title="Download comparison as PDF"
      >
        <FileCode2 className="w-3.5 h-3.5" />
        <span className={clsx(badgeClass, 'bg-red-900/40 text-red-300')}>PDF</span>
      </a>
      <button
        type="button"
        onClick={() => downloadJson(report)}
        className={linkClass}
        title="Download comparison as JSON"
      >
        <FileJson className="w-3.5 h-3.5" />
        <span className={clsx(badgeClass, 'bg-amber-900/40 text-amber-300')}>JSON</span>
      </button>
    </span>
  )
}

type ComparisonPhase = 'preliminary' | 'full'

/** issue-local-035: everything issue-local-020/021 built, now scoped to a
 *  single phase — mounted once per tab (keyed by phase in the parent) so
 *  each phase's dialog/query state stays fully isolated from the other. */
function ComparisonPhasePanel({
  pkgId,
  runs,
  phase,
}: {
  pkgId: string
  /** issue-local-021: needed for the Assess & Compare run picker. */
  runs: THuntPackageRun[]
  phase: ComparisonPhase
}) {
  const { isResearcher } = useAuth()
  const qc = useQueryClient()
  const navigate = useNavigate()

  const { data: latestReport, isLoading } = useQuery({
    queryKey: ['th-comparison', pkgId, phase],
    queryFn: () => api.threatHunting.getComparison(pkgId, phase).catch(() => null),
    retry: false,
  })

  // issue-local-040: every saved assessment for this phase, so a named one
  // stays reachable instead of being shadowed by the next "Assess & Compare".
  const { data: savedReports = [] } = useQuery({
    queryKey: ['th-comparisons', pkgId, phase],
    queryFn: () => api.threatHunting.listComparisons(pkgId, phase),
  })
  const [selectedReportId, setSelectedReportId] = useState<string>('')
  const report =
    selectedReportId && savedReports.length > 0
      ? (savedReports.find((r) => r.id === selectedReportId) ?? latestReport)
      : latestReport

  // issue-local-035 follow-up: the comparison now runs as a backend job
  // decoupled from this dialog — poll its status so progress renders
  // whether or not the triggering dialog (or even this tab) stayed open,
  // and stop polling once it reaches a terminal state.
  const { data: job } = useQuery({
    queryKey: ['th-comparison-job', pkgId, phase],
    queryFn: () => api.threatHunting.getComparisonJobStatus(pkgId, phase).catch(() => null),
    refetchInterval: (query) => {
      const status = (query.state.data as THComparisonJob | null)?.status
      return status === 'running' ? 2000 : false
    },
  })

  // Once the job completes, the report it produced needs to replace
  // whatever is currently shown — invalidate exactly once per completion,
  // not on every poll tick while it's already completed.
  const lastHandledJobId = useRef<string | null>(null)
  useEffect(() => {
    if (job?.status === 'completed' && lastHandledJobId.current !== job.id) {
      lastHandledJobId.current = job.id
      qc.invalidateQueries({ queryKey: ['th-comparison', pkgId, phase] })
      qc.invalidateQueries({ queryKey: ['th-comparisons', pkgId, phase] })
      // A freshly completed job's report is the one to look at — drop any
      // older saved-assessment selection so the new one shows immediately.
      setSelectedReportId('')
    }
  }, [job, qc, pkgId, phase])

  // issue-local-035: Recommended Combination card actions.
  const [showRerunPicker, setShowRerunPicker] = useState(false)
  const [rerunRunIds, setRerunRunIds] = useState<Set<string>>(new Set())

  const consolidateMut = useMutation({
    mutationFn: () => api.threatHunting.consolidateComparison(pkgId, phase),
  })

  const rerunMut = useMutation({
    mutationFn: (runIds: string[] | undefined) =>
      api.threatHunting.rerunFromRecommendation(pkgId, { run_ids: runIds, phase }),
    onSuccess: (result) => {
      setShowRerunPicker(false)
      navigate(`../${result.package.id}`, { relative: 'path' })
    },
  })

  // issue-local-040: "Create a new run from recommendations" — unlike
  // rerunMut above, this does NOT clone into a new package. It synthesizes
  // one consolidated plan from the compared runs' actual outputs and seeds
  // a new run IN THIS SAME PACKAGE (run_origin='consolidated'), surfaced by
  // the Hunt Packages page's "Consolidated Runs" sub-tab.
  const recommendationRunMut = useMutation({
    mutationFn: () => api.threatHunting.createRecommendationRun(pkgId, { phase }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['th-runs', pkgId] })
    },
  })

  // issue-local-021: Assess & Compare dialog — run picker (all selected by
  // default) + model dropdown.
  const [showCompareDialog, setShowCompareDialog] = useState(false)
  const [compareModelChoice, setCompareModelChoice] = useState('')
  const [compareRunIds, setCompareRunIds] = useState<Set<string>>(new Set())
  // issue-local-040: optional saved-assessment name; blank auto-names it
  // "manual_<timestamp>" server-side.
  const [compareName, setCompareName] = useState('')

  const { data: providers = [] } = useQuery({
    queryKey: ['llm-providers'],
    queryFn: () => api.llm.listProviders(),
    staleTime: 60_000,
    enabled: showCompareDialog,
  })

  const modelOptions = useMemo(() => {
    const opts: { provider: string; model: string }[] = []
    const seen = new Set<string>()
    for (const p of providers as LLMProviderSummary[]) {
      for (const m of p.available_models ?? []) {
        const key = `${p.name}\x00${m}`
        if (seen.has(key)) continue
        seen.add(key)
        opts.push({ provider: p.name, model: m })
      }
    }
    return opts
  }, [providers])

  const chosenModel = compareModelChoice !== '' ? (modelOptions[Number(compareModelChoice)] ?? null) : null

  // issue-local-035 follow-up: this used to await the whole comparison
  // (including the LLM call) inline and only close the dialog once a
  // report came back — closing the dialog or navigating away mid-request
  // killed it. Now it just starts the background job and returns
  // immediately; ComparisonProgress (polling `job` above) shows the rest.
  const compareMut = useMutation({
    mutationFn: () => {
      const allSelected = runs.length > 0 && compareRunIds.size === runs.length
      return api.threatHunting.compareRuns(pkgId, {
        run_ids: allSelected ? undefined : Array.from(compareRunIds),
        provider_name: chosenModel?.provider ?? undefined,
        model_name: chosenModel?.model ?? undefined,
        phase,
        name: compareName.trim() || undefined,
      })
    },
    onSuccess: (startedJob) => {
      // Seed the poll immediately so progress renders on the very next
      // paint instead of waiting for the first refetchInterval tick.
      qc.setQueryData(['th-comparison-job', pkgId, phase], startedJob)
      setShowCompareDialog(false)
    },
  })

  const openDialog = () => {
    setCompareRunIds(new Set(runs.map((r) => r.id)))
    setCompareName('')
    setShowCompareDialog(true)
  }

  const jobRunning = job?.status === 'running'

  const assessButton = isResearcher && runs.length > 0 && (
    <button
      className="btn-primary text-sm flex items-center gap-1.5"
      disabled={compareMut.isPending || jobRunning}
      onClick={openDialog}
    >
      {compareMut.isPending || jobRunning ? (
        <Loader2 className="w-3.5 h-3.5 animate-spin" />
      ) : (
        <GitCompare className="w-3.5 h-3.5" />
      )}
      {jobRunning ? 'Comparing…' : report ? 'Re-Assess & Compare' : 'Assess & Compare'}
    </button>
  )

  const dialog = showCompareDialog && (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="bg-gray-900 border border-gray-700 rounded-xl shadow-xl w-full max-w-sm mx-4 p-5 space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-semibold text-gray-100">Assess &amp; Compare Runs</h3>
          <button
            className="btn-ghost p-1.5 text-gray-500 hover:text-gray-300"
            onClick={() => setShowCompareDialog(false)}
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="space-y-1.5">
          <label className="block text-sm text-gray-400">Name (optional)</label>
          <input
            type="text"
            className="input w-full text-sm"
            placeholder={`Auto-named "manual_<timestamp>" if left blank`}
            value={compareName}
            onChange={(e) => setCompareName(e.target.value)}
          />
        </div>

        <div className="space-y-1.5">
          <label className="block text-sm text-gray-400">Model</label>
          <div className="relative">
            <select
              className="input w-full text-sm pr-7 appearance-none"
              value={compareModelChoice}
              onChange={(e) => setCompareModelChoice(e.target.value)}
            >
              <option value="">Configured default</option>
              {modelOptions.map((opt, i) => (
                <option key={`${opt.provider}:${opt.model}`} value={String(i)}>
                  {opt.provider} · {opt.model}
                </option>
              ))}
            </select>
            <ChevronDown className="absolute right-2 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-gray-500 pointer-events-none" />
          </div>
        </div>

        <div className="space-y-1.5">
          <div className="flex items-center justify-between">
            <label className="block text-sm text-gray-400">Runs to include</label>
            <div className="flex gap-2 text-[11px]">
              <button
                type="button"
                className="text-brand-400 hover:text-brand-300"
                onClick={() => setCompareRunIds(new Set(runs.map((r) => r.id)))}
              >
                All
              </button>
              <button
                type="button"
                className="text-gray-500 hover:text-gray-300"
                onClick={() => setCompareRunIds(new Set())}
              >
                None
              </button>
            </div>
          </div>
          <div className="max-h-40 overflow-y-auto space-y-1 pr-1">
            {runs.map((run) => (
              <label key={run.id} className="flex items-center gap-2 text-[12px] text-gray-400">
                <input
                  type="checkbox"
                  checked={compareRunIds.has(run.id)}
                  onChange={(e) =>
                    setCompareRunIds((prev) => {
                      const next = new Set(prev)
                      if (e.target.checked) next.add(run.id)
                      else next.delete(run.id)
                      return next
                    })
                  }
                  className="accent-brand-500"
                />
                <span className="font-mono">{run.run_id_display || run.id.slice(0, 8)}</span>
                <span className="text-gray-600">
                  {run.llm_model ?? run.llm_provider ?? ''}
                  {runLabel(run) ? ` · ${runLabel(run)}` : ''}
                </span>
              </label>
            ))}
          </div>
        </div>

        <p className="text-[11px] text-gray-600">
          {chosenModel ? `${chosenModel.provider} / ${chosenModel.model}` : 'Default model'}{' '}
          · {compareRunIds.size} of {runs.length} run{runs.length === 1 ? '' : 's'} selected
        </p>

        {compareMut.isError && (
          <div className="flex items-start gap-2 p-2 rounded-lg bg-red-900/20 border border-red-800/30">
            <AlertTriangle className="w-3.5 h-3.5 text-red-400 shrink-0" />
            <p className="text-[11px] text-red-300">
              {compareMut.error instanceof Error ? compareMut.error.message : 'Comparison failed'}
            </p>
          </div>
        )}

        <div className="flex gap-2 justify-end pt-1">
          <button
            className="btn-ghost text-sm"
            onClick={() => setShowCompareDialog(false)}
            disabled={compareMut.isPending}
          >
            Cancel
          </button>
          <button
            className="btn-primary text-sm"
            disabled={compareMut.isPending || compareRunIds.size === 0}
            onClick={() => compareMut.mutate()}
          >
            {compareMut.isPending ? 'Comparing…' : 'Compare'}
          </button>
        </div>
      </div>
    </div>
  )

  // issue-local-035 follow-up: shown above whichever branch renders below —
  // the empty state, or a stale-while-revalidating existing report — so
  // progress is visible regardless of what was on screen when the job
  // started, and independent of the dialog that triggered it (which is
  // already closed by the time this can be seen).
  const progressBanner = job && job.status !== 'completed' && <ComparisonProgress job={job} />

  if (isLoading) {
    return (
      <div className="flex items-center gap-2 text-sm text-gray-500 py-8">
        <Loader2 className="w-4 h-4 animate-spin" /> Loading comparison…
      </div>
    )
  }

  if (!report) {
    return (
      <div className="space-y-5">
        {progressBanner}
        {!progressBanner && (
          <div className="text-center py-10 space-y-3">
            <GitCompare className="w-10 h-10 text-gray-700 mx-auto" />
            <p className="text-sm text-gray-500">
              No {phase === 'preliminary' ? 'preliminary' : 'full'} comparison assessment yet.
            </p>
            <p className="text-sm text-gray-600">
              Click <span className="text-brand-400">Assess &amp; Compare</span> below to compare
              runs of this hunt package.
            </p>
            {runs.length > 0 && (
              <p className="text-[11px] text-gray-600">
                Will compare all {runs.length} run{runs.length === 1 ? '' : 's'} using{' '}
                {chosenModel ? `${chosenModel.provider} / ${chosenModel.model}` : 'the configured default model'}{' '}
                unless changed below.
              </p>
            )}
            <div className="flex justify-center">{assessButton}</div>
          </div>
        )}
        {dialog}
      </div>
    )
  }

  const r = report.full_report
  const diffTable = r.diff_table ?? []
  const iocOverview = r.ioc_overview ?? []

  return (
    <div className="space-y-5">
      {progressBanner}
      <div className="flex items-center justify-between gap-4">
        <div className="flex items-center gap-2">
          <GitCompare className="w-5 h-5 text-brand-400" />
          <h3 className="text-sm font-semibold text-gray-200">Comparison Assessment</h3>
          <span className="text-[11px] text-gray-500">
            {r.compared_run_ids.length} run{r.compared_run_ids.length === 1 ? '' : 's'} ·{' '}
            {report.created_at.slice(0, 19).replace('T', ' ')} UTC
          </span>
        </div>
        <div className="flex items-center gap-3">
          {/* issue-local-040: saved-assessment selector — every named
              comparison stays reachable, not just the latest one. */}
          {savedReports.length > 1 && (
            <select
              className="input text-[11px] py-1 max-w-[220px]"
              value={selectedReportId}
              onChange={(e) => setSelectedReportId(e.target.value)}
              title="View a different saved comparison assessment"
            >
              <option value="">Latest</option>
              {savedReports.map((r) => (
                <option key={r.id} value={r.id}>
                  {r.name || r.created_at.slice(0, 19).replace('T', ' ')}
                </option>
              ))}
            </select>
          )}
          <ComparisonDownloadLinks pkgId={pkgId} report={report} phase={phase} />
          {assessButton}
        </div>
      </div>
      {report.name && (
        <p className="text-[11px] text-gray-500 -mt-3">
          Saved as <span className="text-gray-300 font-mono">{report.name}</span>
        </p>
      )}

      {/* Summary */}
      <div className="card space-y-2">
        <div className="flex items-center gap-2">
          <Sparkles className="w-4 h-4 text-brand-400" />
          <h4 className="text-sm font-semibold text-gray-200">Summary</h4>
        </div>
        <p className="text-sm text-gray-300 leading-relaxed">
          {r.summary || <span className="italic text-gray-500">Not available.</span>}
        </p>
      </div>

      {/* Diff table */}
      {diffTable.length > 0 && (
        <div className="overflow-x-auto rounded-lg border border-gray-800">
          <table className="w-full min-w-[900px]">
            <thead>
              <tr className="bg-gray-800/50 text-[10px] uppercase tracking-wider text-gray-500">
                <th className="text-left py-1.5 px-2">Run</th>
                <th className="text-left py-1.5 px-2">Model</th>
                <th className="text-left py-1.5 px-2">Effort</th>
                <th className="text-left py-1.5 px-2">Status</th>
                <th className="text-left py-1.5 px-2">Hypotheses</th>
                <th className="text-left py-1.5 px-2">IOCs (kept/removed)</th>
                <th className="text-left py-1.5 px-2">Total IOCs</th>
                <th className="text-left py-1.5 px-2">Techniques</th>
                <th className="text-left py-1.5 px-2">Events</th>
              </tr>
            </thead>
            <tbody>
              {diffTable.map((row) => (
                <tr key={row.run_id} className="border-t border-gray-800/60">
                  <td className="py-1.5 px-2 text-[11px] text-gray-300 font-mono whitespace-nowrap">
                    {row.run_id_display || row.run_id.slice(0, 8)}
                  </td>
                  <td className="py-1.5 px-2 text-[11px] text-gray-400">{row.model}</td>
                  <td className="py-1.5 px-2 text-[11px] text-gray-400">{row.effort}</td>
                  <td className="py-1.5 px-2 text-[11px] text-gray-400">{row.status}</td>
                  <td className="py-1.5 px-2 text-[11px] text-gray-400">{row.hypothesis_count}</td>
                  <td className="py-1.5 px-2 text-[11px] text-gray-400">
                    {row.sanitized_ioc_count}/{row.removed_ioc_count}
                  </td>
                  <td className="py-1.5 px-2 text-[11px] text-gray-200 font-semibold">{row.total_ioc_count}</td>
                  <td className="py-1.5 px-2 text-[11px] text-gray-400">{row.technique_count}</td>
                  <td className="py-1.5 px-2 text-[11px] text-gray-400">{row.event_count}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Overall IOCs — issue-local-026: every IOC found across the compared
          runs; issue-local-035: consolidated to one row per unique IOC, with
          a per-run occurrence breakdown instead of one row per (run, IOC). */}
      {iocOverview.length > 0 && (
        <div className="border border-gray-700 rounded-lg overflow-hidden">
          <div className="flex items-center gap-2 px-4 py-3 bg-gray-800/40">
            <span className="text-sm font-medium text-gray-200">
              Overall IOCs ({iocOverview.length} unique)
            </span>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full min-w-[900px]">
              <thead>
                <tr className="bg-gray-800/50 text-[10px] uppercase tracking-wider text-gray-500">
                  <th className="text-left py-1.5 px-2">IOC</th>
                  <th className="text-left py-1.5 px-2">Type</th>
                  <th className="text-left py-1.5 px-2">Found in</th>
                  <th className="text-left py-1.5 px-2">Verdict</th>
                  <th className="text-left py-1.5 px-2">Hypotheses / leads</th>
                </tr>
              </thead>
              <tbody>
                {iocOverview.map((row, i) => (
                  <tr key={`${row.ioc_type}-${row.ioc}-${i}`} className="border-t border-gray-800/60">
                    <td className="py-1.5 px-2 text-[11px] text-gray-200 font-mono break-all max-w-xs">
                      {row.ioc}
                    </td>
                    <td className="py-1.5 px-2 text-[11px] text-gray-400 whitespace-nowrap">{row.ioc_type}</td>
                    <td className="py-1.5 px-2 text-[11px]">
                      <div className="flex flex-wrap gap-1">
                        {(row.occurrences ?? []).map((occ, j) => (
                          <span
                            key={`${occ.run_id}-${j}`}
                            title={`${occ.model || 'unknown model'}${
                              occ.confidence_pct != null ? ` · ${occ.confidence_pct}% confidence` : ''
                            }`}
                            className={clsx(
                              'inline-flex items-center gap-1 text-[10px] px-1.5 py-0.5 rounded whitespace-nowrap font-mono',
                              occ.verdict === 'remove'
                                ? 'bg-red-900/20 text-red-400'
                                : 'bg-green-900/20 text-green-400',
                            )}
                          >
                            {occ.run_id_display || occ.run_id.slice(0, 8)}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className="py-1.5 px-2 text-[11px] text-gray-400 whitespace-nowrap">
                      {row.verdict_summary}
                    </td>
                    <td className="py-1.5 px-2 text-[11px] text-gray-400">
                      {row.hypotheses?.length > 0 ? row.hypotheses.join(', ') : '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Key Differences */}
      {r.key_differences.length > 0 && (
        <div className="border border-gray-700 rounded-lg overflow-hidden">
          <div className="flex items-center gap-2 px-4 py-3 bg-gray-800/40">
            <GitCompare className="w-4 h-4 text-brand-400" />
            <span className="text-sm font-medium text-gray-200">Key Differences</span>
          </div>
          <ul className="p-4 space-y-1.5">
            {r.key_differences.map((item, i) => (
              <li key={i} className="text-sm text-gray-300 flex gap-1.5">
                <span className="text-brand-600">•</span>
                {item}
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Gaps */}
      {r.gaps.length > 0 && (
        <div className="border border-gray-700 rounded-lg overflow-hidden">
          <div className="flex items-center gap-2 px-4 py-3 bg-gray-800/40">
            <AlertTriangle className="w-4 h-4 text-amber-400" />
            <span className="text-sm font-medium text-gray-200">Gaps</span>
          </div>
          <ul className="p-4 space-y-1.5">
            {r.gaps.map((item, i) => (
              <li key={i} className="text-sm text-gray-300 flex gap-1.5">
                <span className="text-amber-500">•</span>
                {item}
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Enrichment Opportunities */}
      {r.enrichment_opportunities.length > 0 && (
        <div className="border border-gray-700 rounded-lg overflow-hidden">
          <div className="flex items-center gap-2 px-4 py-3 bg-gray-800/40">
            <Lightbulb className="w-4 h-4 text-brand-400" />
            <span className="text-sm font-medium text-gray-200">Enrichment Opportunities</span>
          </div>
          <ul className="p-4 space-y-1.5">
            {r.enrichment_opportunities.map((item, i) => (
              <li key={i} className="text-sm text-gray-300 flex gap-1.5">
                <span className="text-brand-600">•</span>
                {item}
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Recommended Combination — issue-local-035: three actions on top of
          the narrative: snapshot as a consolidated report (no execution), or
          re-run generation seeded from all/selected compared runs. */}
      {r.recommended_combination && (
        <div className="card space-y-3">
          <h4 className="text-sm font-semibold text-gray-200">Recommended Combination</h4>
          <p className="text-sm text-gray-300 leading-relaxed">{r.recommended_combination}</p>

          {isResearcher && (
            <div className="flex flex-wrap gap-2 pt-1">
              <button
                type="button"
                className="btn-secondary text-sm flex items-center gap-1.5"
                disabled={consolidateMut.isPending}
                onClick={() => consolidateMut.mutate()}
              >
                {consolidateMut.isPending ? (
                  <Loader2 className="w-3.5 h-3.5 animate-spin" />
                ) : (
                  <Layers className="w-3.5 h-3.5" />
                )}
                Use as Consolidated Report
              </button>
              <button
                type="button"
                className="btn-secondary text-sm flex items-center gap-1.5"
                disabled={rerunMut.isPending}
                onClick={() => rerunMut.mutate(undefined)}
              >
                {rerunMut.isPending ? (
                  <Loader2 className="w-3.5 h-3.5 animate-spin" />
                ) : (
                  <RefreshCw className="w-3.5 h-3.5" />
                )}
                Re-run with All Compared Runs
              </button>
              <button
                type="button"
                className="btn-secondary text-sm flex items-center gap-1.5"
                onClick={() => {
                  // Seed selection from runs that are both compared AND still
                  // known to `runs` — anything else has no checkbox to
                  // uncheck, so it must never be silently pre-selected.
                  const knownIds = new Set(runs.map((run) => run.id))
                  setRerunRunIds(
                    new Set(r.compared_run_ids.filter((id) => knownIds.has(id))),
                  )
                  setShowRerunPicker(true)
                }}
              >
                <ListChecks className="w-3.5 h-3.5" />
                Re-run with Selected Runs…
              </button>
              <button
                type="button"
                className="btn-secondary text-sm flex items-center gap-1.5"
                disabled={recommendationRunMut.isPending}
                onClick={() => recommendationRunMut.mutate()}
                title="Synthesize one consolidated plan from the compared runs' actual outputs and start a new run in THIS package"
              >
                {recommendationRunMut.isPending ? (
                  <Loader2 className="w-3.5 h-3.5 animate-spin" />
                ) : (
                  <Wand2 className="w-3.5 h-3.5" />
                )}
                Create a New Run from Recommendations
              </button>
            </div>
          )}

          {consolidateMut.isSuccess && (
            <div className="flex items-start gap-2 p-2 rounded-lg bg-green-900/20 border border-green-800/30">
              <CheckCircle2 className="w-3.5 h-3.5 text-green-400 shrink-0 mt-0.5" />
              <div className="text-[11px] text-green-300 space-y-1">
                <p>Consolidated report created.</p>
                <span className="flex items-center gap-3">
                  <a
                    className="underline hover:text-green-200"
                    href={api.threatHunting.downloadConsolidatedMarkdown(pkgId, phase)}
                  >
                    Download Markdown
                  </a>
                  <a
                    className="underline hover:text-green-200"
                    href={api.threatHunting.downloadConsolidatedPdf(pkgId, phase)}
                  >
                    Download PDF
                  </a>
                </span>
              </div>
            </div>
          )}
          {consolidateMut.isError && (
            <div className="flex items-start gap-2 p-2 rounded-lg bg-red-900/20 border border-red-800/30">
              <AlertTriangle className="w-3.5 h-3.5 text-red-400 shrink-0" />
              <p className="text-[11px] text-red-300">
                {consolidateMut.error instanceof Error
                  ? consolidateMut.error.message
                  : 'Consolidation failed'}
              </p>
            </div>
          )}
          {rerunMut.isError && (
            <div className="flex items-start gap-2 p-2 rounded-lg bg-red-900/20 border border-red-800/30">
              <AlertTriangle className="w-3.5 h-3.5 text-red-400 shrink-0" />
              <p className="text-[11px] text-red-300">
                {rerunMut.error instanceof Error ? rerunMut.error.message : 'Re-run failed'}
              </p>
            </div>
          )}
          {recommendationRunMut.isSuccess && (
            <div className="flex items-start gap-2 p-2 rounded-lg bg-green-900/20 border border-green-800/30">
              <CheckCircle2 className="w-3.5 h-3.5 text-green-400 shrink-0 mt-0.5" />
              <p className="text-[11px] text-green-300">
                New run started in this package from the synthesized recommendations — see the
                Consolidated Runs tab in the runs table above.
              </p>
            </div>
          )}
          {recommendationRunMut.isError && (
            <div className="flex items-start gap-2 p-2 rounded-lg bg-red-900/20 border border-red-800/30">
              <AlertTriangle className="w-3.5 h-3.5 text-red-400 shrink-0" />
              <p className="text-[11px] text-red-300">
                {recommendationRunMut.error instanceof Error
                  ? recommendationRunMut.error.message
                  : 'Failed to create a run from recommendations'}
              </p>
            </div>
          )}
        </div>
      )}

      {showRerunPicker && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="bg-gray-900 border border-gray-700 rounded-xl shadow-xl w-full max-w-sm mx-4 p-5 space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-semibold text-gray-100">Re-run with Selected Runs</h3>
              <button
                className="btn-ghost p-1.5 text-gray-500 hover:text-gray-300"
                onClick={() => setShowRerunPicker(false)}
              >
                <X className="w-4 h-4" />
              </button>
            </div>
            <div className="max-h-48 overflow-y-auto space-y-1 pr-1">
              {runs
                .filter((run) => r.compared_run_ids.includes(run.id))
                .map((run) => (
                  <label key={run.id} className="flex items-center gap-2 text-[12px] text-gray-400">
                    <input
                      type="checkbox"
                      checked={rerunRunIds.has(run.id)}
                      onChange={(e) =>
                        setRerunRunIds((prev) => {
                          const next = new Set(prev)
                          if (e.target.checked) next.add(run.id)
                          else next.delete(run.id)
                          return next
                        })
                      }
                      className="accent-brand-500"
                    />
                    <span className="font-mono">{run.run_id_display || run.id.slice(0, 8)}</span>
                  </label>
                ))}
            </div>
            {rerunMut.isError && (
              <div className="flex items-start gap-2 p-2 rounded-lg bg-red-900/20 border border-red-800/30">
                <AlertTriangle className="w-3.5 h-3.5 text-red-400 shrink-0" />
                <p className="text-[11px] text-red-300">
                  {rerunMut.error instanceof Error ? rerunMut.error.message : 'Re-run failed'}
                </p>
              </div>
            )}
            <div className="flex gap-2 justify-end pt-1">
              <button
                className="btn-ghost text-sm"
                onClick={() => setShowRerunPicker(false)}
                disabled={rerunMut.isPending}
              >
                Cancel
              </button>
              <button
                className="btn-primary text-sm"
                disabled={rerunMut.isPending || rerunRunIds.size === 0}
                onClick={() => rerunMut.mutate(Array.from(rerunRunIds))}
              >
                {rerunMut.isPending ? 'Starting…' : 'Re-run'}
              </button>
            </div>
          </div>
        </div>
      )}

      {dialog}
    </div>
  )
}

/** issue-local-035: Comparison Assessment split into two tabs — Preliminary
 *  Analysis (pre-SIEM-execution) and Full Assessment (post-execution). Each
 *  tab is a fully separate `ComparisonPhasePanel` mount (keyed by phase) so
 *  switching tabs never bleeds one phase's dialog/query state into the
 *  other. */
export default function ComparisonAssessmentTab({
  pkgId,
  runs,
}: {
  pkgId: string
  runs: THuntPackageRun[]
}) {
  const [activePhase, setActivePhase] = useState<ComparisonPhase>('full')

  const tabs: { phase: ComparisonPhase; label: string }[] = [
    { phase: 'preliminary', label: 'Preliminary Analysis' },
    { phase: 'full', label: 'Full Assessment' },
  ]

  return (
    <div className="space-y-4">
      <nav className="flex gap-4 border-b border-gray-800">
        {tabs.map((t) => (
          <button
            key={t.phase}
            type="button"
            onClick={() => setActivePhase(t.phase)}
            className={clsx(
              'pb-2 text-sm font-medium transition-colors',
              activePhase === t.phase
                ? 'text-brand-400 border-b-2 border-brand-400'
                : 'text-gray-500 hover:text-gray-300',
            )}
          >
            {t.label}
          </button>
        ))}
      </nav>
      <ComparisonPhasePanel key={activePhase} pkgId={pkgId} runs={runs} phase={activePhase} />
    </div>
  )
}
