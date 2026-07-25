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
import { useState, useMemo } from 'react'
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
} from 'lucide-react'
import { api, type THComparisonReport, type THuntPackageRun, type LLMProviderSummary } from '../../api/client'
import { useAuth } from '../../auth/useAuth'
import { runLabel } from './runStatusUtils'

function downloadJson(report: THComparisonReport) {
  const blob = new Blob([JSON.stringify(report.full_report, null, 2)], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `hunt-comparison-${report.hunt_package_id.slice(0, 8)}.json`
  a.click()
  URL.revokeObjectURL(url)
}

function ComparisonDownloadLinks({ pkgId, report }: { pkgId: string; report: THComparisonReport }) {
  const linkClass = 'flex items-center gap-1 text-gray-500 hover:text-brand-400 transition-colors'
  const badgeClass = 'text-[9px] font-bold px-1 py-0.5 rounded leading-none tracking-wide'
  return (
    <span className="flex items-center gap-3">
      <a
        href={api.threatHunting.downloadComparisonMarkdown(pkgId)}
        className={linkClass}
        title="Download comparison as Markdown"
      >
        <FileText className="w-3.5 h-3.5" />
        <span className={clsx(badgeClass, 'bg-blue-900/40 text-blue-300')}>MD</span>
      </a>
      <a
        href={api.threatHunting.downloadComparisonPdf(pkgId)}
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

export default function ComparisonAssessmentTab({
  pkgId,
  runs,
}: {
  pkgId: string
  /** issue-local-021: needed for the Assess & Compare run picker. */
  runs: THuntPackageRun[]
}) {
  const { isResearcher } = useAuth()
  const qc = useQueryClient()

  const { data: report, isLoading } = useQuery({
    queryKey: ['th-comparison', pkgId],
    queryFn: () => api.threatHunting.getComparison(pkgId).catch(() => null),
    retry: false,
  })

  // issue-local-021: Assess & Compare dialog — run picker (all selected by
  // default) + model dropdown.
  const [showCompareDialog, setShowCompareDialog] = useState(false)
  const [compareModelChoice, setCompareModelChoice] = useState('')
  const [compareRunIds, setCompareRunIds] = useState<Set<string>>(new Set())

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

  const compareMut = useMutation({
    mutationFn: () => {
      const allSelected = runs.length > 0 && compareRunIds.size === runs.length
      return api.threatHunting.compareRuns(pkgId, {
        run_ids: allSelected ? undefined : Array.from(compareRunIds),
        provider_name: chosenModel?.provider ?? undefined,
        model_name: chosenModel?.model ?? undefined,
      })
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['th-comparison', pkgId] })
      setShowCompareDialog(false)
    },
  })

  const openDialog = () => {
    setCompareRunIds(new Set(runs.map((r) => r.id)))
    setShowCompareDialog(true)
  }

  const assessButton = isResearcher && runs.length > 0 && (
    <button
      className="btn-primary text-sm flex items-center gap-1.5"
      disabled={compareMut.isPending}
      onClick={openDialog}
    >
      {compareMut.isPending ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <GitCompare className="w-3.5 h-3.5" />}
      {report ? 'Re-Assess & Compare' : 'Assess & Compare'}
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
        <div className="text-center py-10 space-y-3">
          <GitCompare className="w-10 h-10 text-gray-700 mx-auto" />
          <p className="text-sm text-gray-500">No comparison assessment yet.</p>
          <p className="text-sm text-gray-600">
            Click <span className="text-brand-400">Assess &amp; Compare</span> below to compare
            runs of this hunt package.
          </p>
          <div className="flex justify-center">{assessButton}</div>
        </div>
        {dialog}
      </div>
    )
  }

  const r = report.full_report
  const diffTable = r.diff_table ?? []

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between gap-4">
        <div className="flex items-center gap-2">
          <GitCompare className="w-5 h-5 text-brand-400" />
          <h3 className="text-sm font-semibold text-gray-200">Comparison Assessment</h3>
          <span className="text-[11px] text-gray-500">
            {r.compared_run_ids.length} run{r.compared_run_ids.length === 1 ? '' : 's'} ·{' '}
            {report.created_at.slice(0, 19).replace('T', ' ')} UTC
          </span>
        </div>
        <div className="flex items-center gap-4">
          <ComparisonDownloadLinks pkgId={pkgId} report={report} />
          {assessButton}
        </div>
      </div>

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
                  <td className="py-1.5 px-2 text-[11px] text-gray-400">{row.technique_count}</td>
                  <td className="py-1.5 px-2 text-[11px] text-gray-400">{row.event_count}</td>
                </tr>
              ))}
            </tbody>
          </table>
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

      {/* Recommended Combination */}
      {r.recommended_combination && (
        <div className="card space-y-2">
          <h4 className="text-sm font-semibold text-gray-200">Recommended Combination</h4>
          <p className="text-sm text-gray-300 leading-relaxed">{r.recommended_combination}</p>
        </div>
      )}

      {dialog}
    </div>
  )
}
