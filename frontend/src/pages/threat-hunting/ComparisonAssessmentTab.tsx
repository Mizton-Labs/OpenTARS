/**
 * ComparisonAssessmentTab — "Comparison Assessment" tab (issue-local-020).
 *
 * Read-only display of the latest comparison report for a hunt package
 * (produced by the "Assess & Compare" button in HuntDetail.tsx's header,
 * which triggers backend.threat_hunting.agents.nodes.comparison_analyst).
 *
 * Shows a deterministic per-run diff table (visual grammar matching
 * RunsStatusTable.tsx) plus the LLM-generated narrative sections, with
 * MD/PDF/JSON download links mirroring RunsStatusTable.tsx's ReportLinks
 * icon+badge pattern (issue-local-019).
 */
import { useQuery } from '@tanstack/react-query'
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
} from 'lucide-react'
import { api, type THComparisonReport } from '../../api/client'

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

export default function ComparisonAssessmentTab({ pkgId }: { pkgId: string }) {
  const { data: report, isLoading } = useQuery({
    queryKey: ['th-comparison', pkgId],
    queryFn: () => api.threatHunting.getComparison(pkgId).catch(() => null),
    retry: false,
  })

  if (isLoading) {
    return (
      <div className="flex items-center gap-2 text-sm text-gray-500 py-8">
        <Loader2 className="w-4 h-4 animate-spin" /> Loading comparison…
      </div>
    )
  }

  if (!report) {
    return (
      <div className="text-center py-10 space-y-3">
        <GitCompare className="w-10 h-10 text-gray-700 mx-auto" />
        <p className="text-sm text-gray-500">No comparison assessment yet.</p>
        <p className="text-sm text-gray-600">
          Click <span className="text-brand-400">Assess &amp; Compare</span> above to compare all
          runs of this hunt package.
        </p>
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
        <ComparisonDownloadLinks pkgId={pkgId} report={report} />
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
    </div>
  )
}
