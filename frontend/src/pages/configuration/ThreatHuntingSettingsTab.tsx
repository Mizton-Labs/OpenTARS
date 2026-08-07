/**
 * Threat Hunting Settings Tab — issue-local-004
 *
 * Controls:
 *   1. Research Effort  (high | medium | low)
 *   2. Report Format    (pdf: boolean, markdown: boolean — both default on)
 */

import { useEffect, useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { FileText, Save, Loader2, Search } from 'lucide-react'
import { clsx } from 'clsx'
import { api } from '../../api/client'

// ── Types ─────────────────────────────────────────────────────────────────────

type ResearchEffort = 'high' | 'medium' | 'low'

const EFFORT_OPTIONS: { id: ResearchEffort; label: string; description: string }[] = [
  {
    id: 'high',
    label: 'High',
    description:
      'Checks into more detail which may produce more hunting hypotheses or a deeper level of analysis. Agents process information with greater breadth, larger token budgets, and wider IOC context.',
  },
  {
    id: 'medium',
    label: 'Medium',
    description:
      'Limits the number of hypotheses or checks to do. Ensures most key relevant actions are performed. Balanced between depth and speed. This is the default.',
  },
  {
    id: 'low',
    label: 'Low',
    description:
      'Simplest mode where only basic relevant data is processed. At minimum performs IOC extraction and deep retrohunt as applicable. Fastest execution.',
  },
]

// ── Component ─────────────────────────────────────────────────────────────────

export default function ThreatHuntingSettingsTab() {
  const qc = useQueryClient()

  const { data: effortData, isLoading: effortLoading } = useQuery({
    queryKey: ['th-research-effort'],
    queryFn: () => api.getThResearchEffort(),
  })
  const { data: formatsData, isLoading: formatsLoading } = useQuery({
    queryKey: ['th-report-formats'],
    queryFn: () => api.getThReportFormats(),
  })
  const { data: prefixData, isLoading: prefixLoading } = useQuery({
    queryKey: ['hunt-id-prefix'],
    queryFn: () => api.getHuntIdPrefix(),
  })

  const [effort, setEffort] = useState<ResearchEffort>('high')
  const [pdfEnabled, setPdfEnabled] = useState(true)
  const [markdownEnabled, setMarkdownEnabled] = useState(true)
  const [huntIdPrefix, setHuntIdPrefix] = useState('TH')
  const [saved, setSaved] = useState(false)

  useEffect(() => {
    if (effortData?.th_research_effort) {
      setEffort(effortData.th_research_effort as ResearchEffort)
    }
  }, [effortData])

  useEffect(() => {
    if (formatsData?.th_report_formats) {
      setPdfEnabled(formatsData.th_report_formats.pdf ?? true)
      setMarkdownEnabled(formatsData.th_report_formats.markdown ?? true)
    }
  }, [formatsData])

  useEffect(() => {
    if (prefixData?.hunt_id_prefix) {
      setHuntIdPrefix(prefixData.hunt_id_prefix)
    }
  }, [prefixData])

  const saveMut = useMutation({
    mutationFn: async () => {
      await api.setThResearchEffort(effort)
      await api.setThReportFormats({ pdf: pdfEnabled, markdown: markdownEnabled })
      await api.setHuntIdPrefix(huntIdPrefix)
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['th-research-effort'] })
      qc.invalidateQueries({ queryKey: ['th-report-formats'] })
      qc.invalidateQueries({ queryKey: ['hunt-id-prefix'] })
      setSaved(true)
      setTimeout(() => setSaved(false), 2000)
    },
  })

  const isLoading = effortLoading || formatsLoading || prefixLoading
  const isDirty =
    effort !== (effortData?.th_research_effort ?? 'high') ||
    pdfEnabled !== (formatsData?.th_report_formats?.pdf ?? true) ||
    markdownEnabled !== (formatsData?.th_report_formats?.markdown ?? true) ||
    huntIdPrefix !== (prefixData?.hunt_id_prefix ?? 'TH')

  if (isLoading) {
    return (
      <div className="flex items-center gap-2 text-sm text-gray-500 py-8">
        <Loader2 className="w-4 h-4 animate-spin" />
        Loading Threat Hunting settings…
      </div>
    )
  }

  return (
    <div className="space-y-6 max-w-2xl">
      {/* Header */}
      <div>
        <h3 className="text-sm font-semibold text-gray-200 flex items-center gap-2">
          <Search className="w-4 h-4 text-brand-400" />
          Threat Hunting Packages
        </h3>
        <p className="text-xs text-gray-500 mt-1">
          Configure the default behaviour for hunt generation and report export. Individual hunt
          runs may override Research Effort at generation time.
        </p>
      </div>

      {/* HuntID Prefix (issue-local-018) */}
      <div className="space-y-2">
        <p className="text-xs font-semibold text-gray-300 uppercase tracking-wider">
          HuntID Prefix
        </p>
        <p className="text-xs text-gray-500">
          Each Hunt Package gets an automatic HuntID: this prefix plus a consecutive number, e.g.{' '}
          <span className="font-mono text-gray-400">{huntIdPrefix || 'TH'}01</span>. Runs are then
          numbered under their package's HuntID, e.g.{' '}
          <span className="font-mono text-gray-400">{huntIdPrefix || 'TH'}01-X01</span>.
          {/* issue-local-038: strftime support */}
          {' '}May include date/time codes (e.g. <span className="font-mono text-gray-400">%Y</span>,{' '}
          <span className="font-mono text-gray-400">%m</span>, <span className="font-mono text-gray-400">%d</span>)
          — a prefix of <span className="font-mono text-gray-400">TH-%Y%m%d</span> gives{' '}
          <span className="font-mono text-gray-400">TH-20260805</span>01, stamped with each
          package's own creation date so it never changes later. Codes are case-sensitive.
        </p>
        <input
          type="text"
          className="input w-48 font-mono"
          maxLength={24}
          value={huntIdPrefix}
          onChange={(e) => setHuntIdPrefix(e.target.value)}
        />
      </div>

      {/* Research Effort */}
      <div className="space-y-2">
        <p className="text-xs font-semibold text-gray-300 uppercase tracking-wider">
          Threat Hunting Research Effort
        </p>
        <div className="space-y-2">
          {EFFORT_OPTIONS.map((opt) => (
            <button
              key={opt.id}
              onClick={() => setEffort(opt.id)}
              className={clsx(
                'w-full text-left rounded-lg border px-4 py-3 transition-colors',
                effort === opt.id
                  ? 'border-brand-500 bg-brand-900/20'
                  : 'border-gray-700 hover:border-gray-500 bg-gray-800/30',
              )}
            >
              <div className="flex items-center gap-2">
                <div
                  className={clsx(
                    'w-3.5 h-3.5 rounded-full border-2 shrink-0',
                    effort === opt.id ? 'border-brand-400 bg-brand-400' : 'border-gray-600',
                  )}
                />
                <span
                  className={clsx(
                    'text-sm font-medium',
                    effort === opt.id ? 'text-brand-300' : 'text-gray-300',
                  )}
                >
                  {opt.label}
                </span>
              </div>
              <p className="text-xs text-gray-500 mt-1 pl-5">{opt.description}</p>
            </button>
          ))}
        </div>
      </div>

      {/* Report Format */}
      <div className="space-y-3">
        <p className="text-xs font-semibold text-gray-300 uppercase tracking-wider">
          Report Format
        </p>
        <p className="text-xs text-gray-500">
          Choose which formats are generated when a hunt report is produced. Download links
          appear on the Report tab of each Hunt Package.
        </p>
        <div className="space-y-2">
          {/* PDF toggle */}
          <button
            onClick={() => setPdfEnabled(!pdfEnabled)}
            className={clsx(
              'w-full flex items-center justify-between rounded-lg border px-4 py-3 transition-colors',
              pdfEnabled
                ? 'border-brand-500 bg-brand-900/20'
                : 'border-gray-700 hover:border-gray-500 bg-gray-800/30',
            )}
          >
            <div className="flex items-center gap-3">
              <FileText
                className={clsx('w-4 h-4', pdfEnabled ? 'text-brand-400' : 'text-gray-600')}
              />
              <div className="text-left">
                <p
                  className={clsx(
                    'text-sm font-medium',
                    pdfEnabled ? 'text-brand-300' : 'text-gray-400',
                  )}
                >
                  PDF
                </p>
                <p className="text-xs text-gray-500">
                  Structured PDF document generated on demand via reportlab. No OS dependencies.
                </p>
              </div>
            </div>
            <div
              className={clsx(
                'w-10 h-5 rounded-full transition-colors relative shrink-0',
                pdfEnabled ? 'bg-brand-500' : 'bg-gray-700',
              )}
            >
              <div
                className={clsx(
                  'absolute top-0.5 w-4 h-4 rounded-full bg-white transition-transform',
                  pdfEnabled ? 'translate-x-5' : 'translate-x-0.5',
                )}
              />
            </div>
          </button>

          {/* Markdown toggle */}
          <button
            onClick={() => setMarkdownEnabled(!markdownEnabled)}
            className={clsx(
              'w-full flex items-center justify-between rounded-lg border px-4 py-3 transition-colors',
              markdownEnabled
                ? 'border-brand-500 bg-brand-900/20'
                : 'border-gray-700 hover:border-gray-500 bg-gray-800/30',
            )}
          >
            <div className="flex items-center gap-3">
              <FileText
                className={clsx(
                  'w-4 h-4',
                  markdownEnabled ? 'text-brand-400' : 'text-gray-600',
                )}
              />
              <div className="text-left">
                <p
                  className={clsx(
                    'text-sm font-medium',
                    markdownEnabled ? 'text-brand-300' : 'text-gray-400',
                  )}
                >
                  Markdown
                </p>
                <p className="text-xs text-gray-500">
                  Plain Markdown (.md) document. Suitable for version control, wikis, and
                  further processing.
                </p>
              </div>
            </div>
            <div
              className={clsx(
                'w-10 h-5 rounded-full transition-colors relative shrink-0',
                markdownEnabled ? 'bg-brand-500' : 'bg-gray-700',
              )}
            >
              <div
                className={clsx(
                  'absolute top-0.5 w-4 h-4 rounded-full bg-white transition-transform',
                  markdownEnabled ? 'translate-x-5' : 'translate-x-0.5',
                )}
              />
            </div>
          </button>
        </div>

        {!pdfEnabled && !markdownEnabled && (
          <p className="text-xs text-amber-400 px-1">
            At least one format should be enabled for report export to work.
          </p>
        )}
      </div>

      {/* Save */}
      <div className="flex items-center gap-3">
        <button
          className="btn-primary flex items-center gap-2 text-sm"
          disabled={!isDirty || saveMut.isPending}
          onClick={() => saveMut.mutate()}
        >
          {saveMut.isPending ? (
            <Loader2 className="w-4 h-4 animate-spin" />
          ) : (
            <Save className="w-4 h-4" />
          )}
          {saveMut.isPending ? 'Saving…' : 'Save'}
        </button>
        {saved && <span className="text-xs text-green-400">Saved.</span>}
        {saveMut.isError && (
          <span className="text-xs text-red-400">Save failed. Try again.</span>
        )}
      </div>
    </div>
  )
}
