/**
 * RetrohuntPanel — Phase 4 Deep Retrohunt Lead review UI
 *
 * Displays the output of the `deep_retrohunt_planner` agent node:
 *   - Statistics bar (total / noisy / high-noise IOC counts)
 *   - IOC review table with per-IOC noise badge, type chip, search token,
 *     and collapsible noise reasons
 *   - Canonical IOC CSV download button
 *   - SPL draft viewer (collapsible code block)
 *   - Search hint (plain-language summary for non-Splunk SIEMs)
 *   - Analyst notes section
 *
 * This panel is purely informational — it does not trigger any mutations.
 * Execution (running the SPL against Splunk) is Phase 5.
 */

import { useState } from 'react'
import { clsx } from 'clsx'
import {
  ChevronDown,
  ChevronRight,
  Download,
  Code2,
  Search,
  AlertTriangle,
  ShieldAlert,
  CheckCircle,
  Info,
} from 'lucide-react'
import type { THDeepRetrohuntLead, THSanitizedIOC } from '../../api/client'

// ── Sub-components ────────────────────────────────────────────────────────────

function NoiseBar({ score }: { score: number }) {
  const pct = Math.round(score * 100)
  const color =
    score >= 0.8 ? 'bg-red-500' : score >= 0.5 ? 'bg-amber-500' : 'bg-green-500'
  return (
    <div className="flex items-center gap-1.5 min-w-[60px]">
      <div className="w-12 h-1.5 rounded-full bg-gray-700 overflow-hidden">
        <div className={clsx('h-full rounded-full', color)} style={{ width: `${pct}%` }} />
      </div>
      <span
        className={clsx(
          'text-[10px] tabular-nums',
          score >= 0.8 ? 'text-red-400' : score >= 0.5 ? 'text-amber-400' : 'text-green-400',
        )}
      >
        {pct}
      </span>
    </div>
  )
}

function NoiseBadge({ score }: { score: number }) {
  if (score >= 0.8)
    return (
      <span className="inline-flex items-center gap-1 text-[10px] px-1.5 py-0.5 rounded bg-red-900/40 text-red-400 border border-red-800/40">
        <ShieldAlert className="w-3 h-3" /> High Noise
      </span>
    )
  if (score >= 0.5)
    return (
      <span className="inline-flex items-center gap-1 text-[10px] px-1.5 py-0.5 rounded bg-amber-900/40 text-amber-400 border border-amber-800/40">
        <AlertTriangle className="w-3 h-3" /> Noisy
      </span>
    )
  return (
    <span className="inline-flex items-center gap-1 text-[10px] px-1.5 py-0.5 rounded bg-green-900/30 text-green-400 border border-green-800/30">
      <CheckCircle className="w-3 h-3" /> Clean
    </span>
  )
}

function IOCTypeChip({ type }: { type: string }) {
  const colors: Record<string, string> = {
    ip: 'bg-blue-900/40 text-blue-300',
    domain: 'bg-purple-900/40 text-purple-300',
    url: 'bg-indigo-900/40 text-indigo-300',
    hash_md5: 'bg-gray-800 text-gray-300',
    hash_sha1: 'bg-gray-800 text-gray-300',
    hash_sha256: 'bg-gray-800 text-gray-300',
    email: 'bg-teal-900/40 text-teal-300',
    cve: 'bg-orange-900/40 text-orange-300',
    registry_key: 'bg-yellow-900/40 text-yellow-300',
    filepath: 'bg-pink-900/40 text-pink-300',
  }
  return (
    <span
      className={clsx(
        'text-[10px] font-mono px-1.5 py-0.5 rounded',
        colors[type] ?? 'bg-gray-800 text-gray-400',
      )}
    >
      {type.replace('hash_', '')}
    </span>
  )
}

function IOCRow({ ioc }: { ioc: THSanitizedIOC }) {
  const [expanded, setExpanded] = useState(false)
  const hasReasons = ioc.noise_reasons.length > 0

  return (
    <>
      <tr
        className={clsx(
          'border-b border-gray-800/60 hover:bg-gray-800/30 transition-colors',
          ioc.noise_score >= 0.8 && 'bg-red-950/10',
          ioc.noise_score >= 0.5 && ioc.noise_score < 0.8 && 'bg-amber-950/10',
        )}
      >
        {/* Expand toggle (only shown when there are noise reasons) */}
        <td className="w-6 pl-2 py-1.5">
          {hasReasons ? (
            <button
              onClick={() => setExpanded((v) => !v)}
              className="text-gray-500 hover:text-gray-300"
              aria-label="Toggle noise reasons"
            >
              {expanded ? (
                <ChevronDown className="w-3.5 h-3.5" />
              ) : (
                <ChevronRight className="w-3.5 h-3.5" />
              )}
            </button>
          ) : (
            <span className="w-3.5 h-3.5 block" />
          )}
        </td>
        {/* IOC value */}
        <td className="py-1.5 pr-2">
          <span className="font-mono text-[11px] text-gray-200 break-all">{ioc.ioc}</span>
        </td>
        {/* Type */}
        <td className="py-1.5 pr-2 whitespace-nowrap">
          <IOCTypeChip type={ioc.ioc_type} />
        </td>
        {/* Description */}
        <td className="py-1.5 pr-2 max-w-[200px]">
          <span className="text-[11px] text-gray-400 truncate block">{ioc.ioc_description || '—'}</span>
        </td>
        {/* Search token */}
        <td className="py-1.5 pr-2">
          <span className="font-mono text-[10px] text-brand-400 break-all">{ioc.search_token}</span>
        </td>
        {/* Noise */}
        <td className="py-1.5 pr-2 whitespace-nowrap">
          <div className="flex items-center gap-2">
            <NoiseBar score={ioc.noise_score} />
            <NoiseBadge score={ioc.noise_score} />
          </div>
        </td>
      </tr>
      {/* Expanded noise reasons */}
      {expanded && hasReasons && (
        <tr className="border-b border-gray-800/40">
          <td colSpan={6} className="pb-2 pt-0 pl-8 pr-2">
            <ul className="space-y-0.5">
              {ioc.noise_reasons.map((r, i) => (
                <li key={i} className="text-[10px] text-amber-400 flex gap-1.5">
                  <AlertTriangle className="w-3 h-3 shrink-0 mt-0.5" />
                  {r}
                </li>
              ))}
            </ul>
          </td>
        </tr>
      )}
    </>
  )
}

// ── CSV Download ──────────────────────────────────────────────────────────────

function downloadCsv(csv: string, filename: string) {
  const blob = new Blob([csv], { type: 'text/csv' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.click()
  URL.revokeObjectURL(url)
}

// ── SPL Draft block ───────────────────────────────────────────────────────────

function SplDraftBlock({
  draft,
  macroName,
}: {
  draft: string
  macroName: string
}) {
  const [open, setOpen] = useState(false)
  return (
    <div className="border border-gray-700 rounded-lg overflow-hidden">
      <button
        className="w-full flex items-center gap-2 px-4 py-3 bg-gray-800/40 hover:bg-gray-800/70 transition-colors"
        onClick={() => setOpen((v) => !v)}
      >
        <Code2 className="w-4 h-4 text-brand-400 shrink-0" />
        <span className="text-sm font-medium text-gray-200 flex-1 text-left">
          SPL Draft — <span className="font-mono text-brand-300">{macroName}</span>
        </span>
        {open ? (
          <ChevronDown className="w-4 h-4 text-gray-500" />
        ) : (
          <ChevronRight className="w-4 h-4 text-gray-500" />
        )}
      </button>
      {open && (
        <div className="p-4">
          {draft ? (
            <pre className="bg-gray-950 border border-gray-800 rounded p-3 text-[11px] text-green-400 font-mono overflow-x-auto whitespace-pre-wrap leading-relaxed">
              {draft}
            </pre>
          ) : (
            <p className="text-xs text-gray-500 italic">
              SPL draft unavailable — LLM enrichment failed or LLM is disabled.
            </p>
          )}
        </div>
      )}
    </div>
  )
}

// ── Main panel ────────────────────────────────────────────────────────────────

export default function RetrohuntPanel({
  retrohunt,
  pkgId,
}: {
  retrohunt: THDeepRetrohuntLead
  pkgId: string
}) {
  const [iocFilter, setIocFilter] = useState<'all' | 'clean' | 'noisy'>('all')

  const filteredIocs = retrohunt.sanitized_iocs.filter((ioc) => {
    if (iocFilter === 'clean') return ioc.noise_score < 0.5
    if (iocFilter === 'noisy') return ioc.noise_score >= 0.5
    return true
  })

  return (
    <div className="space-y-5">
      {/* Header / statistics */}
      <div className="card space-y-3">
        <div className="flex items-start justify-between gap-4">
          <div>
            <h3 className="text-sm font-semibold text-gray-200">Deep Retrohunt Lead</h3>
            <p className="text-xs text-gray-500 mt-0.5">
              Sanitized IOC list ready for retrohunt execution against your SIEM.
            </p>
          </div>
          <button
            className="btn-secondary text-xs flex items-center gap-1.5 shrink-0"
            onClick={() => downloadCsv(retrohunt.ioc_csv, `retrohunt-iocs-${pkgId.slice(0, 8)}.csv`)}
            title="Download canonical IOC CSV"
          >
            <Download className="w-3.5 h-3.5" />
            IOC CSV
          </button>
        </div>

        {/* Stats chips */}
        <div className="flex flex-wrap gap-2">
          <span className="text-[11px] px-2 py-1 rounded bg-gray-800 text-gray-300">
            Total IOCs: <span className="font-semibold text-gray-100">{retrohunt.total_ioc_count}</span>
          </span>
          {retrohunt.noisy_ioc_count > 0 && (
            <span className="text-[11px] px-2 py-1 rounded bg-amber-900/30 text-amber-400">
              Noisy (≥50%): <span className="font-semibold">{retrohunt.noisy_ioc_count}</span>
            </span>
          )}
          {retrohunt.high_noise_ioc_count > 0 && (
            <span className="text-[11px] px-2 py-1 rounded bg-red-900/30 text-red-400">
              High Noise (≥80%): <span className="font-semibold">{retrohunt.high_noise_ioc_count}</span>
            </span>
          )}
          {retrohunt.llm_parse_error && (
            <span className="text-[11px] px-2 py-1 rounded bg-amber-900/30 text-amber-400 flex items-center gap-1">
              <AlertTriangle className="w-3 h-3" /> LLM enrichment unavailable
            </span>
          )}
        </div>

        {/* Search hint */}
        {retrohunt.search_hint && (
          <div className="flex gap-2 p-2.5 rounded-lg bg-brand-900/20 border border-brand-800/30">
            <Search className="w-4 h-4 text-brand-400 shrink-0 mt-0.5" />
            <p className="text-xs text-gray-300">{retrohunt.search_hint}</p>
          </div>
        )}
      </div>

      {/* IOC table */}
      {retrohunt.sanitized_iocs.length > 0 && (
        <div className="card space-y-3">
          <div className="flex items-center justify-between gap-4">
            <h4 className="text-xs font-semibold text-gray-300 uppercase tracking-wider">
              Sanitized IOCs ({retrohunt.sanitized_iocs.length})
            </h4>
            {/* Filter buttons */}
            <div className="flex gap-1">
              {(['all', 'clean', 'noisy'] as const).map((f) => (
                <button
                  key={f}
                  onClick={() => setIocFilter(f)}
                  className={clsx(
                    'text-[10px] px-2 py-0.5 rounded transition-colors capitalize',
                    iocFilter === f
                      ? 'bg-brand-600/30 text-brand-300 border border-brand-700/40'
                      : 'text-gray-500 hover:text-gray-300',
                  )}
                >
                  {f}
                </button>
              ))}
            </div>
          </div>

          <div className="overflow-x-auto rounded-lg border border-gray-800">
            <table className="w-full min-w-[640px]">
              <thead>
                <tr className="bg-gray-800/50 text-[10px] uppercase tracking-wider text-gray-500">
                  <th className="w-6 pl-2 py-2" />
                  <th className="text-left py-2 pr-2">IOC</th>
                  <th className="text-left py-2 pr-2">Type</th>
                  <th className="text-left py-2 pr-2">Description</th>
                  <th className="text-left py-2 pr-2">Search Token</th>
                  <th className="text-left py-2 pr-2">Noise</th>
                </tr>
              </thead>
              <tbody>
                {filteredIocs.length > 0 ? (
                  filteredIocs.map((ioc, i) => <IOCRow key={`${ioc.ioc_type}-${ioc.ioc}-${i}`} ioc={ioc} />)
                ) : (
                  <tr>
                    <td colSpan={6} className="py-4 text-center text-xs text-gray-500 italic">
                      No IOCs match the current filter.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>

          {retrohunt.high_noise_ioc_count > 0 && (
            <div className="flex gap-2 p-2.5 rounded-lg bg-red-900/10 border border-red-800/30">
              <AlertTriangle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
              <p className="text-xs text-red-300">
                <span className="font-semibold">{retrohunt.high_noise_ioc_count} high-noise IOC{retrohunt.high_noise_ioc_count !== 1 ? 's' : ''}</span>
                {' '}flagged. Review analyst notes and consider excluding them from SIEM execution to
                prevent alert storms.
              </p>
            </div>
          )}
        </div>
      )}

      {/* SPL draft */}
      <SplDraftBlock
        draft={retrohunt.spl_draft}
        macroName={retrohunt.spl_macro_name}
      />

      {/* Analyst notes */}
      {retrohunt.analyst_notes && (
        <div className="card space-y-2">
          <div className="flex items-center gap-2">
            <Info className="w-4 h-4 text-brand-400 shrink-0" />
            <h4 className="text-xs font-semibold text-gray-300 uppercase tracking-wider">
              Analyst Notes
            </h4>
          </div>
          <p className="text-xs text-gray-400 whitespace-pre-wrap leading-relaxed">
            {retrohunt.analyst_notes}
          </p>
        </div>
      )}
    </div>
  )
}
