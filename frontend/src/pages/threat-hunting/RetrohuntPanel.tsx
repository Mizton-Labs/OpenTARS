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

import { useMemo, useState } from 'react'
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
  Ban,
} from 'lucide-react'
import type { THDeepRetrohuntLead, THSanitizedIOC } from '../../api/client'
import IocVerdictToggle, { type IocVerdict } from './IocVerdictToggle'
import IocApplyBar, { type IocApplyBarProps } from './IocApplyBar'

// Must match NOISE_THRESHOLD / HIGH_NOISE_THRESHOLD in backend/threat_hunting/iocs.py.
const NOISE_THRESHOLD = 0.7
const HIGH_NOISE_THRESHOLD = 0.85

// ── Sub-components ────────────────────────────────────────────────────────────

function NoiseBar({ score }: { score: number }) {
  const pct = Math.round(score * 100)
  const color =
    score >= HIGH_NOISE_THRESHOLD ? 'bg-red-500' : score >= NOISE_THRESHOLD ? 'bg-amber-500' : 'bg-green-500'
  return (
    <div className="flex items-center gap-1.5 min-w-[60px]">
      <div className="w-12 h-1.5 rounded-full bg-gray-700 overflow-hidden">
        <div className={clsx('h-full rounded-full', color)} style={{ width: `${pct}%` }} />
      </div>
      <span
        className={clsx(
          'text-[11px] tabular-nums',
          score >= HIGH_NOISE_THRESHOLD ? 'text-red-400' : score >= NOISE_THRESHOLD ? 'text-amber-400' : 'text-green-400',
        )}
      >
        {pct}
      </span>
    </div>
  )
}

function NoiseBadge({ score }: { score: number }) {
  if (score >= HIGH_NOISE_THRESHOLD)
    return (
      <span className="inline-flex items-center gap-1 text-[11px] px-1.5 py-0.5 rounded bg-red-900/40 text-red-400 border border-red-800/40">
        <ShieldAlert className="w-3 h-3" /> High Noise
      </span>
    )
  if (score >= NOISE_THRESHOLD)
    return (
      <span className="inline-flex items-center gap-1 text-[11px] px-1.5 py-0.5 rounded bg-amber-900/40 text-amber-400 border border-amber-800/40">
        <AlertTriangle className="w-3 h-3" /> Noisy
      </span>
    )
  return (
    <span className="inline-flex items-center gap-1 text-[11px] px-1.5 py-0.5 rounded bg-green-900/30 text-green-400 border border-green-800/30">
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
        'text-[11px] font-mono px-1.5 py-0.5 rounded',
        colors[type] ?? 'bg-gray-800 text-gray-400',
      )}
    >
      {type.replace('hash_', '')}
    </span>
  )
}

function IOCRow({
  ioc,
  pendingFor,
  onStageVerdict,
  commonRemovalReasons,
}: {
  ioc: THSanitizedIOC
  /** When provided (together with onStageVerdict), the Action column becomes
   *  an interactive Keep/Remove toggle instead of the static noise/removed
   *  badge — omitted for read-only draft views. */
  pendingFor?: (ioc: string, iocType: string) => IocVerdict | undefined
  onStageVerdict?: (ioc: string, iocType: string, action: IocVerdict, serverValue: IocVerdict) => void
  /** issue-local-022 (item 6): reason strings shared by 2+ removed IOCs
   *  (e.g. the deterministic "excluded by active cleaning (remove_noisy)"
   *  text) — already surfaced once in the panel-level summary above the
   *  table, so they're filtered out of each row's own expanded list rather
   *  than repeated on every matching row. */
  commonRemovalReasons?: Set<string>
}) {
  const serverValue: IocVerdict = ioc.action ?? 'keep'
  const removed = serverValue === 'remove'
  const displayReasons =
    removed && commonRemovalReasons
      ? ioc.noise_reasons.filter((r) => !commonRemovalReasons.has(r))
      : ioc.noise_reasons
  const hasReasons = displayReasons.length > 0
  // Removed IOCs default to expanded — the rationale for removal must be
  // fully visible, not hidden behind a click (issue-local-015 feedback).
  const [expanded, setExpanded] = useState(removed && hasReasons)
  const interactive = !!onStageVerdict

  return (
    <>
      <tr
        className={clsx(
          'border-b border-gray-800/60 hover:bg-gray-800/30 transition-colors',
          !removed && ioc.noise_score >= HIGH_NOISE_THRESHOLD && 'bg-red-950/10',
          !removed && ioc.noise_score >= NOISE_THRESHOLD && ioc.noise_score < HIGH_NOISE_THRESHOLD && 'bg-amber-950/10',
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
          {/* issue-local-033 (3rd): no strikethrough, no row-level dimming —
              the "Removed" badge below is the sole removal indicator, so a
              removed IOC reads exactly like a kept one at a glance. */}
          <span className="font-mono text-[12px] break-all text-gray-200">{ioc.ioc}</span>
        </td>
        {/* Type */}
        <td className="py-1.5 pr-2 whitespace-nowrap">
          <IOCTypeChip type={ioc.ioc_type} />
        </td>
        {/* Description — the LLM's per-IOC assessment; wraps in full rather
            than truncating, matching how the removal rationale (noise_reasons)
            below is never cut off either. */}
        <td className="py-1.5 pr-2 max-w-[280px]">
          <span className="text-[12px] text-gray-400 block whitespace-normal break-words">
            {ioc.ioc_description || '—'}
          </span>
        </td>
        {/* Search token */}
        <td className="py-1.5 pr-2">
          <span className="font-mono text-[11px] text-brand-400 break-all">{ioc.search_token}</span>
        </td>
        {/* Noise / Action */}
        <td className="py-1.5 pr-2 whitespace-nowrap">
          <div className="flex items-center gap-2">
            {removed ? (
              <span className="inline-flex items-center gap-1 text-[11px] px-1.5 py-0.5 rounded bg-red-900/30 text-red-400 border border-red-800/40">
                <Ban className="w-3 h-3" /> Removed
              </span>
            ) : (
              <>
                <NoiseBar score={ioc.noise_score} />
                <NoiseBadge score={ioc.noise_score} />
              </>
            )}
            {interactive && (
              <IocVerdictToggle
                value={serverValue}
                pending={pendingFor?.(ioc.ioc, ioc.ioc_type)}
                onChange={(next) => onStageVerdict?.(ioc.ioc, ioc.ioc_type, next, serverValue)}
              />
            )}
          </div>
        </td>
      </tr>
      {/* Expanded reasons — for removed IOCs, this IS the removal rationale
          (leads the list, see deep_retrohunt_planner._sanitize_ioc_list) */}
      {expanded && hasReasons && (
        <tr className="border-b border-gray-800/40">
          <td colSpan={6} className="pb-2 pt-0 pl-8 pr-2">
            <ul className="space-y-0.5">
              {displayReasons.map((r, i) => (
                <li
                  key={i}
                  className={clsx(
                    'text-[11px] flex gap-1.5',
                    removed ? 'text-red-300' : 'text-amber-400',
                  )}
                >
                  {removed ? (
                    <Ban className="w-3 h-3 shrink-0 mt-0.5" />
                  ) : (
                    <AlertTriangle className="w-3 h-3 shrink-0 mt-0.5" />
                  )}
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
            <pre className="bg-gray-950 border border-gray-800 rounded p-3 text-[12px] text-green-400 font-mono overflow-x-auto whitespace-pre-wrap leading-relaxed">
              {draft}
            </pre>
          ) : (
            <p className="text-sm text-gray-500 italic">
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
  pendingFor,
  onStageVerdict,
  iocApplyBar,
}: {
  retrohunt: THDeepRetrohuntLead
  pkgId: string
  /** When provided (together with onStageVerdict), each row gets an
   *  interactive Keep/Remove toggle — omitted for read-only draft views. */
  pendingFor?: (ioc: string, iocType: string) => IocVerdict | undefined
  onStageVerdict?: (ioc: string, iocType: string, action: IocVerdict, serverValue: IocVerdict) => void
  /** issue-local-018 follow-up: rendered next to the All/Sanitized/Removed
   *  filter buttons below — omitted for read-only draft views, same as
   *  pendingFor/onStageVerdict. */
  iocApplyBar?: IocApplyBarProps
}) {
  // issue-local-016: default view is the actionable set ('sanitized' — what
  // actually feeds the SPL query). 'all' is a true union of every IOC seen,
  // 'removed' is opt-in. Noise level is already visible per-row via the
  // NoiseBar/NoiseBadge, so a separate 'noisy' filter tab is redundant.
  const [iocFilter, setIocFilter] = useState<'all' | 'sanitized' | 'removed'>('sanitized')

  const removedIocs = retrohunt.sanitized_iocs.filter((ioc) => ioc.action === 'remove')
  const filteredIocs = retrohunt.sanitized_iocs.filter((ioc) => {
    if (iocFilter === 'removed') return ioc.action === 'remove'
    if (iocFilter === 'sanitized') return ioc.action !== 'remove'
    return true
  })

  // issue-local-022 (item 6): reasons shared by 2+ removed IOCs (almost
  // always the deterministic active-cleaning-toggle text, e.g. "Flagged as
  // noisy — excluded by active cleaning (remove_noisy)") get hoisted into a
  // single summary line instead of being repeated verbatim on every row.
  const removalReasonCounts = useMemo(() => {
    const counts = new Map<string, number>()
    for (const ioc of removedIocs) {
      for (const reason of ioc.noise_reasons) {
        counts.set(reason, (counts.get(reason) ?? 0) + 1)
      }
    }
    return counts
  }, [removedIocs])
  const commonRemovalReasons = useMemo(
    () => new Set([...removalReasonCounts.entries()].filter(([, count]) => count > 1).map(([r]) => r)),
    [removalReasonCounts],
  )

  return (
    <div className="space-y-5">
      {/* Header / statistics */}
      <div className="card space-y-3">
        <div className="flex items-start justify-between gap-4">
          <div>
            <h3 className="text-sm font-semibold text-gray-200">Deep Retrohunt Lead</h3>
            <p className="text-sm text-gray-500 mt-0.5">
              Sanitized IOC list ready for retrohunt execution against your SIEM.
            </p>
          </div>
          <button
            className="btn-secondary text-sm flex items-center gap-1.5 shrink-0"
            onClick={() => downloadCsv(retrohunt.ioc_csv, `retrohunt-iocs-${pkgId.slice(0, 8)}.csv`)}
            title="Download canonical IOC CSV"
          >
            <Download className="w-3.5 h-3.5" />
            IOC CSV
          </button>
        </div>

        {/* Stats chips */}
        <div className="flex flex-wrap gap-2">
          {/* issue-local-026: explicit Total, always computed as
              sanitized + removed right here (never a separately-stored
              number) so it can never drift from the two counts shown
              alongside it. */}
          <span className="text-[12px] px-2 py-1 rounded bg-gray-800 text-gray-100 font-semibold">
            Total IOCs: {retrohunt.total_ioc_count + removedIocs.length}
          </span>
          <span className="text-[12px] px-2 py-1 rounded bg-gray-800 text-gray-300">
            Sanitized IOCs: <span className="font-semibold text-gray-100">{retrohunt.total_ioc_count}</span>
          </span>
          {retrohunt.noisy_ioc_count > 0 && (
            <span className="text-[12px] px-2 py-1 rounded bg-amber-900/30 text-amber-400">
              Noisy (≥{Math.round(NOISE_THRESHOLD * 100)}%): <span className="font-semibold">{retrohunt.noisy_ioc_count}</span>
            </span>
          )}
          {retrohunt.high_noise_ioc_count > 0 && (
            <span className="text-[12px] px-2 py-1 rounded bg-red-900/30 text-red-400">
              High Noise (≥{Math.round(HIGH_NOISE_THRESHOLD * 100)}%): <span className="font-semibold">{retrohunt.high_noise_ioc_count}</span>
            </span>
          )}
          {removedIocs.length > 0 && (
            <span className="text-[12px] px-2 py-1 rounded bg-gray-800 text-gray-500">
              Removed (active cleaning): <span className="font-semibold">{removedIocs.length}</span>
            </span>
          )}
          {retrohunt.llm_parse_error && (
            <span className="text-[12px] px-2 py-1 rounded bg-amber-900/30 text-amber-400 flex items-center gap-1">
              <AlertTriangle className="w-3 h-3" /> LLM enrichment unavailable
            </span>
          )}
        </div>

        {/* Search hint */}
        {retrohunt.search_hint && (
          <div className="flex gap-2 p-2.5 rounded-lg bg-brand-900/20 border border-brand-800/30">
            <Search className="w-4 h-4 text-brand-400 shrink-0 mt-0.5" />
            <p className="text-sm text-gray-300">{retrohunt.search_hint}</p>
          </div>
        )}
      </div>

      {/* IOC table */}
      {retrohunt.sanitized_iocs.length > 0 && (
        <div className="card space-y-3">
          <div className="flex items-center justify-between gap-4">
            <h4 className="text-sm font-semibold text-gray-300 uppercase tracking-wider">
              Sanitized IOCs ({filteredIocs.length}/{retrohunt.sanitized_iocs.length})
            </h4>
            <div className="flex items-center gap-3">
              {/* Filter buttons — default 'sanitized' (actionable set that
                  feeds the SPL query); 'all' is a true union, 'removed' is
                  opt-in — no bucket is a misleading mix of the other two. */}
              <div className="flex gap-1">
                {(
                  [
                    ['all', 'All'],
                    ['sanitized', 'Sanitized'],
                    ['removed', `Removed${removedIocs.length ? ` (${removedIocs.length})` : ''}`],
                  ] as const
                ).map(([f, label]) => (
                  <button
                    key={f}
                    onClick={() => setIocFilter(f)}
                    className={clsx(
                      'text-[11px] px-2 py-0.5 rounded transition-colors',
                      iocFilter === f
                        ? 'bg-brand-600/30 text-brand-300 border border-brand-700/40'
                        : 'text-gray-500 hover:text-gray-300',
                    )}
                  >
                    {label}
                  </button>
                ))}
              </div>
              {/* issue-local-018 follow-up: Apply changes, right next to the
                  filter it affects rather than a detached page banner. */}
              {iocApplyBar && (
                <IocApplyBar
                  isDirty={iocApplyBar.isDirty}
                  pendingCount={iocApplyBar.pendingCount}
                  isApplying={iocApplyBar.isApplying}
                  justApplied={iocApplyBar.justApplied}
                  onApply={iocApplyBar.onApply}
                />
              )}
            </div>
          </div>

          {/* issue-local-022 (item 6): removal-reason summary — shown once,
              here, instead of repeated verbatim on every matching row below. */}
          {commonRemovalReasons.size > 0 && iocFilter !== 'sanitized' && (
            <div className="rounded-lg border border-red-800/30 bg-red-900/10 p-2.5 space-y-1">
              <p className="text-[11px] font-semibold text-red-300 uppercase tracking-wider">
                Removal reasons
              </p>
              <ul className="space-y-0.5">
                {[...commonRemovalReasons]
                  .map((reason) => [reason, removalReasonCounts.get(reason) ?? 0] as const)
                  .map(([reason, count]) => (
                    <li key={reason} className="text-[12px] text-red-300 flex items-start gap-1.5">
                      <Ban className="w-3 h-3 shrink-0 mt-0.5" />
                      <span>
                        {reason} — <span className="font-semibold">{count}</span> IOC{count !== 1 ? 's' : ''}
                      </span>
                    </li>
                  ))}
              </ul>
            </div>
          )}

          <div className="overflow-x-auto rounded-lg border border-gray-800">
            <table className="w-full min-w-[640px]">
              <thead>
                <tr className="bg-gray-800/50 text-[11px] uppercase tracking-wider text-gray-500">
                  <th className="w-6 pl-2 py-2" />
                  <th className="text-left py-2 pr-2">IOC</th>
                  <th className="text-left py-2 pr-2">Type</th>
                  <th className="text-left py-2 pr-2">Description</th>
                  <th className="text-left py-2 pr-2">Search Token</th>
                  <th className="text-left py-2 pr-2">Noise / Action</th>
                </tr>
              </thead>
              <tbody>
                {filteredIocs.length > 0 ? (
                  filteredIocs.map((ioc, i) => (
                    <IOCRow
                      key={`${ioc.ioc_type}-${ioc.ioc}-${i}`}
                      ioc={ioc}
                      pendingFor={pendingFor}
                      onStageVerdict={onStageVerdict}
                      commonRemovalReasons={commonRemovalReasons}
                    />
                  ))
                ) : (
                  <tr>
                    <td colSpan={6} className="py-4 text-center text-sm text-gray-500 italic">
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
              <p className="text-sm text-red-300">
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
            <h4 className="text-sm font-semibold text-gray-300 uppercase tracking-wider">
              Analyst Notes
            </h4>
          </div>
          <p className="text-sm text-gray-400 whitespace-pre-wrap leading-relaxed">
            {retrohunt.analyst_notes}
          </p>
        </div>
      )}
    </div>
  )
}
