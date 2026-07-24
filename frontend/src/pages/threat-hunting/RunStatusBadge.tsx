/**
 * RunStatusBadge (issue-local-016) — a single generation run's status
 * indicator. Used as a plain <span> for HuntDetail's run-selector status
 * pill, and as a clickable <button> tab on the hunt-package list view
 * (ThreatHunting.tsx), where each tab also acts as a run selector for that
 * card's stage rail — the tab styling makes the active/inactive contrast
 * (and thus which run is selected) unambiguous at a glance.
 */
import { clsx } from 'clsx'
import type { THRunSummary, THuntPackageRun } from '../../api/client'
import { runStatusClass, runStatusDotClass, runStatusTextClass, runTabLabel } from './runStatusUtils'

export default function RunStatusBadge({
  run,
  active,
  onClick,
  size = 'sm',
}: {
  run: THRunSummary | THuntPackageRun
  /** Highlighted as the currently-selected run (list-card tab usage only). */
  active?: boolean
  /** Present → renders as a clickable <button> tab (list-card chip row). Absent → plain <span> (detail-view status pill). */
  onClick?: () => void
  size?: 'sm' | 'xs'
}) {
  const status = run.generation_status ?? '—'

  if (onClick) {
    const label = runTabLabel(run)
    return (
      <button
        type="button"
        title={runLabelTitle(run)}
        onClick={onClick}
        className={clsx(
          'flex items-center gap-1.5 text-[12px] font-medium px-3 py-1.5 rounded-t border border-b-0 transition-colors shrink-0',
          active
            ? 'bg-gray-700 border-brand-500 text-gray-100 -mb-px shadow-sm'
            : 'bg-gray-900/50 border-gray-800 text-gray-500 hover:text-gray-300 hover:bg-gray-800/60 hover:border-gray-700',
        )}
      >
        <span className={clsx('w-1.5 h-1.5 rounded-full shrink-0', runStatusDotClass(run.generation_status))} />
        {label && (
          <>
            <span>{label}</span>
            <span className="opacity-50">·</span>
          </>
        )}
        <span className={runStatusTextClass(run.generation_status)}>{status}</span>
      </button>
    )
  }

  const className = clsx(
    'rounded shrink-0 transition-colors',
    size === 'xs' ? 'text-[10px] px-1.5 py-0.5' : 'text-[11px] px-2 py-0.5',
    runStatusClass(run.generation_status),
  )
  return (
    <span title={runLabelTitle(run)} className={className}>
      {status}
    </span>
  )
}

function runLabelTitle(run: THRunSummary | THuntPackageRun): string | undefined {
  const label = runTabLabel(run)
  return label || undefined
}
