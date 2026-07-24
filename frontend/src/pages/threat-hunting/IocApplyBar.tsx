/**
 * IocApplyBar (issue-local-018 follow-up) — compact "N staged · Apply
 * changes" control for manually-overridden IOC keep/remove verdicts,
 * rendered inline next to wherever the analyst is looking at IOCs (the
 * Analysis tab's Sanitized IOCs filter row, and the IOCs tab's summary
 * row), rather than a page-wide banner detached from that context.
 * Shows a brief "Applied" confirmation after a successful save.
 */
import { CheckCircle, Save } from 'lucide-react'

export interface IocApplyBarProps {
  isDirty: boolean
  pendingCount: number
  isApplying: boolean
  justApplied: boolean
  onApply: () => void
}

export default function IocApplyBar({ isDirty, pendingCount, isApplying, justApplied, onApply }: IocApplyBarProps) {
  if (justApplied && !isDirty) {
    return (
      <span className="flex items-center gap-1 text-xs text-green-400 shrink-0">
        <CheckCircle className="w-3.5 h-3.5" />
        Applied
      </span>
    )
  }

  if (!isDirty) return null

  return (
    <div className="flex items-center gap-2 px-2 py-1 rounded-md border border-amber-600/60 bg-amber-900/25 shrink-0">
      <span className="text-[11px] text-amber-300 whitespace-nowrap">
        {pendingCount} staged
      </span>
      <button
        type="button"
        className="btn-primary text-[11px] px-2 py-1 flex items-center gap-1"
        disabled={isApplying}
        onClick={onApply}
      >
        <Save className="w-3 h-3" />
        {isApplying ? 'Applying…' : 'Apply changes'}
      </button>
    </div>
  )
}
