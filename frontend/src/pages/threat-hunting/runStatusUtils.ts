/**
 * Shared status-color + model/effort label logic for a single generation
 * run (issue-local-016), extracted from HuntDetail.tsx's run-selector status
 * pill. Used by RunStatusBadge.tsx and directly by HuntDetail.tsx.
 */
import type { THRunSummary, THuntPackageRun } from '../../api/client'

const STATUS_STYLES: Record<string, string> = {
  completed: 'bg-green-900/30 text-green-400',
  running: 'bg-blue-900/30 text-blue-400',
  awaiting_approval: 'bg-amber-900/30 text-amber-400',
  error: 'bg-red-900/30 text-red-400',
}
const STATUS_DEFAULT = 'bg-gray-800 text-gray-500'

// issue-local-016 (run tabs): a solid dot color per status, distinct from
// STATUS_STYLES's translucent pill pair — used as a small color-coded glyph
// on the run-tab strip rather than the whole tab's background.
const STATUS_DOT_STYLES: Record<string, string> = {
  completed: 'bg-green-400',
  running: 'bg-blue-400',
  awaiting_approval: 'bg-amber-400',
  error: 'bg-red-400',
}
const STATUS_DOT_DEFAULT = 'bg-gray-500'

// issue-local-016 (run tabs): text-only color, matching STATUS_DOT_STYLES'
// hue — used for the status word on a tab whose background is already the
// active/inactive tab color, not a status-tinted pill background.
const STATUS_TEXT_STYLES: Record<string, string> = {
  completed: 'text-green-400',
  running: 'text-blue-400',
  awaiting_approval: 'text-amber-400',
  error: 'text-red-400',
}
const STATUS_TEXT_DEFAULT = 'text-gray-500'

export function runStatusClass(status: string | null | undefined): string {
  return (status && STATUS_STYLES[status]) || STATUS_DEFAULT
}

export function runStatusDotClass(status: string | null | undefined): string {
  return (status && STATUS_DOT_STYLES[status]) || STATUS_DOT_DEFAULT
}

export function runStatusTextClass(status: string | null | undefined): string {
  return (status && STATUS_TEXT_STYLES[status]) || STATUS_TEXT_DEFAULT
}

export function runLabel(run: THRunSummary | THuntPackageRun): string {
  const model = run.llm_model ?? run.llm_provider ?? ''
  const effort = run.research_effort ?? ''
  return [model, effort].filter(Boolean).join(' · ')
}

// issue-local-016 (run tabs): every tab needs some distinguishing text even
// when a run predates model/effort being stored — fall back to a short
// "MM-DD HH:mm" slice of created_at rather than rendering a blank tab.
export function runTabLabel(run: THRunSummary | THuntPackageRun): string {
  const label = runLabel(run)
  if (label) return label
  return run.created_at ? run.created_at.slice(5, 16).replace('T', ' ') : ''
}

// HuntID/RunID badge (issue-local-018 follow-up) — HuntID/RunID are the
// primary way analysts refer to a package/run, so they render as an
// emphasized bordered chip rather than a plain gray label. Shared across
// every hunt_id_display/run_id_display render site.
export const HUNT_ID_BADGE =
  'inline-flex items-center px-1.5 py-0.5 rounded-md border border-brand-700/60 bg-brand-900/25 font-mono font-bold text-brand-300 shrink-0'
