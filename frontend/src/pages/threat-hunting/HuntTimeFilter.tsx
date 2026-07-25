/**
 * HuntTimeFilter — time-range filter for the hunt package list (issue-local-020).
 *
 * Three sub-modes as a segmented control (matching the density-toggle visual
 * pattern in ThreatHunting.tsx):
 *   - Relative: "Last N days" number input.
 *   - Time Range: two native <input type="date"> for a specific date range.
 *   - Presets: Last 1d/7d/15d/30d/3m/6m, Year to Date, Last Year.
 *
 * Emits {from, to} as ISO date strings via onChange — `to` always gets
 * T23:59:59 appended so the end date is inclusive of the whole day.
 */
import { useState } from 'react'
import { Calendar, X } from 'lucide-react'
import { clsx } from 'clsx'

export interface HuntTimeRange {
  from?: string
  to?: string
}

type TimeMode = 'relative' | 'range' | 'presets'

const PRESETS: { label: string; days?: number; special?: 'ytd' | 'last_year' }[] = [
  { label: 'Last 1d', days: 1 },
  { label: 'Last 7d', days: 7 },
  { label: 'Last 15d', days: 15 },
  { label: 'Last 30d', days: 30 },
  { label: 'Last 3m', days: 90 },
  { label: 'Last 6m', days: 180 },
  { label: 'Year to Date', special: 'ytd' },
  { label: 'Last Year', special: 'last_year' },
]

function toDateOnly(d: Date): string {
  return d.toISOString().slice(0, 10)
}

function withEndOfDay(dateOnly: string): string {
  return `${dateOnly}T23:59:59`
}

const TOGGLE_BTN =
  'px-2 py-1 transition-colors text-xs'
const TOGGLE_BTN_ACTIVE = 'bg-gray-700 text-gray-100'
const TOGGLE_BTN_INACTIVE = 'bg-transparent text-gray-500 hover:text-gray-300'

export default function HuntTimeFilter({
  value,
  onChange,
}: {
  value: HuntTimeRange
  onChange: (range: HuntTimeRange) => void
}) {
  const [mode, setMode] = useState<TimeMode>('presets')
  const [relativeDays, setRelativeDays] = useState(7)
  const hasFilter = Boolean(value.from || value.to)

  const applyRelative = (days: number) => {
    setRelativeDays(days)
    const from = new Date()
    from.setDate(from.getDate() - days)
    onChange({ from: toDateOnly(from), to: undefined })
  }

  const applyPreset = (preset: (typeof PRESETS)[number]) => {
    const now = new Date()
    if (preset.special === 'ytd') {
      const start = new Date(now.getFullYear(), 0, 1)
      onChange({ from: toDateOnly(start), to: withEndOfDay(toDateOnly(now)) })
      return
    }
    if (preset.special === 'last_year') {
      const start = new Date(now.getFullYear() - 1, 0, 1)
      const end = new Date(now.getFullYear() - 1, 11, 31)
      onChange({ from: toDateOnly(start), to: withEndOfDay(toDateOnly(end)) })
      return
    }
    if (preset.days) {
      const from = new Date()
      from.setDate(from.getDate() - preset.days)
      onChange({ from: toDateOnly(from), to: withEndOfDay(toDateOnly(now)) })
    }
  }

  const clear = () => onChange({ from: undefined, to: undefined })

  return (
    <div className="flex items-center gap-2 flex-wrap">
      <div className="flex items-center rounded-lg overflow-hidden border border-gray-700">
        <button
          type="button"
          className={clsx(TOGGLE_BTN, mode === 'relative' ? TOGGLE_BTN_ACTIVE : TOGGLE_BTN_INACTIVE)}
          onClick={() => setMode('relative')}
        >
          Relative
        </button>
        <button
          type="button"
          className={clsx(TOGGLE_BTN, mode === 'range' ? TOGGLE_BTN_ACTIVE : TOGGLE_BTN_INACTIVE)}
          onClick={() => setMode('range')}
        >
          Time Range
        </button>
        <button
          type="button"
          className={clsx(TOGGLE_BTN, mode === 'presets' ? TOGGLE_BTN_ACTIVE : TOGGLE_BTN_INACTIVE)}
          onClick={() => setMode('presets')}
        >
          Presets
        </button>
      </div>

      {mode === 'relative' && (
        <div className="flex items-center gap-1.5 text-xs">
          <span className="text-gray-500">Last</span>
          <input
            type="number"
            min={1}
            className="input py-1 w-16 text-xs"
            value={relativeDays}
            onChange={(e) => applyRelative(Math.max(1, Number(e.target.value) || 1))}
            aria-label="Number of days"
          />
          <span className="text-gray-500">days</span>
        </div>
      )}

      {mode === 'range' && (
        <div className="flex items-center gap-1.5 text-xs">
          <Calendar className="w-3.5 h-3.5 text-gray-500" />
          <input
            type="date"
            className="input py-1 text-xs"
            value={value.from ?? ''}
            onChange={(e) => onChange({ from: e.target.value || undefined, to: value.to })}
            aria-label="From date"
          />
          <span className="text-gray-500">to</span>
          <input
            type="date"
            className="input py-1 text-xs"
            value={(value.to ?? '').slice(0, 10)}
            onChange={(e) =>
              onChange({
                from: value.from,
                to: e.target.value ? withEndOfDay(e.target.value) : undefined,
              })
            }
            aria-label="To date"
          />
        </div>
      )}

      {mode === 'presets' && (
        <div className="flex items-center gap-1 flex-wrap">
          {PRESETS.map((p) => (
            <button
              key={p.label}
              type="button"
              className="px-2 py-1 rounded text-xs bg-gray-800/60 text-gray-400 hover:bg-gray-700 hover:text-gray-200 transition-colors"
              onClick={() => applyPreset(p)}
            >
              {p.label}
            </button>
          ))}
        </div>
      )}

      {hasFilter && (
        <button
          type="button"
          onClick={clear}
          className="flex items-center gap-1 text-xs text-gray-500 hover:text-gray-300"
        >
          <X className="w-3 h-3" />
          Clear
        </button>
      )}
    </div>
  )
}
