/**
 * Visual building blocks for HuntDashboard.tsx — stat tiles, bar/pie
 * breakdowns, and timeline charts (issue-local-032/033/034). Split out of
 * HuntDashboard.tsx once it grew past "one page, one file" — this module
 * owns rendering only, HuntDashboard.tsx owns data-fetching/layout.
 *
 * No charting library: hand-rolled SVG (TimelineChart) and a CSS
 * conic-gradient (PieChart). Both are small, fixed-shape charts — pulling
 * in a charting dependency for two chart types isn't worth the bundle cost,
 * consistent with the rest of this app (no charting lib anywhere else).
 */
import { useState } from 'react'
import { clsx } from 'clsx'
import type { THTimelinePoint } from '../../api/client'
import Pagination from '../../components/Pagination'

// ── Stat tile ────────────────────────────────────────────────────────────────

export function StatCard({
  icon: Icon,
  label,
  value,
  sub,
  onClick,
}: {
  icon: React.ElementType
  label: string
  value: number
  sub?: string
  /** Deep-links to the Data Explorer category backing this stat (issue-local-033). */
  onClick?: () => void
}) {
  const Tag = onClick ? 'button' : 'div'
  return (
    <Tag
      type={onClick ? 'button' : undefined}
      onClick={onClick}
      className={clsx(
        'card flex items-start gap-3 py-4 text-left w-full',
        onClick && 'cursor-pointer hover:border-brand-600/50 hover:bg-gray-800/40 transition-colors',
      )}
    >
      <div className="rounded-lg bg-brand-900/30 border border-brand-800/40 p-2 shrink-0">
        <Icon className="w-4 h-4 text-brand-400" />
      </div>
      <div className="min-w-0">
        <p className="text-2xl font-semibold text-gray-100 leading-none">{value.toLocaleString()}</p>
        <p className="text-xs text-gray-500 mt-1.5">{label}</p>
        {sub && <p className="text-[11px] text-gray-600 mt-0.5">{sub}</p>}
      </div>
    </Tag>
  )
}

// ── Shared panel chrome ──────────────────────────────────────────────────────

function PanelHeader({
  title,
  icon: Icon,
  onClick,
  extra,
}: {
  title: string
  icon: React.ElementType
  onClick?: () => void
  extra?: React.ReactNode
}) {
  const content = (
    <>
      <Icon className="w-4 h-4 text-brand-400" />
      <span className="text-sm font-medium text-gray-200">{title}</span>
    </>
  )
  return onClick ? (
    <button
      type="button"
      onClick={onClick}
      className="flex w-full items-center justify-between gap-2 px-4 py-3 bg-gray-800/40 hover:bg-gray-800/70 transition-colors text-left"
    >
      <span className="flex items-center gap-2">{content}</span>
      {extra}
    </button>
  ) : (
    <div className="flex items-center justify-between gap-2 px-4 py-3 bg-gray-800/40">
      <span className="flex items-center gap-2">{content}</span>
      {extra}
    </div>
  )
}

const MODEL_PANEL_PAGE_SIZE = 10

// ── Bar breakdown (issue-local-034: paginated at 10 rows/page — used for
// the two model panels only; Evidence/Packages moved to PieChart below) ────

export function BarBreakdown({
  title,
  icon: Icon,
  rows,
  onClick,
}: {
  title: string
  icon: React.ElementType
  rows: [string, number][]
  /** Deep-links to the Data Explorer category backing this breakdown (issue-local-033). */
  onClick?: () => void
}) {
  const [page, setPage] = useState(1)
  const totalPages = Math.max(1, Math.ceil(rows.length / MODEL_PANEL_PAGE_SIZE))
  const clampedPage = Math.min(page, totalPages)
  const pageRows = rows.slice(
    (clampedPage - 1) * MODEL_PANEL_PAGE_SIZE,
    clampedPage * MODEL_PANEL_PAGE_SIZE,
  )
  const max = Math.max(1, ...rows.map(([, n]) => n))

  return (
    <div className="border border-gray-700 rounded-lg overflow-hidden">
      <PanelHeader title={title} icon={Icon} onClick={onClick} />
      <div className="p-4 space-y-2.5">
        {rows.length === 0 ? (
          <p className="text-sm text-gray-500 italic">No data yet.</p>
        ) : (
          pageRows.map(([label, count]) => (
            <div key={label}>
              <div className="flex items-center justify-between text-[11px] text-gray-400 mb-0.5">
                <span className="truncate">{label}</span>
                <span className="font-mono text-gray-500 shrink-0 ml-2">{count}</span>
              </div>
              <div className="h-1.5 rounded-full bg-gray-800 overflow-hidden">
                <div
                  className="h-full rounded-full bg-brand-500"
                  style={{ width: `${Math.max(4, (count / max) * 100)}%` }}
                />
              </div>
            </div>
          ))
        )}
      </div>
      {rows.length > MODEL_PANEL_PAGE_SIZE && (
        <div className="px-4 pb-4">
          <Pagination
            page={clampedPage}
            totalPages={totalPages}
            totalItems={rows.length}
            onPageChange={setPage}
          />
        </div>
      )}
    </div>
  )
}

// ── Pie chart (issue-local-034: Evidence by Type / Packages by Status) ─────

const PIE_COLORS = [
  '#2f58f0', // brand blue
  '#10b981', // emerald
  '#f59e0b', // amber
  '#f43f5e', // rose
  '#0ea5e9', // sky
  '#8b5cf6', // violet
  '#14b8a6', // teal
  '#fb923c', // orange
]

export function PieChart({
  title,
  icon: Icon,
  rows,
  onClick,
}: {
  title: string
  icon: React.ElementType
  rows: [string, number][]
  onClick?: () => void
}) {
  const total = rows.reduce((sum, [, n]) => sum + n, 0)

  let cumulative = 0
  const slices = rows.map(([label, count], i) => {
    const start = total > 0 ? (cumulative / total) * 360 : 0
    cumulative += count
    const end = total > 0 ? (cumulative / total) * 360 : 0
    return { label, count, color: PIE_COLORS[i % PIE_COLORS.length], start, end }
  })
  const gradient =
    slices.length > 0
      ? `conic-gradient(${slices.map((s) => `${s.color} ${s.start}deg ${s.end}deg`).join(', ')})`
      : undefined

  return (
    <div className="border border-gray-700 rounded-lg overflow-hidden">
      <PanelHeader title={title} icon={Icon} onClick={onClick} />
      <div className="p-4">
        {rows.length === 0 || total === 0 ? (
          <p className="text-sm text-gray-500 italic">No data yet.</p>
        ) : (
          <div className="flex items-center gap-4">
            <div
              className="w-24 h-24 rounded-full shrink-0"
              style={{ background: gradient }}
              role="img"
              aria-label={`${title} pie chart`}
            />
            <div className="flex-1 min-w-0 space-y-1.5">
              {slices.map((s) => (
                <div key={s.label} className="flex items-center gap-2 text-[11px]">
                  <span
                    className="w-2.5 h-2.5 rounded-full shrink-0"
                    style={{ background: s.color }}
                  />
                  <span className="truncate text-gray-300 flex-1">{s.label}</span>
                  <span className="text-gray-500 font-mono shrink-0">
                    {s.count} ({Math.round((s.count / total) * 100)}%)
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

// ── Timeline chart (issue-local-034: Hunts per day / IOCs per day) ─────────

export function TimelineChart({
  title,
  icon: Icon,
  data,
}: {
  title: string
  icon: React.ElementType
  data: THTimelinePoint[]
}) {
  const W = 600
  const H = 140
  const PAD_X = 8
  const PAD_Y = 16
  const total = data.reduce((sum, d) => sum + d.count, 0)

  let linePath = ''
  let areaPath = ''
  let points: { x: number; y: number; d: THTimelinePoint }[] = []
  if (data.length > 0) {
    const max = Math.max(1, ...data.map((d) => d.count))
    const stepX = data.length > 1 ? (W - PAD_X * 2) / (data.length - 1) : 0
    points = data.map((d, i) => ({
      x: data.length > 1 ? PAD_X + i * stepX : W / 2,
      y: H - PAD_Y - (d.count / max) * (H - PAD_Y * 2),
      d,
    }))
    linePath = points.map((p, i) => `${i === 0 ? 'M' : 'L'}${p.x},${p.y}`).join(' ')
    areaPath = `${linePath} L${points[points.length - 1].x},${H - PAD_Y} L${points[0].x},${H - PAD_Y} Z`
  }

  return (
    <div className="border border-gray-700 rounded-lg overflow-hidden">
      <PanelHeader
        title={title}
        icon={Icon}
        extra={<span className="text-xs text-gray-500">Total: {total.toLocaleString()}</span>}
      />
      <div className="p-4">
        {data.length === 0 ? (
          <p className="text-sm text-gray-500 italic py-8 text-center">No data yet.</p>
        ) : (
          <>
            <svg viewBox={`0 0 ${W} ${H}`} className="w-full h-32" preserveAspectRatio="none">
              <path d={areaPath} className="fill-brand-500/15" stroke="none" />
              <path d={linePath} className="fill-none stroke-brand-500" strokeWidth={2} />
              {points.map((p) => (
                <circle key={p.d.date} cx={p.x} cy={p.y} r={2.5} className="fill-brand-400">
                  <title>
                    {p.d.date}: {p.d.count}
                  </title>
                </circle>
              ))}
            </svg>
            <div className="flex justify-between text-[10px] text-gray-600 mt-1">
              <span>{data[0].date}</span>
              {data.length > 1 && <span>{data[data.length - 1].date}</span>}
            </div>
          </>
        )}
      </div>
    </div>
  )
}
