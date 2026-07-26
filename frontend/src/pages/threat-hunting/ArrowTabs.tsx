/**
 * ArrowTabs — HuntDetail.tsx's tab bar rendered as connected SmartArt-style
 * arrow/chevron segments (issue-local-022 item 5), instead of the plain
 * underline tabs used elsewhere. Each segment points into the next, echoing
 * the same "sequential process" visual grammar as ThreatHunting.tsx's
 * ProcessArrow phase rail — adapted here into clickable nav tabs rather than
 * a status-only rail.
 *
 * Disabled tabs (phases the active run hasn't reached yet) stay visibly
 * greyed at all times, not just while unclickable, so it's obvious at a
 * glance which phases are actually available.
 */

import { clsx } from 'clsx'

export interface ArrowTabItem {
  key: string
  label: React.ReactNode
  disabled?: boolean
  title?: string
}

// How deep the arrow point/notch cuts into each segment, in px.
const NOTCH = 14

function arrowClipPath(isFirst: boolean, isLast: boolean): string | undefined {
  if (isFirst && isLast) return undefined
  if (isFirst) {
    return `polygon(0 0, calc(100% - ${NOTCH}px) 0, 100% 50%, calc(100% - ${NOTCH}px) 100%, 0 100%)`
  }
  if (isLast) {
    return `polygon(0 0, 100% 0, 100% 100%, 0 100%, ${NOTCH}px 50%)`
  }
  return `polygon(0 0, calc(100% - ${NOTCH}px) 0, 100% 50%, calc(100% - ${NOTCH}px) 100%, 0 100%, ${NOTCH}px 50%)`
}

export default function ArrowTabs({
  tabs,
  active,
  onSelect,
}: {
  tabs: ArrowTabItem[]
  active: string
  onSelect: (key: string) => void
}) {
  return (
    <div className="flex items-stretch overflow-x-auto">
      {tabs.map((tab, i) => {
        const isFirst = i === 0
        const isLast = i === tabs.length - 1
        const isActive = active === tab.key
        return (
          <button
            key={tab.key}
            onClick={() => !tab.disabled && onSelect(tab.key)}
            disabled={tab.disabled}
            title={tab.title}
            style={{
              clipPath: arrowClipPath(isFirst, isLast),
              marginLeft: isFirst ? 0 : -NOTCH,
            }}
            className={clsx(
              'relative shrink-0 px-5 py-2 text-sm font-medium whitespace-nowrap transition-colors border',
              tab.disabled
                ? 'bg-gray-900/70 border-gray-800/60 text-gray-700 cursor-not-allowed'
                : isActive
                  ? 'bg-brand-700 border-brand-500 text-white'
                  : 'bg-gray-800/70 border-gray-700/60 text-gray-400 hover:bg-gray-700 hover:text-gray-200',
            )}
          >
            {tab.label}
          </button>
        )
      })}
    </div>
  )
}
