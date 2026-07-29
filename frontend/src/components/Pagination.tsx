/**
 * Pagination — prev/next + page info, with an optional page-size dropdown
 * (issue-local-034). Mirrors the page-size-selector + prev/next footer
 * pattern ThreatHunting.tsx already used for the hunt-package list, pulled
 * out so the Data Explorer and the Dashboard's model breakdown panels don't
 * each reimplement it.
 */
import { ChevronLeft, ChevronRight } from 'lucide-react'

export default function Pagination({
  page,
  totalPages,
  totalItems,
  itemLabel = 'item',
  onPageChange,
  pageSize,
  pageSizeOptions,
  onPageSizeChange,
}: {
  page: number
  totalPages: number
  totalItems: number
  itemLabel?: string
  onPageChange: (page: number) => void
  /** Omit pageSize/pageSizeOptions/onPageSizeChange for a fixed page size (no dropdown). */
  pageSize?: number
  pageSizeOptions?: readonly number[]
  onPageSizeChange?: (size: number) => void
}) {
  const showPageSize = pageSize !== undefined && pageSizeOptions && onPageSizeChange

  if (totalPages <= 1 && !showPageSize) return null

  return (
    <div className="flex items-center justify-center gap-3 text-sm text-gray-500 flex-wrap">
      {showPageSize && (
        <div className="flex items-center gap-1.5 text-xs">
          <label htmlFor="pagination-page-size" className="text-gray-500 shrink-0">
            Show
          </label>
          <select
            id="pagination-page-size"
            className="input py-1 text-xs w-auto"
            value={pageSize}
            onChange={(e) => onPageSizeChange(Number(e.target.value))}
          >
            {pageSizeOptions.map((n) => (
              <option key={n} value={n}>
                {n}
              </option>
            ))}
          </select>
        </div>
      )}
      {totalPages > 1 && (
        <>
          <button
            type="button"
            className="btn btn-secondary px-2 py-1"
            disabled={page <= 1}
            onClick={() => onPageChange(Math.max(1, page - 1))}
            aria-label="Previous page"
          >
            <ChevronLeft className="w-4 h-4" />
          </button>
          <span>
            Page {page} of {totalPages} · {totalItems.toLocaleString()} {itemLabel}
            {totalItems === 1 ? '' : 's'}
          </span>
          <button
            type="button"
            className="btn btn-secondary px-2 py-1"
            disabled={page >= totalPages}
            onClick={() => onPageChange(Math.min(totalPages, page + 1))}
            aria-label="Next page"
          >
            <ChevronRight className="w-4 h-4" />
          </button>
        </>
      )}
    </div>
  )
}
