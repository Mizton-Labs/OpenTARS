/**
 * useHuntPageSize — page-size selector for the hunt-package list's
 * pagination (issue-local-018 follow-up). Persists the user's choice in
 * localStorage under 'sfi.th.pageSize', mirroring useHuntDensity.ts.
 */
import { useState, useEffect } from 'react'

export const HUNT_PAGE_SIZE_OPTIONS = [10, 20, 50, 100] as const
export type HuntPageSize = (typeof HUNT_PAGE_SIZE_OPTIONS)[number]

const STORAGE_KEY = 'sfi.th.pageSize'
const DEFAULT_PAGE_SIZE: HuntPageSize = 20

function isHuntPageSize(value: unknown): value is HuntPageSize {
  return typeof value === 'number' && (HUNT_PAGE_SIZE_OPTIONS as readonly number[]).includes(value)
}

export function useHuntPageSize(): { pageSize: HuntPageSize; setPageSize: (n: HuntPageSize) => void } {
  const [pageSize, setPageSizeState] = useState<HuntPageSize>(() => {
    try {
      const stored = Number(localStorage.getItem(STORAGE_KEY))
      if (isHuntPageSize(stored)) return stored
    } catch {
      // ignore
    }
    return DEFAULT_PAGE_SIZE
  })

  useEffect(() => {
    try {
      localStorage.setItem(STORAGE_KEY, String(pageSize))
    } catch {
      // ignore
    }
  }, [pageSize])

  return { pageSize, setPageSize: setPageSizeState }
}
