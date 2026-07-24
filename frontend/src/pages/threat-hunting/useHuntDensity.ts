/**
 * useHuntDensity — compact/detailed density selector for the Threat Hunting
 * list view (issue-local-016). Persists the user's choice in localStorage
 * under 'sfi.th.cardDensity'. Controls how much per-card detail renders —
 * the 16-step stage rail hides in 'compact'.
 */
import { useState, useEffect } from 'react'

export type HuntDensity = 'compact' | 'detailed' | 'table'

const STORAGE_KEY = 'sfi.th.cardDensity'
const DEFAULT_DENSITY: HuntDensity = 'detailed'

export function useHuntDensity(): { density: HuntDensity; setDensity: (d: HuntDensity) => void } {
  const [density, setDensityState] = useState<HuntDensity>(() => {
    try {
      const stored = localStorage.getItem(STORAGE_KEY)
      if (stored === 'compact' || stored === 'detailed' || stored === 'table') return stored
    } catch {
      // ignore
    }
    return DEFAULT_DENSITY
  })

  useEffect(() => {
    try {
      localStorage.setItem(STORAGE_KEY, density)
    } catch {
      // ignore
    }
  }, [density])

  return { density, setDensity: setDensityState }
}
