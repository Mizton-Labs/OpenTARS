/**
 * useHuntTheme — 2-theme selector for the Threat Hunting list view.
 * Persists the user's choice in localStorage under 'sfi.th.cardTheme'.
 */
import { useState, useEffect } from 'react'

export type HuntTheme = 'classic' | 'modern'

const STORAGE_KEY = 'sfi.th.cardTheme'
const DEFAULT_THEME: HuntTheme = 'classic'

export function useHuntTheme(): { theme: HuntTheme; setTheme: (t: HuntTheme) => void } {
  const [theme, setThemeState] = useState<HuntTheme>(() => {
    try {
      const stored = localStorage.getItem(STORAGE_KEY)
      if (stored === 'classic' || stored === 'modern') return stored
    } catch {
      // ignore
    }
    return DEFAULT_THEME
  })

  useEffect(() => {
    try {
      localStorage.setItem(STORAGE_KEY, theme)
    } catch {
      // ignore
    }
  }, [theme])

  return { theme, setTheme: setThemeState }
}
