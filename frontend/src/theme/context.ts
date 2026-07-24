/**
 * Theme context object + value type (issue-local-016).
 *
 * Mirrors the auth/ context/useAuth split: a non-component module so the
 * provider file can export ONLY <ThemeProvider> and the hook file can export
 * ONLY useTheme, satisfying react-refresh/only-export-components.
 */
import { createContext } from 'react'

export type ThemeName = 'classic' | 'energy'

export interface ThemeContextValue {
  /** Effective theme actually applied — userOverride if set, else instanceDefault. */
  theme: ThemeName
  /** The signed-in user's personal override, or null when following the instance default. */
  userOverride: ThemeName | null
  /** Instance-wide default, as configured by an admin (GET /api/app/theme). */
  instanceDefault: ThemeName
  /**
   * Set (or, with `null`, clear) the caller's personal override. Clearing
   * falls back to instanceDefault. No-op (throws) for unauthenticated
   * callers — only meaningful once signed in.
   */
  setTheme: (theme: ThemeName | null) => Promise<void>
}

export const ThemeContext = createContext<ThemeContextValue | null>(null)
