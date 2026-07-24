/**
 * Theme provider (issue-local-016).
 *
 * Resolves the effective UI theme as: the signed-in user's personal override
 * (AuthUser.theme) if set, else the instance-wide default (GET
 * /api/app/theme, public — works pre-login so the login screen themes
 * correctly too). Applies it via a `data-theme` attribute on <html>, which
 * the CSS custom properties in src/index.css key off of.
 *
 * Must be nested INSIDE <AuthProvider> (consumes useAuth() for the current
 * user) — see main.tsx.
 *
 * FOUC: there's a brief flash of the CSS fallback (Classic — see
 * src/index.css's bare `:root` block) before the instance-default fetch
 * resolves. Accepted as low-stakes, consistent with how app_title already
 * behaves (tab title flashes default then updates) — no inline
 * FOUC-avoidance script.
 */
import { useCallback, useEffect, useState, type ReactNode } from 'react'
import { api } from '../api/client'
import { useAuth } from '../auth/useAuth'
import { ThemeContext, type ThemeContextValue, type ThemeName } from './context'

const VALID_THEMES: readonly ThemeName[] = ['classic', 'energy', 'light', 'ocean']

function asThemeName(value: unknown): ThemeName | null {
  return typeof value === 'string' && (VALID_THEMES as readonly string[]).includes(value)
    ? (value as ThemeName)
    : null
}

export function ThemeProvider({ children }: { children: ReactNode }) {
  const { user } = useAuth()
  const [instanceDefault, setInstanceDefault] = useState<ThemeName>('classic')
  const [userOverride, setUserOverride] = useState<ThemeName | null>(null)

  useEffect(() => {
    let cancelled = false
    api
      .getDefaultTheme()
      .then(({ theme }) => {
        const parsed = asThemeName(theme)
        if (!cancelled && parsed !== null) setInstanceDefault(parsed)
      })
      .catch(() => {
        // Unreachable / not-yet-authenticated edge cases → keep Classic.
      })
    return () => {
      cancelled = true
    }
  }, [])

  // Follow the signed-in user's stored override whenever it changes (login,
  // logout, or an external refresh() of the auth context).
  useEffect(() => {
    setUserOverride(asThemeName(user?.theme))
  }, [user])

  const theme: ThemeName = userOverride ?? instanceDefault

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme)
  }, [theme])

  const setTheme = useCallback(
    async (next: ThemeName | null) => {
      const previous = userOverride
      setUserOverride(next)
      try {
        await api.auth.setOwnTheme(next)
      } catch (err) {
        setUserOverride(previous)
        throw err
      }
    },
    [userOverride],
  )

  const value: ThemeContextValue = { theme, userOverride, instanceDefault, setTheme }

  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>
}
