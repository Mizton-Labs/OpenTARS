/**
 * useTheme hook (issue-local-016).
 *
 * Separate module so it is the file's only export (react-refresh rule).
 */
import { useContext } from 'react'
import { ThemeContext, type ThemeContextValue } from './context'

export function useTheme(): ThemeContextValue {
  const ctx = useContext(ThemeContext)
  if (ctx === null) {
    throw new Error('useTheme must be used within a ThemeProvider')
  }
  return ctx
}
