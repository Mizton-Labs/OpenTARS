/**
 * Auth context object + value type (prompts-045).
 *
 * Kept in a non-component module so the provider file can export ONLY the
 * <AuthProvider> component and the hook file can export ONLY useAuth — both
 * required to satisfy react-refresh/only-export-components.
 */
import { createContext } from 'react'
import type { AuthUser, PasswordPolicy } from '../api/client'

export interface AuthContextValue {
  loading: boolean
  authEnabled: boolean
  user: AuthUser | null
  isAuthenticated: boolean
  /** True when auth is disabled (open app) OR role === 'admin'. */
  isAdmin: boolean
  /**
   * True when auth is disabled OR role is 'admin' or 'threat-researcher'.
   * Use to gate Threat Hunting write operations.
   */
  isResearcher: boolean
  /**
   * True when auth is disabled OR role is any authenticated role.
   * Effectively the same as isAuthenticated for read-only TH access.
   */
  isViewer: boolean
  passwordPolicy: PasswordPolicy
  login: (username: string, password: string) => Promise<void>
  logout: () => Promise<void>
  refresh: () => Promise<void>
}

export const AuthContext = createContext<AuthContextValue | null>(null)
