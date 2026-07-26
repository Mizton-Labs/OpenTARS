/**
 * Login screen (prompts-045, issue-local-010).
 *
 * Rendered OUTSIDE the sidebar shell (see App.tsx). Only reachable when auth
 * enforcement is enabled. On success the AuthContext caches the user and we
 * navigate to the route the user originally requested (location.state.from)
 * or fall back to the viewer.
 *
 * issue-local-010: when SSO is enabled, shows a prominent "Sign in with SSO"
 * button above the local form. Both methods coexist so the local admin
 * account always works as a break-glass path.
 *
 * Security: the backend returns a single generic error for any failed login
 * (bad username, bad password, disabled account), so this screen must NOT try
 * to distinguish those cases — it surfaces whatever generic message the API
 * returns.
 */
import { useState, type FormEvent } from 'react'
import { useNavigate, useLocation, Navigate, useSearchParams } from 'react-router-dom'
import { Loader2, LogIn } from 'lucide-react'
import { useAuth } from '../auth/useAuth'
import { ssoLoginUrl } from '../api/client'
import BrandLogo from '../components/BrandLogo'

interface LocationState {
  from?: { pathname: string }
}

// SSO error code → human-readable message
const _SSO_ERRORS: Record<string, string> = {
  missing_params:  'SSO login failed: missing parameters.',
  auth_failed:     'SSO authentication failed. Check your IdP configuration.',
  server_error:    'SSO login encountered a server error. Try again or use local login.',
  access_denied:   'Access denied by the identity provider.',
}

export default function Login() {
  const { login, authEnabled, isAuthenticated, loading: authLoading, ssoEnabled, ssoButtonLabel } = useAuth()

  const navigate = useNavigate()
  const location = useLocation()
  const [searchParams] = useSearchParams()

  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // location.state.from.pathname is an absolute, basename-relative path (set by
  // ProtectedLayout). The fallback is the absolute '/viewer' so navigation
  // resolves against the router basename — NOT relative to '/login'.
  const from = (location.state as LocationState | null)?.from?.pathname ?? '/viewer'

  // SSO callback error surfaced via ?sso_error= query param
  const ssoError = searchParams.get('sso_error')
  const ssoErrorMsg = ssoError ? (_SSO_ERRORS[ssoError] ?? 'SSO login failed.') : null

  // If auth is disabled, or the user is already authenticated, there is no
  // login to perform — send them into the app.
  if (!authLoading && (!authEnabled || isAuthenticated)) {
    return <Navigate to={from} replace />
  }

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    setError(null)
    setSubmitting(true)
    try {
      await login(username.trim(), password)
      navigate(from, { replace: true })
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Login failed')
    } finally {
      setSubmitting(false)
    }
  }

  function handleSsoLogin() {
    window.location.href = ssoLoginUrl(from)
  }

  return (
    <div className="flex items-center justify-center min-h-screen bg-gray-950 px-4">
      <div className="card w-full max-w-sm">
        <div className="flex flex-col items-center gap-3 mb-6">
          <BrandLogo size={48} />
          <div className="text-center">
            <h1 className="text-base font-semibold text-gray-100">OpenTARS</h1>
            <p className="text-xs text-gray-500">Sign in to continue</p>
          </div>
        </div>

        {/* SSO error from callback redirect */}
        {ssoErrorMsg && (
          <p role="alert" className="text-xs text-red-400 mb-3">
            {ssoErrorMsg}
          </p>
        )}

        {/* SSO button — shown when SSO is enabled */}
        {ssoEnabled && (
          <>
            <button
              type="button"
              className="btn-primary w-full justify-center flex items-center gap-2 mb-4"
              onClick={handleSsoLogin}
            >
              <LogIn className="w-4 h-4" />
              {ssoButtonLabel}
            </button>
            <div className="flex items-center gap-2 mb-4">
              <div className="flex-1 border-t border-gray-700" />
              <span className="text-[10px] text-gray-600 uppercase tracking-wide">or</span>
              <div className="flex-1 border-t border-gray-700" />
            </div>
          </>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label htmlFor="username" className="label">
              Username
            </label>
            <input
              id="username"
              type="text"
              autoComplete="username"
              className="input"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              disabled={submitting}
              autoFocus={!ssoEnabled}
              required
            />
          </div>

          <div>
            <label htmlFor="password" className="label">
              Password
            </label>
            <input
              id="password"
              type="password"
              autoComplete="current-password"
              className="input"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              disabled={submitting}
              required
            />
          </div>

          {error !== null && (
            <p role="alert" className="text-xs text-red-400">
              {error}
            </p>
          )}

          <button type="submit" className="btn-primary w-full justify-center" disabled={submitting}>
            {submitting && <Loader2 className="w-4 h-4 animate-spin" />}
            {submitting ? 'Signing in…' : 'Sign in'}
          </button>
        </form>
      </div>
    </div>
  )
}
