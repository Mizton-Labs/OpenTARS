/**
 * ProtectedLayout (prompts-045).
 *
 * The authenticated application shell: the sidebar plus an <Outlet/> for the
 * in-shell SHELL_ROUTES. Guards access based on AuthContext:
 *   - while auth state is still bootstrapping → render a neutral spinner so we
 *     never flash the login screen or the app before we know the real state.
 *   - auth enabled AND no user → redirect to /login, remembering the requested
 *     path so Login can send the user back after a successful sign-in.
 *   - auth enabled AND the user must change a default password (prompts-047) →
 *     render a full-screen forced change-password step (no shell, logout only)
 *     until the flag clears. Mirrors the server-side middleware gate.
 *   - auth disabled (open app) OR user present → render the shell.
 */
import { Navigate, Outlet, useLocation } from 'react-router-dom'
import { Loader2 } from 'lucide-react'
import Sidebar from './Sidebar'
import ChangePasswordCard from './ChangePasswordCard'
import ConfigDriftBanner from './ConfigDriftBanner'
import SmartSearchDrawer from './SmartSearchDrawer'
import { useAuth } from '../auth/useAuth'

export default function ProtectedLayout() {
  const { loading, authEnabled, user, refresh, logout } = useAuth()
  const location = useLocation()

  if (loading) {
    return (
      <div className="flex items-center justify-center h-screen bg-gray-950">
        <Loader2 className="w-6 h-6 text-gray-500 animate-spin" />
      </div>
    )
  }

  if (authEnabled && user === null) {
    return <Navigate to="login" replace state={{ from: location }} />
  }

  // issue-local-013: SSO-authenticated users (idp is set) are exempt from the
  // forced-password-reset screen.  Their local password may be an unusable random
  // hash; requiring them to "change" it makes no sense.  The backend also clears
  // the flag at SSO login time and skips the 403 gate for idp-linked accounts,
  // but this guard ensures the SPA never shows the screen to SSO users even
  // before the /me response is refreshed.
  if (authEnabled && user?.must_change_password && !user?.idp) {
    return (
      <div className="flex items-center justify-center min-h-screen bg-gray-950 p-4">
        <div className="w-full max-w-sm space-y-4 rounded-lg border border-gray-800 bg-gray-900 p-6">
          <div className="space-y-1">
            <h1 className="text-lg font-semibold text-gray-100">
              Set a new password
            </h1>
            <p className="text-xs text-gray-400">
              Your current password is a temporary default. Choose a new password
              to continue.
            </p>
          </div>
          <ChangePasswordCard onSuccess={() => void refresh()} />
          <div className="flex justify-end border-t border-gray-800 pt-3">
            <button
              type="button"
              onClick={() => void logout()}
              className="text-xs text-gray-400 hover:text-gray-200"
            >
              Log out
            </button>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="flex flex-col h-screen overflow-hidden bg-gray-950">
      <ConfigDriftBanner />
      <div className="flex flex-1 overflow-hidden">
        <Sidebar />
        {/* issue-local-031: the right-hand gutter is the search button's slot.
            Reserving it here — rather than letting the button float over the
            page — is what keeps it from covering page header controls such as
            Threat Hunting's "New Package". */}
        <main className="flex-1 overflow-auto pr-11">
          <Outlet />
        </main>
        {/* Search is global, so the entry point is available from every page. */}
        <SmartSearchDrawer />
      </div>
    </div>
  )
}
