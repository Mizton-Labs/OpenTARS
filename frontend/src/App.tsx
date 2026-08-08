import { useEffect } from 'react'
import { Routes, Route, Navigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import ProtectedLayout from './components/ProtectedLayout'
import Viewer from './pages/Viewer'
import Configuration from './pages/Configuration'
import Normalizer from './pages/Normalizer'
import Watchers from './pages/Watchers'
import ThreatHunting from './pages/ThreatHunting'
import HuntDashboard from './pages/threat-hunting/HuntDashboard'
import Account from './pages/Account'
import About from './pages/About'
import Assistant from './pages/Assistant'
import Audit from './pages/Audit'
import Login from './pages/Login'
import Home from './pages/Home'
import ThreatHuntingNew from './pages/threat-hunting/ThreatHuntingNew'
import ThreatHuntingDetail from './pages/threat-hunting/ThreatHuntingDetail'
import ThreatIntelTracking from './pages/threat-hunting/ThreatIntelTracking'
import DataExplorer from './pages/threat-hunting/DataExplorer'
import PlaybooksPage from './pages/threat-hunting/PlaybooksPage'
import { api } from './api/client'
import { useAuth } from './auth/useAuth'
import { KNOWN_ROUTES } from './utils/basePrefix'

// Routes use RELATIVE paths (no leading slash) so the application produces
// document-relative <a href> values when no base prefix is configured.
// React Router v6 resolves these against the router's basename (which is
// set from the runtime app-base-prefix in main.tsx — itself resolved via
// the three-tier precedence in utils/basePrefix.ts).
//
// KNOWN_ROUTES is the single source of truth shared with the auto-detect
// logic in utils/basePrefix.ts. It includes 'login', which is rendered
// OUTSIDE the sidebar shell. The in-shell SHELL_ROUTES are derived by
// excluding 'login'; each maps to a page component below. Adding a new
// in-shell route REQUIRES adding the slug to KNOWN_ROUTES so reverse-proxy
// alias auto-detection continues to recognise it as a route-suffix.
type ShellRoute = Exclude<(typeof KNOWN_ROUTES)[number], 'login'>

const SHELL_ROUTES = KNOWN_ROUTES.filter((r): r is ShellRoute => r !== 'login')

const PAGE_COMPONENTS: Record<ShellRoute, React.ComponentType> = {
  home: Home,
  viewer: Viewer,
  configuration: Configuration,
  normalizer: Normalizer,
  watchers: Watchers,
  // issue-local-032: the Dashboard is the module's default view; the
  // package list moved to its own nested route (threat-hunting/packages,
  // registered below alongside /new, /tracking, /:id).
  'threat-hunting': HuntDashboard,
  assistant: Assistant,
  audit: Audit,
  account: Account,
  about: About,
}

// Route-level access guards (prompts-046). Hiding the sidebar links is not
// sufficient — a normal user can still type an admin URL directly. These
// wrappers bounce unauthorised navigation back to /viewer (the one page every
// authenticated user can always reach).
//
// The redirect target is the ABSOLUTE in-router path "/viewer" (not a relative
// "viewer", which from e.g. /configuration would resolve to the nonexistent
// /configuration/viewer). React Router applies the router basename to absolute
// paths, so this stays correct under a reverse-proxy base prefix.
//
// In open mode (auth disabled) isAdmin is true and authEnabled is false, so:
//   - RequireAdmin lets every page through (the app is fully open), and
//   - RequireAuthEnabled redirects the account page to /viewer (there is no
//     signed-in user to manage when auth is off).
const ADMIN_ONLY_ROUTES = new Set<ShellRoute>(['configuration', 'normalizer', 'watchers'])
const AUTH_ENABLED_ROUTES = new Set<ShellRoute>(['account'])

function RequireAdmin({ children }: { children: React.ReactElement }) {
  const { isAdmin } = useAuth()
  return isAdmin ? children : <Navigate to="/viewer" replace />
}

function RequireAuthEnabled({ children }: { children: React.ReactElement }) {
  const { authEnabled } = useAuth()
  return authEnabled ? children : <Navigate to="/viewer" replace />
}

// issue-local-041: Hunt Playbooks — researcher-or-admin, not a plain
// authenticated (threat-viewer) user. Admins pass isAdmin, so this is a
// min-role check (researcher and above), the same tier the backend's own
// middleware already enforces for /api/threat-hunting/ writes.
function RequireResearcher({ children }: { children: React.ReactElement }) {
  const { isResearcher, isAdmin } = useAuth()
  return isResearcher || isAdmin ? children : <Navigate to="/viewer" replace />
}

export { RequireAdmin, RequireAuthEnabled, RequireResearcher }

function guard(slug: ShellRoute, element: React.ReactElement): React.ReactElement {
  if (ADMIN_ONLY_ROUTES.has(slug)) return <RequireAdmin>{element}</RequireAdmin>
  if (AUTH_ENABLED_ROUTES.has(slug)) return <RequireAuthEnabled>{element}</RequireAuthEnabled>
  return element
}

export default function App() {
  // Sync browser tab title with the operator-configured display name.
  // Public endpoint — resolves before and after login. Falls back to the
  // static product name when empty or not yet fetched.
  const { data: titleData } = useQuery({
    queryKey: ['app-title'],
    queryFn: api.getAppTitle,
    staleTime: 5 * 60 * 1000,
  })
  useEffect(() => {
    document.title = titleData?.app_title || 'OpenTARS'
  }, [titleData?.app_title])

  return (
    <Routes>
      {/* Login is rendered outside the sidebar shell. */}
      <Route path="login" element={<Login />} />

      {/* Everything else lives inside the authenticated shell. */}
      <Route element={<ProtectedLayout />}>
        <Route index element={<Navigate to="home" replace />} />
        {SHELL_ROUTES.map((slug) => {
          const Component = PAGE_COMPONENTS[slug]
          return <Route key={slug} path={slug} element={guard(slug, <Component />)} />
        })}
        {/* Nested TH routes (issue-local-011 Part 5) — must come AFTER the
            generic SHELL_ROUTES map so they take precedence over the flat
            threat-hunting entry (now the Dashboard, issue-local-032). */}
        <Route path="threat-hunting/packages" element={<ThreatHunting />} />
        <Route path="threat-hunting/new" element={<ThreatHuntingNew />} />
        {/* issue-local-021: cross-hunt Threat Intel Tracking dashboard — a
            static segment, so React Router's route ranking already prefers
            it over threat-hunting/:id regardless of declaration order, but
            it's declared first anyway for clarity, matching threat-hunting/new. */}
        <Route path="threat-hunting/tracking" element={<ThreatIntelTracking />} />
        {/* issue-local-033: row-level data behind each Dashboard panel. */}
        <Route path="threat-hunting/explorer" element={<DataExplorer />} />
        {/* issue-local-041: moved out of admin-only Configuration — researcher
            or admin (not threat-viewer). */}
        <Route
          path="threat-hunting/playbooks"
          element={<RequireResearcher><PlaybooksPage /></RequireResearcher>}
        />
        <Route path="threat-hunting/:id" element={<ThreatHuntingDetail />} />
      </Route>
    </Routes>
  )
}
