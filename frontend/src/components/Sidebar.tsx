import { useState, useEffect } from 'react'
import { NavLink } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import {
  LayoutDashboard,
  Settings,
  Sparkles,
  Eye,
  UserCircle,
  Info,
  LogOut,
  PanelLeftClose,
  PanelLeftOpen,
  Radar,
  Crosshair,
  Home as HomeIcon,
} from 'lucide-react'
import { clsx } from 'clsx'
import { api } from '../api/client'
import { useAuth } from '../auth/useAuth'
import BrandLogo from './BrandLogo'

// NavLink `to` values are RELATIVE (no leading slash) so the rendered
// <a href> respects the document's <base href> when no prefix is configured,
// and is correctly prefixed when one is. React Router v6 resolves these
// against the router's basename (set from the runtime app-base-prefix).
//
// Visibility flags (prompts-046):
//   adminOnly — hidden from 'normal' (Viewer-only) users. When auth is disabled
//               the app is open (isAdmin true) so the item still shows.
//   authOnly  — only meaningful when auth enforcement is ON. Hidden entirely in
//               open mode (there is no signed-in identity to manage).
// Both link-hiding and route guards (App.tsx) are applied: hiding alone does not
// stop a user typing the URL directly.

type NavItem = {
  to: string
  label: string
  icon: React.ComponentType<{ className?: string }>
  adminOnly: boolean
  authOnly: boolean
}

type NavSection = {
  label: string
  icon: React.ComponentType<{ className?: string }>
  items: NavItem[]
}

const navSections: NavSection[] = [
  {
    label: 'Home',
    icon: HomeIcon,
    items: [
      { to: 'home', label: 'Home', icon: HomeIcon, adminOnly: false, authOnly: false },
    ],
  },
  {
    label: 'Threat Intel',
    icon: Radar,
    items: [
      { to: 'viewer',     label: 'Viewer',     icon: LayoutDashboard, adminOnly: false, authOnly: false },
      { to: 'normalizer', label: 'Normalizer', icon: Sparkles,        adminOnly: true,  authOnly: false },
      { to: 'watchers',   label: 'Watchers',   icon: Eye,             adminOnly: true,  authOnly: false },
    ],
  },
  {
    label: 'Threat Hunting',
    icon: Crosshair,
    items: [
      { to: 'threat-hunting', label: 'Threat Hunting', icon: Crosshair, adminOnly: false, authOnly: false },
    ],
  },
]

const utilityItems: NavItem[] = [
  { to: 'configuration', label: 'Configuration', icon: Settings,   adminOnly: true,  authOnly: false },
  { to: 'account',       label: 'Account',       icon: UserCircle, adminOnly: false, authOnly: true  },
  { to: 'about',         label: 'About',         icon: Info,       adminOnly: false, authOnly: false },
]

const COLLAPSE_KEY = 'sfi.sidebar.collapsed'

function readCollapsed(): boolean {
  try {
    return localStorage.getItem(COLLAPSE_KEY) === '1'
  } catch {
    return false
  }
}

export default function Sidebar() {
  const { authEnabled, isAdmin, isResearcher, user, logout } = useAuth()
  const [collapsed, setCollapsed] = useState<boolean>(readCollapsed)

  useEffect(() => {
    try {
      localStorage.setItem(COLLAPSE_KEY, collapsed ? '1' : '0')
    } catch {
      /* storage unavailable — non-fatal */
    }
  }, [collapsed])

  // Logo presence (authenticated/open context can query this). Drives whether
  // BrandLogo paints the image or the default icon on first render.
  const { data: logoInfo } = useQuery({
    queryKey: ['logo-info'],
    queryFn: api.getLogoInfo,
  })

  // App display title — configurable via Application settings tab.
  const { data: titleData } = useQuery({
    queryKey: ['app-title'],
    queryFn: api.getAppTitle,
  })
  const displayTitle = titleData?.app_title?.trim() || 'Mizton-ThreatBox'

  // Unused: isResearcher is available for future gating within sections
  void isResearcher

  const filterItems = (items: NavItem[]) =>
    items.filter((it) => (!it.adminOnly || isAdmin) && (!it.authOnly || authEnabled))

  const filteredUtility = filterItems(utilityItems)

  function renderNavItem(item: NavItem) {
    return (
      <NavLink
        key={item.to}
        to={item.to}
        title={collapsed ? item.label : undefined}
        className={({ isActive }) =>
          clsx(
            'flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium mb-0.5 transition-colors',
            collapsed && 'justify-center',
            isActive
              ? 'bg-brand-600/20 text-brand-400 nav-item-active'
              : 'text-gray-400 hover:text-gray-100 hover:bg-gray-800',
          )
        }
      >
        <item.icon className="w-4 h-4 shrink-0" />
        {!collapsed && item.label}
      </NavLink>
    )
  }

  return (
    <aside
      className={clsx(
        'flex flex-col shrink-0 bg-gray-900 border-r border-gray-800 h-screen transition-[width] duration-150',
        collapsed ? 'w-[64px]' : 'w-[256px]',
      )}
    >
      {/* Header: logo + title + collapse toggle. Expanded → toggle pinned right;
          collapsed → stacked below the logo, centered. */}
      <div
        className={clsx(
          'border-b border-gray-800 px-3 py-4',
          collapsed ? 'flex flex-col items-center gap-3' : 'flex items-center gap-2.5 px-5',
        )}
      >
        <BrandLogo hasLogo={logoInfo?.has_logo} size={28} />
        {!collapsed && (
          <div className="flex-1 min-w-0">
            <p className="text-xs font-semibold text-gray-100 leading-tight truncate">
              {displayTitle}
            </p>
            <p className="text-[10px] text-gray-500 leading-tight">TI & Hunting Ops Framework</p>
          </div>
        )}
        <button
          className="btn-ghost p-1.5"
          title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          onClick={() => setCollapsed((c) => !c)}
        >
          {collapsed ? <PanelLeftOpen className="w-4 h-4" /> : <PanelLeftClose className="w-4 h-4" />}
        </button>
      </div>

      {/* Nav — sectioned */}
      <nav className="flex-1 py-3 px-2 overflow-y-auto">
        {navSections.map((section) => {
          const sectionItems = filterItems(section.items)
          return (
            <div key={section.label} className="mb-3">
              {/* Section header — hidden when collapsed */}
              {!collapsed ? (
                <div className="flex items-center gap-1.5 px-3 mb-1">
                  <section.icon className="w-3.5 h-3.5 text-gray-500 shrink-0" />
                  <span className="text-[10px] uppercase tracking-wider text-gray-500 font-medium">
                    {section.label}
                  </span>
                </div>
              ) : (
                <div className="flex justify-center mb-1">
                  <section.icon className="w-3.5 h-3.5 text-gray-500" />
                </div>
              )}
              {sectionItems.length > 0
                ? sectionItems.map(renderNavItem)
                : !collapsed && (
                    <p className="px-3 text-[10px] text-gray-600 italic">Coming soon</p>
                  )}
            </div>
          )
        })}

        {/* Utility items — separated by a border */}
        {filteredUtility.length > 0 && (
          <div className="border-t border-gray-800 pt-3 mt-1">
            {filteredUtility.map(renderNavItem)}
          </div>
        )}
      </nav>

      {/* Footer: optional user/logout, version */}
      <div className="border-t border-gray-800">
        {authEnabled && user && (
          <div
            className={clsx(
              'flex items-center gap-2 px-3 py-2.5',
              collapsed ? 'justify-center' : 'justify-between',
            )}
          >
            {!collapsed && (
              <div className="flex-1 min-w-0">
                <p className="text-xs text-gray-300 font-medium truncate">{user.username}</p>
                <p className="text-[10px] text-gray-500 capitalize">{user.role}</p>
              </div>
            )}
            <button
              className="btn-ghost p-1.5"
              title="Sign out"
              aria-label="Sign out"
              onClick={() => { void logout() }}
            >
              <LogOut className="w-4 h-4" />
            </button>
          </div>
        )}

        {!collapsed && (
          <div className="px-3 py-2.5 border-t border-gray-800">
            <p className="text-[10px] text-gray-600">v0.1.0</p>
          </div>
        )}
      </div>
    </aside>
  )
}
