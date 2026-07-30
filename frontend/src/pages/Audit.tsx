/**
 * Audit — "Audit" sidebar entry (issue-local-033).
 *
 * Four tabs, one per log category: Application, User, Agent, System. Visible
 * to every signed-in user, but scoped: an admin sees every category and
 * every actor; a normal user sees Application/User/Agent — their own
 * everyday activity, authentication activity, and agent-triggered runs —
 * scoped to themselves. Only System (operational health, not "activity") is
 * admin-only (enforced server-side by GET /api/audit/events — this page
 * never trusts a client-side check alone, the same convention every
 * admin-gated view in this app follows).
 */
import { useEffect, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { clsx } from 'clsx'
import { ScrollText, Search, X, Loader2, ChevronDown, ChevronRight, Boxes, User, Bot, Server } from 'lucide-react'
import { api, type AuditEvent } from '../api/client'
import { useAuth } from '../auth/useAuth'
import Pagination from '../components/Pagination'

const PAGE_SIZE_OPTIONS = [25, 50, 100, 200] as const

interface AuditCategory {
  id: string
  label: string
  icon: React.ElementType
  adminOnly: boolean
}

// Order matches the issue's own listing: Application, User, Agent, System.
// Only System is admin-only — Application moved into non-admin-visible
// territory alongside User/Agent (issue-local-033 follow-up): it now covers
// a non-admin's own everyday activity (hunt packages, evidence, IOC
// verdicts, ...), not just admin-facing ingestion/watcher events.
const AUDIT_CATEGORIES: AuditCategory[] = [
  { id: 'application', label: 'Application', icon: Boxes, adminOnly: false },
  { id: 'user', label: 'User', icon: User, adminOnly: false },
  { id: 'agent', label: 'Agent', icon: Bot, adminOnly: false },
  { id: 'system', label: 'System', icon: Server, adminOnly: true },
]

function formatTimestamp(iso: string): string {
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString()
}

function EventRow({ event }: { event: AuditEvent }) {
  const [expanded, setExpanded] = useState(false)
  const hasDetail = event.detail && Object.keys(event.detail).length > 0

  return (
    <>
      <tr className="border-t border-gray-800/60">
        <td className="py-1.5 px-2 text-[12px] text-gray-400 whitespace-nowrap">
          {formatTimestamp(event.created_at)}
        </td>
        <td className="py-1.5 px-2 text-[12px] text-gray-300">{event.action}</td>
        <td className="py-1.5 px-2 text-[12px] text-gray-300">
          {event.username ? (
            <span>
              {event.username}
              {event.role && <span className="text-gray-500"> · {event.role}</span>}
            </span>
          ) : (
            <span className="text-gray-600">—</span>
          )}
        </td>
        <td className="py-1.5 px-2 text-[12px] text-gray-300">{event.summary}</td>
        <td className="py-1.5 px-2 text-[12px]">
          {hasDetail && (
            <button
              type="button"
              onClick={() => setExpanded((e) => !e)}
              className="flex items-center gap-1 text-gray-500 hover:text-gray-300 transition-colors"
              aria-label={expanded ? 'Hide details' : 'Show details'}
            >
              {expanded ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
              Details
            </button>
          )}
        </td>
      </tr>
      {expanded && hasDetail && (
        <tr className="border-t border-gray-800/40 bg-gray-950/40">
          <td colSpan={5} className="py-2 px-2">
            <pre className="text-[11px] text-gray-400 whitespace-pre-wrap break-all font-mono">
              {JSON.stringify(event.detail, null, 2)}
            </pre>
          </td>
        </tr>
      )}
    </>
  )
}

export default function Audit() {
  const { isAdmin } = useAuth()
  const visibleCategories = AUDIT_CATEGORIES.filter((c) => isAdmin || !c.adminOnly)

  const [category, setCategory] = useState('user')
  const [searchInput, setSearchInput] = useState('')
  const [debouncedSearch, setDebouncedSearch] = useState('')
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState<(typeof PAGE_SIZE_OPTIONS)[number]>(25)

  // If the caller's admin status is not (or no longer) true, never leave the
  // selection sitting on an admin-only tab — mirrors the server-side 403.
  useEffect(() => {
    if (!isAdmin && category === 'system') {
      setCategory('user')
    }
  }, [isAdmin, category])

  useEffect(() => {
    const t = setTimeout(() => setDebouncedSearch(searchInput.trim()), 350)
    return () => clearTimeout(t)
  }, [searchInput])

  useEffect(() => {
    setPage(1)
  }, [category, debouncedSearch, pageSize])

  const { data, isLoading } = useQuery({
    queryKey: ['audit-events', category, debouncedSearch, page, pageSize],
    queryFn: () =>
      api.audit.listEvents(category, {
        search: debouncedSearch || undefined,
        limit: pageSize,
        offset: (page - 1) * pageSize,
      }),
  })

  const events = data?.events ?? []
  const total = data?.total ?? 0
  const totalPages = Math.max(1, Math.ceil(total / pageSize))

  return (
    <div className="p-6 space-y-5">
      <div>
        <h1 className="text-lg font-semibold text-gray-100 flex items-center gap-2">
          <ScrollText className="w-5 h-5 text-brand-400" />
          Audit
        </h1>
        <p className="text-sm text-gray-500">
          {isAdmin
            ? 'Application, user, agent, and system activity across the whole instance.'
            : 'Your own account and agent activity.'}
        </p>
      </div>

      <div className="border-b border-gray-800">
        <nav className="flex flex-wrap gap-x-4 gap-y-2">
          {visibleCategories.map((c) => (
            <button
              key={c.id}
              type="button"
              onClick={() => setCategory(c.id)}
              className={clsx(
                'flex items-center gap-1.5 pb-3 text-sm font-medium whitespace-nowrap transition-colors',
                category === c.id ? 'tab-active' : 'tab-inactive',
              )}
            >
              <c.icon className="w-3.5 h-3.5" />
              {c.label}
            </button>
          ))}
        </nav>
      </div>

      <div className="relative max-w-xs">
        <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-gray-500 pointer-events-none" />
        <input
          type="text"
          placeholder="Search…"
          value={searchInput}
          onChange={(e) => setSearchInput(e.target.value)}
          className="input pl-8 pr-8 w-full text-sm"
          aria-label="Search"
        />
        {searchInput && (
          <button
            type="button"
            onClick={() => setSearchInput('')}
            className="absolute right-2 top-2 text-gray-500 hover:text-gray-300"
            aria-label="Clear search"
          >
            <X className="h-4 w-4" />
          </button>
        )}
      </div>

      {isLoading ? (
        <div className="flex items-center gap-2 text-sm text-gray-500 py-8">
          <Loader2 className="w-4 h-4 animate-spin" /> Loading…
        </div>
      ) : events.length === 0 ? (
        <p className="text-sm text-gray-500 text-center py-8">No activity yet.</p>
      ) : (
        <>
          <div className="overflow-x-auto rounded-lg border border-gray-800">
            <table className="w-full min-w-[700px]">
              <thead>
                <tr className="bg-gray-800/50 text-[10px] uppercase tracking-wider text-gray-500">
                  <th className="text-left py-1.5 px-2">Time</th>
                  <th className="text-left py-1.5 px-2">Action</th>
                  <th className="text-left py-1.5 px-2">Actor</th>
                  <th className="text-left py-1.5 px-2">Summary</th>
                  <th className="text-left py-1.5 px-2" />
                </tr>
              </thead>
              <tbody>
                {events.map((event) => (
                  <EventRow key={event.id} event={event} />
                ))}
              </tbody>
            </table>
          </div>

          <Pagination
            page={page}
            totalPages={totalPages}
            totalItems={total}
            itemLabel="event"
            onPageChange={setPage}
            pageSize={pageSize}
            pageSizeOptions={PAGE_SIZE_OPTIONS}
            onPageSizeChange={(n) => setPageSize(n as (typeof PAGE_SIZE_OPTIONS)[number])}
          />
        </>
      )}
    </div>
  )
}
