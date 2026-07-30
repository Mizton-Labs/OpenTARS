/**
 * DataExplorer — "Data Explorer" sidebar entry, below Threat Intel Tracking
 * (issue-local-033).
 *
 * One tab per Dashboard panel/stat card (HuntDashboard.tsx) — every panel
 * there links here with the matching tab pre-selected (`?tab=<category>`,
 * the same query-param deep-linking pattern Configuration/About/Viewer
 * already use), so "what does this number actually consist of" is always
 * one click away. Categories and their row shape come straight from
 * `GET /api/threat-hunting/explorer/{category}` (db.list_explorer_rows) —
 * see that function's docstring for the search/date-range rules per
 * category (hunt-scoped categories filter like the package list; the five
 * Threat Intel categories are global and only match by name).
 */
import { useEffect, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useLocation, useNavigate } from 'react-router-dom'
import { clsx } from 'clsx'
import {
  Compass,
  Search,
  X,
  Shield,
  Layers,
  FileStack,
  Lightbulb,
  Crosshair,
  Terminal,
  Radar,
  Users,
  Flag,
  Boxes,
  Database,
  Loader2,
  ChevronDown,
  ChevronRight,
} from 'lucide-react'
import { api, type ExplorerRow } from '../../api/client'
import { HUNT_ID_BADGE } from './runStatusUtils'
import Pagination from '../../components/Pagination'
import EvidenceContent from './EvidenceContent'

const PAGE_SIZE_OPTIONS = [25, 50, 100, 200] as const

interface Category {
  id: string
  label: string
  icon: React.ElementType
}

const EXPLORER_CATEGORIES: Category[] = [
  { id: 'hunts', label: 'Hunt Packages', icon: Shield },
  { id: 'runs', label: 'Runs', icon: Layers },
  { id: 'evidence', label: 'Evidence', icon: FileStack },
  { id: 'hypotheses', label: 'Hypotheses', icon: Lightbulb },
  { id: 'hunting_leads', label: 'Hunting Leads', icon: Crosshair },
  { id: 'queries', label: 'Queries Drafted', icon: Terminal },
  { id: 'iocs', label: 'IOCs Extracted', icon: Radar },
  { id: 'siem_searches', label: 'SIEM Searches', icon: Database },
  { id: 'threat_actors', label: 'Threat Actors', icon: Users },
  { id: 'campaigns', label: 'Campaigns', icon: Flag },
  { id: 'malware_families', label: 'Malware Families', icon: Boxes },
  { id: 'ttps', label: 'MITRE Techniques', icon: Crosshair },
  { id: 'feed_sources', label: 'Feed Sources', icon: Database },
]

const DEFAULT_CATEGORY = EXPLORER_CATEGORIES[0].id

function HuntLink({ id, display }: { id?: string; display?: string }) {
  const navigate = useNavigate()
  if (!id || !display) return <span className="text-gray-600">—</span>
  return (
    <button
      type="button"
      onClick={() => navigate(`/threat-hunting/${id}`)}
      className={clsx(HUNT_ID_BADGE, 'text-[10px] hover:border-brand-500 transition-colors')}
    >
      {display}
    </button>
  )
}

// issue-local-034: deep-links to a SPECIFIC run within a hunt package, not
// just the package (which lands on its newest run) — read by
// ThreatHuntingDetail.tsx's `?run=` query param.
function RunLink({ pkgId, runId, display }: { pkgId?: string; runId?: string; display?: string }) {
  const navigate = useNavigate()
  if (!pkgId || !runId || !display) return <span className="text-gray-600">—</span>
  return (
    <button
      type="button"
      onClick={() => navigate(`/threat-hunting/${pkgId}?run=${runId}`)}
      className={clsx(HUNT_ID_BADGE, 'text-[10px] hover:border-brand-500 transition-colors')}
    >
      {display}
    </button>
  )
}

// issue-local-034: archived hunts/runs are included in Data Explorer (unlike
// the Dashboard/main package list), tagged rather than hidden.
function ArchivedBadge() {
  return (
    <span className="text-[10px] px-1.5 py-0.5 rounded bg-gray-800 text-gray-400 border border-gray-700">
      Archived
    </span>
  )
}

function SourceBadges({ sources }: { sources?: ExplorerRow['sources'] }) {
  const navigate = useNavigate()
  if (!sources || sources.length === 0) return <span className="text-gray-600">—</span>
  return (
    <div className="flex flex-wrap gap-1">
      {sources.map((s) => (
        <button
          key={s.id}
          type="button"
          onClick={() => navigate(`/threat-hunting/${s.id}`)}
          className={clsx(HUNT_ID_BADGE, 'text-[10px] hover:border-brand-500 transition-colors')}
          title={s.name}
        >
          {s.hunt_id_display || s.name}
        </button>
      ))}
    </div>
  )
}

function cell(value: unknown): React.ReactNode {
  if (value === null || value === undefined || value === '') return <span className="text-gray-600">—</span>
  if (typeof value === 'boolean') return value ? 'Yes' : 'No'
  return String(value)
}

// Column definitions per category — (header, cell renderer). Kept as one
// switch rather than 13 separate table components: same table chrome
// throughout, only the columns differ.
function columnsFor(category: string): { header: string; render: (r: ExplorerRow) => React.ReactNode }[] {
  switch (category) {
    case 'hunts':
      return [
        { header: 'Hunt', render: (r) => <HuntLink id={r.id} display={r.hunt_id_display} /> },
        { header: 'Name', render: (r) => cell(r.name) },
        {
          header: 'Status',
          render: (r) => (
            <span className="flex items-center gap-1.5">
              {cell(r.status)}
              {r.status === 'archived' && <ArchivedBadge />}
            </span>
          ),
        },
      ]
    case 'runs':
      return [
        {
          header: 'Run',
          render: (r) => (
            <span className="flex items-center gap-1.5">
              <RunLink pkgId={r.hunt_package_id} runId={r.id} display={r.run_id_display} />
              {r.archived && <ArchivedBadge />}
            </span>
          ),
        },
        {
          header: 'Hunt',
          render: (r) => <HuntLink id={r.hunt_package_id} display={r.hunt_id_display} />,
        },
        { header: 'Model', render: (r) => cell(r.llm_model) },
        { header: 'Status', render: (r) => cell(r.generation_status) },
        { header: 'Effort', render: (r) => cell(r.research_effort) },
        { header: 'Created', render: (r) => cell(r.created_at) },
      ]
    case 'evidence':
      return [
        {
          header: 'Hunt',
          render: (r) => <HuntLink id={r.hunt_package_id} display={r.hunt_id_display} />,
        },
        { header: 'Type', render: (r) => cell(r.item_type) },
        { header: 'Label', render: (r) => cell(r.label) },
        { header: 'Created', render: (r) => cell(r.created_at) },
      ]
    case 'hypotheses':
      return [
        {
          header: 'Hunt',
          render: (r) => <HuntLink id={r.hunt_package_id} display={r.hunt_id_display} />,
        },
        {
          header: 'Run',
          render: (r) => <RunLink pkgId={r.hunt_package_id} runId={r.run_id} display={r.run_id_display} />,
        },
        { header: 'Title', render: (r) => cell(r.title) },
        { header: 'Relevance', render: (r) => cell(r.relevance) },
        { header: 'Confidence', render: (r) => cell(r.confidence) },
        { header: 'Discarded', render: (r) => cell(r.discarded) },
      ]
    case 'hunting_leads':
      return [
        {
          header: 'Hunt',
          render: (r) => <HuntLink id={r.hunt_package_id} display={r.hunt_id_display} />,
        },
        {
          header: 'Run',
          render: (r) => <RunLink pkgId={r.hunt_package_id} runId={r.run_id} display={r.run_id_display} />,
        },
        { header: 'Title', render: (r) => cell(r.title) },
        { header: 'Priority', render: (r) => cell(r.priority) },
        { header: 'Discarded', render: (r) => cell(r.discarded) },
      ]
    case 'queries':
      return [
        {
          header: 'Hunt',
          render: (r) => <HuntLink id={r.hunt_package_id} display={r.hunt_id_display} />,
        },
        {
          header: 'Run',
          render: (r) => <RunLink pkgId={r.hunt_package_id} runId={r.run_id} display={r.run_id_display} />,
        },
        { header: 'Title', render: (r) => cell(r.title) },
        { header: 'Language', render: (r) => cell(r.language) },
        {
          header: 'Query',
          render: (r) => (
            <span className="font-mono text-[11px] text-gray-400">{cell(r.query)}</span>
          ),
        },
      ]
    case 'iocs':
      return [
        {
          header: 'Hunt',
          render: (r) => <HuntLink id={r.hunt_package_id} display={r.hunt_id_display} />,
        },
        {
          header: 'Run',
          render: (r) => <RunLink pkgId={r.hunt_package_id} runId={r.run_id} display={r.run_id_display} />,
        },
        { header: 'IOC', render: (r) => <span className="font-mono">{cell(r.ioc)}</span> },
        { header: 'Type', render: (r) => cell(r.ioc_type) },
        { header: 'Action', render: (r) => cell(r.action) },
        { header: 'Noise', render: (r) => cell(r.noise_score) },
      ]
    case 'siem_searches':
      return [
        {
          header: 'Hunt',
          render: (r) => <HuntLink id={r.hunt_package_id} display={r.hunt_id_display} />,
        },
        {
          header: 'Run',
          render: (r) => <RunLink pkgId={r.hunt_package_id} runId={r.run_id} display={r.run_id_display} />,
        },
        { header: 'Type', render: (r) => cell(r.task_type) },
        { header: 'Connector', render: (r) => cell(r.siem_connector) },
        { header: 'Status', render: (r) => cell(r.status) },
        {
          header: 'Query',
          render: (r) => (
            <span className="font-mono text-[11px] text-gray-400">{cell(r.query_text)}</span>
          ),
        },
      ]
    case 'threat_actors':
      return [
        { header: 'Name', render: (r) => cell(r.name) },
        { header: 'Confidence', render: (r) => cell(r.confidence) },
        { header: 'Rationale', render: (r) => cell(r.rationale) },
        { header: 'Hunts', render: (r) => <SourceBadges sources={r.sources} /> },
      ]
    case 'campaigns':
      return [
        { header: 'Name', render: (r) => cell(r.name) },
        { header: 'Description', render: (r) => cell(r.description) },
        { header: 'Hunts', render: (r) => <SourceBadges sources={r.sources} /> },
      ]
    case 'malware_families':
      return [
        { header: 'Name', render: (r) => cell(r.name) },
        { header: 'Hunts', render: (r) => <SourceBadges sources={r.sources} /> },
      ]
    case 'ttps':
      return [
        { header: 'Technique', render: (r) => `${r.technique_id ?? ''} ${r.technique_name ?? ''}`.trim() },
        { header: 'Tactic', render: (r) => cell(r.tactic) },
        { header: 'Hunts', render: (r) => <SourceBadges sources={r.sources} /> },
      ]
    case 'feed_sources':
      // issue-local-034: rebuilt from unrelated ingestion-pipeline stats
      // into evidence-source aggregation — same {name, count, sources}
      // shape the other global-style categories already use.
      return [
        { header: 'Source', render: (r) => cell(r.name) },
        { header: 'Entries', render: (r) => cell(r.count) },
        { header: 'Hunts', render: (r) => <SourceBadges sources={r.sources} /> },
      ]
    default:
      return []
  }
}

// issue-local-034: expandable evidence row — reuses EvidenceContent.tsx (the
// same preview HuntDetail's Evidence tab uses) instead of a second copy.
// Explorer's evidence rows are intentionally lightweight (no extracted_text/
// mime_type — that would bloat every page load), so expanding lazily fetches
// the item's package's full evidence list; react-query dedupes/caches by
// hunt_package_id, so expanding a second row from the same package is free.
function EvidenceExplorerRow({ row, columns }: { row: ExplorerRow; columns: { header: string; render: (r: ExplorerRow) => React.ReactNode }[] }) {
  const [expanded, setExpanded] = useState(false)
  const { data: items, isLoading } = useQuery({
    queryKey: ['th-evidence', row.hunt_package_id],
    queryFn: () => api.threatHunting.listEvidence(row.hunt_package_id!),
    enabled: expanded && !!row.hunt_package_id,
  })
  const item = items?.find((i) => i.id === row.id)

  return (
    <>
      <tr className="border-t border-gray-800/60">
        <td className="py-1.5 pl-2 pr-0 w-6">
          <button
            type="button"
            onClick={() => setExpanded((v) => !v)}
            className="text-gray-500 hover:text-gray-300"
            aria-label={expanded ? 'Hide preview' : 'Show preview'}
          >
            {expanded ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
          </button>
        </td>
        {columns.map((col) => (
          <td key={col.header} className="py-1.5 px-2 text-[12px] text-gray-300">
            {col.render(row)}
          </td>
        ))}
      </tr>
      {expanded && (
        <tr className="border-t border-gray-800/40 bg-gray-950/40">
          <td colSpan={columns.length + 1} className="p-3">
            {isLoading ? (
              <div className="flex items-center gap-2 text-sm text-gray-500 py-4">
                <Loader2 className="w-4 h-4 animate-spin" /> Loading…
              </div>
            ) : item ? (
              <div className="card min-h-[160px] flex flex-col">
                <EvidenceContent item={item} pkgId={row.hunt_package_id!} />
              </div>
            ) : (
              <p className="text-sm text-gray-500 py-2">Evidence item not found.</p>
            )}
          </td>
        </tr>
      )}
    </>
  )
}

export default function DataExplorer() {
  const location = useLocation()
  const [category, setCategory] = useState(DEFAULT_CATEGORY)
  const [searchInput, setSearchInput] = useState('')
  const [debouncedSearch, setDebouncedSearch] = useState('')
  // issue-local-034: pagination, page-size selectable (default 25).
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState<(typeof PAGE_SIZE_OPTIONS)[number]>(25)

  // Deep-link from a Dashboard panel — same ?tab= pattern as Configuration/
  // About/Viewer.
  useEffect(() => {
    const tab = new URLSearchParams(location.search).get('tab')
    if (tab && EXPLORER_CATEGORIES.some((c) => c.id === tab)) {
      setCategory(tab)
    }
  }, [location.search])

  useEffect(() => {
    const t = setTimeout(() => setDebouncedSearch(searchInput.trim()), 350)
    return () => clearTimeout(t)
  }, [searchInput])

  // Changing category or search invalidates the current page.
  useEffect(() => {
    setPage(1)
  }, [category, debouncedSearch])

  const { data: rows = [], isLoading } = useQuery({
    queryKey: ['th-explorer', category, debouncedSearch],
    queryFn: () => api.threatHunting.getExplorerRows(category, { search: debouncedSearch || undefined }),
  })

  const columns = columnsFor(category)
  const totalPages = Math.max(1, Math.ceil(rows.length / pageSize))
  const clampedPage = Math.min(page, totalPages)
  const pageRows = rows.slice((clampedPage - 1) * pageSize, clampedPage * pageSize)

  return (
    <div className="p-6 space-y-5">
      <div>
        <h1 className="text-lg font-semibold text-gray-100 flex items-center gap-2">
          <Compass className="w-5 h-5 text-brand-400" />
          Data Explorer
        </h1>
        <p className="text-sm text-gray-500">
          The row-level data behind each Dashboard panel — pick a category, or arrive here
          straight from one of the Dashboard's panels.
        </p>
      </div>

      {/* issue-local-034: wraps onto a second row instead of scrolling
          horizontally — 13 categories don't fit one row at any reasonable
          width. */}
      <div className="border-b border-gray-800">
        <nav className="flex flex-wrap gap-x-4 gap-y-2">
          {EXPLORER_CATEGORIES.map((c) => (
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
      ) : rows.length === 0 ? (
        <p className="text-sm text-gray-500 text-center py-8">No data yet.</p>
      ) : (
        <>
          <div className="overflow-x-auto rounded-lg border border-gray-800">
            <table className="w-full min-w-[700px]">
              <thead>
                <tr className="bg-gray-800/50 text-[10px] uppercase tracking-wider text-gray-500">
                  {category === 'evidence' && <th className="w-6" />}
                  {columns.map((col) => (
                    <th key={col.header} className="text-left py-1.5 px-2">
                      {col.header}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {category === 'evidence'
                  ? pageRows.map((row, i) => (
                      <EvidenceExplorerRow key={row.id ?? i} row={row} columns={columns} />
                    ))
                  : pageRows.map((row, i) => (
                      <tr key={row.id ?? i} className="border-t border-gray-800/60">
                        {columns.map((col) => (
                          <td key={col.header} className="py-1.5 px-2 text-[12px] text-gray-300">
                            {col.render(row)}
                          </td>
                        ))}
                      </tr>
                    ))}
              </tbody>
            </table>
          </div>

          <Pagination
            page={clampedPage}
            totalPages={totalPages}
            totalItems={rows.length}
            onPageChange={setPage}
            pageSize={pageSize}
            pageSizeOptions={PAGE_SIZE_OPTIONS}
            onPageSizeChange={(n) => {
              setPageSize(n as (typeof PAGE_SIZE_OPTIONS)[number])
              setPage(1)
            }}
          />
        </>
      )}
    </div>
  )
}
