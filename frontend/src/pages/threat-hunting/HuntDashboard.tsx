/**
 * HuntDashboard — the Threat Hunting module's default view (issue-local-032).
 *
 * A metrics-first overview replacing the hunt-package list as the landing
 * page for the module: hunt/run/evidence/IOC/query counts, a per-model
 * breakdown of runs, and a summary of the Threat Intel identified across
 * hunts. The package list itself moved to its own sidebar entry ("Hunt
 * Packages", threat-hunting/packages) — nothing about it changed, it just
 * isn't the first thing you see anymore.
 *
 * Shares the same search + time-range filter as the Hunt Packages list
 * (same debounce, same HuntTimeFilter component, same query-param shape) so
 * the numbers here always describe the same set that filter would show
 * there. The Threat Intel summary panel is deliberately NOT filtered by
 * search/date — see get_hunt_dashboard_stats's docstring for why.
 *
 * No charting library: this app has none, and one card of stat tiles plus
 * proportional-width bar rows doesn't need one.
 */
import { useEffect, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import {
  Gauge,
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
  ShieldAlert,
  Database,
} from 'lucide-react'
import { api, type THDashboardStats } from '../../api/client'
import HuntTimeFilter, { type HuntTimeRange } from './HuntTimeFilter'

function StatCard({
  icon: Icon,
  label,
  value,
  sub,
}: {
  icon: React.ElementType
  label: string
  value: number
  sub?: string
}) {
  return (
    <div className="card flex items-start gap-3 py-4">
      <div className="rounded-lg bg-brand-900/30 border border-brand-800/40 p-2 shrink-0">
        <Icon className="w-4 h-4 text-brand-400" />
      </div>
      <div className="min-w-0">
        <p className="text-2xl font-semibold text-gray-100 leading-none">{value.toLocaleString()}</p>
        <p className="text-xs text-gray-500 mt-1.5">{label}</p>
        {sub && <p className="text-[11px] text-gray-600 mt-0.5">{sub}</p>}
      </div>
    </div>
  )
}

function BarBreakdown({
  title,
  icon: Icon,
  rows,
}: {
  title: string
  icon: React.ElementType
  rows: [string, number][]
}) {
  const max = Math.max(1, ...rows.map(([, n]) => n))
  return (
    <div className="border border-gray-700 rounded-lg overflow-hidden">
      <div className="flex items-center gap-2 px-4 py-3 bg-gray-800/40">
        <Icon className="w-4 h-4 text-brand-400" />
        <span className="text-sm font-medium text-gray-200">{title}</span>
      </div>
      <div className="p-4 space-y-2.5">
        {rows.length === 0 ? (
          <p className="text-sm text-gray-500 italic">No data yet.</p>
        ) : (
          rows.map(([label, count]) => (
            <div key={label}>
              <div className="flex items-center justify-between text-[11px] text-gray-400 mb-0.5">
                <span className="truncate">{label}</span>
                <span className="font-mono text-gray-500 shrink-0 ml-2">{count}</span>
              </div>
              <div className="h-1.5 rounded-full bg-gray-800 overflow-hidden">
                <div
                  className="h-full rounded-full bg-brand-500"
                  style={{ width: `${Math.max(4, (count / max) * 100)}%` }}
                />
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  )
}

function sortedEntries(rec: Record<string, number>): [string, number][] {
  return Object.entries(rec).sort((a, b) => b[1] - a[1])
}

const EMPTY: THDashboardStats = {
  packages_total: 0,
  packages_by_status: {},
  runs_total: 0,
  runs_by_model: {},
  hunts_by_model: {},
  evidence_total: 0,
  evidence_by_type: {},
  hypotheses_total: 0,
  hunting_leads_total: 0,
  queries_total: 0,
  iocs_extracted_total: 0,
  iocs_kept_total: 0,
  siem_searches_total: 0,
  siem_searches_completed: 0,
  siem_events_total: 0,
  threat_actors_total: 0,
  campaigns_total: 0,
  malware_families_total: 0,
  ttps_total: 0,
  sources_processed: 0,
}

export default function HuntDashboard() {
  const navigate = useNavigate()
  const [searchInput, setSearchInput] = useState('')
  const [debouncedSearch, setDebouncedSearch] = useState('')
  useEffect(() => {
    const t = setTimeout(() => setDebouncedSearch(searchInput.trim()), 350)
    return () => clearTimeout(t)
  }, [searchInput])
  const [timeRange, setTimeRange] = useState<HuntTimeRange>({})

  const { data = EMPTY, isLoading } = useQuery({
    queryKey: ['th-dashboard', debouncedSearch, timeRange.from, timeRange.to],
    queryFn: () =>
      api.threatHunting.getDashboard({
        search: debouncedSearch || undefined,
        date_from: timeRange.from,
        date_to: timeRange.to,
      }),
  })

  const filtered = Boolean(debouncedSearch || timeRange.from || timeRange.to)

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-lg font-semibold text-gray-100 flex items-center gap-2">
            <Gauge className="w-5 h-5 text-brand-400" />
            Dashboard
          </h1>
          <p className="text-sm text-gray-500">
            Overview of hunt packages, runs, and the threat intel identified across them.
          </p>
        </div>
        <button
          type="button"
          className="btn-secondary text-sm"
          onClick={() => navigate('../packages', { relative: 'path' })}
        >
          View Hunt Packages
        </button>
      </div>

      {/* Same search + time-range filter as the Hunt Packages list. */}
      <div className="flex items-center gap-3 flex-wrap">
        <div className="relative w-full max-w-xs">
          <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-gray-500 pointer-events-none" />
          <input
            type="text"
            placeholder="Search hunt packages…"
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
            className="input pl-8 pr-8 w-full text-sm"
            aria-label="Search hunt packages"
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
        <HuntTimeFilter value={timeRange} onChange={setTimeRange} />
        {filtered && (
          <span className="text-xs text-gray-600">{data.packages_total} matching package{data.packages_total === 1 ? '' : 's'}</span>
        )}
      </div>

      {isLoading ? (
        <p className="text-sm text-gray-500">Loading…</p>
      ) : (
        <>
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
            <StatCard icon={Shield} label="Hunt Packages" value={data.packages_total} />
            <StatCard icon={Layers} label="Runs" value={data.runs_total} />
            <StatCard icon={FileStack} label="Evidence Items" value={data.evidence_total} />
            <StatCard icon={Lightbulb} label="Hypotheses" value={data.hypotheses_total} />
            <StatCard icon={Crosshair} label="Hunting Leads" value={data.hunting_leads_total} />
            <StatCard icon={Terminal} label="Queries Drafted" value={data.queries_total} />
            <StatCard
              icon={Radar}
              label="IOCs Extracted"
              value={data.iocs_extracted_total}
              sub={`${data.iocs_kept_total} kept`}
            />
            <StatCard
              icon={Database}
              label="SIEM Searches Executed"
              value={data.siem_searches_total}
              sub={`${data.siem_searches_completed} completed`}
            />
            <StatCard
              icon={Terminal}
              label="Events Retrieved"
              value={data.siem_events_total}
              sub="from SIEM execution results"
            />
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <BarBreakdown title="Runs by Model" icon={Layers} rows={sortedEntries(data.runs_by_model)} />
            <BarBreakdown
              title="Hunt Packages by Model"
              icon={Shield}
              rows={sortedEntries(data.hunts_by_model)}
            />
            <BarBreakdown
              title="Evidence by Type"
              icon={FileStack}
              rows={sortedEntries(data.evidence_by_type)}
            />
            <BarBreakdown
              title="Packages by Status"
              icon={Shield}
              rows={sortedEntries(data.packages_by_status)}
            />
          </div>

          {/* Threat Intel summary — global across every hunt, not filtered by
              the search/time controls above (see backend docstring). */}
          <div>
            <p className="text-sm font-medium text-gray-300 mb-3 flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-brand-400" />
              Threat Intel — across all hunts
            </p>
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
              <StatCard icon={Users} label="Threat Actors" value={data.threat_actors_total} />
              <StatCard icon={Flag} label="Campaigns" value={data.campaigns_total} />
              <StatCard icon={Boxes} label="Malware Families" value={data.malware_families_total} />
              <StatCard icon={Crosshair} label="MITRE Techniques" value={data.ttps_total} />
              <StatCard icon={Database} label="Feed Sources Processed" value={data.sources_processed} />
            </div>
          </div>
        </>
      )}
    </div>
  )
}
