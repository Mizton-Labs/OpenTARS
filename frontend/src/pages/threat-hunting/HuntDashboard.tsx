/**
 * HuntDashboard — the Threat Hunting module's default view (issue-local-032).
 *
 * A metrics-first overview replacing the hunt-package list as the landing
 * page for the module: two timeline charts up top (issue-local-034), then
 * the Threat Intel summary, then hunt/run/evidence/IOC/query counts, then
 * pie/bar breakdowns. The package list itself moved to its own sidebar
 * entry ("Hunt Packages", threat-hunting/packages) — nothing about it
 * changed, it just isn't the first thing you see anymore.
 *
 * Shares the same search + time-range filter as the Hunt Packages list
 * (same debounce, same HuntTimeFilter component, same query-param shape) so
 * the numbers here always describe the same set that filter would show
 * there. The Threat Intel summary panel is deliberately NOT filtered by
 * search/date — see get_hunt_dashboard_stats's docstring for why.
 *
 * Rendering building blocks (StatCard/BarBreakdown/PieChart/TimelineChart)
 * live in DashboardCharts.tsx — this file owns data-fetching and layout.
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
  TrendingUp,
} from 'lucide-react'
import { api, type THDashboardStats } from '../../api/client'
import HuntTimeFilter, { type HuntTimeRange } from './HuntTimeFilter'
import { StatCard, BarBreakdown, PieChart, TimelineChart } from './DashboardCharts'

function sortedEntries(rec: Record<string, number>): [string, number][] {
  return Object.entries(rec).sort((a, b) => b[1] - a[1])
}

const EMPTY: THDashboardStats = {
  packages_total: 0,
  packages_by_status: {},
  hunts_per_day: [],
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
  iocs_per_day: [],
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

  // issue-local-033: every panel/stat card links to the Data Explorer
  // category it summarizes, via the same ?tab= deep-linking pattern
  // Configuration/About/Viewer already use.
  function goToExplorer(category: string) {
    navigate(`/threat-hunting/explorer?tab=${category}`)
  }

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
          // Absolute path, not relative: this page is mounted at the bare
          // "threat-hunting" route (a single segment), so a relative
          // '../packages' with { relative: 'path' } strips that one segment
          // down to root and appends "packages", landing on the
          // nonexistent "/packages" — an empty page. Fixed by navigating to
          // the absolute in-router path, which still gets the reverse-proxy
          // basename prepended automatically.
          onClick={() => navigate('/threat-hunting/packages')}
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
          {/* issue-local-034: timeline charts lead the page. */}
          <div>
            <p className="text-sm font-medium text-gray-300 mb-3 flex items-center gap-2">
              <TrendingUp className="w-4 h-4 text-brand-400" />
              Activity over time
            </p>
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              <TimelineChart title="Hunts per Day" icon={Shield} data={data.hunts_per_day} />
              <TimelineChart title="IOCs per Day" icon={Radar} data={data.iocs_per_day} />
            </div>
          </div>

          {/* Threat Intel summary — global across every hunt, not filtered
              by the search/time controls above (see backend docstring).
              Each tile links to its Data Explorer category (issue-local-033). */}
          <div>
            <p className="text-sm font-medium text-gray-300 mb-3 flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-brand-400" />
              Threat Intel — across all hunts
            </p>
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
              <StatCard
                icon={Users}
                label="Threat Actors"
                value={data.threat_actors_total}
                onClick={() => goToExplorer('threat_actors')}
              />
              <StatCard
                icon={Flag}
                label="Campaigns"
                value={data.campaigns_total}
                onClick={() => goToExplorer('campaigns')}
              />
              <StatCard
                icon={Boxes}
                label="Malware Families"
                value={data.malware_families_total}
                onClick={() => goToExplorer('malware_families')}
              />
              <StatCard
                icon={Crosshair}
                label="MITRE Techniques"
                value={data.ttps_total}
                onClick={() => goToExplorer('ttps')}
              />
              <StatCard
                icon={Database}
                label="Feed Sources Processed"
                value={data.sources_processed}
                onClick={() => goToExplorer('feed_sources')}
              />
            </div>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
            <StatCard
              icon={Shield}
              label="Hunt Packages"
              value={data.packages_total}
              onClick={() => goToExplorer('hunts')}
            />
            <StatCard
              icon={Layers}
              label="Runs"
              value={data.runs_total}
              onClick={() => goToExplorer('runs')}
            />
            <StatCard
              icon={FileStack}
              label="Evidence Items"
              value={data.evidence_total}
              onClick={() => goToExplorer('evidence')}
            />
            <StatCard
              icon={Lightbulb}
              label="Hypotheses"
              value={data.hypotheses_total}
              onClick={() => goToExplorer('hypotheses')}
            />
            <StatCard
              icon={Crosshair}
              label="Hunting Leads"
              value={data.hunting_leads_total}
              onClick={() => goToExplorer('hunting_leads')}
            />
            <StatCard
              icon={Terminal}
              label="Queries Drafted"
              value={data.queries_total}
              onClick={() => goToExplorer('queries')}
            />
            <StatCard
              icon={Radar}
              label="IOCs Extracted"
              value={data.iocs_extracted_total}
              sub={`${data.iocs_kept_total} kept`}
              onClick={() => goToExplorer('iocs')}
            />
            <StatCard
              icon={Database}
              label="SIEM Searches Executed"
              value={data.siem_searches_total}
              sub={`${data.siem_searches_completed} completed`}
              onClick={() => goToExplorer('siem_searches')}
            />
            <StatCard
              icon={Terminal}
              label="Events Retrieved"
              value={data.siem_events_total}
              sub="from SIEM execution results"
              onClick={() => goToExplorer('siem_searches')}
            />
          </div>

          {/* Evidence by Type / Packages by Status — pie charts, ahead of
              the (paginated) model breakdowns. */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <PieChart
              title="Evidence by Type"
              icon={FileStack}
              rows={sortedEntries(data.evidence_by_type)}
              onClick={() => goToExplorer('evidence')}
            />
            <PieChart
              title="Packages by Status"
              icon={Shield}
              rows={sortedEntries(data.packages_by_status)}
              onClick={() => goToExplorer('hunts')}
            />
            <BarBreakdown
              title="Runs by Model"
              icon={Layers}
              rows={sortedEntries(data.runs_by_model)}
              onClick={() => goToExplorer('runs')}
            />
            <BarBreakdown
              title="Hunt Packages by Model"
              icon={Shield}
              rows={sortedEntries(data.hunts_by_model)}
              onClick={() => goToExplorer('runs')}
            />
          </div>
        </>
      )}
    </div>
  )
}
