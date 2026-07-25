/**
 * ThreatIntelTracking — "Threat Intel Tracking" sidebar subsection (issue-local-021).
 *
 * A cross-hunt correlation dashboard: aggregates IOCs, threat actors,
 * campaigns, malware families, TTPs, and CVEs across every non-excluded hunt
 * package, showing each item's source hunt package(s) (the "relationship of
 * the source of the data" the spec asks for). Two tabs:
 *   - Dashboard: search + panels for each data category.
 *   - Hunts: every hunt package with Include/Exclude/Delete controls.
 *
 * This is a read/aggregate layer over data that already exists per-hunt —
 * no new agent runs happen here (see db.py's "Threat Intel Tracking
 * dashboard" section for the aggregation queries).
 */
import { useState, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { clsx } from 'clsx'
import {
  Network,
  Search,
  Radar,
  Users,
  Boxes,
  Flag,
  Crosshair,
  ShieldAlert,
  Loader2,
  EyeOff,
  Eye,
  Trash2,
} from 'lucide-react'
import {
  api,
  type THTrackingSource,
  type THTrackingIoc,
  type THTrackingThreatActor,
  type THTrackingCampaign,
  type THTrackingMalwareFamily,
  type THTrackingTtp,
  type THTrackingHunt,
} from '../../api/client'
import ConfirmDialog from '../../components/ConfirmDialog'
import { HUNT_ID_BADGE } from './runStatusUtils'

type TrackingTab = 'dashboard' | 'hunts'

// ── Shared source-badge list ─────────────────────────────────────────────────

function SourceBadges({ sources }: { sources: THTrackingSource[] }) {
  const navigate = useNavigate()
  if (!sources.length) return null
  return (
    <div className="flex flex-wrap gap-1 mt-1">
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

// ── Panel shell ───────────────────────────────────────────────────────────────

function Panel({
  title,
  icon: Icon,
  count,
  children,
}: {
  title: string
  icon: React.ElementType
  count: number
  children: React.ReactNode
}) {
  return (
    <div className="border border-gray-700 rounded-lg overflow-hidden">
      <div className="flex items-center gap-2 px-4 py-3 bg-gray-800/40">
        <Icon className="w-4 h-4 text-brand-400" />
        <span className="text-sm font-medium text-gray-200">
          {title} ({count})
        </span>
      </div>
      <div className="p-4 space-y-2 max-h-80 overflow-y-auto">
        {count === 0 ? (
          <p className="text-sm text-gray-500 italic">No data yet.</p>
        ) : (
          children
        )}
      </div>
    </div>
  )
}

// ── Dashboard tab ─────────────────────────────────────────────────────────────

function DashboardTab() {
  const [searchInput, setSearchInput] = useState('')
  const [debouncedSearch, setDebouncedSearch] = useState('')
  useEffect(() => {
    const t = setTimeout(() => setDebouncedSearch(searchInput.trim()), 350)
    return () => clearTimeout(t)
  }, [searchInput])

  const { data, isLoading } = useQuery({
    queryKey: ['th-tracking-dashboard', debouncedSearch],
    queryFn: () => api.threatHunting.tracking.getDashboard(debouncedSearch || undefined),
  })

  return (
    <div className="space-y-5">
      <div className="relative max-w-xs">
        <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-gray-500 pointer-events-none" />
        <input
          type="text"
          placeholder="Search IOCs and CVEs…"
          value={searchInput}
          onChange={(e) => setSearchInput(e.target.value)}
          className="input pl-8 w-full text-sm"
          aria-label="Search IOCs and CVEs"
        />
      </div>

      {isLoading ? (
        <div className="flex items-center gap-2 text-sm text-gray-500 py-8">
          <Loader2 className="w-4 h-4 animate-spin" /> Loading dashboard…
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <Panel title="IOCs" icon={Radar} count={data?.iocs.length ?? 0}>
            {(data?.iocs as THTrackingIoc[] | undefined)?.map((item, i) => (
              <div key={i} className="border-b border-gray-800/60 pb-2 last:border-b-0 last:pb-0">
                <div className="flex items-center gap-2">
                  <span className="text-sm font-mono text-gray-200">{item.ioc}</span>
                  <span className="text-[10px] text-gray-500">{item.ioc_type}</span>
                  {item.hunt_count > 1 && (
                    <span className="text-[10px] text-amber-400">{item.hunt_count} hunts</span>
                  )}
                </div>
                <SourceBadges sources={item.hunt_packages} />
              </div>
            ))}
          </Panel>

          <Panel title="CVEs" icon={ShieldAlert} count={data?.cves.length ?? 0}>
            {(data?.cves as THTrackingIoc[] | undefined)?.map((item, i) => (
              <div key={i} className="border-b border-gray-800/60 pb-2 last:border-b-0 last:pb-0">
                <div className="flex items-center gap-2">
                  <span className="text-sm font-mono text-gray-200">{item.ioc}</span>
                  {item.hunt_count > 1 && (
                    <span className="text-[10px] text-amber-400">{item.hunt_count} hunts</span>
                  )}
                </div>
                <SourceBadges sources={item.hunt_packages} />
              </div>
            ))}
          </Panel>

          <Panel title="Threat Actors" icon={Users} count={data?.threat_actors.length ?? 0}>
            {(data?.threat_actors as THTrackingThreatActor[] | undefined)?.map((item, i) => (
              <div key={i} className="border-b border-gray-800/60 pb-2 last:border-b-0 last:pb-0">
                <div className="flex items-center gap-2">
                  <span className="text-sm font-medium text-gray-200">{item.name}</span>
                  {item.confidence && (
                    <span className="text-[10px] text-gray-500">{item.confidence}</span>
                  )}
                </div>
                {item.rationale && <p className="text-[11px] text-gray-500 mt-0.5">{item.rationale}</p>}
                <SourceBadges sources={item.sources} />
              </div>
            ))}
          </Panel>

          <Panel title="Campaigns" icon={Flag} count={data?.campaigns.length ?? 0}>
            {(data?.campaigns as THTrackingCampaign[] | undefined)?.map((item, i) => (
              <div key={i} className="border-b border-gray-800/60 pb-2 last:border-b-0 last:pb-0">
                <span className="text-sm font-medium text-gray-200">{item.name}</span>
                {item.description && (
                  <p className="text-[11px] text-gray-500 mt-0.5">{item.description}</p>
                )}
                <SourceBadges sources={item.sources} />
              </div>
            ))}
          </Panel>

          <Panel title="Malware Families" icon={Boxes} count={data?.malware_families.length ?? 0}>
            {(data?.malware_families as THTrackingMalwareFamily[] | undefined)?.map((item, i) => (
              <div key={i} className="border-b border-gray-800/60 pb-2 last:border-b-0 last:pb-0">
                <span className="text-sm font-medium text-gray-200">{item.name}</span>
                <SourceBadges sources={item.sources} />
              </div>
            ))}
          </Panel>

          <Panel title="TTPs" icon={Crosshair} count={data?.ttps.length ?? 0}>
            {(data?.ttps as THTrackingTtp[] | undefined)?.map((item, i) => (
              <div key={i} className="border-b border-gray-800/60 pb-2 last:border-b-0 last:pb-0">
                <div className="flex items-center gap-2">
                  <span className="text-[11px] font-mono text-brand-400">{item.technique_id}</span>
                  <span className="text-sm text-gray-200">{item.technique_name}</span>
                  <span className="text-[10px] text-gray-500">{item.tactic}</span>
                </div>
                <SourceBadges sources={item.sources} />
              </div>
            ))}
          </Panel>
        </div>
      )}
    </div>
  )
}

// ── Hunts tab ─────────────────────────────────────────────────────────────────

function HuntsTab() {
  const qc = useQueryClient()
  const [deleteTarget, setDeleteTarget] = useState<THTrackingHunt | null>(null)

  const { data: hunts = [], isLoading } = useQuery({
    queryKey: ['th-tracking-hunts'],
    queryFn: () => api.threatHunting.tracking.listHunts(),
  })

  const invalidateAll = () => {
    qc.invalidateQueries({ queryKey: ['th-tracking-hunts'] })
    qc.invalidateQueries({ queryKey: ['th-tracking-dashboard'] })
  }

  const excludeMut = useMutation({
    mutationFn: ({ id, excluded }: { id: string; excluded: boolean }) =>
      api.threatHunting.tracking.setHuntExcluded(id, excluded),
    onSuccess: invalidateAll,
  })

  const deleteMut = useMutation({
    mutationFn: (id: string) => api.threatHunting.tracking.deleteHunt(id),
    onSuccess: () => {
      invalidateAll()
      qc.invalidateQueries({ queryKey: ['th-packages'] })
      setDeleteTarget(null)
    },
  })

  if (isLoading) {
    return (
      <div className="flex items-center gap-2 text-sm text-gray-500 py-8">
        <Loader2 className="w-4 h-4 animate-spin" /> Loading hunts…
      </div>
    )
  }

  if (hunts.length === 0) {
    return <p className="text-sm text-gray-500 text-center py-8">No hunt packages yet.</p>
  }

  return (
    <>
      <div className="overflow-x-auto rounded-lg border border-gray-800">
        <table className="w-full min-w-[700px]">
          <thead>
            <tr className="bg-gray-800/50 text-[10px] uppercase tracking-wider text-gray-500">
              <th className="text-left py-1.5 px-2">Hunt</th>
              <th className="text-left py-1.5 px-2">Status</th>
              <th className="text-left py-1.5 px-2">IOCs</th>
              <th className="text-left py-1.5 px-2">Threat Intel</th>
              <th className="text-left py-1.5 px-2">Correlation</th>
              <th className="text-left py-1.5 px-2">Actions</th>
            </tr>
          </thead>
          <tbody>
            {hunts.map((hunt) => (
              <tr key={hunt.id} className={clsx('border-t border-gray-800/60', hunt.excluded_from_correlation && 'opacity-50')}>
                <td className="py-1.5 px-2 text-[12px]">
                  <span className={clsx(HUNT_ID_BADGE, 'text-[10px] mr-1.5')}>{hunt.hunt_id_display}</span>
                  <span className="text-gray-200">{hunt.name}</span>
                </td>
                <td className="py-1.5 px-2 text-[11px] text-gray-400">{hunt.status}</td>
                <td className="py-1.5 px-2 text-[11px] text-gray-400">{hunt.ioc_count}</td>
                <td className="py-1.5 px-2 text-[11px] text-gray-400">
                  {hunt.has_threat_intel ? 'yes' : '—'}
                </td>
                <td className="py-1.5 px-2 text-[11px]">
                  {hunt.excluded_from_correlation ? (
                    <span className="text-gray-500">Excluded</span>
                  ) : (
                    <span className="text-green-400">Included</span>
                  )}
                </td>
                <td className="py-1.5 px-2">
                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      className="flex items-center gap-1 text-[11px] text-gray-400 hover:text-gray-200 transition-colors"
                      disabled={excludeMut.isPending}
                      onClick={() =>
                        excludeMut.mutate({ id: hunt.id, excluded: !hunt.excluded_from_correlation })
                      }
                      title={hunt.excluded_from_correlation ? 'Include in correlation' : 'Exclude from correlation'}
                    >
                      {hunt.excluded_from_correlation ? (
                        <Eye className="w-3.5 h-3.5" />
                      ) : (
                        <EyeOff className="w-3.5 h-3.5" />
                      )}
                      {hunt.excluded_from_correlation ? 'Include' : 'Exclude'}
                    </button>
                    <button
                      type="button"
                      className="flex items-center gap-1 text-[11px] text-red-400 hover:text-red-300 transition-colors"
                      onClick={() => setDeleteTarget(hunt)}
                      title="Delete hunt package"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                      Delete
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {deleteTarget && (
        <ConfirmDialog
          title="Delete Hunt Package?"
          message={`This will permanently delete "${deleteTarget.name}" and remove it from the Threat Hunting list. This cannot be undone.`}
          confirmLabel="Delete"
          onConfirm={() => deleteMut.mutate(deleteTarget.id)}
          onCancel={() => setDeleteTarget(null)}
        />
      )}
    </>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function ThreatIntelTracking() {
  const [activeTab, setActiveTab] = useState<TrackingTab>('dashboard')

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-lg font-semibold text-gray-100 flex items-center gap-2">
          <Network className="w-5 h-5 text-brand-400" />
          Threat Intel Tracking
        </h1>
        <p className="text-sm text-gray-500">
          Correlated IOCs, threat actors, campaigns, malware families, TTPs, and CVEs across every
          hunt package.
        </p>
      </div>

      <div className="border-b border-gray-800">
        <nav className="flex gap-6">
          <button
            onClick={() => setActiveTab('dashboard')}
            className={clsx('pb-3 text-sm font-medium transition-colors', activeTab === 'dashboard' ? 'tab-active' : 'tab-inactive')}
          >
            Dashboard
          </button>
          <button
            onClick={() => setActiveTab('hunts')}
            className={clsx('pb-3 text-sm font-medium transition-colors', activeTab === 'hunts' ? 'tab-active' : 'tab-inactive')}
          >
            Hunts
          </button>
        </nav>
      </div>

      {activeTab === 'dashboard' && <DashboardTab />}
      {activeTab === 'hunts' && <HuntsTab />}
    </div>
  )
}
