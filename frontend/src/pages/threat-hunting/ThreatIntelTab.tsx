/**
 * ThreatIntelTab — "Threat Intelligence" tab (issue-local-020).
 *
 * Shows the Threat Hunt Intelligence Analyst's output for the active run:
 * threat actors, attribution, malware families, campaigns, correlated IOCs
 * (shared with other hunt packages), and related vendor reporting.
 *
 * Normally populated automatically after SIEM execution (see
 * backend/threat_hunting/agents/nodes/threat_intel_analyst.py); the
 * "Analyze" / "Re-analyze" button covers packages that never executed and
 * lets an analyst manually (re-)trigger it once new correlating hunts exist.
 */
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { clsx } from 'clsx'
import { Radar, RefreshCw, Loader2, AlertTriangle, Shield, Users, Boxes, Link2, Newspaper } from 'lucide-react'
import { api } from '../../api/client'
import { useAuth } from '../../auth/useAuth'

const CONFIDENCE_CLASS: Record<string, string> = {
  high: 'bg-red-900/30 text-red-400',
  medium: 'bg-amber-900/30 text-amber-400',
  low: 'bg-gray-800 text-gray-500',
}

export default function ThreatIntelTab({ pkgId, runId }: { pkgId: string; runId?: string }) {
  const { isResearcher } = useAuth()
  const qc = useQueryClient()

  const { data: intel, isLoading } = useQuery({
    queryKey: ['th-threat-intel', pkgId, runId],
    queryFn: () => {
      if (runId) return api.threatHunting.getRunThreatIntel(pkgId, runId).catch(() => null)
      return api.threatHunting.getThreatIntel(pkgId).catch(() => null)
    },
    retry: false,
  })

  const analyzeMut = useMutation({
    mutationFn: () => api.threatHunting.triggerRunThreatIntel(pkgId, runId!),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['th-threat-intel', pkgId, runId] }),
  })

  if (isLoading) {
    return (
      <div className="flex items-center gap-2 text-sm text-gray-500 py-8">
        <Loader2 className="w-4 h-4 animate-spin" /> Loading threat intelligence…
      </div>
    )
  }

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between gap-4">
        <div className="flex items-center gap-2">
          <Radar className="w-5 h-5 text-brand-400" />
          <h3 className="text-sm font-semibold text-gray-200">Threat Intelligence</h3>
          {intel && (
            <span className="text-[11px] text-gray-500">
              {intel.created_at.slice(0, 19).replace('T', ' ')} UTC
            </span>
          )}
        </div>
        {isResearcher && runId && (
          <button
            className="btn-secondary text-sm flex items-center gap-1.5"
            disabled={analyzeMut.isPending}
            onClick={() => analyzeMut.mutate()}
          >
            {analyzeMut.isPending ? (
              <Loader2 className="w-3.5 h-3.5 animate-spin" />
            ) : (
              <RefreshCw className="w-3.5 h-3.5" />
            )}
            {intel ? 'Re-analyze' : 'Analyze'}
          </button>
        )}
      </div>

      {analyzeMut.isError && (
        <div className="flex items-start gap-2 p-3 rounded-lg bg-red-900/20 border border-red-800/30">
          <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
          <p className="text-sm text-red-300">
            {analyzeMut.error instanceof Error ? analyzeMut.error.message : 'Analysis failed'}
          </p>
        </div>
      )}

      {!intel && !analyzeMut.isPending && (
        <div className="text-center py-10 space-y-3">
          <Radar className="w-10 h-10 text-gray-700 mx-auto" />
          <p className="text-sm text-gray-500">No threat intelligence analysis yet.</p>
          <p className="text-sm text-gray-600">
            This runs automatically after SIEM execution completes.
            {isResearcher && runId && (
              <>
                {' '}Or click <span className="text-brand-400">Analyze</span> above to run it now.
              </>
            )}
          </p>
        </div>
      )}

      {intel && (
        <div className="space-y-4">
          {/* Summary */}
          <div className="card space-y-2">
            <div className="flex items-center gap-2">
              <Shield className="w-4 h-4 text-brand-400" />
              <h4 className="text-sm font-semibold text-gray-200">Summary</h4>
            </div>
            <p className="text-sm text-gray-300 leading-relaxed">
              {intel.summary || <span className="italic text-gray-500">Not available.</span>}
            </p>
          </div>

          {/* Threat Actors */}
          <div className="border border-gray-700 rounded-lg overflow-hidden">
            <div className="flex items-center gap-2 px-4 py-3 bg-gray-800/40">
              <Users className="w-4 h-4 text-brand-400" />
              <span className="text-sm font-medium text-gray-200">
                Threat Actors ({intel.threat_actors.length})
              </span>
            </div>
            <div className="p-4 space-y-2">
              {intel.threat_actors.length === 0 ? (
                <p className="text-sm text-gray-500 italic">No threat actor identified.</p>
              ) : (
                intel.threat_actors.map((actor, i) => (
                  <div key={i} className="border border-gray-700 rounded-lg p-3 space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-medium text-gray-200">{actor.name}</span>
                      <span
                        className={clsx(
                          'text-[11px] px-1.5 py-0.5 rounded',
                          CONFIDENCE_CLASS[actor.confidence] ?? CONFIDENCE_CLASS.low,
                        )}
                      >
                        {actor.confidence}
                      </span>
                    </div>
                    {actor.rationale && <p className="text-sm text-gray-400">{actor.rationale}</p>}
                  </div>
                ))
              )}
            </div>
          </div>

          {/* Attribution */}
          {intel.attribution && (
            <div className="card space-y-1.5">
              <div className="flex items-center gap-2">
                <Shield className="w-4 h-4 text-amber-400" />
                <h4 className="text-sm font-semibold text-gray-200">Attribution</h4>
                <span
                  className={clsx(
                    'text-[11px] px-1.5 py-0.5 rounded',
                    CONFIDENCE_CLASS[intel.attribution.confidence] ?? CONFIDENCE_CLASS.low,
                  )}
                >
                  {intel.attribution.confidence}
                </span>
              </div>
              <p className="text-sm text-gray-200 font-medium">{intel.attribution.assessment}</p>
              {intel.attribution.rationale && (
                <p className="text-sm text-gray-400">{intel.attribution.rationale}</p>
              )}
            </div>
          )}

          {/* Malware Families / Campaigns */}
          {(intel.malware_families.length > 0 || intel.campaigns.length > 0) && (
            <div className="border border-gray-700 rounded-lg overflow-hidden">
              <div className="flex items-center gap-2 px-4 py-3 bg-gray-800/40">
                <Boxes className="w-4 h-4 text-brand-400" />
                <span className="text-sm font-medium text-gray-200">Malware Families & Campaigns</span>
              </div>
              <div className="p-4 space-y-3">
                {intel.malware_families.length > 0 && (
                  <div className="flex flex-wrap gap-1.5">
                    {intel.malware_families.map((family) => (
                      <span
                        key={family}
                        className="text-[11px] font-mono bg-gray-800 text-gray-300 border border-gray-700 rounded px-2 py-0.5"
                      >
                        {family}
                      </span>
                    ))}
                  </div>
                )}
                {intel.campaigns.length > 0 && (
                  <div className="flex flex-wrap gap-1.5">
                    {intel.campaigns.map((c, i) => (
                      <span
                        key={i}
                        className="text-[11px] bg-indigo-900/30 text-indigo-300 border border-indigo-800/40 rounded px-2 py-0.5"
                        title={c.description || undefined}
                      >
                        {c.name}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Correlated IOCs */}
          <div className="border border-gray-700 rounded-lg overflow-hidden">
            <div className="flex items-center gap-2 px-4 py-3 bg-gray-800/40">
              <Link2 className="w-4 h-4 text-brand-400" />
              <span className="text-sm font-medium text-gray-200">
                Correlated IOCs ({intel.correlated_iocs.length})
              </span>
            </div>
            <div className="p-4">
              {intel.correlated_iocs.length === 0 ? (
                <p className="text-sm text-gray-500 italic">
                  No IOCs from this run were found in other hunt packages.
                </p>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full min-w-[500px]">
                    <thead>
                      <tr className="text-[10px] uppercase tracking-wider text-gray-500">
                        <th className="text-left py-1.5 pr-3">IOC</th>
                        <th className="text-left py-1.5 pr-3">Type</th>
                        <th className="text-left py-1.5">Found in other hunt</th>
                      </tr>
                    </thead>
                    <tbody>
                      {intel.correlated_iocs.map((m, i) => (
                        <tr key={i} className="border-t border-gray-800/60">
                          <td className="py-1.5 pr-3 text-[11px] font-mono text-gray-300">{m.ioc}</td>
                          <td className="py-1.5 pr-3 text-[11px] text-gray-400">{m.ioc_type}</td>
                          <td className="py-1.5 text-[11px] text-gray-400">{m.hunt_name}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>

          {/* Related Vendor Reporting */}
          {intel.related_vendors.length > 0 && (
            <div className="border border-gray-700 rounded-lg overflow-hidden">
              <div className="flex items-center gap-2 px-4 py-3 bg-gray-800/40">
                <Newspaper className="w-4 h-4 text-brand-400" />
                <span className="text-sm font-medium text-gray-200">Related Vendor Reporting</span>
              </div>
              <div className="p-4 space-y-2">
                {intel.related_vendors.map((v, i) => (
                  <div key={i} className="text-sm text-gray-300">
                    <span className="font-medium text-gray-200">{v.vendor}</span>
                    {v.campaign && <span className="text-gray-500"> — {v.campaign}</span>}
                    {v.report && <p className="text-sm text-gray-400">{v.report}</p>}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
