/**
 * ConfigDriftBanner (issue-local-024 follow-up).
 *
 * A persistent top-bar strip, visible to admins only, that appears whenever
 * a newer release shipped config content (new core fields, new settings)
 * that this deployment's live, gitignored config files haven't picked up
 * yet — see backend/config/drift.py for what this can and can't detect.
 * Renders nothing when there's no drift, so the common case is invisible.
 */
import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { AlertTriangle } from 'lucide-react'
import { api } from '../api/client'
import { useAuth } from '../auth/useAuth'
import ConfigDriftModal from './ConfigDriftModal'

export default function ConfigDriftBanner() {
  const { isAdmin } = useAuth()
  const [showModal, setShowModal] = useState(false)

  const { data } = useQuery({
    queryKey: ['config-drift'],
    queryFn: api.getConfigDrift,
    enabled: isAdmin,
    staleTime: 5 * 60 * 1000,
    refetchInterval: 5 * 60 * 1000,
  })

  const reports = data?.reports ?? []
  if (!isAdmin || reports.length === 0) return null

  const totalCount = reports.reduce(
    (n, r) => n + r.missing_keys.length + r.missing_core_fields.length,
    0,
  )

  return (
    <>
      <div className="flex items-center justify-between gap-3 border-b border-amber-700/40 bg-amber-900/20 px-4 py-1.5 text-xs text-amber-300 shrink-0">
        <div className="flex items-center gap-2">
          <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
          <span>
            {totalCount} new configuration item{totalCount === 1 ? '' : 's'} available from a
            recent update.
          </span>
        </div>
        <button
          className="shrink-0 text-amber-200 underline hover:text-amber-100"
          onClick={() => setShowModal(true)}
        >
          Review &amp; update
        </button>
      </div>
      {showModal && (
        <ConfigDriftModal reports={reports} onClose={() => setShowModal(false)} />
      )}
    </>
  )
}
