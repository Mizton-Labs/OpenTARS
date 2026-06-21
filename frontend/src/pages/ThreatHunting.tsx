import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Plus, Shield, Trash2, ChevronRight } from 'lucide-react'
import { clsx } from 'clsx'
import { api, type THuntPackage } from '../api/client'
import { useAuth } from '../auth/useAuth'
import HuntPackageWizard from './threat-hunting/HuntPackageWizard'
import HuntDetail from './threat-hunting/HuntDetail'

const STATUS_COLORS: Record<string, string> = {
  draft: 'bg-gray-700/50 text-gray-400',
  planning: 'bg-blue-900/40 text-blue-400',
  approved: 'bg-green-900/40 text-green-400',
  executing: 'bg-yellow-900/40 text-yellow-400',
  completed: 'bg-brand-900/40 text-brand-400',
  archived: 'bg-gray-800/40 text-gray-600',
}

export default function ThreatHunting() {
  const { isResearcher } = useAuth()
  const qc = useQueryClient()
  const [showWizard, setShowWizard] = useState(false)
  const [selectedId, setSelectedId] = useState<string | null>(null)

  const { data: packages = [], isLoading } = useQuery({
    queryKey: ['th-packages'],
    queryFn: api.threatHunting.listPackages,
  })

  const archiveMut = useMutation({
    mutationFn: (id: string) => api.threatHunting.archivePackage(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['th-packages'] }),
  })

  if (selectedId) {
    return (
      <HuntDetail
        pkgId={selectedId}
        onBack={() => setSelectedId(null)}
      />
    )
  }

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold text-gray-100">Threat Hunting</h1>
          <p className="text-sm text-gray-500">
            Agentic Threat Hunting Operations Framework
          </p>
        </div>
        {isResearcher && (
          <button className="btn-primary flex items-center gap-2" onClick={() => setShowWizard(true)}>
            <Plus className="w-4 h-4" />
            New Hunt Package
          </button>
        )}
      </div>

      {isLoading ? (
        <p className="text-sm text-gray-500">Loading...</p>
      ) : packages.length === 0 ? (
        <div className="card text-center py-12 space-y-3">
          <Shield className="w-10 h-10 text-gray-600 mx-auto" />
          <p className="text-sm text-gray-400">No hunt packages yet.</p>
          {isResearcher && (
            <button className="btn-primary text-sm" onClick={() => setShowWizard(true)}>
              Create your first Hunt Package
            </button>
          )}
        </div>
      ) : (
        <div className="space-y-2">
          {packages.map((pkg: THuntPackage) => (
            <div
              key={pkg.id}
              className="card flex items-center gap-4 cursor-pointer hover:bg-gray-800/60 transition-colors"
              onClick={() => setSelectedId(pkg.id)}
            >
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <p className="text-sm font-medium text-gray-100 truncate">{pkg.name}</p>
                  <span className={clsx('badge text-[10px] px-1.5 py-0.5 rounded', STATUS_COLORS[pkg.status] ?? STATUS_COLORS.draft)}>
                    {pkg.status}
                  </span>
                </div>
                {pkg.description && (
                  <p className="text-xs text-gray-500 truncate mt-0.5">{pkg.description}</p>
                )}
                <p className="text-[10px] text-gray-600 mt-1">
                  {pkg.evidence_count} evidence item{pkg.evidence_count !== 1 ? 's' : ''} ·{' '}
                  {new Date(pkg.created_at).toLocaleDateString()}
                </p>
              </div>
              <div className="flex items-center gap-2">
                {isResearcher && (
                  <button
                    className="btn-ghost p-1.5 text-gray-600 hover:text-red-400"
                    title="Archive"
                    onClick={(e) => { e.stopPropagation(); archiveMut.mutate(pkg.id) }}
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                )}
                <ChevronRight className="w-4 h-4 text-gray-600" />
              </div>
            </div>
          ))}
        </div>
      )}

      {showWizard && (
        <HuntPackageWizard
          onClose={() => setShowWizard(false)}
          onCreated={(id) => { setShowWizard(false); setSelectedId(id) }}
        />
      )}
    </div>
  )
}
