import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { ArrowLeft, Plus, Trash2, AlertTriangle, CheckCircle, Clock } from 'lucide-react'
import { clsx } from 'clsx'
import { api, type THEvidenceItem, type THExtractedIOC } from '../../api/client'
import { useAuth } from '../../auth/useAuth'
import AddEvidenceModal from './AddEvidenceModal'
import AnalysisTab from './AnalysisTab'
import ExecutionPanel from './ExecutionPanel'
import ReportPanel from './ReportPanel'

type DetailTab = 'evidence' | 'iocs' | 'analysis' | 'execution' | 'report'

export default function HuntDetail({ pkgId, onBack }: { pkgId: string; onBack: () => void }) {
  const { isResearcher } = useAuth()
  const qc = useQueryClient()
  const [showAddItem, setShowAddItem] = useState(false)
  const [activeTab, setActiveTab] = useState<DetailTab>('evidence')

  const { data: pkg } = useQuery({
    queryKey: ['th-package', pkgId],
    queryFn: () => api.threatHunting.getPackage(pkgId),
  })

  const { data: evidence = [] } = useQuery({
    queryKey: ['th-evidence', pkgId],
    queryFn: () => api.threatHunting.listEvidence(pkgId),
  })

  const { data: iocs = [] } = useQuery({
    queryKey: ['th-iocs', pkgId],
    queryFn: () => api.threatHunting.listIocs(pkgId),
    enabled: activeTab === 'iocs',
  })

  const deleteEvidenceMut = useMutation({
    mutationFn: (itemId: string) => api.threatHunting.deleteEvidence(pkgId, itemId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['th-evidence', pkgId] })
      qc.invalidateQueries({ queryKey: ['th-package', pkgId] })
      qc.invalidateQueries({ queryKey: ['th-packages'] })
    },
  })

  const PARSE_STATUS_ICON = {
    ok: <CheckCircle className="w-3.5 h-3.5 text-green-400" />,
    partial: <Clock className="w-3.5 h-3.5 text-amber-400" />,
    error: <AlertTriangle className="w-3.5 h-3.5 text-red-400" />,
  }

  const noisyCount = (iocs as THExtractedIOC[]).filter((i) => i.flagged_noisy).length
  const cleanCount = (iocs as THExtractedIOC[]).length - noisyCount

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center gap-3">
        <button className="btn-ghost p-1.5" onClick={onBack}>
          <ArrowLeft className="w-4 h-4" />
        </button>
        <div className="flex-1 min-w-0">
          <h1 className="text-lg font-semibold text-gray-100 truncate">{pkg?.name ?? '…'}</h1>
          {pkg?.description && <p className="text-sm text-gray-500 truncate">{pkg.description}</p>}
        </div>
        {isResearcher && (
          <button className="btn-secondary flex items-center gap-2 text-sm" onClick={() => setShowAddItem(true)}>
            <Plus className="w-4 h-4" />
            Add Item
          </button>
        )}
      </div>

      {/* Tabs */}
      <div className="border-b border-gray-800">
        <nav className="flex gap-6">
          <button
            onClick={() => setActiveTab('evidence')}
            className={clsx('pb-3 text-sm font-medium transition-colors', activeTab === 'evidence' ? 'tab-active' : 'tab-inactive')}
          >
            Evidence ({evidence.length})
          </button>
          <button
            onClick={() => setActiveTab('iocs')}
            className={clsx('pb-3 text-sm font-medium transition-colors', activeTab === 'iocs' ? 'tab-active' : 'tab-inactive')}
          >
            IOCs ({(iocs as THExtractedIOC[]).length})
          </button>
          <button
            onClick={() => setActiveTab('analysis')}
            className={clsx('pb-3 text-sm font-medium transition-colors', activeTab === 'analysis' ? 'tab-active' : 'tab-inactive')}
          >
            Analysis
          </button>
          {/* Execution tab — shown when package is approved or completed */}
          {(pkg?.status === 'approved' || pkg?.status === 'completed') && (
            <button
              onClick={() => setActiveTab('execution')}
              className={clsx('pb-3 text-sm font-medium transition-colors', activeTab === 'execution' ? 'tab-active' : 'tab-inactive')}
            >
              Execution
            </button>
          )}
          {/* Report tab — shown when package is approved or completed */}
          {(pkg?.status === 'approved' || pkg?.status === 'completed') && (
            <button
              onClick={() => setActiveTab('report')}
              className={clsx('pb-3 text-sm font-medium transition-colors', activeTab === 'report' ? 'tab-active' : 'tab-inactive')}
            >
              Report
            </button>
          )}
        </nav>
      </div>

      {/* Evidence tab */}
      {activeTab === 'evidence' && (
        <div className="space-y-2">
          {evidence.length === 0 ? (
            <p className="text-sm text-gray-500 text-center py-8">No evidence items yet.</p>
          ) : (
            (evidence as THEvidenceItem[]).map((item) => (
              <div key={item.id} className="card flex items-start gap-3">
                <div className="mt-0.5 shrink-0">
                  {PARSE_STATUS_ICON[item.parse_status as keyof typeof PARSE_STATUS_ICON] ?? PARSE_STATUS_ICON.ok}
                </div>
                <div className="flex-1 min-w-0 space-y-0.5">
                  <p className="text-sm text-gray-200 font-medium truncate">{item.label || item.source_ref}</p>
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-[10px] text-gray-500 bg-gray-800 px-1.5 py-0.5 rounded">{item.item_type}</span>
                    <span className="text-[10px] text-gray-500">{item.parser_used}</span>
                    {item.parse_warnings.length > 0 && (
                      <span className="text-[10px] text-amber-500">{item.parse_warnings.length} warning{item.parse_warnings.length > 1 ? 's' : ''}</span>
                    )}
                  </div>
                  {item.source_ref && item.item_type === 'url' && (
                    <p className="text-[10px] text-gray-600 font-mono truncate">{item.final_url || item.source_ref}</p>
                  )}
                </div>
                {isResearcher && (
                  <button
                    className="btn-ghost p-1 text-gray-600 hover:text-red-400 shrink-0"
                    onClick={() => deleteEvidenceMut.mutate(item.id)}
                    title="Remove"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                )}
              </div>
            ))
          )}
        </div>
      )}

      {/* IOCs tab */}
      {activeTab === 'iocs' && (
        <div className="space-y-3">
          {(iocs as THExtractedIOC[]).length === 0 ? (
            <p className="text-sm text-gray-500 text-center py-8">No IOCs extracted yet.</p>
          ) : (
            <>
              <div className="flex gap-4 text-xs text-gray-500">
                <span className="text-green-400">{cleanCount} actionable</span>
                <span className="text-amber-400">{noisyCount} noisy / flagged</span>
              </div>
              <div className="space-y-1">
                {(iocs as THExtractedIOC[]).map((ioc) => (
                  <div key={ioc.id} className={clsx('flex items-center gap-3 px-3 py-2 rounded-lg text-xs', ioc.flagged_noisy ? 'bg-amber-900/10 border border-amber-800/30' : 'bg-gray-800/40')}>
                    <span className="text-gray-500 w-24 shrink-0">{ioc.ioc_type}</span>
                    <span className="font-mono text-gray-200 flex-1 truncate">{ioc.ioc}</span>
                    {ioc.flagged_noisy && <span className="text-amber-500 text-[10px] shrink-0">noisy</span>}
                    <span className="text-gray-600 text-[10px] shrink-0">{(ioc.noise_score * 100).toFixed(0)}%</span>
                  </div>
                ))}
              </div>
            </>
          )}
        </div>
      )}

      {/* Analysis tab */}
      {activeTab === 'analysis' && <AnalysisTab pkgId={pkgId} />}

      {/* Execution tab */}
      {activeTab === 'execution' && (
        <ExecutionPanel
          pkgId={pkgId}
          retrohunt={undefined}
        />
      )}

      {/* Report tab */}
      {activeTab === 'report' && <ReportPanel pkgId={pkgId} />}

      {/* Add item modal */}
      {showAddItem && (
        <AddEvidenceModal
          pkgId={pkgId}
          onClose={() => setShowAddItem(false)}
          onAdded={() => {
            qc.invalidateQueries({ queryKey: ['th-evidence', pkgId] })
            qc.invalidateQueries({ queryKey: ['th-package', pkgId] })
            qc.invalidateQueries({ queryKey: ['th-packages'] })
            setShowAddItem(false)
          }}
        />
      )}
    </div>
  )
}
