import { useState, useEffect, useMemo } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { ArrowLeft, Plus, Trash2, AlertTriangle, CheckCircle, Clock, RefreshCw, ChevronDown, X } from 'lucide-react'
import { clsx } from 'clsx'
import { api, type THEvidenceItem, type THExtractedIOC, type THRunSummary, type LLMProviderSummary } from '../../api/client'
import { useAuth } from '../../auth/useAuth'
import AddEvidenceModal from './AddEvidenceModal'
import AnalysisTab from './AnalysisTab'
import ExecutionPanel from './ExecutionPanel'
import ReportPanel from './ReportPanel'

type DetailTab = 'evidence' | 'iocs' | 'analysis' | 'execution' | 'report'

const EFFORT_OPTIONS = ['low', 'medium', 'high'] as const

export default function HuntDetail({ pkgId, onBack }: { pkgId: string; onBack: () => void }) {
  const { isResearcher } = useAuth()
  const qc = useQueryClient()
  const [showAddItem, setShowAddItem] = useState(false)
  const [activeTab, setActiveTab] = useState<DetailTab>('evidence')
  const [activeRunId, setActiveRunId] = useState<string | undefined>(undefined)

  // issue-006-G: re-run dialog state
  const [showRerunDialog, setShowRerunDialog] = useState(false)
  const [rerunModelChoice, setRerunModelChoice] = useState<string>('')
  const [rerunEffort, setRerunEffort] = useState<string>('medium')

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

  // Load all generation runs for this package
  const { data: runs = [] } = useQuery({
    queryKey: ['th-runs', pkgId],
    queryFn: () => api.threatHunting.listRuns(pkgId),
    refetchInterval: 5000, // keep run list fresh
  })

  // issue-006-G: LLM providers for re-run dialog model selector
  const { data: rerunProviders = [] } = useQuery({
    queryKey: ['llm-providers'],
    queryFn: () => api.llm.listProviders(),
    staleTime: 60_000,
    enabled: showRerunDialog,
  })

  const rerunModelOptions = useMemo(() => {
    const opts: { provider: string; model: string }[] = []
    const seen = new Set<string>()
    for (const p of rerunProviders as LLMProviderSummary[]) {
      for (const m of p.available_models ?? []) {
        const key = `${p.name}\x00${m}`
        if (seen.has(key)) continue
        seen.add(key)
        opts.push({ provider: p.name, model: m })
      }
    }
    return opts
  }, [rerunProviders])

  const rerunChosenModel = rerunModelChoice !== '' ? (rerunModelOptions[Number(rerunModelChoice)] ?? null) : null

  // Auto-select the latest run when runs load/change
  useEffect(() => {
    if (runs.length > 0 && !activeRunId) {
      setActiveRunId(runs[0].id)
    }
  }, [runs, activeRunId])

  const deleteEvidenceMut = useMutation({
    mutationFn: (itemId: string) => api.threatHunting.deleteEvidence(pkgId, itemId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['th-evidence', pkgId] })
      qc.invalidateQueries({ queryKey: ['th-package', pkgId] })
      qc.invalidateQueries({ queryKey: ['th-packages'] })
    },
  })

  // issue-006-G: Re-run with model+effort from dialog
  const rerunMut = useMutation({
    mutationFn: () => api.threatHunting.startGeneration(pkgId, {
      research_effort: rerunEffort || 'medium',
      provider_name: rerunChosenModel?.provider ?? undefined,
      model_name: rerunChosenModel?.model ?? undefined,
    }),
    onSuccess: (data) => {
      qc.invalidateQueries({ queryKey: ['th-runs', pkgId] })
      qc.invalidateQueries({ queryKey: ['th-package', pkgId] })
      const newRunId = data.run_id ?? data.id
      if (newRunId) setActiveRunId(newRunId)
      setActiveTab('analysis')
      setShowRerunDialog(false)
    },
  })

  const PARSE_STATUS_ICON = {
    ok: <CheckCircle className="w-3.5 h-3.5 text-green-400" />,
    partial: <Clock className="w-3.5 h-3.5 text-amber-400" />,
    error: <AlertTriangle className="w-3.5 h-3.5 text-red-400" />,
  }

  const noisyCount = (iocs as THExtractedIOC[]).filter((i) => i.flagged_noisy).length
  const cleanCount = (iocs as THExtractedIOC[]).length - noisyCount

  const isFinished = pkg?.status === 'approved' || pkg?.status === 'completed'
  // A run is active when the latest run (index 0) is in running/awaiting_approval state
  const latestRunActive = runs.length > 0 && (
    runs[0].generation_status === 'running' ||
    runs[0].generation_status === 'awaiting_approval'
  )

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
        <div className="flex items-center gap-2">
          {/* Re-run button — visible when package is finished and no run is active (issue-006-G: opens dialog) */}
          {isResearcher && isFinished && !latestRunActive && (
            <button
              className="btn-secondary flex items-center gap-2 text-sm"
              disabled={rerunMut.isPending}
              onClick={() => setShowRerunDialog(true)}
              title="Re-run this hunt package — choose model and effort level"
            >
              <RefreshCw className="w-4 h-4" />
              Re-run
            </button>
          )}
          {isResearcher && (
            <button className="btn-secondary flex items-center gap-2 text-sm" onClick={() => setShowAddItem(true)}>
              <Plus className="w-4 h-4" />
              Add Item
            </button>
          )}
        </div>
      </div>

      {/* Run selector — shown when there are multiple runs */}
      {runs.length > 0 && (
        <div className="flex items-center gap-3 px-3 py-2 bg-gray-800/40 rounded-lg border border-gray-700/50">
          <span className="text-xs text-gray-500 shrink-0">Run:</span>
          <div className="relative flex-1 max-w-xs">
            <select
              className="input w-full text-xs pr-7 appearance-none"
              value={activeRunId ?? ''}
              onChange={(e) => setActiveRunId(e.target.value)}
            >
              {runs.map((run: THRunSummary, idx: number) => {
                const label = run.created_at.slice(0, 19).replace('T', ' ')
                const model = run.llm_model ?? run.llm_provider ?? ''
                const effort = run.research_effort ?? ''
                const suffix = [model, effort].filter(Boolean).join(' · ')
                const status = run.generation_status
                const isActive = status === 'running' || status === 'awaiting_approval'
                return (
                  <option key={run.id} value={run.id}>
                    {idx === 0 ? '★ ' : ''}{label}{suffix ? ` (${suffix})` : ''}{isActive ? ' ⟳' : ''}
                  </option>
                )
              })}
            </select>
            <ChevronDown className="absolute right-2 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-gray-500 pointer-events-none" />
          </div>
          <span className={clsx('text-[10px] px-2 py-0.5 rounded shrink-0',
            runs.find(r => r.id === activeRunId)?.generation_status === 'completed' ? 'bg-green-900/30 text-green-400' :
            runs.find(r => r.id === activeRunId)?.generation_status === 'running' ? 'bg-blue-900/30 text-blue-400' :
            runs.find(r => r.id === activeRunId)?.generation_status === 'awaiting_approval' ? 'bg-amber-900/30 text-amber-400' :
            runs.find(r => r.id === activeRunId)?.generation_status === 'error' ? 'bg-red-900/30 text-red-400' :
            'bg-gray-800 text-gray-500'
          )}>
            {runs.find(r => r.id === activeRunId)?.generation_status ?? '—'}
          </span>
        </div>
      )}

      {/* Tabs */}
      <div className="border-b border-gray-800">
        <nav className="flex gap-6">
          <button
            onClick={() => setActiveTab('evidence')}
            className={clsx('pb-3 text-sm font-medium transition-colors', activeTab === 'evidence' ? 'tab-active' : 'tab-inactive')}
          >
            Evidence ({evidence.length})
          </button>
          {/* issue-008-2B: IOC tab only visible once analysis has produced IOCs */}
          {(iocs as THExtractedIOC[]).length > 0 && (
            <button
              onClick={() => setActiveTab('iocs')}
              className={clsx('pb-3 text-sm font-medium transition-colors', activeTab === 'iocs' ? 'tab-active' : 'tab-inactive')}
            >
              IOCs ({(iocs as THExtractedIOC[]).length})
            </button>
          )}
          <button
            onClick={() => setActiveTab('analysis')}
            className={clsx('pb-3 text-sm font-medium transition-colors', activeTab === 'analysis' ? 'tab-active' : 'tab-inactive')}
          >
            Analysis
          </button>
          {/* Execution tab — shown when package is approved or completed */}
          {isFinished && (
            <button
              onClick={() => setActiveTab('execution')}
              className={clsx('pb-3 text-sm font-medium transition-colors', activeTab === 'execution' ? 'tab-active' : 'tab-inactive')}
            >
              Execution
            </button>
          )}
          {/* Report tab — shown when package is approved or completed */}
          {isFinished && (
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
                   {item.parse_status === 'pending'
                     ? <Clock className="w-3.5 h-3.5 text-blue-500" />
                     : (PARSE_STATUS_ICON[item.parse_status as keyof typeof PARSE_STATUS_ICON] ?? PARSE_STATUS_ICON.ok)}
                 </div>
                 <div className="flex-1 min-w-0 space-y-0.5">
                   <p className="text-sm text-gray-200 font-medium truncate">{item.label || item.source_ref}</p>
                   <div className="flex items-center gap-2 flex-wrap">
                     <span className="text-[10px] text-gray-500 bg-gray-800 px-1.5 py-0.5 rounded">{item.item_type}</span>
                     {item.parse_status === 'pending' ? (
                       <span className="text-[10px] text-blue-400 font-mono">⟳ pending — fetched during analysis</span>
                     ) : (
                       <span className="text-[10px] text-gray-500">{item.parser_used}</span>
                     )}
                     {item.parse_warnings.length > 0 && item.parse_status !== 'pending' && (
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

      {/* Analysis tab — passes activeRunId so it polls the correct run */}
      {activeTab === 'analysis' && (
        <AnalysisTab
          pkgId={pkgId}
          runId={activeRunId}
          onRunCreated={(id) => {
            setActiveRunId(id)
            qc.invalidateQueries({ queryKey: ['th-runs', pkgId] })
          }}
        />
      )}

      {/* Execution tab */}
      {activeTab === 'execution' && (
        <ExecutionPanel
          pkgId={pkgId}
          runId={activeRunId}
          retrohunt={undefined}
        />
      )}

      {/* Report tab */}
      {activeTab === 'report' && <ReportPanel pkgId={pkgId} runId={activeRunId} />}

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

      {/* issue-006-G: Re-run dialog — model + effort selector */}
      {showRerunDialog && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="bg-gray-900 border border-gray-700 rounded-xl shadow-xl w-full max-w-sm mx-4 p-5 space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-semibold text-gray-100">Re-run Hunt Package</h3>
              <button
                className="btn-ghost p-1.5 text-gray-500 hover:text-gray-300"
                onClick={() => setShowRerunDialog(false)}
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Model selector */}
            <div className="space-y-1.5">
              <label className="block text-xs text-gray-400">Model</label>
              <div className="relative">
                <select
                  className="input w-full text-xs pr-7 appearance-none"
                  value={rerunModelChoice}
                  onChange={(e) => setRerunModelChoice(e.target.value)}
                >
                  <option value="">Configured default</option>
                  {rerunModelOptions.map((opt, i) => (
                    <option key={`${opt.provider}:${opt.model}`} value={String(i)}>
                      {opt.provider} · {opt.model}
                    </option>
                  ))}
                </select>
                <ChevronDown className="absolute right-2 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-gray-500 pointer-events-none" />
              </div>
            </div>

            {/* Effort pills */}
            <div className="space-y-1.5">
              <label className="block text-xs text-gray-400">Research Effort</label>
              <div className="flex gap-2">
                {EFFORT_OPTIONS.map((e) => (
                  <button
                    key={e}
                    className={clsx(
                      'flex-1 py-1.5 text-xs rounded border transition-colors',
                      rerunEffort === e
                        ? 'bg-brand-900/40 text-brand-300 border-brand-700/60'
                        : 'bg-gray-800/50 text-gray-500 border-gray-700/40 hover:text-gray-300',
                    )}
                    onClick={() => setRerunEffort(e)}
                  >
                    {e}
                  </button>
                ))}
              </div>
            </div>

            {/* Selected summary */}
            <p className="text-[10px] text-gray-600">
              {rerunChosenModel
                ? `${rerunChosenModel.provider} / ${rerunChosenModel.model}`
                : 'Default model'}{' '}
              · effort: {rerunEffort}
            </p>

            {/* Actions */}
            <div className="flex gap-2 justify-end pt-1">
              <button
                className="btn-ghost text-xs"
                onClick={() => setShowRerunDialog(false)}
                disabled={rerunMut.isPending}
              >
                Cancel
              </button>
              <button
                className="btn-primary text-xs"
                disabled={rerunMut.isPending}
                onClick={() => rerunMut.mutate()}
              >
                {rerunMut.isPending ? 'Starting…' : 'Start Re-run'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
