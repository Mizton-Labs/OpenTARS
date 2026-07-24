import { useState, useEffect, useMemo } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { ArrowLeft, Plus, Trash2, AlertTriangle, CheckCircle, Clock, RefreshCw, ChevronDown, X, Save } from 'lucide-react'
import { clsx } from 'clsx'
import { api, type THEvidenceItem, type THExtractedIOC, type THRunSummary, type LLMProviderSummary } from '../../api/client'
import { useAuth } from '../../auth/useAuth'
import AddEvidenceModal from './AddEvidenceModal'
import AnalysisTab from './AnalysisTab'
import ExecutionPanel from './ExecutionPanel'
import PipelineStepper from './PipelineStepper'
import ReportPanel from './ReportPanel'
import ConfirmDialog from '../../components/ConfirmDialog'
import { runStatusClass, runLabel } from './runStatusUtils'
import IocVerdictToggle from './IocVerdictToggle'
import { useIocVerdictStaging } from './useIocVerdictStaging'
import RunsStatusTable from './RunsStatusTable'

type DetailTab = 'evidence' | 'iocs' | 'analysis' | 'execution' | 'report'

const EFFORT_OPTIONS = ['low', 'medium', 'high'] as const

export default function HuntDetail({ pkgId, onBack }: { pkgId: string; onBack: () => void }) {
  const { isResearcher } = useAuth()
  const qc = useQueryClient()
  const [showAddItem, setShowAddItem] = useState(false)
  const [activeTab, setActiveTab] = useState<DetailTab>('evidence')
  const [activeRunId, setActiveRunId] = useState<string | undefined>(undefined)

  // Part 4: evidence delete confirmation
  const [confirmEvidenceId, setConfirmEvidenceId] = useState<string | null>(null)

  // issue-006-G: re-run dialog state
  const [showRerunDialog, setShowRerunDialog] = useState(false)
  const [rerunModelChoice, setRerunModelChoice] = useState<string>('')
  const [rerunEffort, setRerunEffort] = useState<string>('medium')
  // issue-local-015: per-run IOC handling config
  const [iocMode, setIocMode] = useState<'tagging_only' | 'active_cleaning'>('tagging_only')
  const [iocCleaningOptions, setIocCleaningOptions] = useState({
    remove_noisy: true,
    remove_legit_domains: true,
    remove_cdn_ranges: true,
    remove_legit_services: false,
  })

  const { data: pkg } = useQuery({
    queryKey: ['th-package', pkgId],
    queryFn: () => api.threatHunting.getPackage(pkgId),
  })

  const { data: evidence = [] } = useQuery({
    queryKey: ['th-evidence', pkgId],
    queryFn: () => api.threatHunting.listEvidence(pkgId),
  })

  const { data: iocs = [] } = useQuery({
    queryKey: ['th-iocs', pkgId, activeRunId],
    queryFn: () => api.threatHunting.listIocs(pkgId, activeRunId),
    enabled: activeTab === 'iocs' && !!activeRunId,
  })

  // Load all generation runs for this package
  const { data: runs = [] } = useQuery({
    queryKey: ['th-runs', pkgId],
    queryFn: () => api.threatHunting.listRuns(pkgId),
    refetchInterval: 5000, // keep run list fresh
  })

  // issue-local-015: selected run's full record, for the header progress
  // stepper. Same query key/shape as AnalysisTab.tsx's own fetch — React
  // Query dedupes identical keys, so this doesn't double the polling when
  // the Analysis tab is also active.
  const { data: headerGenRecord } = useQuery({
    queryKey: ['th-generation', pkgId, activeRunId],
    queryFn: () => {
      if (activeRunId) return api.threatHunting.getRunStatus(pkgId, activeRunId).catch(() => null)
      return api.threatHunting.getGenerationStatus(pkgId).catch(() => null)
    },
    refetchInterval: (query) => {
      const status = (query.state.data as { generation_status?: string } | null)?.generation_status
      return status === 'running' ? 3000 : false
    },
    enabled: !!activeRunId,
  })

  // issue-local-015: lightweight existence checks for the Execution/Report
  // phases of the header stepper — same query keys ExecutionPanel.tsx /
  // ReportPanel.tsx already use, so this shares cache rather than
  // duplicating fetches once those tabs are visited.
  const { data: headerResults = [] } = useQuery({
    queryKey: ['th-results', pkgId, activeRunId],
    queryFn: () => (activeRunId ? api.threatHunting.listRunResults(pkgId, activeRunId) : Promise.resolve([])),
    enabled: !!activeRunId,
  })
  const { data: headerReport } = useQuery({
    queryKey: ['th-report', pkgId, activeRunId],
    queryFn: () => (activeRunId ? api.threatHunting.getRunReport(pkgId, activeRunId).catch(() => null) : Promise.resolve(null)),
    enabled: !!activeRunId,
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

  // issue-local-016: manual IOC verdict overrides, staged until "Apply
  // changes" — lifted here (parent of both the IOCs tab and the Analysis
  // tab's embedded RetrohuntPanel) so a change staged in one tab is still
  // pending when switching to the other. Scoped to the active run only.
  const iocStaging = useIocVerdictStaging(pkgId, activeRunId)

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
      run_config: {
        ioc_mode: iocMode,
        ioc_cleaning_options: iocMode === 'active_cleaning' ? iocCleaningOptions : undefined,
      },
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
  const removedCount = (iocs as THExtractedIOC[]).filter((i) => i.action === 'remove').length

  const isFinished = pkg?.status === 'approved' || pkg?.status === 'completed'
  // issue-local-014: re-run is available regardless of any run's status —
  // including while a run is still active — so parallel runs (e.g. a
  // different model/effort) can be started at any time. The run selector
  // above already lists and marks every concurrently active run.
  const canRerun = isResearcher && (pkg?.evidence_count ?? 0) > 0

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
          {/* Re-run button — always available once evidence exists, even mid-run (issue-local-014) */}
          {canRerun && (
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

      {/* issue-local-016: staged IOC verdict changes — visible regardless of
          active tab, since a change can be staged from either the IOCs tab
          or the Analysis tab's Sanitized IOCs table. */}
      {iocStaging.isDirty && (
        <div className="flex items-center justify-between gap-3 px-3 py-2 rounded-lg border border-brand-700/50 bg-brand-900/10">
          <p className="text-sm text-brand-300">
            {iocStaging.pendingCount} IOC verdict change{iocStaging.pendingCount !== 1 ? 's' : ''} staged for this run.
          </p>
          <button
            className="btn-primary flex items-center gap-2 text-sm shrink-0"
            disabled={iocStaging.isApplying}
            onClick={() => iocStaging.apply()}
          >
            <Save className="w-3.5 h-3.5" />
            {iocStaging.isApplying ? 'Applying...' : 'Apply changes'}
          </button>
        </div>
      )}

      {/* Run selector — shown when there are multiple runs */}
      {runs.length > 0 && (
        <div className="space-y-2 px-3 py-2 bg-gray-800/40 rounded-lg border border-gray-700/50">
          <div className="flex items-center gap-3">
            <span className="text-sm text-gray-500 shrink-0">Run:</span>
            <div className="relative flex-1 max-w-xs">
              <select
                className="input w-full text-sm pr-7 appearance-none"
                value={activeRunId ?? ''}
                onChange={(e) => setActiveRunId(e.target.value)}
              >
                {runs.map((run: THRunSummary, idx: number) => {
                  const label = run.created_at.slice(0, 19).replace('T', ' ')
                  const suffix = runLabel(run)
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
            <span className={clsx(
              'text-[11px] px-2 py-0.5 rounded shrink-0',
              runStatusClass(runs.find(r => r.id === activeRunId)?.generation_status),
            )}>
              {runs.find(r => r.id === activeRunId)?.generation_status ?? '—'}
            </span>
          </div>
          {/* issue-local-015: progress-block stepper for the selected run */}
          <PipelineStepper
            genRecord={headerGenRecord ?? undefined}
            hasEvidence={evidence.length > 0}
            hasResults={headerResults.length > 0}
            hasReport={!!headerReport}
          />
        </div>
      )}

      {/* issue-local-017: compact all-runs overview — model, status, and
          workflow progress for every run at once, so switching the run
          selector back and forth isn't needed just to check overall state. */}
      {runs.length > 0 && (
        <div className="space-y-1.5">
          <p className="text-[10px] text-gray-500 uppercase tracking-wider font-semibold">
            All runs
          </p>
          <RunsStatusTable pkgId={pkgId} runs={runs} />
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
                     <span className="text-[11px] text-gray-500 bg-gray-800 px-1.5 py-0.5 rounded">{item.item_type}</span>
                     {item.parse_status === 'pending' ? (
                       <span className="text-[11px] text-blue-400 font-mono">⟳ pending — fetched during analysis</span>
                     ) : (
                       <span className="text-[11px] text-gray-500">{item.parser_used}</span>
                     )}
                     {item.parse_warnings.length > 0 && item.parse_status !== 'pending' && (
                       <span className="text-[11px] text-amber-500">{item.parse_warnings.length} warning{item.parse_warnings.length > 1 ? 's' : ''}</span>
                     )}
                   </div>
                   {item.source_ref && item.item_type === 'url' && (
                     <p className="text-[11px] text-gray-600 font-mono truncate">{item.final_url || item.source_ref}</p>
                   )}
                 </div>
                 {isResearcher && (
                   <button
                     className="btn-ghost p-1 text-gray-600 hover:text-red-400 shrink-0"
                     onClick={() => setConfirmEvidenceId(item.id)}
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
              <div className="flex gap-4 text-sm text-gray-500">
                <span className="text-green-400">{cleanCount} actionable</span>
                <span className="text-amber-400">{noisyCount} noisy / flagged</span>
                {removedCount > 0 && (
                  <span className="text-red-400">{removedCount} removed (active cleaning)</span>
                )}
              </div>
              {/* Column headers */}
              <div className="flex items-center gap-3 px-3 text-[11px] text-gray-600 uppercase tracking-wider">
                <span className="w-24 shrink-0">Type</span>
                <span className="flex-1">IOC</span>
                <span className="w-28 shrink-0">Result</span>
                <span className="w-32 shrink-0 text-right">Verdict</span>
              </div>
              <div className="space-y-1">
                {(iocs as THExtractedIOC[]).map((ioc) => {
                  const serverValue = ioc.action ?? 'keep'
                  const removed = serverValue === 'remove'
                  return (
                    <div
                      key={ioc.id}
                      className={clsx(
                        'flex items-center gap-3 px-3 py-2 rounded-lg text-sm',
                        removed
                          ? 'bg-red-900/10 border border-red-900/30 opacity-60'
                          : ioc.flagged_noisy
                            ? 'bg-amber-900/10 border border-amber-800/30'
                            : 'bg-gray-800/40',
                      )}
                    >
                      <span className="text-gray-500 w-24 shrink-0">{ioc.ioc_type}</span>
                      <span
                        className={clsx(
                          'font-mono flex-1 truncate',
                          removed ? 'text-gray-500 line-through' : 'text-gray-200',
                        )}
                      >
                        {ioc.ioc}
                      </span>
                      <span className="w-28 shrink-0 flex items-center gap-1.5">
                        {ioc.flagged_noisy && (
                          <span className="text-amber-500 text-[11px]">noisy</span>
                        )}
                        <span className="text-gray-600 text-[11px]">
                          {(ioc.noise_score * 100).toFixed(0)}%
                        </span>
                      </span>
                      <span className="w-32 shrink-0 flex justify-end">
                        {isResearcher ? (
                          <IocVerdictToggle
                            value={serverValue}
                            pending={iocStaging.pendingFor(ioc.ioc, ioc.ioc_type)}
                            onChange={(next) => iocStaging.stage(ioc.ioc, ioc.ioc_type, next, serverValue)}
                          />
                        ) : (
                          <span
                            className={clsx(
                              'text-[11px] font-medium',
                              removed ? 'text-red-400' : 'text-green-400',
                            )}
                          >
                            {removed ? 'remove' : 'keep'}
                          </span>
                        )}
                      </span>
                    </div>
                  )
                })}
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
          onShowIocs={() => setActiveTab('iocs')}
          pendingVerdictFor={isResearcher ? iocStaging.pendingFor : undefined}
          onStageVerdict={isResearcher ? iocStaging.stage : undefined}
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

      {/* Part 4: Evidence delete confirmation dialog */}
      {confirmEvidenceId && (
        <ConfirmDialog
          title="Delete Evidence Item?"
          message="This permanently removes this evidence item. If analysis has been run, the results will not be affected."
          confirmLabel="Delete"
          onConfirm={() => {
            deleteEvidenceMut.mutate(confirmEvidenceId)
            setConfirmEvidenceId(null)
          }}
          onCancel={() => setConfirmEvidenceId(null)}
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
              <label className="block text-sm text-gray-400">Model</label>
              <div className="relative">
                <select
                  className="input w-full text-sm pr-7 appearance-none"
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
              <label className="block text-sm text-gray-400">Research Effort</label>
              <div className="flex gap-2">
                {EFFORT_OPTIONS.map((e) => (
                  <button
                    key={e}
                    className={clsx(
                      'flex-1 py-1.5 text-sm rounded border transition-colors',
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

            {/* issue-local-015: IOC handling mode */}
            <div className="space-y-1.5">
              <label className="block text-sm text-gray-400">IOC Handling</label>
              <div className="flex gap-2">
                {(['tagging_only', 'active_cleaning'] as const).map((m) => (
                  <button
                    key={m}
                    className={clsx(
                      'flex-1 py-1.5 text-[12px] rounded border transition-colors',
                      iocMode === m
                        ? 'bg-brand-900/40 text-brand-300 border-brand-700/60'
                        : 'bg-gray-800/50 text-gray-500 border-gray-700/40 hover:text-gray-300',
                    )}
                    onClick={() => setIocMode(m)}
                  >
                    {m === 'tagging_only' ? 'Tagging only' : 'Active cleaning'}
                  </button>
                ))}
              </div>
              {iocMode === 'active_cleaning' && (
                <div className="space-y-1 pt-1">
                  {(
                    [
                      ['remove_noisy', 'Remove noisy IOCs'],
                      ['remove_legit_domains', 'Remove known legit domains'],
                      ['remove_cdn_ranges', 'Remove known CDN ranges'],
                      ['remove_legit_services', 'Remove known legit services'],
                    ] as const
                  ).map(([key, label]) => (
                    <label key={key} className="flex items-center gap-2 text-[12px] text-gray-400">
                      <input
                        type="checkbox"
                        checked={iocCleaningOptions[key]}
                        onChange={(e) =>
                          setIocCleaningOptions((prev) => ({ ...prev, [key]: e.target.checked }))
                        }
                        className="accent-brand-500"
                      />
                      {label}
                    </label>
                  ))}
                </div>
              )}
            </div>

            {/* Selected summary */}
            <p className="text-[11px] text-gray-600">
              {rerunChosenModel
                ? `${rerunChosenModel.provider} / ${rerunChosenModel.model}`
                : 'Default model'}{' '}
              · effort: {rerunEffort} · IOC: {iocMode === 'tagging_only' ? 'tagging only' : 'active cleaning'}
            </p>

            {/* Actions */}
            <div className="flex gap-2 justify-end pt-1">
              <button
                className="btn-ghost text-sm"
                onClick={() => setShowRerunDialog(false)}
                disabled={rerunMut.isPending}
              >
                Cancel
              </button>
              <button
                className="btn-primary text-sm"
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
