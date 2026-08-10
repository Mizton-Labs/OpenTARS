import { useState, useMemo, lazy, Suspense } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Play, Loader2, CheckCircle, AlertTriangle,
  ChevronDown, ChevronRight, Code2, Target, Brain, Crosshair, Ban, RotateCcw, Network, Workflow,
} from 'lucide-react'
import { clsx } from 'clsx'
import {
  api,
  type THGenerationRecord,
  type THHypothesis,
  type THHuntingLead,
  type THQueryDraft,
  type THHuntTask,
  type LLMProviderSummary,
  type THPlaybookJob,
  type THQueryLanguages,
} from '../../api/client'
import { useAuth } from '../../auth/useAuth'
import WorkflowVisualizer from './WorkflowVisualizer'
import { asDisplayText } from './llmTextUtils'
import ReportMarkdown from '../../components/ReportMarkdown'
import RunConfigForm from './RunConfigForm'
import {
  buildRunConfig,
  modelOptionsFromProviders,
  playbookIdFromChoice,
  DEFAULT_IOC_MODE,
  DEFAULT_IOC_CLEANING_OPTIONS,
  DEFAULT_INCLUDE_THREAT_INTEL,
  DEFAULT_QUERY_LANGUAGES,
} from './runConfigUtils'

// issue-local-022 (item 2): lazy-loaded, matching WorkflowVisualizer.tsx's
// treatment of its own @xyflow/react-based visualizer.
const HypothesisLeadIocChart = lazy(() => import('./HypothesisLeadIocChart'))

// issue-local-015: prominent, highly-visible discard/restore action for a
// hypothesis or hunting-lead card — a standalone button card rather than a
// small inline text link, per explicit feedback that the original discard
// link was too easy to miss.
function DiscardButtonCard({
  discarded,
  onClick,
  disabled,
}: {
  discarded: boolean
  onClick: () => void
  disabled: boolean
}) {
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      className={clsx(
        'w-full flex items-center justify-center gap-2 rounded-lg border-2 px-3 py-2 text-sm font-semibold transition-colors mt-1.5',
        discarded
          ? 'border-green-700/60 bg-green-900/15 text-green-400 hover:bg-green-900/25'
          : 'border-red-800/50 bg-red-900/15 text-red-400 hover:bg-red-900/25',
        disabled && 'opacity-50 cursor-not-allowed',
      )}
    >
      {discarded ? <RotateCcw className="w-4 h-4" /> : <Ban className="w-4 h-4" />}
      {discarded ? 'Restore this item' : 'Discard this item'}
    </button>
  )
}

// Defensive: some LLMs (observed with an ES DSL draft) return `query` as a
// nested JSON object instead of the string the schema asks for. The backend
// now normalizes this going forward, but records generated before that fix
// still have the raw object — rendering it directly as a React child throws
// "Objects are not valid as a React child" and blanks the whole page. Coerce
// anything non-string to readable JSON instead of trusting the TS type.
function asQueryText(query: unknown): string {
  if (typeof query === 'string') return query
  try {
    return JSON.stringify(query, null, 2)
  } catch {
    return String(query)
  }
}

export default function AnalysisTab({
  pkgId,
  runId,
  onRunCreated,
  onPlaybookStarted,
  onShowIocs,
  iocVerdictsDirty,
}: {
  pkgId: string
  runId?: string
  onRunCreated?: (runId: string) => void
  /** issue-local-042 (item 21): a Playbook selection fires N runs at once —
   *  no single run_id to hand to onRunCreated — so HuntDetail.tsx can still
   *  switch the run-selector's sub-tab to "Playbook Runs" instead of
   *  leaving it wherever it was, which otherwise looked like nothing had
   *  started. */
  onPlaybookStarted?: () => void
  /** Called when the user clicks "View IOCs" in the workflow timeline. */
  onShowIocs?: () => void
  /** issue-local-018 follow-up: true while there are staged-but-unapplied
   *  IOC keep/remove overrides for this run (HuntDetail.tsx's iocStaging —
   *  staging itself now happens in HuntDetail's IOCs tab, issue-local-022
   *  item 6, but Approve here still must not proceed on stale IOC data).
   *  Approving with unsaved verdicts would move the package into Execution
   *  using stale IOC data, so Approve is disabled until they're applied. */
  iocVerdictsDirty?: boolean
}) {
  const { isResearcher } = useAuth()
  const qc = useQueryClient()
  const [approvalNotes, setApprovalNotes] = useState('')
  const [showApproveForm, setShowApproveForm] = useState(false)
  const [selectedEffort, setSelectedEffort] = useState<string>('')
  const [modelChoice, setModelChoice] = useState<string>('')
  // issue-local-022 (item 3): shared defaults with HuntDetail.tsx's Re-run
  // dialog via RunConfigForm.tsx, instead of an independently-drifted copy.
  const [iocMode, setIocMode] = useState<'tagging_only' | 'active_cleaning'>(DEFAULT_IOC_MODE)
  const [iocCleaningOptions, setIocCleaningOptions] = useState(DEFAULT_IOC_CLEANING_OPTIONS)
  const [includeThreatIntel, setIncludeThreatIntel] = useState(DEFAULT_INCLUDE_THREAT_INTEL)
  // issue-local-041: null until the user actually touches a toggle — see
  // buildRunConfig's docstring for why an untouched form omits the key
  // entirely rather than freezing in the default at page-load time.
  const [queryLanguagesOverride, setQueryLanguagesOverride] = useState<THQueryLanguages | null>(null)

  // Load global default effort for the Generate screen
  const { data: effortData } = useQuery({
    queryKey: ['th-research-effort'],
    queryFn: () => api.getThResearchEffort(),
    staleTime: 30_000,
  })

  // issue-local-041: configured default query languages for the Generate screen.
  const { data: queryLanguagesData } = useQuery({
    queryKey: ['th-query-languages'],
    queryFn: () => api.getThQueryLanguages(),
    staleTime: 30_000,
  })
  const effectiveQueryLanguages =
    queryLanguagesOverride ?? queryLanguagesData?.th_query_languages ?? DEFAULT_QUERY_LANGUAGES

  // Load LLM providers for the model selector
  const { data: providers = [] } = useQuery({
    queryKey: ['llm-providers'],
    queryFn: () => api.llm.listProviders(),
    staleTime: 60_000,
  })

  // Build flat list of provider·model options (mirrors SmartProposalConfirmModal)
  const modelOptions = useMemo(
    () => modelOptionsFromProviders(providers as LLMProviderSummary[]),
    [providers],
  )

  // issue-local-040: Hunt Playbooks offered alongside standalone models.
  const { data: playbooks = [] } = useQuery({
    queryKey: ['hunt-playbooks'],
    queryFn: () => api.threatHunting.playbooks.list(),
    staleTime: 60_000,
  })

  const chosenPlaybookId = playbookIdFromChoice(modelChoice)
  const chosenModel =
    modelChoice !== '' && !chosenPlaybookId ? (modelOptions[Number(modelChoice)] ?? null) : null

  // Poll generation status for the active run (or latest if no runId)
  const { data: genRecord, isLoading } = useQuery({
    queryKey: ['th-generation', pkgId, runId],
    queryFn: () => {
      if (runId) return api.threatHunting.getRunStatus(pkgId, runId).catch(() => null)
      return api.threatHunting.getGenerationStatus(pkgId).catch(() => null)
    },
    refetchInterval: (query) => {
      const status = (query.state.data as THGenerationRecord | null)?.generation_status
      return status === 'running' ? 3000 : false
    },
  })

  const startMut = useMutation<THGenerationRecord | THPlaybookJob, Error, void>({
    mutationFn: () => {
      // issue-local-040: a Hunt Playbook selection fires the whole
      // playbook (N runs, one per its enabled model) instead of a single
      // standalone-model run.
      if (chosenPlaybookId) {
        return api.threatHunting.playbooks.run(pkgId, chosenPlaybookId)
      }
      const effort = selectedEffort || effortData?.th_research_effort || 'high'
      return api.threatHunting.startGeneration(pkgId, {
        research_effort: effort,
        provider_name: chosenModel?.provider ?? undefined,
        model_name: chosenModel?.model ?? undefined,
        run_config: buildRunConfig(iocMode, iocCleaningOptions, includeThreatIntel, queryLanguagesOverride),
      })
    },
    onSuccess: (data) => {
      // A playbook job (identified by its run_ids array — unique to
      // THPlaybookJob) has no single run_id, since it fires several — just
      // refresh the runs list so they show up. A standalone-model run still
      // hands off its one run_id to the caller so it can jump straight to it.
      if ('run_ids' in data) {
        onPlaybookStarted?.()
      } else {
        const newRunId = data.run_id ?? data.id
        if (newRunId && onRunCreated) onRunCreated(newRunId)
      }
      qc.invalidateQueries({ queryKey: ['th-generation', pkgId] })
      qc.invalidateQueries({ queryKey: ['th-runs', pkgId] })
    },
  })

  const approveMut = useMutation({
    mutationFn: () => {
      const effectiveRunId = runId ?? (genRecord?.run_id ?? genRecord?.id)
      if (effectiveRunId) return api.threatHunting.approveRun(pkgId, effectiveRunId, approvalNotes)
      return api.threatHunting.approveGeneration(pkgId, approvalNotes)
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['th-generation', pkgId, runId] })
      qc.invalidateQueries({ queryKey: ['th-package', pkgId] })
      qc.invalidateQueries({ queryKey: ['th-packages'] })
      qc.invalidateQueries({ queryKey: ['th-runs', pkgId] })
      setShowApproveForm(false)
    },
  })

  const rejectMut = useMutation({
    mutationFn: () => {
      const effectiveRunId = runId ?? (genRecord?.run_id ?? genRecord?.id)
      if (effectiveRunId) return api.threatHunting.rejectRun(pkgId, effectiveRunId, approvalNotes)
      return api.threatHunting.rejectGeneration(pkgId, approvalNotes)
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['th-generation', pkgId, runId] })
      qc.invalidateQueries({ queryKey: ['th-package', pkgId] })
      qc.invalidateQueries({ queryKey: ['th-packages'] })
      qc.invalidateQueries({ queryKey: ['th-runs', pkgId] })
    },
  })

  if (isLoading) {
    return <div className="text-sm text-gray-500 text-center py-8">Loading...</div>
  }

  const status = genRecord?.generation_status

  // No generation yet — show start button
  if (!genRecord || status === 'error') {
    return (
      <div className="space-y-4">
        {status === 'error' && (
          <div className="rounded-lg border border-red-800/40 bg-red-900/10 p-3 text-sm text-red-400">
            <p className="font-medium mb-1">Generation failed</p>
            {genRecord?.generation_errors?.map((e: string, i: number) => (
              <p key={i}>• {e}</p>
            ))}
          </div>
        )}
        <div className="card text-center py-10 space-y-4">
          <Brain className="w-10 h-10 text-gray-600 mx-auto" />
          <div>
            <p className="text-sm font-medium text-gray-200">Generate Hunting Package</p>
            <p className="text-sm text-gray-500 mt-1">
              The LLM agent pipeline will analyze all evidence items and produce:
              threat context, hunting hypotheses, leads, TTP analysis, and SIEM query drafts.
            </p>
          </div>
          {isResearcher ? (
            <div className="space-y-3">
              <RunConfigForm
                variant="compact"
                effort={selectedEffort || effortData?.th_research_effort || 'high'}
                onEffortChange={setSelectedEffort}
                modelChoice={modelChoice}
                onModelChoiceChange={setModelChoice}
                modelOptions={modelOptions}
                playbookOptions={playbooks}
                iocMode={iocMode}
                onIocModeChange={setIocMode}
                iocCleaningOptions={iocCleaningOptions}
                onIocCleaningOptionsChange={setIocCleaningOptions}
                includeThreatIntel={includeThreatIntel}
                onIncludeThreatIntelChange={setIncludeThreatIntel}
                queryLanguages={effectiveQueryLanguages}
                onQueryLanguagesChange={(updater) =>
                  setQueryLanguagesOverride((prev) => updater(prev ?? effectiveQueryLanguages))
                }
              />
              <button
                className="btn-primary flex items-center gap-2 mx-auto"
                disabled={startMut.isPending}
                onClick={() => startMut.mutate()}
              >
                {startMut.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
                {startMut.isPending ? 'Starting...' : 'Generate'}
              </button>
            </div>
          ) : (
            <p className="text-sm text-gray-600">Requires threat-researcher or admin role.</p>
          )}
        </div>
      </div>
    )
  }

  // Running — show progress
  if (status === 'running') {
    const currentStep = genRecord?.current_step || 'initializing'
    return (
      <div className="card space-y-4">
        <div className="flex items-center gap-3">
          <Loader2 className="w-5 h-5 text-blue-400 animate-spin" />
          <div>
            <p className="text-sm font-medium text-gray-200">Generating hunt package...</p>
            <p className="text-sm text-gray-500">
              Current step: <span className="text-blue-400">{currentStep.replace(/_/g, ' ')}</span>
              {genRecord?.research_effort && (
                <span className="ml-2 text-gray-600">· effort: {genRecord.research_effort}</span>
              )}
              {genRecord?.model_name && (
                <span className="ml-2 text-gray-600">· {genRecord.provider_name} / {genRecord.model_name}</span>
              )}
            </p>
          </div>
        </div>
        {genRecord && <WorkflowVisualizer genRecord={genRecord} onShowIocs={onShowIocs} />}
      </div>
    )
  }

  // Awaiting approval — show full draft review
  if (status === 'awaiting_approval') {
    return (
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-amber-400" />
            <p className="text-sm font-semibold text-amber-400">Awaiting Operator Review</p>
          </div>
          {isResearcher && (
            <div className="flex gap-2">
              <button
                className="btn-ghost text-sm text-red-400 hover:text-red-300"
                disabled={rejectMut.isPending}
                onClick={() => rejectMut.mutate()}
              >
                {rejectMut.isPending ? 'Rejecting...' : 'Reject'}
              </button>
              <button
                className="btn-primary text-sm"
                disabled={iocVerdictsDirty}
                title={iocVerdictsDirty ? 'Apply the staged IOC verdict changes before approving' : undefined}
                onClick={() => setShowApproveForm(!showApproveForm)}
              >
                Approve
              </button>
            </div>
          )}
        </div>

        {iocVerdictsDirty && isResearcher && (
          <p className="text-sm text-amber-400">
            You have unapplied IOC verdict changes — apply them before approving this run for Execution.
          </p>
        )}

        {showApproveForm && isResearcher && (
          <div className="border border-green-800/40 bg-green-900/10 rounded-lg p-3 space-y-2">
            <p className="text-sm text-gray-400">Approval notes (optional):</p>
            <textarea
              className="input w-full h-16 resize-none text-sm"
              placeholder="Add notes about this approval..."
              value={approvalNotes}
              onChange={(e) => setApprovalNotes(e.target.value)}
            />
            <div className="flex gap-2 justify-end">
              <button className="btn-ghost text-sm" onClick={() => setShowApproveForm(false)}>Cancel</button>
              <button
                className="btn-primary text-sm"
                disabled={approveMut.isPending || iocVerdictsDirty}
                title={iocVerdictsDirty ? 'Apply the staged IOC verdict changes before approving' : undefined}
                onClick={() => approveMut.mutate()}
              >
                {approveMut.isPending ? 'Approving...' : 'Confirm Approval'}
              </button>
            </div>
          </div>
        )}

        <HuntingPackageDraft record={genRecord} pkgId={pkgId} runId={runId} onShowIocs={onShowIocs} />
      </div>
    )
  }

  // Approved / completed — read-only view
  return (
    <div className="space-y-6">
      <div className="flex items-center gap-2">
        <CheckCircle className="w-4 h-4 text-green-400" />
        <p className="text-sm font-semibold text-green-400">Hunt Package Approved</p>
      </div>
      <HuntingPackageDraft record={genRecord} pkgId={pkgId} runId={runId} onShowIocs={onShowIocs} readOnly />
    </div>
  )
}

// ── Draft review component ────────────────────────────────────────────────────

function HuntingPackageDraft({
  record,
  pkgId,
  runId,
  onShowIocs,
  readOnly = false,
}: {
  record: THGenerationRecord
  pkgId: string
  runId?: string
  /** Called when the user clicks "View IOCs" in the pipeline diagram. */
  onShowIocs?: () => void
  readOnly?: boolean
}) {
  const qc = useQueryClient()

  // issue-local-015: evidence-source chips on hypothesis cards are derived
  // client-side (no new backend field) — ioc_basis values are looked up in
  // this run's IOC list to find evidence_item_id, then in the evidence list
  // for a human label. Same query keys HuntDetail.tsx uses for its own IOC
  // tab / evidence tab, so this shares cache rather than re-fetching.
  const { data: iocsForChips = [] } = useQuery({
    queryKey: ['th-iocs', pkgId, runId],
    queryFn: () => (runId ? api.threatHunting.listIocs(pkgId, runId) : Promise.resolve([])),
    enabled: !!runId,
  })
  const { data: evidenceForChips = [] } = useQuery({
    queryKey: ['th-evidence', pkgId],
    queryFn: () => api.threatHunting.listEvidence(pkgId),
  })

  const evidenceLabelByIoc = useMemo(() => {
    const evidenceLabelById = new Map(evidenceForChips.map((e) => [e.id, e.label || e.item_type]))
    const map = new Map<string, string>()
    for (const ioc of iocsForChips) {
      const label = evidenceLabelById.get(ioc.evidence_item_id)
      if (label) map.set(ioc.ioc, label)
    }
    return map
  }, [iocsForChips, evidenceForChips])

  // issue-local-016: manual IOC verdict overrides are visible on hypothesis
  // evidence chips as a struck-through flag, not an auto-discard — the
  // analyst should still see an IOC WAS cited, just that it's no longer
  // considered valid. Hunting leads only reference IOCs transitively via
  // their hypothesis, so no separate lead-level flag is needed.
  const iocActionByValue = useMemo(() => {
    const map = new Map<string, string | undefined>()
    for (const ioc of iocsForChips) map.set(ioc.ioc, ioc.action)
    return map
  }, [iocsForChips])

  // issue-local-023: relationship chart collapsed by default — the analyst
  // opts in via the emphasized button below rather than it always taking
  // up space above the main summary.
  const [showChart, setShowChart] = useState(false)

  // issue-local-041 follow-up: the pipeline diagram (with its per-node hover
  // tooltips) previously only rendered while a run's status was 'running' —
  // once a run reached awaiting_approval/completed it disappeared entirely,
  // so the tooltips were unreachable during review, the state a run is in
  // almost all the time. Collapsed by default, same as the relationship
  // chart above, so the review screen doesn't default to two large diagrams.
  const [showPipeline, setShowPipeline] = useState(false)

  const discardMut = useMutation({
    mutationFn: ({ hypothesisId, discarded }: { hypothesisId: string; discarded: boolean }) =>
      api.threatHunting.discardHypothesis(pkgId, runId ?? '', hypothesisId, discarded),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['th-generation', pkgId, runId] })
    },
  })

  const discardLeadMut = useMutation({
    mutationFn: ({ leadId, discarded }: { leadId: string; discarded: boolean }) =>
      api.threatHunting.discardHuntingLead(pkgId, runId ?? '', leadId, discarded),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['th-generation', pkgId, runId] })
    },
  })

  return (
    <div className="space-y-5">
      {/* Threat Context (main summary) */}
      {record.threat_context && <ThreatContextCard ctx={record.threat_context} />}

      {/* issue-local-041 follow-up: pipeline diagram — collapsed by default,
          right below the Threat Context summary. Gives review of a
          finished/awaiting-approval run access to the same hover-tooltip
          flowchart shown live while the run was 'running'. */}
      <div className="space-y-3">
        <button
          onClick={() => setShowPipeline((v) => !v)}
          className="w-full flex items-center justify-center gap-2 rounded-lg border-2 border-brand-600/60 bg-brand-900/20 text-brand-300 hover:bg-brand-900/30 hover:border-brand-500 px-4 py-2.5 text-sm font-semibold transition-colors"
        >
          <Workflow className="w-4 h-4" />
          {showPipeline ? 'Hide Pipeline Diagram' : 'Show Pipeline Diagram'}
          {showPipeline ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
        </button>
        {showPipeline && <WorkflowVisualizer genRecord={record} onShowIocs={onShowIocs} />}
      </div>

      {/* issue-local-023: relationship overview chart — moved below the main
          summary, collapsed by default behind an emphasized toggle rather
          than always taking up space. Still a navigational aid above the
          flat lists below it, not a replacement for them (those still carry
          the full text + approve/reject workflow). */}
      <div className="space-y-3">
        <button
          onClick={() => setShowChart((v) => !v)}
          className="w-full flex items-center justify-center gap-2 rounded-lg border-2 border-brand-600/60 bg-brand-900/20 text-brand-300 hover:bg-brand-900/30 hover:border-brand-500 px-4 py-2.5 text-sm font-semibold transition-colors"
        >
          <Network className="w-4 h-4" />
          {showChart ? 'Hide Hunting Artifacts Relationship' : 'Show Hunting Artifacts Relationship'}
          {showChart ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
        </button>
        {showChart && (
          <Suspense
            fallback={
              <div className="card flex items-center gap-2 text-sm text-gray-500">
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
                Loading relationship chart…
              </div>
            }
          >
            <HypothesisLeadIocChart record={record} iocs={iocsForChips} pkgId={pkgId} runId={runId} />
          </Suspense>
        )}
      </div>

      {/* issue-local-022 (item 6): the Deep Retrohunt Lead / Sanitized IOCs
          table used to render here — it now lives in HuntDetail.tsx's IOCs
          tab (the enriched All/Sanitized/Removed table replaced the old flat
          list there), so it isn't duplicated across two tabs. */}

      {/* Hypotheses */}
      {record.hypotheses && record.hypotheses.length > 0 && (
        <CollapsibleSection title={`Hypotheses (${record.hypotheses.length})`} icon={Brain} defaultOpen>
          <div className="space-y-3">
            {record.hypotheses.map((h: THHypothesis) => {
              // issue-local-015: evidence sources this hypothesis draws on,
              // derived from ioc_basis → IOC → evidence label (deduplicated).
              const evidenceLabels = Array.from(
                new Set((h.ioc_basis ?? []).map((ioc) => evidenceLabelByIoc.get(ioc)).filter(Boolean)),
              ) as string[]
              return (
                <div
                  key={h.id}
                  className={clsx(
                    'border rounded-lg p-3 space-y-1.5 transition-opacity',
                    h.discarded ? 'border-gray-800 opacity-50' : 'border-gray-700',
                  )}
                >
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-[11px] text-brand-400 font-mono">{h.id}</span>
                    <span className={clsx('text-[11px] px-1.5 py-0.5 rounded', h.relevance === 'high' ? 'bg-red-900/30 text-red-400' : h.relevance === 'medium' ? 'bg-amber-900/30 text-amber-400' : 'bg-gray-800 text-gray-500')}>
                      {h.relevance}
                    </span>
                    {/* issue-local-015: confidence score */}
                    {h.confidence != null && (
                      <span
                        className="text-[11px] px-1.5 py-0.5 rounded bg-gray-800 text-gray-400"
                        title="LLM-assessed confidence this hypothesis is correct"
                      >
                        {h.confidence}% confidence
                      </span>
                    )}
                    {h.discarded && (
                      <span className="text-[11px] px-1.5 py-0.5 rounded bg-gray-800 text-gray-500">
                        Discarded
                      </span>
                    )}
                  </div>
                  <p className={clsx('text-base font-semibold', h.discarded ? 'text-gray-400 line-through' : 'text-gray-200')}>
                    {h.title}
                  </p>
                  {h.description && <ReportMarkdown>{h.description}</ReportMarkdown>}
                  {h.justification && <p className="text-sm text-gray-500 italic">{h.justification}</p>}
                  {/* issue-006-E: ioc_basis — issue-local-041: labeled "Related IOCs" subcard */}
                  {h.ioc_basis && h.ioc_basis.length > 0 && (
                    <div className="mt-1.5 pl-2 border-l border-gray-700 space-y-1">
                      <p className="text-sm font-semibold text-gray-400 uppercase tracking-wide">Related IOCs</p>
                      <div className="flex flex-wrap gap-1">
                        {h.ioc_basis.map((ioc) => {
                          const removed = iocActionByValue.get(ioc) === 'remove'
                          return (
                            <span
                              key={ioc}
                              className={clsx(
                                'text-sm font-mono border rounded px-1',
                                removed
                                  ? 'bg-red-950/20 text-red-500/70 border-red-900/40 line-through'
                                  : 'bg-gray-800 text-gray-400 border-gray-700',
                              )}
                              title={removed ? 'This IOC was manually removed and is no longer part of the sanitized set' : undefined}
                            >
                              {ioc}
                            </span>
                          )
                        })}
                      </div>
                    </div>
                  )}
                  {/* issue-local-015: evidence-source cards — issue-local-041: labeled "Source" subcard */}
                  {evidenceLabels.length > 0 && (
                    <div className="mt-1.5 pl-2 border-l border-blue-800/40 space-y-1">
                      <p className="text-sm font-semibold text-gray-400 uppercase tracking-wide">Source</p>
                      <div className="flex flex-wrap gap-1">
                        {evidenceLabels.map((label) => (
                          <span key={label} className="text-sm bg-blue-900/20 text-blue-400 border border-blue-800/30 rounded px-1.5 py-0.5">
                            {label}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                  {/* issue-006-E: suggested_actions — issue-local-042 (item 5): a real
                      bulleted list; (item 22.3): each action is code/a query, so it gets
                      its own indented card under its bullet, not bare font-mono text. */}
                  {h.suggested_actions && h.suggested_actions.length > 0 && (
                    <div className="mt-1.5 pl-2 border-l border-brand-800/40 space-y-1">
                      <p className="text-sm font-semibold text-gray-400 uppercase tracking-wide">Suggested Actions</p>
                      <ul className="list-disc list-outside pl-4 space-y-2">
                        {h.suggested_actions.map((action, i) => (
                          <li key={i} className="text-sm text-gray-400 leading-relaxed marker:text-gray-600">
                            <pre className="mt-1 ml-2 bg-gray-950 border border-gray-800 rounded p-2 text-sm text-green-400 font-mono overflow-x-auto whitespace-pre-wrap">
                              {asDisplayText(action, ['action', 'text', 'description'])}
                            </pre>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                  {!readOnly && runId && (
                    <DiscardButtonCard
                      discarded={!!h.discarded}
                      disabled={discardMut.isPending}
                      onClick={() =>
                        discardMut.mutate({ hypothesisId: h.id, discarded: !h.discarded })
                      }
                    />
                  )}
                </div>
              )
            })}
          </div>
        </CollapsibleSection>
      )}

      {/* Hunting Leads */}
      {record.hunting_leads && record.hunting_leads.length > 0 && (
        <CollapsibleSection title={`Hunting Leads (${record.hunting_leads.length})`} icon={Target}>
          <div className="space-y-3">
            {record.hunting_leads.map((lead: THHuntingLead) => {
              // issue-local-015: show which hypothesis this lead was derived
              // from — the data (hypothesis_id) already existed, just wasn't
              // surfaced anywhere in the UI.
              const sourceHypothesis = record.hypotheses?.find((h) => h.id === lead.hypothesis_id)
              return (
              <div
                key={lead.id}
                className={clsx(
                  'border rounded-lg p-3 space-y-2 transition-opacity',
                  lead.discarded ? 'border-gray-800 opacity-50' : 'border-gray-700',
                )}
              >
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-[11px] text-brand-400 font-mono">{lead.id}</span>
                  <span className={clsx('text-[11px] px-1.5 py-0.5 rounded', lead.priority === 'high' ? 'bg-red-900/30 text-red-400' : lead.priority === 'medium' ? 'bg-amber-900/30 text-amber-400' : 'bg-gray-800 text-gray-500')}>
                    {lead.priority}
                  </span>
                  {lead.hypothesis_id && (
                    <span
                      className="text-[11px] px-1.5 py-0.5 rounded bg-brand-900/20 text-brand-400 border border-brand-800/30"
                      title={sourceHypothesis?.title}
                    >
                      Derived from: {lead.hypothesis_id}
                      {sourceHypothesis?.discarded && ' (discarded)'}
                    </span>
                  )}
                  {lead.discarded && (
                    <span className="text-[11px] px-1.5 py-0.5 rounded bg-gray-800 text-gray-500">
                      Discarded
                    </span>
                  )}
                </div>
                <p className={clsx('text-base font-semibold', lead.discarded ? 'text-gray-400 line-through' : 'text-gray-200')}>
                  {lead.title}
                </p>
                <p className="text-sm text-gray-400">{lead.description}</p>
                {lead.tasks && lead.tasks.length > 0 && (
                  <div className="pl-3 border-l border-gray-700 space-y-2 mt-2">
                    {lead.tasks.map((task: THHuntTask) => (
                      <div key={task.id}>
                        <p className="text-sm text-gray-300 font-medium">{task.id}: {task.title}</p>
                        <p className="text-sm text-gray-500">{task.description}</p>
                        {/* issue-local-042 (items 2, 5): a code card, not
                            plain mono text, so it's clear this is a query
                            artifact — indented one step further than the
                            task itself. */}
                        {task.query_hint && (
                          <pre className="ml-3 mt-1 bg-gray-950 border border-gray-800 rounded p-2 text-sm text-green-400 font-mono overflow-x-auto whitespace-pre-wrap">
                            {task.query_hint}
                          </pre>
                        )}
                      </div>
                    ))}
                  </div>
                )}
                {!readOnly && runId && (
                  <DiscardButtonCard
                    discarded={!!lead.discarded}
                    disabled={discardLeadMut.isPending}
                    onClick={() =>
                      discardLeadMut.mutate({ leadId: lead.id, discarded: !lead.discarded })
                    }
                  />
                )}
              </div>
              )
            })}
          </div>
        </CollapsibleSection>
      )}

      {/* TTP Analysis */}
      {record.ttp_analysis && (
        <CollapsibleSection title="Behavioral TTP Analysis" icon={Crosshair}>
          <div className="space-y-3">
            {record.ttp_analysis.summary && (
              <p className="text-sm text-gray-300">{record.ttp_analysis.summary}</p>
            )}
            {record.ttp_analysis.techniques?.map((t) => (
              <div key={t.technique_id} className="border border-gray-700 rounded p-2.5 space-y-0.5">
                <div className="flex items-center gap-2">
                  <span className="text-[11px] font-mono text-brand-400">{t.technique_id}</span>
                  <span className="text-[11px] text-gray-500">{t.tactic}</span>
                </div>
                <p className="text-base font-semibold text-gray-200">{t.technique_name}</p>
                <p className="text-sm text-gray-500">{t.description}</p>
              </div>
            ))}
            {record.ttp_analysis.detection_opportunities?.length > 0 && (
              <div>
                <p className="text-sm font-semibold text-gray-400 uppercase tracking-wide mb-1">Detection Opportunities:</p>
                <ul className="space-y-0.5">
                  {record.ttp_analysis.detection_opportunities.map((opp, i) => (
                    <li key={i} className="text-sm text-gray-500 flex gap-1.5">
                      <span className="text-brand-600">•</span>
                      {asDisplayText(opp, ['description', 'text', 'detail'])}
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        </CollapsibleSection>
      )}

      {/* Query Drafts */}
      {record.query_drafts && record.query_drafts.length > 0 && (
        <CollapsibleSection title={`Query Drafts (${record.query_drafts.length})`} icon={Code2}>
          <div className="space-y-3">
            {record.query_drafts.map((q: THQueryDraft) => (
              <div key={q.id} className="border border-gray-700 rounded-lg p-3 space-y-2">
                <div className="flex items-center gap-2">
                  <span className="text-[11px] px-1.5 py-0.5 rounded bg-gray-800 text-gray-400 font-mono uppercase">{q.language}</span>
                  <p className="text-base font-semibold text-gray-200">{q.title}</p>
                </div>
                {q.description && <p className="text-sm text-gray-500">{q.description}</p>}
                <pre className="bg-gray-950 border border-gray-800 rounded p-2 text-sm text-green-400 font-mono overflow-x-auto whitespace-pre-wrap">{asQueryText(q.query)}</pre>
              </div>
            ))}
          </div>
        </CollapsibleSection>
      )}

      {/* Errors */}
      {record.generation_errors && record.generation_errors.length > 0 && (
        <div className="rounded-lg border border-amber-800/40 bg-amber-900/10 p-3 space-y-1">
          <p className="text-sm font-semibold text-amber-400 uppercase tracking-wide">Generation warnings:</p>
          {record.generation_errors.map((e: string, i: number) => (
            <p key={i} className="text-sm text-amber-500">• {e}</p>
          ))}
        </div>
      )}
    </div>
  )
}

function ThreatContextCard({ ctx }: { ctx: Record<string, unknown> }) {
  if (ctx.parse_error) {
    return (
      <div className="card space-y-2">
        <p className="text-base font-semibold text-gray-200">Threat Context</p>
        <p className="text-sm text-gray-500 whitespace-pre-wrap">{String(ctx.raw_response || '')}</p>
      </div>
    )
  }
  // Normalise unknown fields to strings for safe JSX rendering
  const summary      = typeof ctx.summary      === 'string' ? ctx.summary      : ''
  const threatActor  = typeof ctx.threat_actor  === 'string' ? ctx.threat_actor  : ''
  const campaignName = typeof ctx.campaign_name === 'string' ? ctx.campaign_name : ''
  const confidence   = typeof ctx.confidence   === 'string' ? ctx.confidence   : ''
  return (
    <div className="card space-y-3">
      <p className="text-base font-semibold text-gray-200">Threat Context</p>
      {summary      && <ReportMarkdown>{summary}</ReportMarkdown>}
      {/* issue-local-042 (item 19): Actor/Campaign/Confidence as their own
          stat cards — matches the bg-gray-800/50 card idiom already used
          for Evidence & Coverage's stats, instead of plain inline text. */}
      {(threatActor || campaignName || confidence) && (
        <div className="grid grid-cols-3 gap-2">
          {threatActor && (
            <div className="bg-gray-800/50 rounded-lg p-3">
              <p className="text-sm text-gray-500">Actor</p>
              <p className="text-base font-semibold text-gray-100 truncate" title={threatActor}>{threatActor}</p>
            </div>
          )}
          {campaignName && (
            <div className="bg-gray-800/50 rounded-lg p-3">
              <p className="text-sm text-gray-500">Campaign</p>
              <p className="text-base font-semibold text-gray-100 truncate" title={campaignName}>{campaignName}</p>
            </div>
          )}
          {confidence && (
            <div className="bg-gray-800/50 rounded-lg p-3">
              <p className="text-sm text-gray-500">Confidence</p>
              <p className={clsx('text-base font-semibold capitalize', confidence === 'high' ? 'text-green-400' : confidence === 'medium' ? 'text-amber-400' : 'text-gray-400')}>
                {confidence}
              </p>
            </div>
          )}
        </div>
      )}
      {Array.isArray(ctx.key_observations) && ctx.key_observations.length > 0 && (
        <div>
          <p className="text-sm font-semibold text-gray-400 uppercase tracking-wide mb-1">Key observations:</p>
          <ul className="space-y-0.5">
            {(ctx.key_observations as unknown[]).map((obs, i) => (
              <li key={i} className="text-sm text-gray-400 flex gap-1.5">
                <span className="text-brand-600">•</span>
                {asDisplayText(obs, ['observation', 'text', 'description', 'summary'])}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}

function CollapsibleSection({
  title,
  icon: Icon,
  defaultOpen = false,
  children,
}: {
  title: string
  icon: React.ElementType
  defaultOpen?: boolean
  children: React.ReactNode
}) {
  const [open, setOpen] = useState(defaultOpen)
  return (
    <div className="border border-gray-700 rounded-lg overflow-hidden">
      <button
        className="w-full flex items-center gap-2 px-4 py-3 bg-gray-800/40 hover:bg-gray-800/70 transition-colors"
        onClick={() => setOpen(!open)}
      >
        <Icon className="w-4 h-4 text-brand-400 shrink-0" />
        <span className="text-base font-semibold text-gray-200 flex-1 text-left">{title}</span>
        {open ? <ChevronDown className="w-4 h-4 text-gray-500" /> : <ChevronRight className="w-4 h-4 text-gray-500" />}
      </button>
      {open && <div className="p-4">{children}</div>}
    </div>
  )
}
