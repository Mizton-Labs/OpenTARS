import { useState, useEffect, useMemo, useRef } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { ArrowLeft, Plus, Trash2, RefreshCw, ChevronDown, X, MessageSquare, Send, GitCompare, Archive, ArchiveRestore, Copy, Pencil } from 'lucide-react'
import { clsx } from 'clsx'
import { api, type THExtractedIOC, type THRunSummary, type THRunComment, type LLMProviderSummary, type THGenerationRecord, type THPlaybookJob, type THQueryLanguages } from '../../api/client'
import { useAuth } from '../../auth/useAuth'
import AddEvidenceModal from './AddEvidenceModal'
import AnalysisTab from './AnalysisTab'
import EvidenceTab from './EvidenceTab'
import ExecutionPanel from './ExecutionPanel'
import PipelineStepper from './PipelineStepper'
import ReportPanel from './ReportPanel'
import ThreatIntelTab from './ThreatIntelTab'
import ComparisonAssessmentTab from './ComparisonAssessmentTab'
import ArrowTabs from './ArrowTabs'
import ConfirmDialog from '../../components/ConfirmDialog'
import { runStatusClass, runLabel, HUNT_ID_BADGE } from './runStatusUtils'
import IocVerdictToggle from './IocVerdictToggle'
import IocApplyBar from './IocApplyBar'
import RetrohuntPanel from './RetrohuntPanel'
import { useIocVerdictStaging } from './useIocVerdictStaging'
import RunsStatusTable, { subTabOf, type RunSubTab } from './RunsStatusTable'
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

type DetailTab = 'evidence' | 'iocs' | 'analysis' | 'execution' | 'threat-intel' | 'comparison' | 'report' | 'comments'

// issue-local-022 (item 5): run statuses at or past approval — the point
// where Execution/Threat-Intel/Report tabs have something to show.
const POST_APPROVAL_RUN_STATUSES = new Set(['approved', 'executing', 'reporting', 'completed'])

export default function HuntDetail({
  pkgId,
  onBack,
  initialRunId,
  initialTab,
}: {
  pkgId: string
  onBack: () => void
  /** issue-local-018: deep-link to a specific run (e.g. from the hunt-package
   *  list's Table density mode). Falls back to the newest run when absent
   *  or when it doesn't match any run in this package (stale deep-link). */
  initialRunId?: string
  /** issue-local-040: set only right after the evidence-upload wizard
   *  closes (via `?tab=analysis`) — every other page load keeps the general
   *  'evidence' default. */
  initialTab?: DetailTab
}) {
  const { isResearcher, isAdmin } = useAuth()
  const qc = useQueryClient()
  const [showAddItem, setShowAddItem] = useState(false)
  const [activeTab, setActiveTab] = useState<DetailTab>(initialTab ?? 'evidence')
  const [activeRunId, setActiveRunId] = useState<string | undefined>(undefined)
  // issue-local-041: which of the Runs/Playbook Runs/Consolidated Runs
  // sub-tabs is selected — lifted up from RunsStatusTable so switching it
  // can also drive activeRunId (and, when the sub-tab is empty, show a real
  // empty state below instead of leaking whichever run was active before).
  const [runSubTab, setRunSubTab] = useState<RunSubTab>('runs')
  // issue-local-041: "center the view from where the row with phases
  // starts" when a new analysis run begins — this page renders a tall
  // header + run selector + all-runs table above the tab panels, so a
  // newly-started run's phase progress (PipelineStepper, just below the run
  // selector) can be scrolled off-screen. rAF (not a plain call) defers the
  // scroll until after the runs list has re-rendered with the new run — the
  // run-selector block (and its ref) only mounts once runs.length > 0.
  const phasesRowRef = useRef<HTMLDivElement | null>(null)
  function scrollToPhasesRow() {
    requestAnimationFrame(() => {
      phasesRowRef.current?.scrollIntoView({ behavior: 'smooth', block: 'center' })
    })
  }
  const [newComment, setNewComment] = useState('')

  // issue-local-034: permanent-package-delete confirmation (admin-only)
  const [showDeletePackageConfirm, setShowDeletePackageConfirm] = useState(false)

  // issue-006-G: re-run dialog state
  const [showRerunDialog, setShowRerunDialog] = useState(false)

  // issue-local-038: clone dialog state — mirrors the list page's own
  // CloneTarget dialog (ThreatHunting.tsx), just scoped to this one package.
  const [cloneName, setCloneName] = useState<string | null>(null)
  // issue-local-042: rename dialog state — mirrors cloneName above.
  const [renameName, setRenameName] = useState<string | null>(null)
  const [rerunModelChoice, setRerunModelChoice] = useState<string>('')
  // issue-local-041: '' (not a hardcoded level) so the effective effort
  // below falls through to the configured default until the user actually
  // picks one — mirrors AnalysisTab.tsx's first-run form, which this dialog
  // previously didn't (it hardcoded 'medium', silently overriding a
  // configured 'high' default on every re-run).
  const [rerunEffort, setRerunEffort] = useState<string>('')
  // issue-local-022 (item 3): shared defaults with AnalysisTab.tsx's
  // first-run form via RunConfigForm.tsx, instead of an independently-
  // drifted copy.
  const [iocMode, setIocMode] = useState<'tagging_only' | 'active_cleaning'>(DEFAULT_IOC_MODE)
  const [iocCleaningOptions, setIocCleaningOptions] = useState(DEFAULT_IOC_CLEANING_OPTIONS)
  const [includeThreatIntel, setIncludeThreatIntel] = useState(DEFAULT_INCLUDE_THREAT_INTEL)
  // issue-local-041: null until the user touches a toggle — see
  // buildRunConfig's docstring.
  const [queryLanguagesOverride, setQueryLanguagesOverride] = useState<THQueryLanguages | null>(null)

  const { data: pkg } = useQuery({
    queryKey: ['th-package', pkgId],
    queryFn: () => api.threatHunting.getPackage(pkgId),
  })

  const { data: evidence = [] } = useQuery({
    queryKey: ['th-evidence', pkgId],
    queryFn: () => api.threatHunting.listEvidence(pkgId),
  })

  // issue-local-021: the IOCs tab is now always visible (not gated on
  // iocs.length>0), so this query must load as soon as a run is selected —
  // not only once the IOCs tab is actually visited.
  const { data: iocs = [] } = useQuery({
    queryKey: ['th-iocs', pkgId, activeRunId],
    queryFn: () => api.threatHunting.listIocs(pkgId, activeRunId),
    enabled: !!activeRunId,
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

  // issue-local-018: per-run analyst comments
  const { data: comments = [] } = useQuery({
    queryKey: ['th-comments', pkgId, activeRunId],
    queryFn: () => api.threatHunting.listRunComments(pkgId, activeRunId!),
    enabled: activeTab === 'comments' && !!activeRunId,
  })

  // issue-local-041: configured default effort, same query key AnalysisTab.tsx
  // uses — react-query dedupes it, so this doesn't add an extra fetch when
  // both are mounted.
  const { data: rerunEffortData } = useQuery({
    queryKey: ['th-research-effort'],
    queryFn: () => api.getThResearchEffort(),
    staleTime: 30_000,
    enabled: showRerunDialog,
  })
  const effectiveRerunEffort = rerunEffort || rerunEffortData?.th_research_effort || 'high'

  // issue-local-041: configured default query languages, same query key
  // AnalysisTab.tsx uses.
  const { data: rerunQueryLanguagesData } = useQuery({
    queryKey: ['th-query-languages'],
    queryFn: () => api.getThQueryLanguages(),
    staleTime: 30_000,
    enabled: showRerunDialog,
  })
  const effectiveQueryLanguages =
    queryLanguagesOverride ?? rerunQueryLanguagesData?.th_query_languages ?? DEFAULT_QUERY_LANGUAGES

  // issue-006-G: LLM providers for re-run dialog model selector
  const { data: rerunProviders = [] } = useQuery({
    queryKey: ['llm-providers'],
    queryFn: () => api.llm.listProviders(),
    staleTime: 60_000,
    enabled: showRerunDialog,
  })

  const rerunModelOptions = useMemo(
    () => modelOptionsFromProviders(rerunProviders as LLMProviderSummary[]),
    [rerunProviders],
  )

  // issue-local-040: Hunt Playbooks offered alongside standalone models.
  const { data: rerunPlaybooks = [] } = useQuery({
    queryKey: ['hunt-playbooks'],
    queryFn: () => api.threatHunting.playbooks.list(),
    staleTime: 60_000,
    enabled: showRerunDialog,
  })

  const rerunChosenPlaybookId = playbookIdFromChoice(rerunModelChoice)
  const rerunChosenModel =
    rerunModelChoice !== '' && !rerunChosenPlaybookId
      ? (rerunModelOptions[Number(rerunModelChoice)] ?? null)
      : null

  // Auto-select the requested run (issue-local-018 deep-link) or else the
  // latest run when runs load/change. Falls back to newest if initialRunId
  // doesn't match any run in this package (e.g. a stale deep-link).
  useEffect(() => {
    if (runs.length > 0 && !activeRunId) {
      const requested = initialRunId && runs.some((r) => r.id === initialRunId) ? initialRunId : undefined
      setActiveRunId(requested ?? runs[0].id)
    }
  }, [runs, activeRunId, initialRunId])

  // issue-local-016: manual IOC verdict overrides, staged until "Apply
  // changes" — lifted here (parent of both the IOCs tab and the Analysis
  // tab's embedded RetrohuntPanel) so a change staged in one tab is still
  // pending when switching to the other. Scoped to the active run only.
  const iocStaging = useIocVerdictStaging(pkgId, activeRunId)

  // issue-local-018: per-run analyst comments
  const createCommentMut = useMutation({
    mutationFn: (body: string) => api.threatHunting.createRunComment(pkgId, activeRunId!, body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['th-comments', pkgId, activeRunId] })
      setNewComment('')
    },
  })
  const deleteCommentMut = useMutation({
    mutationFn: (commentId: string) => api.threatHunting.deleteRunComment(pkgId, activeRunId!, commentId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['th-comments', pkgId, activeRunId] })
    },
  })

  // issue-006-G: Re-run with model+effort from dialog
  const rerunMut = useMutation<THGenerationRecord | THPlaybookJob, Error, void>({
    mutationFn: () => {
      // issue-local-040: a Hunt Playbook selection fires the whole
      // playbook (N runs) instead of a single standalone-model re-run.
      if (rerunChosenPlaybookId) {
        return api.threatHunting.playbooks.run(pkgId, rerunChosenPlaybookId)
      }
      return api.threatHunting.startGeneration(pkgId, {
        research_effort: effectiveRerunEffort,
        provider_name: rerunChosenModel?.provider ?? undefined,
        model_name: rerunChosenModel?.model ?? undefined,
        run_config: buildRunConfig(iocMode, iocCleaningOptions, includeThreatIntel, queryLanguagesOverride),
      })
    },
    onSuccess: (data) => {
      qc.invalidateQueries({ queryKey: ['th-runs', pkgId] })
      qc.invalidateQueries({ queryKey: ['th-package', pkgId] })
      // A playbook job fires several runs, so there's no single one to jump
      // to — only a standalone-model run hands off its run_id.
      // issue-local-042 (item 21): switch to the matching sub-tab either
      // way, so a re-run/playbook-fire's own view is what's shown next,
      // regardless of which sub-tab happened to be selected before.
      if ('run_ids' in data) {
        handleRunSubTabChange('playbook')
      } else {
        setRunSubTab('runs')
        const newRunId = data.run_id ?? data.id
        if (newRunId) setActiveRunId(newRunId)
      }
      setActiveTab('analysis')
      setShowRerunDialog(false)
      scrollToPhasesRow()
    },
  })

  // issue-local-042 (item 8): cancel moved to a per-run action in
  // RunsStatusTable.tsx — no longer a single header button tied to whichever
  // run the run-selector happened to have active.

  // issue-local-034: Archive/Unarchive the whole package (reversible,
  // researcher+ — same as every other TH mutation) — reuses the existing
  // archive/update routes, no dedicated backend endpoint needed.
  const archivePackageMut = useMutation({
    mutationFn: async () => {
      if (pkg?.status === 'archived') {
        await api.threatHunting.updatePackage(pkgId, { status: 'draft' })
      } else {
        await api.threatHunting.archivePackage(pkgId)
      }
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['th-package', pkgId] })
      qc.invalidateQueries({ queryKey: ['th-packages'] })
    },
  })

  // issue-local-034: permanent, cascading delete — admin-only, irreversible.
  const deletePackageMut = useMutation({
    mutationFn: () => api.threatHunting.hardDeletePackage(pkgId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['th-packages'] })
      setShowDeletePackageConfirm(false)
      onBack()
    },
  })

  // issue-local-038: clone this package — same backend route/behavior as the
  // list page's clone dialog (evidence copied, runs/reports/IOCs reset to a
  // fresh draft). Returns to the list afterward, same as delete above, where
  // the new "Copy of ..." package is visible.
  const cloneMut = useMutation({
    mutationFn: (name: string) => api.threatHunting.clonePackage(pkgId, name),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['th-packages'] })
      setCloneName(null)
      onBack()
    },
  })

  // issue-local-042: rename this package — reuses the existing PUT
  // /packages/{id} route (already supports a name-only partial update), no
  // new backend endpoint needed.
  const renameMut = useMutation({
    mutationFn: (name: string) => api.threatHunting.updatePackage(pkgId, { name }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['th-package', pkgId] })
      qc.invalidateQueries({ queryKey: ['th-packages'] })
      setRenameName(null)
    },
  })

  const noisyCount = (iocs as THExtractedIOC[]).filter((i) => i.flagged_noisy).length
  const cleanCount = (iocs as THExtractedIOC[]).length - noisyCount
  const removedCount = (iocs as THExtractedIOC[]).filter((i) => i.action === 'remove').length

  // issue-local-018 follow-up: hoisted so the header indicator card and the
  // run-selector status pill share one lookup instead of each re-scanning
  // `runs` inline.
  const activeRun = runs.find((r) => r.id === activeRunId)

  // issue-local-041: runs belonging to the currently-selected sub-tab, and a
  // handler that both updates the sub-tab and jumps activeRunId to that
  // sub-tab's newest run (list_generation_runs already returns runs newest
  // first) — or leaves activeRunId untouched when the sub-tab is empty, so
  // the "empty" branch below renders instead of AnalysisTab/ReportPanel
  // silently falling back to the package's latest run when runId is unset.
  const runsInSubTab = useMemo(() => runs.filter((r) => subTabOf(r) === runSubTab), [runs, runSubTab])
  function handleRunSubTabChange(tab: RunSubTab) {
    setRunSubTab(tab)
    const match = runs.filter((r) => subTabOf(r) === tab)
    if (match.length > 0) setActiveRunId(match[0].id)
  }

  // issue-local-022 (item 5): gated on the ACTIVE RUN's own generation_status,
  // not the package's — pkg.status only ever moves forward and is never reset
  // when a NEW run starts on an already-completed package, so it used to stay
  // stuck on 'approved'/'completed' from the PRIOR run for the entire
  // duration of the new run's pipeline, leaving Execution/Threat-Intel/Report
  // tabs wrongly enabled while the active run was still mid-analysis.
  const isFinished = !!activeRun && POST_APPROVAL_RUN_STATUSES.has(activeRun.generation_status)
  // issue-local-022 (item 3): a Threat Intel analysis in flight for the
  // active run — Re-run and report generation are gated on this so they
  // don't race the analysis that's still writing to this same run.
  const threatIntelRunning = activeRun?.threat_intel_status === 'running'
  // issue-local-014: re-run is available regardless of any run's status —
  // including while a run is still active — so parallel runs (e.g. a
  // different model/effort) can be started at any time. The run selector
  // above already lists and marks every concurrently active run.
  const canRerun = isResearcher && (pkg?.evidence_count ?? 0) > 0

  return (
    <div className="p-6 space-y-6">
      {/* Header — issue-local-042 (item 14): back button + HuntID/RunID
          badges on the left, every action button top-right on the same row;
          the title gets its own row below that (with the Archived badge,
          since it qualifies the title itself), and the subtitle/description
          its own row below the title. */}
      <div className="flex items-center gap-3">
        <button className="btn-ghost p-1.5" onClick={onBack}>
          <ArrowLeft className="w-4 h-4" />
        </button>
        <div className="flex-1 min-w-0 flex items-center gap-2 flex-wrap">
          {pkg?.hunt_id_display && (
            <span className={clsx(HUNT_ID_BADGE, 'text-sm')}>{pkg.hunt_id_display}</span>
          )}
          {activeRun?.run_id_display && (
            <span className={clsx(HUNT_ID_BADGE, 'text-sm')}>{activeRun.run_id_display}</span>
          )}
        </div>
        <div className="flex items-center gap-2 flex-wrap shrink-0">
        {/* issue-local-042: rename this package */}
        {isResearcher && (
          <button
            className="btn-secondary flex items-center gap-2 text-sm"
            onClick={() => setRenameName(pkg?.name ?? '')}
            title="Rename this hunt package"
          >
            <Pencil className="w-4 h-4" />
            Rename
          </button>
        )}
        {/* Re-run button — always available once evidence exists, even mid-run (issue-local-014) */}
        {canRerun && (
          <button
            className="btn-secondary flex items-center gap-2 text-sm"
            disabled={rerunMut.isPending || threatIntelRunning}
            onClick={() => setShowRerunDialog(true)}
            title={
              threatIntelRunning
                ? 'Threat Intel analysis is still running for this run'
                : 'Re-run this hunt package — choose model and effort level'
            }
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
        {/* issue-local-038: clone this package */}
        {isResearcher && (
          <button
            className="btn-secondary flex items-center gap-2 text-sm"
            onClick={() => setCloneName(`Copy of ${pkg?.name ?? ''}`)}
            title="Clone this hunt package"
          >
            <Copy className="w-4 h-4" />
            Clone
          </button>
        )}
        {/* issue-local-034: Archive/Unarchive the whole package — reversible, researcher+ */}
        {isResearcher && (
          <button
            className="btn-secondary flex items-center gap-2 text-sm"
            disabled={archivePackageMut.isPending}
            onClick={() => archivePackageMut.mutate()}
            title={pkg?.status === 'archived' ? 'Unarchive this hunt package' : 'Archive this hunt package'}
          >
            {pkg?.status === 'archived' ? (
              <ArchiveRestore className="w-4 h-4" />
            ) : (
              <Archive className="w-4 h-4" />
            )}
            {pkg?.status === 'archived' ? 'Unarchive' : 'Archive'}
          </button>
        )}
        {/* issue-local-034: permanent, cascading delete — admin-only */}
        {isAdmin && (
          <button
            className="btn-secondary flex items-center gap-2 text-sm text-red-400 hover:text-red-300"
            onClick={() => setShowDeletePackageConfirm(true)}
            title="Permanently delete this hunt package and everything in it"
          >
            <Trash2 className="w-4 h-4" />
            Delete
          </button>
        )}
        </div>
      </div>

      {/* issue-local-042 (item 14): Title, its own row below the HuntID
          badges — the Archived badge stays with it since it qualifies the
          title itself. */}
      <h1 className="text-lg font-semibold text-gray-100 flex items-center gap-2">
        {pkg?.name ?? '…'}
        {pkg?.status === 'archived' && (
          <span className="text-[11px] px-1.5 py-0.5 rounded bg-gray-800 text-gray-400 border border-gray-700">
            Archived
          </span>
        )}
      </h1>
      {/* Subtitle/description, its own row below the title. */}
      {pkg?.description && <p className="text-sm text-gray-500">{pkg.description}</p>}

      {/* Run selector — shown when there are multiple runs */}
      {runs.length > 0 && (
        <div ref={phasesRowRef} className="space-y-2 px-3 py-2 bg-gray-800/40 rounded-lg border border-gray-700/50">
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
              runStatusClass(activeRun?.generation_status),
            )}>
              {activeRun?.generation_status ?? '—'}
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
          <div className="flex items-center justify-between">
            <p className="text-[10px] text-gray-500 uppercase tracking-wider font-semibold">
              All runs
            </p>
            {/* issue-local-021: Comparison Assessment trigger relocated here
                (was a tab-bar button) — signals this is a package-level view
                across all runs, not a per-run one. The actual "Assess &
                Compare" action (run picker + model dropdown) now lives
                inside ComparisonAssessmentTab itself, mirroring
                ThreatIntelTab's self-contained Analyze button.
                issue-local-022 (item 4): restyled as its own bordered
                button-card in purple/indigo — a color distinct from the
                brand-blue used by the arrow tab bar's active state and
                Threat Intel's highlighted button, so it visually reads as a
                different KIND of action (package-level across all runs, not
                a workflow phase). */}
            <button
              className={clsx(
                // issue-local-042 (item 16): comparison-assessment-btn is a
                // pure hook for a scoped light-theme contrast override (see
                // index.css) — light-purple text on a light-tinted purple
                // background (both fixed Tailwind purple, not theme-aware)
                // was very hard to read once Light's page background went
                // near-white. Other unrelated bg-purple-900/text-purple-300
                // usages (e.g. the playbook-provenance badge) must not be
                // affected, hence the dedicated class instead of overriding
                // those Tailwind utilities globally.
                'comparison-assessment-btn flex items-center gap-1.5 text-[11px] px-2.5 py-1.5 rounded-lg border transition-colors font-medium',
                activeTab === 'comparison'
                  ? 'bg-purple-900/30 border-purple-600/60 text-purple-200'
                  : 'bg-purple-900/10 border-purple-800/40 text-purple-300 hover:bg-purple-900/20 hover:border-purple-700/60',
              )}
              onClick={() => setActiveTab('comparison')}
              title="View the comparison assessment across all runs"
            >
              <GitCompare className="w-3.5 h-3.5" />
              Comparison Assessment
            </button>
          </div>
          <RunsStatusTable
            pkgId={pkgId}
            runs={runs}
            onSelectRun={(runId) => setActiveRunId(runId)}
            activeRunId={activeRunId}
            isResearcher={isResearcher}
            isAdmin={isAdmin}
            subTab={runSubTab}
            onSubTabChange={handleRunSubTabChange}
          />
        </div>
      )}

      {/* issue-local-041: the selected sub-tab has no runs yet — show a real
          empty state instead of falling through to ArrowTabs/AnalysisTab/
          ReportPanel, which would otherwise keep displaying whichever run
          was active before (typically a manual run), reading as if the
          Consolidated/Playbook Runs sub-tab silently showed the main run's
          content. */}
      {runSubTab !== 'runs' && runsInSubTab.length === 0 ? (
        <div className="card text-center py-10 space-y-2">
          <p className="text-sm font-medium text-gray-300">
            No {runSubTab === 'consolidated' ? 'consolidated' : 'playbook'} runs yet.
          </p>
          <p className="text-sm text-gray-500">
            {runSubTab === 'consolidated'
              ? 'Create one from the Comparison Assessment tab after comparing runs and generating recommendations.'
              : 'Fire a Hunt Playbook to see its runs here.'}
          </p>
        </div>
      ) : (
      <>
      {/* Tabs — issue-local-022 (item 5): SmartArt-style connected arrow
          segments; disabled (not-yet-reached) phases stay visibly greyed. */}
      <ArrowTabs
        active={activeTab}
        onSelect={(key) => setActiveTab(key as DetailTab)}
        tabs={[
          { key: 'evidence', label: `Evidence (${evidence.length})` },
          { key: 'analysis', label: 'Analysis' },
          // issue-local-021: IOCs tab always visible (was gated on iocs.length>0)
          // issue-local-022: moved after Analysis, matching PipelineStepper's order.
          {
            key: 'iocs',
            // issue-local-026: once deep_retrohunt exists, the tab body below
            // renders RetrohuntPanel over retrohunt.sanitized_iocs (kept+removed,
            // its own independently-deduped list) — the label must count the
            // SAME list, not the raw extracted_iocs table row count, or the two
            // numbers can disagree (two separate dedup passes over the same
            // underlying extraction). Falls back to the raw count only before
            // deep_retrohunt exists, matching the tab body's own fallback.
            label: (() => {
              const count = headerGenRecord?.deep_retrohunt
                ? headerGenRecord.deep_retrohunt.sanitized_iocs.length
                : (iocs as THExtractedIOC[]).length
              return `IOCs${count > 0 ? ` (${count})` : ''}`
            })(),
          },
          {
            key: 'execution',
            label: 'Execution',
            disabled: !isFinished,
            title: isFinished ? undefined : 'Available after execution starts',
          },
          {
            key: 'threat-intel',
            label: 'Threat Intelligence',
            disabled: !isFinished,
            title: isFinished ? undefined : 'Available after execution starts',
          },
          {
            key: 'report',
            label: 'Report',
            disabled: !isFinished,
            title: isFinished ? undefined : 'Available after execution starts',
          },
          // Comments tab (issue-local-018) — always visible, per-run free-text notes
          { key: 'comments', label: `Comments${comments.length > 0 ? ` (${comments.length})` : ''}` },
        ]}
      />

      {/* Evidence tab — issue-local-023: two-pane sidebar list + content
          viewer (PDF/plaintext rendered, binary files not processed), fully
          self-contained (owns its own delete flow/confirmation now). */}
      {activeTab === 'evidence' && (
        <EvidenceTab
          pkgId={pkgId}
          isResearcher={isResearcher}
          hasRuns={runs.length > 0}
          onGoToAnalysis={() => setActiveTab('analysis')}
        />
      )}

      {/* IOCs tab — issue-local-022 (item 6): once the run's Deep Retrohunt
          Lead exists, show the richer enriched All/Sanitized/Removed table
          (RetrohuntPanel — previously only reachable via the Analysis tab's
          collapsible section) instead of the plain flat list. Early in a
          run, before deep_retrohunt_planner has produced that lead yet, fall
          back to the flat extracted_iocs list so the tab isn't empty. */}
      {activeTab === 'iocs' && (
        headerGenRecord?.deep_retrohunt ? (
          <RetrohuntPanel
            retrohunt={headerGenRecord.deep_retrohunt}
            pkgId={pkgId}
            pendingFor={isResearcher ? iocStaging.pendingFor : undefined}
            onStageVerdict={isResearcher ? iocStaging.stage : undefined}
            iocApplyBar={
              isResearcher
                ? {
                    isDirty: iocStaging.isDirty,
                    pendingCount: iocStaging.pendingCount,
                    isApplying: iocStaging.isApplying,
                    justApplied: iocStaging.justApplied,
                    onApply: iocStaging.apply,
                  }
                : undefined
            }
          />
        ) : (
          <div className="space-y-3">
            {(iocs as THExtractedIOC[]).length === 0 ? (
              <p className="text-sm text-gray-500 text-center py-8">No IOCs extracted yet.</p>
            ) : (
              <>
                <div className="flex items-center justify-between gap-4">
                  <div className="flex gap-4 text-sm text-gray-500">
                    <span className="text-green-400">{cleanCount} actionable</span>
                    <span className="text-amber-400">{noisyCount} noisy / flagged</span>
                    {removedCount > 0 && (
                      <span className="text-red-400">{removedCount} removed (active cleaning)</span>
                    )}
                  </div>
                  {isResearcher && (
                    <IocApplyBar
                      isDirty={iocStaging.isDirty}
                      pendingCount={iocStaging.pendingCount}
                      isApplying={iocStaging.isApplying}
                      justApplied={iocStaging.justApplied}
                      onApply={iocStaging.apply}
                    />
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
                            ? 'bg-red-900/10 border border-red-900/30'
                            : ioc.flagged_noisy
                              ? 'bg-amber-900/10 border border-amber-800/30'
                              : 'bg-gray-800/40',
                        )}
                      >
                        <span className="text-gray-500 w-24 shrink-0">{ioc.ioc_type}</span>
                        {/* issue-local-033 (3rd): no strikethrough, no row-level
                            dimming — the red background/border above plus the
                            'remove' verdict badge below are the sole removal
                            indicators, so a removed IOC reads exactly like a
                            kept one at a glance. */}
                        <span className="font-mono flex-1 truncate text-gray-200">{ioc.ioc}</span>
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
        )
      )}

      {/* Analysis tab — passes activeRunId so it polls the correct run */}
      {activeTab === 'analysis' && (
        <AnalysisTab
          pkgId={pkgId}
          runId={activeRunId}
          onRunCreated={(id) => {
            // issue-local-042 (item 21): setRunSubTab directly (not
            // handleRunSubTabChange) — that helper also jumps activeRunId
            // to the sub-tab's current newest run from the (not-yet-
            // refetched, so still stale) runs list, which would overwrite
            // the just-created run's own id set explicitly right after.
            setRunSubTab('runs')
            setActiveRunId(id)
            qc.invalidateQueries({ queryKey: ['th-runs', pkgId] })
            scrollToPhasesRow()
          }}
          onPlaybookStarted={() => {
            handleRunSubTabChange('playbook')
            scrollToPhasesRow()
          }}
          onShowIocs={() => setActiveTab('iocs')}
          iocVerdictsDirty={iocStaging.isDirty}
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

      {/* Threat Intelligence tab (issue-local-020) */}
      {activeTab === 'threat-intel' && <ThreatIntelTab pkgId={pkgId} runId={activeRunId} />}

      {/* Comparison Assessment tab (issue-local-020) */}
      {activeTab === 'comparison' && <ComparisonAssessmentTab pkgId={pkgId} runs={runs} />}

      {/* Report tab */}
      {activeTab === 'report' && (
        <ReportPanel pkgId={pkgId} runId={activeRunId} threatIntelRunning={threatIntelRunning} />
      )}

      {/* Comments tab (issue-local-018) — free-text analyst notes on the active run */}
      {activeTab === 'comments' && (
        <div className="space-y-3">
          {isResearcher && (
            <div className="flex items-start gap-2">
              <textarea
                className="input flex-1 text-sm min-h-[70px] resize-y"
                placeholder="Add a comment about this run…"
                value={newComment}
                onChange={(e) => setNewComment(e.target.value)}
              />
              <button
                className="btn-primary flex items-center gap-2 text-sm shrink-0"
                disabled={!newComment.trim() || createCommentMut.isPending}
                onClick={() => createCommentMut.mutate(newComment.trim())}
              >
                <Send className="w-3.5 h-3.5" />
                Post
              </button>
            </div>
          )}
          {(comments as THRunComment[]).length === 0 ? (
            <p className="text-sm text-gray-500 text-center py-8 flex flex-col items-center gap-2">
              <MessageSquare className="w-5 h-5 text-gray-700" />
              No comments yet.
            </p>
          ) : (
            <div className="space-y-2">
              {(comments as THRunComment[]).map((c) => (
                <div key={c.id} className="card flex items-start gap-3">
                  <div className="flex-1 min-w-0 space-y-1">
                    <div className="flex items-center gap-2 text-[11px] text-gray-500">
                      <span className="font-medium text-gray-300">{c.created_by ?? 'unknown'}</span>
                      <span>{c.created_at.slice(0, 19).replace('T', ' ')}</span>
                    </div>
                    <p className="text-sm text-gray-200 whitespace-pre-wrap">{c.body}</p>
                  </div>
                  {(isResearcher || isAdmin) && (
                    <button
                      className="btn-ghost p-1 text-gray-600 hover:text-red-400 shrink-0"
                      onClick={() => deleteCommentMut.mutate(c.id)}
                      title="Delete comment"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}
      </>
      )}

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


      {/* issue-local-034: permanent-package-delete confirmation */}
      {showDeletePackageConfirm && (
        <ConfirmDialog
          title="Permanently Delete Hunt Package?"
          message={`This permanently deletes ${pkg?.hunt_id_display ?? 'this hunt package'} — every run, evidence item, IOC, task result, report, comment, and threat-intel analysis tied to it. This cannot be undone — use Archive instead if you just want to hide it.`}
          confirmLabel="Delete Permanently"
          onConfirm={() => deletePackageMut.mutate()}
          onCancel={() => setShowDeletePackageConfirm(false)}
        />
      )}

      {/* issue-local-042: rename dialog */}
      {renameName !== null && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
          <div className="bg-gray-900 border border-gray-700 rounded-xl shadow-2xl w-full max-w-md p-5 space-y-4">
            <h2 className="text-base font-semibold text-gray-100">Rename Hunt Package</h2>
            <input
              className="input w-full"
              value={renameName}
              onChange={(e) => setRenameName(e.target.value)}
              placeholder="Hunt package name"
              autoFocus
            />
            {renameMut.isError && (
              <p className="text-sm text-red-400">
                Rename failed: {renameMut.error instanceof Error ? renameMut.error.message : String(renameMut.error)}
              </p>
            )}
            <div className="flex justify-end gap-2">
              <button
                className="btn-ghost text-sm"
                onClick={() => { setRenameName(null); renameMut.reset() }}
                disabled={renameMut.isPending}
              >
                Cancel
              </button>
              <button
                className="btn-primary text-sm flex items-center gap-2"
                disabled={!renameName.trim() || renameName.trim() === pkg?.name || renameMut.isPending}
                onClick={() => renameMut.mutate(renameName.trim())}
              >
                {renameMut.isPending ? <><span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin inline-block" /> Renaming…</> : 'Rename'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* issue-local-038: clone dialog */}
      {cloneName !== null && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
          <div className="bg-gray-900 border border-gray-700 rounded-xl shadow-2xl w-full max-w-md p-5 space-y-4">
            <h2 className="text-base font-semibold text-gray-100">Clone Hunt Package</h2>
            <p className="text-sm text-gray-400">
              Enter a name for the cloned package (cloning &quot;{pkg?.name}&quot;).
            </p>
            <input
              className="input w-full"
              value={cloneName}
              onChange={(e) => setCloneName(e.target.value)}
              placeholder="New package name"
              autoFocus
            />
            {cloneMut.isError && (
              <p className="text-sm text-red-400">
                Clone failed: {cloneMut.error instanceof Error ? cloneMut.error.message : String(cloneMut.error)}
              </p>
            )}
            <div className="flex justify-end gap-2">
              <button
                className="btn-ghost text-sm"
                onClick={() => { setCloneName(null); cloneMut.reset() }}
                disabled={cloneMut.isPending}
              >
                Cancel
              </button>
              <button
                className="btn-primary text-sm flex items-center gap-2"
                disabled={!cloneName.trim() || cloneMut.isPending}
                onClick={() => cloneMut.mutate(cloneName.trim())}
              >
                {cloneMut.isPending ? <><span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin inline-block" /> Cloning…</> : 'Clone'}
              </button>
            </div>
          </div>
        </div>
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

            <RunConfigForm
              variant="dialog"
              effort={effectiveRerunEffort}
              onEffortChange={setRerunEffort}
              modelChoice={rerunModelChoice}
              onModelChoiceChange={setRerunModelChoice}
              modelOptions={rerunModelOptions}
              playbookOptions={rerunPlaybooks}
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

            {/* Selected summary */}
            <p className="text-[11px] text-gray-600">
              {rerunChosenPlaybookId
                ? `Playbook: ${rerunPlaybooks.find((p) => p.id === rerunChosenPlaybookId)?.name ?? rerunChosenPlaybookId}`
                : rerunChosenModel
                  ? `${rerunChosenModel.provider} / ${rerunChosenModel.model}`
                  : 'Default model'}{' '}
              · effort: {effectiveRerunEffort} · IOC: {iocMode === 'tagging_only' ? 'tagging only' : 'active cleaning'}
              {' '}· Threat Intel: {includeThreatIntel ? 'on' : 'off'}
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
