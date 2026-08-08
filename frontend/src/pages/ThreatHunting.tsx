/**
 * ThreatHunting — hunt package list page.
 *
 * Phase/arrow card improvements (issue-008 review):
 *   1. Live refresh — polls every 4s while any package is running; stops when idle.
 *   2. Bigger cards — text-[12px], px-2.5 py-1.5, min-w-[68px].
 *   3. Visible status colors — stronger contrast: bright green/red/blue/amber/gray
 *      with a per-card status glyph (✓ · ✕ · ⟳ · ⊘ · ⋯) for color-independent scanning.
 *   4. Fixed active-step detection — keep last entry per step (handles parallel fan-out
 *      and duplicate step names); derive running step correctly.
 *
 * issue-local-011:
 *   5. Card size reduced to ~1.25x original (Part 3a).
 *   6. 2-theme system (Classic / Modern) stored in localStorage (Part 3b).
 *   7. Delete/archive confirmation dialog (Part 4).
 */
import { useState, useEffect, useMemo } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Plus, Shield, Trash2, ChevronRight, ChevronLeft, Timer, Copy, UserCircle, Search, X } from 'lucide-react'
import { clsx } from 'clsx'
import { api, type THuntPackage, type THPhaseEntry, type THuntPackageRun } from '../api/client'
import { useAuth } from '../auth/useAuth'
import HuntPackageWizard from './threat-hunting/HuntPackageWizard'
import HuntDetail from './threat-hunting/HuntDetail'
import ConfirmDialog from '../components/ConfirmDialog'
import { useHuntDensity, type HuntDensity } from './threat-hunting/useHuntDensity'
import { useHuntPageSize, HUNT_PAGE_SIZE_OPTIONS } from './threat-hunting/useHuntPageSize'
import RunStatusBadge from './threat-hunting/RunStatusBadge'
import RunsStatusTable from './threat-hunting/RunsStatusTable'
import { HUNT_ID_BADGE } from './threat-hunting/runStatusUtils'
import HuntTimeFilter, { type HuntTimeRange } from './threat-hunting/HuntTimeFilter'

const STATUS_COLORS: Record<string, string> = {
  draft: 'bg-gray-700/50 text-gray-400',
  planning: 'bg-blue-900/40 text-blue-400',
  approved: 'bg-green-900/40 text-green-400',
  executing: 'bg-yellow-900/40 text-yellow-400',
  completed: 'bg-green-900/40 text-green-400',
  archived: 'bg-gray-800/40 text-gray-600',
}

const STEP_SHORT_LABELS: Record<string, string> = {
  // Pipeline (LangGraph) steps
  intake_classifier: 'Intake',
  threat_context_builder: 'Context',
  deep_retrohunt_planner: 'Retrohunt',
  hypothesis_generator: 'Hypotheses',
  hunting_lead_planner: 'Leads',
  ttp_analyst: 'TTP',
  query_drafting_agent: 'Queries',
  // Execution steps (issue-local-009)
  siem_connect: 'Connect',
  siem_submit: 'Submit',
  siem_poll: 'Poll',
  siem_fetch: 'Fetch',
  siem_interpret: 'Interpret',
  // Report steps (issue-local-009)
  report_assemble: 'Assemble',
  report_exec_summary: 'Summary',
  report_findings: 'Findings',
  report_render: 'Render',
}

const STEP_ORDER = [
  // LangGraph pipeline
  'intake_classifier',
  'threat_context_builder',
  'deep_retrohunt_planner',
  'hypothesis_generator',
  'hunting_lead_planner',
  'ttp_analyst',
  'query_drafting_agent',
  // SIEM execution (issue-local-009)
  'siem_connect',
  'siem_submit',
  'siem_poll',
  'siem_fetch',
  'siem_interpret',
  // Report generation (issue-local-009)
  'report_assemble',
  'report_exec_summary',
  'report_findings',
  'report_render',
]

// Terminal statuses — a step with one of these is finished (not in-progress).
const TERMINAL_STATUSES = new Set(['ok', 'partial', 'error', 'skipped'])

interface PhaseCardProps {
  phase: THPhaseEntry | undefined
  stepId: string
  currentStep: string | null | undefined
  isLast: boolean
}

function PhaseCard({ phase, stepId, currentStep, isLast }: PhaseCardProps) {
  const isActive = currentStep === stepId
  const isPartial = phase?.status === 'partial'
  const isDone = phase?.status === 'ok' || isPartial
  const isError = phase?.status === 'error'
  const isSkipped = phase?.status === 'skipped'

  const hasTools = (phase?.tools_used?.length ?? 0) > 0
  const hasCounts = phase?.item_count != null || phase?.ioc_count != null

  // Glyph: color-independent, large enough to read
  const glyph = isActive ? '⟳' : isDone ? '✓' : isError ? '✕' : isSkipped ? '⊘' : '·'

  // Status word shown under the label — makes meaning explicit without relying on color alone
  const statusWord = isActive
    ? 'running'
    : isDone
      ? isPartial ? 'partial' : 'done'
      : isError
        ? 'error'
        : isSkipped
          ? 'skipped'
          : 'pending'

  // ── Card body classes (issue-local-018: Classic only, Modern removed) ─────
  const classicActive   = 'border-blue-400 bg-blue-800/60 text-blue-100 animate-pulse'
  const classicDone     = isPartial
    ? 'border-amber-400 bg-amber-800/50 text-amber-100'
    : 'border-green-500 bg-green-800/60 text-green-100'
  const classicError    = 'border-red-500 bg-red-800/60 text-red-100'
  const classicSkipped  = 'border-gray-600 bg-gray-800/50 text-gray-400'
  const classicPending  = 'border-gray-700 border-dashed bg-gray-900/50 text-gray-600'

  const bodyClass = isActive
    ? classicActive
    : isDone
      ? classicDone
      : isError
        ? classicError
        : isSkipped
          ? classicSkipped
          : classicPending

  return (
    <div className="flex items-start gap-1">
      <div className="flex flex-col">
        {/* ── Card body ── */}
        <div
          className={clsx(
            // Part 3a: reduced sizing (px-3 py-2 text-[13px] min-w-[88px])
            'px-3 py-2 rounded text-[13px] font-semibold transition-all min-w-[88px] text-center select-none border-2',
            bodyClass,
          )}
          title={`${stepId}${phase ? ` — ${phase.status} (${phase.elapsed_s}s)` : ' — pending'}`}
        >
          {/* Glyph + step name */}
          <div className="flex items-center justify-center gap-1">
            <span className={clsx(
              // Part 3a: glyph text-[15px]
              'text-[15px] font-bold leading-none',
              isActive ? 'text-blue-200' :
              isDone ? isPartial ? 'text-amber-300' : 'text-green-300' :
              isError ? 'text-red-300' :
              'text-gray-600',
            )}>
              {glyph}
            </span>
            <span className="leading-none tracking-tight">
              {STEP_SHORT_LABELS[stepId] ?? stepId}
            </span>
          </div>

          {/* Status word + elapsed — Part 3a: text-[11px] mt-0.5 */}
          <div className="flex items-center justify-center gap-1.5 mt-0.5">
            <span className={clsx(
              'text-[11px] font-normal leading-none',
              isActive ? 'text-blue-300' :
              isDone ? isPartial ? 'text-amber-400' : 'text-green-400' :
              isError ? 'text-red-400' :
              isSkipped ? 'text-gray-500' :
              'text-gray-700',
            )}>
              {statusWord}
            </span>
            {phase?.elapsed_s != null && phase.elapsed_s > 0 && (
              <span className="text-[11px] font-mono opacity-60 leading-none">
                {phase.elapsed_s}s
              </span>
            )}
          </div>
        </div>

        {/* ── Inline detail (done steps only) — Part 3a: max-w-[112px] text-[11px] ── */}
        {isDone && (hasCounts || hasTools) && (
          <div className="mt-1 space-y-0.5 max-w-[112px]" onClick={(e) => e.stopPropagation()}>
            {hasCounts && (
              <div className="flex flex-wrap gap-0.5">
                {phase!.item_count != null && (
                  <span className="text-[11px] font-mono text-brand-400 leading-none">
                    {phase!.item_count} items
                  </span>
                )}
                {phase!.ioc_count != null && (
                  <span className="text-[11px] font-mono text-blue-400 leading-none">
                    {phase!.ioc_count} IOC{phase!.noisy_count ? ` (${phase!.noisy_count}⚠)` : ''}
                  </span>
                )}
              </div>
            )}
            {hasTools && (
              <div className="flex flex-wrap gap-0.5">
                {[...new Set(phase!.tools_used!)].map((t) => (
                  <span
                    key={t}
                    className="text-[11px] font-mono bg-purple-900/50 text-purple-300 border border-purple-700/50 rounded px-1 leading-none"
                    title={t}
                  >
                    {t.replace(/_/g, ' ')}
                  </span>
                ))}
              </div>
            )}
          </div>
        )}
      </div>

      {/* Part 3a: arrow w-3.5 h-3.5 mt-3 */}
      {!isLast && (
        <ChevronRight className="w-3.5 h-3.5 text-gray-500 shrink-0 mt-3" />
      )}
    </div>
  )
}

/**
 * The subset of a run's fields ProcessArrow needs to render its stage rail —
 * issue-local-016: extracted from `THuntPackage` directly so the parent can
 * resolve "which run is selected" (defaulting to the latest) and pass THAT
 * run's data down, independent of how many runs a package has.
 */
export interface ProcessArrowRunData {
  phases: THPhaseEntry[] | null | undefined
  generation_status: string | null | undefined
  total_elapsed_s: number | null | undefined
  run_created_at: string | null | undefined
}

interface ProcessArrowProps {
  run: ProcessArrowRunData
}

function ProcessArrow({ run: pkg }: ProcessArrowProps) {
  // fix: keep the LAST entry per step so a re-run ok overrides an earlier error,
  // and parallel steps (threat_context_builder / deep_retrohunt_planner) both appear.
  const phaseByStep: Record<string, THPhaseEntry> = {}
  for (const p of pkg.phases ?? []) {
    // Always overwrite — last entry wins (handles retried / duplicate step names)
    phaseByStep[p.step] = p
  }

  // issue-local-009: active across all three runtime phases
  const ACTIVE_STATUSES = new Set(['running', 'executing', 'reporting'])
  const isRunning = pkg.generation_status != null && ACTIVE_STATUSES.has(pkg.generation_status)

  // fix: derive the active step as the first STEP_ORDER step that has no
  // terminal status yet (ok/partial/error/skipped). Falls back to null.
  const runningStep: string | null = isRunning
    ? (STEP_ORDER.find((s) => {
        const p = phaseByStep[s]
        return !p || !TERMINAL_STATUSES.has(p.status)
      }) ?? null)
    : null

  // Live elapsed timer while running
  const [liveElapsed, setLiveElapsed] = useState<number | null>(null)
  useEffect(() => {
    if (!isRunning || !pkg.run_created_at) {
      setLiveElapsed(null)
      return
    }
    const startMs = new Date(pkg.run_created_at).getTime()
    const tick = () => setLiveElapsed(Math.floor((Date.now() - startMs) / 1000))
    tick()
    const id = setInterval(tick, 1000)
    return () => clearInterval(id)
  }, [isRunning, pkg.run_created_at])

  const hasAnyData = pkg.generation_status != null || (pkg.phases?.length ?? 0) > 0

  return (
    <div className="mt-2">
      {/* Status + timer row */}
      {pkg.generation_status && (
        <div className="flex items-center gap-1.5 mb-1.5">
          <span className={clsx(
            'text-[10px] font-mono px-1.5 py-0.5 rounded font-semibold',
            pkg.generation_status === 'completed'
              ? 'bg-green-900/30 text-green-400 border border-green-700/40'
              : pkg.generation_status === 'running'
                ? 'bg-blue-900/30 text-blue-300 border border-blue-700/40'
                : pkg.generation_status === 'executing'
                  ? 'bg-yellow-900/30 text-yellow-300 border border-yellow-700/40'
                  : pkg.generation_status === 'reporting'
                    ? 'bg-purple-900/30 text-purple-300 border border-purple-700/40'
                    : pkg.generation_status === 'awaiting_approval'
                      ? 'bg-amber-900/30 text-amber-300 border border-amber-700/40'
                      : pkg.generation_status === 'error'
                        ? 'bg-red-900/30 text-red-400 border border-red-700/40'
                        : 'bg-gray-800/40 text-gray-500 border border-gray-700/30',
          )}>
            {pkg.generation_status.replace(/_/g, ' ')}
          </span>

          {isRunning && liveElapsed != null ? (
            <span className="flex items-center gap-0.5 text-[10px] text-blue-300 font-mono">
              <Timer className="w-2.5 h-2.5" />
              {liveElapsed}s
            </span>
          ) : pkg.total_elapsed_s != null && !isRunning ? (
            <span className="flex items-center gap-0.5 text-[10px] text-gray-500 font-mono">
              <Timer className="w-2.5 h-2.5" />
              {pkg.total_elapsed_s}s total
            </span>
          ) : null}
        </div>
      )}

      {/* Phase rail — always rendered */}
      <div className="flex items-start flex-wrap gap-1.5">
        {STEP_ORDER.map((stepId, i) => (
          <PhaseCard
            key={stepId}
            phase={phaseByStep[stepId]}
            stepId={stepId}
            currentStep={runningStep}
            isLast={i === STEP_ORDER.length - 1}
          />
        ))}
      </div>

      {!hasAnyData && (
        <p className="text-[10px] text-gray-600 mt-1">No analysis run yet</p>
      )}
    </div>
  )
}

// Outer card class (issue-local-018: Classic only, Modern removed) — module
// scope since it's static, shared by PackageCard below.
const CLASSIC_CARD = 'card cursor-pointer hover:bg-gray-800/60 transition-colors'


/**
 * One hunt-package list card (issue-local-016: extracted from the inline
 * `.map()` body so each card can own its own "which run is selected" state
 * — the run-chip row is a per-run selector, defaulting to the latest run,
 * that drives which run's stage rail ProcessArrow renders).
 */
function PackageCard({
  pkg,
  density,
  isResearcher,
  onSelect,
  onClone,
  onArchive,
}: {
  pkg: THuntPackage
  density: HuntDensity
  isResearcher: boolean
  onSelect: () => void
  onClone: () => void
  onArchive: () => void
}) {
  const runs = useMemo(() => pkg.runs ?? [], [pkg.runs])
  const [selectedRunId, setSelectedRunId] = useState<string | undefined>(runs[0]?.id)

  // Default to the latest run whenever there's no valid selection yet (first
  // render, or the previously-selected run disappeared from a refetch).
  useEffect(() => {
    if (runs.length > 0 && (!selectedRunId || !runs.some((r) => r.id === selectedRunId))) {
      setSelectedRunId(runs[0].id)
    }
  }, [runs, selectedRunId])

  const selectedRun = runs.find((r) => r.id === selectedRunId) ?? runs[0]
  const resolvedRun: ProcessArrowRunData = selectedRun
    ? {
        phases: selectedRun.phases,
        generation_status: selectedRun.generation_status,
        total_elapsed_s: selectedRun.total_elapsed_s,
        run_created_at: selectedRun.created_at,
      }
    : {
        phases: pkg.phases,
        generation_status: pkg.generation_status,
        total_elapsed_s: pkg.total_elapsed_s,
        run_created_at: pkg.run_created_at,
      }

  return (
    <div
      className={CLASSIC_CARD}
      onClick={onSelect}
    >
      <div className="flex items-start gap-4">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            {pkg.hunt_id_display && (
              <span className={clsx(HUNT_ID_BADGE, 'text-[11px]')}>{pkg.hunt_id_display}</span>
            )}
            <p className="text-base font-semibold text-gray-100 truncate">{pkg.name}</p>
            <span className={clsx('badge text-[11px] px-1.5 py-0.5 rounded', STATUS_COLORS[pkg.status] ?? STATUS_COLORS.draft)}>
              {pkg.status}
            </span>
            {pkg.generation_status && pkg.generation_status !== 'completed' && (
              <span className="badge text-[10px] px-1.5 py-0.5 rounded bg-blue-900/30 text-blue-400 border border-blue-800/30">
                {pkg.generation_status.replace(/_/g, ' ')}
              </span>
            )}
          </div>
          {/* issue-local-042 (item 9): a one-sentence, auto-derived subtitle
              once analysis has produced one — falls back only when the
              user hasn't written their own description, so this never
              duplicates or buries an intentional one. */}
          {pkg.description ? (
            <p className="text-sm text-gray-400 truncate mt-0.5">{pkg.description}</p>
          ) : (
            pkg.brief_summary && (
              <p className="text-sm text-gray-400 truncate mt-0.5">{pkg.brief_summary}</p>
            )
          )}
          <p className="text-sm text-gray-500 mt-1 flex items-center gap-2 flex-wrap">
            <span>{pkg.evidence_count} evidence item{pkg.evidence_count !== 1 ? 's' : ''}</span>
            <span>·</span>
            <span>{new Date(pkg.created_at).toLocaleDateString()}</span>
            {pkg.created_by && (
              <span className="flex items-center gap-0.5">
                <UserCircle className="w-3 h-3" />
                {pkg.created_by}
              </span>
            )}
          </p>

          {/* issue-local-016/017: per-run compact status chips — shown for
              every package that has at least one run (including a
              single-run package, so its model/status is visible without
              opening the detail view), in compact/detailed density (only
              the heavier stage rail below is gated by density). Clicking a
              chip selects that run for this card's stage rail. issue-
              local-038: 'simple' density replaces this whole row with a
              one-line run count instead — see below. */}
          {density !== 'simple' && runs.length > 0 && (
            <div
              className="flex items-end gap-1.5 mt-2 border-b border-gray-700 flex-wrap"
              onClick={(e) => e.stopPropagation()}
            >
              <span className="text-[11px] text-gray-500 uppercase tracking-wider font-semibold pb-2 shrink-0">
                Runs
              </span>
              {runs.map((run: THuntPackageRun) => (
                <RunStatusBadge
                  key={run.id}
                  run={run}
                  active={run.id === selectedRun?.id}
                  onClick={() => setSelectedRunId(run.id)}
                />
              ))}
            </div>
          )}

          {/* issue-local-038: 'simple' density — same as compact, minus the
              runs chip row above, replaced with a brief count. */}
          {density === 'simple' && (
            <p className="text-xs text-gray-500 mt-2">
              {runs.length === 0 ? 'No runs yet' : `${runs.length} run${runs.length !== 1 ? 's' : ''}`}
            </p>
          )}

          {density === 'detailed' && <ProcessArrow run={resolvedRun} />}
        </div>
        <div className="flex items-center gap-2 shrink-0">
          {isResearcher && (
            <>
              <button
                className="btn-ghost p-1.5 text-gray-600 hover:text-brand-400"
                title="Clone hunt package"
                onClick={(e) => {
                  e.stopPropagation()
                  onClone()
                }}
              >
                <Copy className="w-3.5 h-3.5" />
              </button>
              <button
                className="btn-ghost p-1.5 text-gray-600 hover:text-red-400"
                title="Archive"
                onClick={(e) => {
                  e.stopPropagation()
                  onArchive()
                }}
              >
                <Trash2 className="w-3.5 h-3.5" />
              </button>
            </>
          )}
          <ChevronRight className="w-4 h-4 text-gray-600" />
        </div>
      </div>
    </div>
  )
}

// ── Confirm dialog state type (Part 4) ────────────────────────────────────────
interface ConfirmTarget {
  id: string
  type: 'archive'
  label: string
}

// ── Clone dialog state ────────────────────────────────────────────────────────
interface CloneTarget {
  id: string
  originalName: string
  newName: string
}

export default function ThreatHunting() {
  const { isResearcher } = useAuth()
  const qc = useQueryClient()
  const [showWizard, setShowWizard] = useState(false)
  const [selectedId, setSelectedId] = useState<string | null>(null)
  // issue-local-018: which run to deep-link HuntDetail to, set when a Run
  // ID/Model cell is clicked in Table density mode. Cleared alongside
  // selectedId so re-opening a package later doesn't carry over a stale run.
  const [selectedRunId, setSelectedRunId] = useState<string | undefined>(undefined)

  // Part 4: archive confirmation
  const [confirmTarget, setConfirmTarget] = useState<ConfirmTarget | null>(null)

  // Part 3b (clone): clone dialog state
  const [cloneTarget, setCloneTarget] = useState<CloneTarget | null>(null)

  // issue-local-016: compact/detailed/table density toggle.
  const { density, setDensity } = useHuntDensity()

  // issue-local-018 follow-up: pagination over the hunt-package list.
  const { pageSize, setPageSize } = useHuntPageSize()
  const [page, setPage] = useState(1)

  // issue-local-020: server-side deep search (debounced) + date-range filter.
  const [searchInput, setSearchInput] = useState('')
  const [debouncedSearch, setDebouncedSearch] = useState('')
  useEffect(() => {
    const t = setTimeout(() => setDebouncedSearch(searchInput.trim()), 350)
    return () => clearTimeout(t)
  }, [searchInput])
  const [timeRange, setTimeRange] = useState<HuntTimeRange>({})

  // Reset to page 1 whenever the effective filter changes.
  useEffect(() => {
    setPage(1)
  }, [debouncedSearch, timeRange.from, timeRange.to])

  const { data: packages = [], isLoading } = useQuery({
    queryKey: ['th-packages', debouncedSearch, timeRange.from, timeRange.to],
    queryFn: () =>
      api.threatHunting.listPackages({
        search: debouncedSearch || undefined,
        date_from: timeRange.from,
        date_to: timeRange.to,
      }),
    // issue-local-009: poll every 4s while any package is active in any phase
    // (running = pipeline, executing = SIEM, reporting = report generation).
    refetchInterval: (query) => {
      const data = query.state.data as THuntPackage[] | undefined
      const activeStatuses = new Set(['running', 'executing', 'reporting'])
      const anyActive = (data ?? []).some(
        (p) => p.generation_status != null && activeStatuses.has(p.generation_status),
      )
      return anyActive ? 4000 : false
    },
  })

  const archiveMut = useMutation({
    mutationFn: (id: string) => api.threatHunting.archivePackage(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['th-packages'] }),
  })

  const cloneMut = useMutation({
    mutationFn: ({ id, name }: { id: string; name: string }) =>
      api.threatHunting.clonePackage(id, name),
    onSuccess: (newPkg) => {
      qc.invalidateQueries({ queryKey: ['th-packages'] })
      setCloneTarget(null)
      setSelectedId(newPkg.id)
    },
  })

  // issue-local-018 follow-up: client-side pagination — the list-fetch has
  // no limit/offset support server-side, and package counts are small
  // enough (dozens, not thousands) that slicing the already-fetched array
  // is simpler than adding backend pagination.
  const totalPages = Math.max(1, Math.ceil(packages.length / pageSize))
  useEffect(() => {
    if (page > totalPages) setPage(totalPages)
  }, [page, totalPages])
  const pagedPackages = packages.slice((page - 1) * pageSize, page * pageSize)

  if (selectedId) {
    return (
      <HuntDetail
        pkgId={selectedId}
        initialRunId={selectedRunId}
        onBack={() => {
          setSelectedId(null)
          setSelectedRunId(undefined)
        }}
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
        <div className="flex items-center gap-3">
          {/* issue-local-016/017/018/038: Simple/Compact/Detailed/Table
              density toggle (the separate Classic/Modern card-color toggle
              was removed — Classic is now the only card design). Compact
              hides the per-stage ProcessArrow rail; Simple additionally
              replaces the per-run chip row with a one-line run count; Table
              replaces the card list with each package's all-runs table (the
              same RunsStatusTable HuntDetail uses); the per-run chip row
              (when a package has multiple runs) shows in both card modes
              except Simple. */}
          <div className="flex items-center rounded-lg overflow-hidden border border-gray-700 text-sm">
            <button
              className={clsx(
                'px-2.5 py-1.5 transition-colors',
                density === 'simple'
                  ? 'bg-gray-700 text-gray-100'
                  : 'bg-transparent text-gray-500 hover:text-gray-300',
              )}
              onClick={() => setDensity('simple')}
              title="Simple view"
            >
              Simple
            </button>
            <button
              className={clsx(
                'px-2.5 py-1.5 transition-colors',
                density === 'detailed'
                  ? 'bg-gray-700 text-gray-100'
                  : 'bg-transparent text-gray-500 hover:text-gray-300',
              )}
              onClick={() => setDensity('detailed')}
              title="Detailed view"
            >
              Detailed
            </button>
            <button
              className={clsx(
                'px-2.5 py-1.5 transition-colors',
                density === 'compact'
                  ? 'bg-gray-700 text-gray-100'
                  : 'bg-transparent text-gray-500 hover:text-gray-300',
              )}
              onClick={() => setDensity('compact')}
              title="Compact view"
            >
              Compact
            </button>
            <button
              className={clsx(
                'px-2.5 py-1.5 transition-colors',
                density === 'table'
                  ? 'bg-gray-700 text-gray-100'
                  : 'bg-transparent text-gray-500 hover:text-gray-300',
              )}
              onClick={() => setDensity('table')}
              title="Table view"
            >
              Table
            </button>
          </div>
          {/* issue-local-018 follow-up: page-size selector for the
              pagination controls below the list. */}
          <div className="flex items-center gap-1.5 text-sm">
            <label htmlFor="th-page-size" className="text-gray-500 text-xs shrink-0">Show</label>
            <select
              id="th-page-size"
              className="input py-1 text-sm w-auto"
              value={pageSize}
              onChange={(e) => {
                setPageSize(Number(e.target.value) as (typeof HUNT_PAGE_SIZE_OPTIONS)[number])
                setPage(1)
              }}
            >
              {HUNT_PAGE_SIZE_OPTIONS.map((n) => (
                <option key={n} value={n}>{n}</option>
              ))}
            </select>
          </div>
          {isResearcher && (
            <button className="btn-primary flex items-center gap-2" onClick={() => setShowWizard(true)}>
              <Plus className="w-4 h-4" />
              New Hunt Package
            </button>
          )}
        </div>
      </div>

      {/* issue-local-020: search + time-range filter row. */}
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
        {!isLoading && (
          <span className="text-xs text-gray-600">
            {packages.length} result{packages.length === 1 ? '' : 's'}
          </span>
        )}
      </div>

      {isLoading ? (
        <p className="text-sm text-gray-500">Loading...</p>
      ) : packages.length === 0 ? (
        <div className="card text-center py-12 space-y-3">
          <Shield className="w-10 h-10 text-gray-600 mx-auto" />
          {debouncedSearch || timeRange.from || timeRange.to ? (
            <p className="text-sm text-gray-400">No hunt packages match your search/filters.</p>
          ) : (
            <>
              <p className="text-sm text-gray-400">No hunt packages yet.</p>
              {isResearcher && (
                <button className="btn-primary text-sm" onClick={() => setShowWizard(true)}>
                  Create your first Hunt Package
                </button>
              )}
            </>
          )}
        </div>
      ) : density === 'table' ? (
        <div className="space-y-5">
          {pagedPackages.map((pkg: THuntPackage) => (
            <div key={pkg.id} className="card space-y-1.5">
              <button
                type="button"
                onClick={() => setSelectedId(pkg.id)}
                className="flex items-center gap-2.5 text-left group w-full px-3 py-2.5 rounded-lg bg-gray-700/70 hover:bg-gray-700/90 transition-colors"
              >
                {pkg.hunt_id_display && (
                  <span className={clsx(HUNT_ID_BADGE, 'text-xs')}>{pkg.hunt_id_display}</span>
                )}
                <p className="text-base font-semibold text-gray-100 group-hover:text-brand-400 transition-colors">
                  {pkg.name}
                </p>
                <span className={clsx('badge text-xs px-2 py-0.5 rounded', STATUS_COLORS[pkg.status] ?? STATUS_COLORS.draft)}>
                  {pkg.status}
                </span>
                <span className="text-xs text-gray-400">{pkg.run_count ?? 0} run{pkg.run_count === 1 ? '' : 's'}</span>
                {pkg.created_by && (
                  <span className="flex items-center gap-1 text-xs font-medium text-brand-300 bg-brand-900/30 px-2 py-0.5 rounded-full ml-auto">
                    <UserCircle className="w-3.5 h-3.5" />
                    {pkg.created_by}
                  </span>
                )}
              </button>
              {/* issue-local-042 (item 9): same auto-derived one-sentence
                  subtitle as the Classic card view. */}
              {(pkg.description || pkg.brief_summary) && (
                <p className="text-sm text-gray-400 truncate px-3">{pkg.description || pkg.brief_summary}</p>
              )}
              {pkg.runs && pkg.runs.length > 0 ? (
                <RunsStatusTable
                  pkgId={pkg.id}
                  runs={pkg.runs}
                  onSelectRun={(runId) => {
                    setSelectedId(pkg.id)
                    setSelectedRunId(runId)
                  }}
                />
              ) : (
                <p className="text-[10px] text-gray-600 italic px-1">No runs yet.</p>
              )}
            </div>
          ))}
        </div>
      ) : (
        <div className="space-y-2">
          {pagedPackages.map((pkg: THuntPackage) => (
            <PackageCard
              key={pkg.id}
              pkg={pkg}
              density={density}
              isResearcher={isResearcher}
              onSelect={() => setSelectedId(pkg.id)}
              onClone={() => setCloneTarget({ id: pkg.id, originalName: pkg.name, newName: `Copy of ${pkg.name}` })}
              onArchive={() => setConfirmTarget({ id: pkg.id, type: 'archive', label: pkg.name })}
            />
          ))}
        </div>
      )}

      {/* issue-local-018 follow-up: pagination footer — only shown once
          there's more than one page, matching NormalizedTable.tsx's pattern. */}
      {!isLoading && totalPages > 1 && (
        <div className="flex items-center justify-center gap-3 text-sm text-gray-500">
          <button
            className="btn btn-secondary px-2 py-1"
            disabled={page <= 1}
            onClick={() => setPage((p) => Math.max(1, p - 1))}
            aria-label="Previous page"
          >
            <ChevronLeft className="w-4 h-4" />
          </button>
          <span>Page {page} of {totalPages} · {packages.length} total</span>
          <button
            className="btn btn-secondary px-2 py-1"
            disabled={page >= totalPages}
            onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
            aria-label="Next page"
          >
            <ChevronRight className="w-4 h-4" />
          </button>
        </div>
      )}

      {showWizard && (
        <HuntPackageWizard
          onClose={() => setShowWizard(false)}
          onCreated={(id) => { setShowWizard(false); setSelectedId(id) }}
        />
      )}

      {/* Part 4: Archive confirmation dialog */}
      {confirmTarget && (
        <ConfirmDialog
          title="Archive Hunt Package?"
          message={`This will archive the hunt package and all its analysis runs. You can restore it from the archived view.`}
          confirmLabel="Archive"
          onConfirm={() => {
            archiveMut.mutate(confirmTarget.id)
            setConfirmTarget(null)
          }}
          onCancel={() => setConfirmTarget(null)}
        />
      )}

      {/* Part 3b: Clone dialog */}
      {cloneTarget && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
          <div className="bg-gray-900 border border-gray-700 rounded-xl shadow-2xl w-full max-w-md p-5 space-y-4">
            <h2 className="text-base font-semibold text-gray-100">Clone Hunt Package</h2>
            <p className="text-sm text-gray-400">
              Enter a name for the cloned package (cloning &quot;{cloneTarget.originalName}&quot;).
            </p>
            <input
              className="input w-full"
              value={cloneTarget.newName}
              onChange={(e) => setCloneTarget({ ...cloneTarget, newName: e.target.value })}
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
                onClick={() => { setCloneTarget(null); cloneMut.reset() }}
                disabled={cloneMut.isPending}
              >
                Cancel
              </button>
              <button
                className="btn-primary text-sm flex items-center gap-2"
                disabled={!cloneTarget.newName.trim() || cloneMut.isPending}
                onClick={() => cloneMut.mutate({ id: cloneTarget.id, name: cloneTarget.newName.trim() })}
              >
                {cloneMut.isPending ? <><span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin inline-block" /> Cloning…</> : 'Clone'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
