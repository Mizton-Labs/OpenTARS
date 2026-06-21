/**
 * ThreatHunting — hunt package list page.
 *
 * Phase/arrow card improvements (issue-008 review):
 *   1. Live refresh — polls every 4s while any package is running; stops when idle.
 *   2. Bigger cards — text-[11px], px-2.5 py-1.5, min-w-[68px].
 *   3. Visible status colors — stronger contrast: bright green/red/blue/amber/gray
 *      with a per-card status glyph (✓ · ✕ · ⟳ · ⊘ · ⋯) for color-independent scanning.
 *   4. Fixed active-step detection — keep last entry per step (handles parallel fan-out
 *      and duplicate step names); derive running step correctly.
 */
import { useState, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Plus, Shield, Trash2, ChevronRight, Timer } from 'lucide-react'
import { clsx } from 'clsx'
import { api, type THuntPackage, type THPhaseEntry } from '../api/client'
import { useAuth } from '../auth/useAuth'
import HuntPackageWizard from './threat-hunting/HuntPackageWizard'
import HuntDetail from './threat-hunting/HuntDetail'

const STATUS_COLORS: Record<string, string> = {
  draft: 'bg-gray-700/50 text-gray-400',
  planning: 'bg-blue-900/40 text-blue-400',
  approved: 'bg-green-900/40 text-green-400',
  executing: 'bg-yellow-900/40 text-yellow-400',
  completed: 'bg-green-900/40 text-green-400',
  archived: 'bg-gray-800/40 text-gray-600',
}

const STEP_SHORT_LABELS: Record<string, string> = {
  intake_classifier: 'Intake',
  threat_context_builder: 'Context',
  deep_retrohunt_planner: 'Retrohunt',
  hypothesis_generator: 'Hypotheses',
  hunting_lead_planner: 'Leads',
  ttp_analyst: 'TTP',
  query_drafting_agent: 'Queries',
}

const STEP_ORDER = [
  'intake_classifier',
  'threat_context_builder',
  'deep_retrohunt_planner',
  'hypothesis_generator',
  'hunting_lead_planner',
  'ttp_analyst',
  'query_drafting_agent',
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
  const isPending = !phase  // no step_log entry yet

  const hasTools = (phase?.tools_used?.length ?? 0) > 0
  const hasCounts = phase?.item_count != null || phase?.ioc_count != null

  // Status glyph — color-independent at-a-glance indicator
  const glyph = isActive
    ? '⟳'
    : isDone
      ? '✓'
      : isError
        ? '✕'
        : isSkipped
          ? '⊘'
          : '⋯'

  return (
    <div className="flex items-start gap-1.5">
      <div className="flex flex-col">
        {/* ── Card body ── */}
        <div
          className={clsx(
            // fix: bigger — text-[11px], px-2.5 py-1.5, min-w-[68px]
            'px-2.5 py-1.5 rounded text-[11px] font-semibold border transition-colors min-w-[68px] text-center select-none',
            isActive
              ? 'border-blue-400 bg-blue-900/50 text-blue-200 animate-pulse shadow-sm shadow-blue-900'
              : isDone
                ? isPartial
                  ? 'border-amber-500 bg-amber-900/40 text-amber-200'
                  : 'border-green-500 bg-green-900/40 text-green-200'
                : isError
                  ? 'border-red-500 bg-red-900/40 text-red-200'
                  : isSkipped
                    // fix: was text-gray-800 (invisible) → text-gray-500
                    ? 'border-gray-600/50 bg-gray-800/30 text-gray-500 opacity-70'
                    : isPending
                      // fix: was text-gray-800 (invisible) → text-gray-500, dashed border
                      ? 'border-gray-600/40 border-dashed bg-transparent text-gray-500'
                      : 'border-gray-700/40 bg-transparent text-gray-500',
          )}
          title={`${stepId}${phase ? ` — ${phase.status} (${phase.elapsed_s}s)` : ' — pending'}`}
        >
          {/* Glyph + label on one line */}
          <div className="flex items-center justify-center gap-1">
            <span className={clsx(
              'text-[10px] leading-none',
              isActive ? 'text-blue-300' :
              isDone ? isPartial ? 'text-amber-300' : 'text-green-400' :
              isError ? 'text-red-400' :
              'text-gray-600',
            )}>
              {glyph}
            </span>
            <span className="leading-none">{STEP_SHORT_LABELS[stepId] ?? stepId}</span>
          </div>
          {/* Elapsed time */}
          {phase?.elapsed_s != null && phase.elapsed_s > 0 && (
            <span className="block text-[9px] opacity-70 mt-0.5 font-normal">
              {phase.elapsed_s}s
            </span>
          )}
        </div>

        {/* ── Inline detail (done steps only) ── */}
        {isDone && (hasCounts || hasTools) && (
          <div
            className="mt-1 space-y-0.5 max-w-[80px]"
            onClick={(e) => e.stopPropagation()}
          >
            {hasCounts && (
              <div className="flex flex-wrap gap-0.5">
                {phase!.item_count != null && (
                  <span className="text-[9px] font-mono text-brand-400 leading-none">
                    {phase!.item_count} items
                  </span>
                )}
                {phase!.ioc_count != null && (
                  <span className="text-[9px] font-mono text-blue-400 leading-none">
                    {phase!.ioc_count} IOC{phase!.noisy_count ? ` (${phase!.noisy_count}⚠)` : ''}
                  </span>
                )}
              </div>
            )}
            {hasTools && (
              <div className="flex flex-wrap gap-0.5">
                {/* Deduplicate tool names for display */}
                {[...new Set(phase!.tools_used!)].map((t) => (
                  <span
                    key={t}
                    className="text-[9px] font-mono bg-purple-900/40 text-purple-300 border border-purple-700/40 rounded px-1 leading-none"
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

      {/* fix: brighter connector arrow */}
      {!isLast && (
        <ChevronRight className="w-3 h-3 text-gray-600 shrink-0 mt-2.5" />
      )}
    </div>
  )
}

interface ProcessArrowProps {
  pkg: THuntPackage
}

function ProcessArrow({ pkg }: ProcessArrowProps) {
  // fix: keep the LAST entry per step so a re-run ok overrides an earlier error,
  // and parallel steps (threat_context_builder / deep_retrohunt_planner) both appear.
  const phaseByStep: Record<string, THPhaseEntry> = {}
  for (const p of pkg.phases ?? []) {
    // Always overwrite — last entry wins (handles retried / duplicate step names)
    phaseByStep[p.step] = p
  }

  const isRunning = pkg.generation_status === 'running'

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
            'text-[9px] font-mono px-1.5 py-0.5 rounded font-semibold',
            pkg.generation_status === 'completed'
              ? 'bg-green-900/30 text-green-400 border border-green-700/40'
              : pkg.generation_status === 'running'
                ? 'bg-blue-900/30 text-blue-300 border border-blue-700/40'
                : pkg.generation_status === 'awaiting_approval'
                  ? 'bg-amber-900/30 text-amber-300 border border-amber-700/40'
                  : pkg.generation_status === 'error'
                    ? 'bg-red-900/30 text-red-400 border border-red-700/40'
                    : 'bg-gray-800/40 text-gray-500 border border-gray-700/30',
          )}>
            {pkg.generation_status.replace(/_/g, ' ')}
          </span>

          {isRunning && liveElapsed != null ? (
            <span className="flex items-center gap-0.5 text-[9px] text-blue-300 font-mono">
              <Timer className="w-2.5 h-2.5" />
              {liveElapsed}s
            </span>
          ) : pkg.total_elapsed_s != null && !isRunning ? (
            <span className="flex items-center gap-0.5 text-[9px] text-gray-500 font-mono">
              <Timer className="w-2.5 h-2.5" />
              {pkg.total_elapsed_s}s total
            </span>
          ) : null}
        </div>
      )}

      {/* Phase rail — always rendered */}
      <div className="flex items-start flex-wrap gap-1">
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
        <p className="text-[9px] text-gray-600 mt-1">No analysis run yet</p>
      )}
    </div>
  )
}

export default function ThreatHunting() {
  const { isResearcher } = useAuth()
  const qc = useQueryClient()
  const [showWizard, setShowWizard] = useState(false)
  const [selectedId, setSelectedId] = useState<string | null>(null)

  const { data: packages = [], isLoading } = useQuery({
    queryKey: ['th-packages'],
    queryFn: api.threatHunting.listPackages,
    // fix: poll every 4s while any package is running; stop when all idle.
    refetchInterval: (query) => {
      const data = query.state.data as THuntPackage[] | undefined
      const anyRunning = (data ?? []).some(
        (p) => p.generation_status === 'running',
      )
      return anyRunning ? 4000 : false
    },
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
              className="card cursor-pointer hover:bg-gray-800/60 transition-colors"
              onClick={() => setSelectedId(pkg.id)}
            >
              <div className="flex items-start gap-4">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <p className="text-sm font-medium text-gray-100 truncate">{pkg.name}</p>
                    <span className={clsx('badge text-[10px] px-1.5 py-0.5 rounded', STATUS_COLORS[pkg.status] ?? STATUS_COLORS.draft)}>
                      {pkg.status}
                    </span>
                    {pkg.generation_status && pkg.generation_status !== 'completed' && (
                      <span className="badge text-[9px] px-1.5 py-0.5 rounded bg-blue-900/30 text-blue-400 border border-blue-800/30">
                        {pkg.generation_status.replace(/_/g, ' ')}
                      </span>
                    )}
                  </div>
                  {pkg.description && (
                    <p className="text-xs text-gray-500 truncate mt-0.5">{pkg.description}</p>
                  )}
                  <p className="text-[10px] text-gray-600 mt-1">
                    {pkg.evidence_count} evidence item{pkg.evidence_count !== 1 ? 's' : ''} ·{' '}
                    {new Date(pkg.created_at).toLocaleDateString()}
                  </p>
                  <ProcessArrow pkg={pkg} />
                </div>
                <div className="flex items-center gap-2 shrink-0">
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
