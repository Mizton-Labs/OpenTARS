/**
 * ThreatHunting — hunt package list page.
 *
 * issue-006-D: process-arrow card with horizontal phase button-cards showing
 * per-step status (green=done, red=error, pulse=active, gray=pending) and
 * total elapsed time. Gracefully falls back to a simple card when no run data.
 */
import { useState, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Plus, Shield, Trash2, ChevronRight, Timer } from 'lucide-react'
import { clsx } from 'clsx'
import { api, type THuntPackage, type THPhaseEntry } from '../api/client'
import { useAuth } from '../auth/useAuth'
import HuntPackageWizard from './threat-hunting/HuntPackageWizard'
import HuntDetail from './threat-hunting/HuntDetail'

// issue-006-D: completed mapped to green (was brand)
const STATUS_COLORS: Record<string, string> = {
  draft: 'bg-gray-700/50 text-gray-400',
  planning: 'bg-blue-900/40 text-blue-400',
  approved: 'bg-green-900/40 text-green-400',
  executing: 'bg-yellow-900/40 text-yellow-400',
  completed: 'bg-green-900/40 text-green-400',
  archived: 'bg-gray-800/40 text-gray-600',
}

// Abbreviated step labels for the process-arrow cards
const STEP_SHORT_LABELS: Record<string, string> = {
  intake_classifier: 'Intake',
  threat_context_builder: 'Context',
  deep_retrohunt_planner: 'Retrohunt',
  hypothesis_generator: 'Hypotheses',
  hunting_lead_planner: 'Leads',
  ttp_analyst: 'TTP',
  query_drafting_agent: 'Queries',
}

// Canonical step order (drives the horizontal arrows even if phases is shorter)
const STEP_ORDER = [
  'intake_classifier',
  'threat_context_builder',
  'deep_retrohunt_planner',
  'hypothesis_generator',
  'hunting_lead_planner',
  'ttp_analyst',
  'query_drafting_agent',
]

interface PhaseCardProps {
  phase: THPhaseEntry | undefined
  stepId: string
  currentStep: string | null | undefined
  isLast: boolean
}

function PhaseCard({ phase, stepId, currentStep, isLast }: PhaseCardProps) {
  const isActive = currentStep === stepId
  const isDone = phase?.status === 'ok' || phase?.status === 'partial'
  const isError = phase?.status === 'error'
  const isSkipped = phase?.status === 'skipped'
  const isPending = !phase  // no step_log entry yet → pending/not-started

  // issue-008-2A: inline tools + counts always visible on done steps (not click-to-expand)
  const hasTools = (phase?.tools_used?.length ?? 0) > 0
  const hasCounts = phase?.item_count != null || phase?.ioc_count != null

  return (
    <div className="flex items-start gap-1">
      <div className="flex flex-col">
        <div
          className={clsx(
            'px-2 py-1 rounded text-[9px] font-medium border transition-colors min-w-[52px] text-center',
            isActive
              ? 'border-blue-500 bg-blue-900/20 text-blue-300 animate-pulse'
              : isDone
                ? 'border-green-700/50 bg-green-900/20 text-green-400'
                : isError
                  ? 'border-red-700/50 bg-red-900/20 text-red-400'
                  : isSkipped
                    ? 'border-gray-700/30 bg-gray-900/10 text-gray-600'
                    : isPending
                      ? 'border-gray-800/30 bg-transparent text-gray-800'
                      : 'border-gray-800/40 bg-transparent text-gray-700',
          )}
          title={`${stepId}${phase ? ` — ${phase.status} (${phase.elapsed_s}s)` : ' — pending'}`}
        >
          <span>{STEP_SHORT_LABELS[stepId] ?? stepId}</span>
          {phase?.elapsed_s != null && (
            <span className="block text-[8px] opacity-60">{phase.elapsed_s}s</span>
          )}
        </div>

        {/* issue-008-2A: inline detail always visible when done (not click-to-expand) */}
        {isDone && (hasCounts || hasTools) && (
          <div className="mt-0.5 space-y-0.5 max-w-[80px]" onClick={(e) => e.stopPropagation()}>
            {hasCounts && (
              <div className="flex flex-wrap gap-0.5">
                {phase!.item_count != null && (
                  <span className="text-[7px] font-mono text-brand-400 leading-none">
                    {phase!.item_count}items
                  </span>
                )}
                {phase!.ioc_count != null && (
                  <span className="text-[7px] font-mono text-blue-400 leading-none">
                    {phase!.ioc_count}ioc{phase!.noisy_count ? `(${phase!.noisy_count}⚠)` : ''}
                  </span>
                )}
              </div>
            )}
            {hasTools && (
              <div className="flex flex-wrap gap-0.5">
                {phase!.tools_used!.map((t) => (
                  <span
                    key={t}
                    className="text-[7px] font-mono bg-purple-900/30 text-purple-400 border border-purple-800/20 rounded px-0.5 leading-none"
                    title={t}
                  >
                    {t.slice(0, 8)}
                  </span>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
      {!isLast && (
        <ChevronRight className="w-2.5 h-2.5 text-gray-800 shrink-0 mt-2" />
      )}
    </div>
  )
}

interface ProcessArrowProps {
  pkg: THuntPackage
}

function ProcessArrow({ pkg }: ProcessArrowProps) {
  // issue-008-2A: always render the 7-step rail, even for draft/never-run packages
  const phaseByStep: Record<string, THPhaseEntry> = {}
  for (const p of pkg.phases ?? []) {
    phaseByStep[p.step] = p
  }

  // Derive current step (first STEP_ORDER entry with no log yet)
  const isRunning = pkg.generation_status === 'running'
  const runningStep = isRunning ? (STEP_ORDER.find((s) => !phaseByStep[s]) ?? null) : null

  // issue-008-2A: live elapsed timer for in-progress runs
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
      {/* Status line */}
      {pkg.generation_status && (
        <div className="flex items-center gap-1 mb-1">
          <span className={clsx(
            'text-[8px] font-mono px-1 py-0.5 rounded',
            pkg.generation_status === 'completed' ? 'bg-green-900/20 text-green-500' :
            pkg.generation_status === 'running' ? 'bg-blue-900/20 text-blue-400' :
            pkg.generation_status === 'awaiting_approval' ? 'bg-amber-900/20 text-amber-400' :
            pkg.generation_status === 'error' ? 'bg-red-900/20 text-red-400' :
            'bg-gray-800/30 text-gray-600',
          )}>
            {pkg.generation_status.replace(/_/g, ' ')}
          </span>
          {/* Live timer (running) or total (finished) */}
          {isRunning && liveElapsed != null ? (
            <span className="flex items-center gap-0.5 text-[8px] text-blue-400 font-mono">
              <Timer className="w-2 h-2" />
              {liveElapsed}s
            </span>
          ) : pkg.total_elapsed_s != null && !isRunning ? (
            <span className="flex items-center gap-0.5 text-[8px] text-gray-600 font-mono">
              <Timer className="w-2 h-2" />
              {pkg.total_elapsed_s}s
            </span>
          ) : null}
        </div>
      )}

      {/* Phase rail — always rendered (all-pending when no run yet) */}
      <div className="flex items-start flex-wrap gap-0.5">
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

      {/* Never-run hint */}
      {!hasAnyData && (
        <p className="text-[8px] text-gray-700 mt-1">No analysis run yet</p>
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
                  <div className="flex items-center gap-2">
                    <p className="text-sm font-medium text-gray-100 truncate">{pkg.name}</p>
                    <span className={clsx('badge text-[10px] px-1.5 py-0.5 rounded', STATUS_COLORS[pkg.status] ?? STATUS_COLORS.draft)}>
                      {pkg.status}
                    </span>
                    {/* generation_status badge (only when different from package status) */}
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
                  {/* issue-006-D: process-arrow (only when run data exists) */}
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
