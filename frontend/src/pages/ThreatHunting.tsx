/**
 * ThreatHunting — hunt package list page.
 *
 * issue-006-D: process-arrow card with horizontal phase button-cards showing
 * per-step status (green=done, red=error, pulse=active, gray=pending) and
 * total elapsed time. Gracefully falls back to a simple card when no run data.
 */
import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Plus, Shield, Trash2, ChevronRight, Timer, ChevronDown } from 'lucide-react'
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
  const [expanded, setExpanded] = useState(false)
  const isActive = currentStep === stepId
  const isDone = phase?.status === 'ok' || phase?.status === 'partial'
  const isError = phase?.status === 'error'
  const isSkipped = phase?.status === 'skipped'

  // Only show expand button when there's richer data to show
  const hasDetail =
    (phase?.tools_used?.length ?? 0) > 0 ||
    !!phase?.decision ||
    phase?.item_count != null ||
    phase?.ioc_count != null

  return (
    <div className="flex items-start gap-1">
      <div className="flex flex-col">
        <button
          type="button"
          onClick={(e) => {
            e.stopPropagation()
            if (hasDetail) setExpanded((v) => !v)
          }}
          className={clsx(
            'px-2 py-1 rounded text-[9px] font-medium border transition-colors min-w-[48px] text-center',
            hasDetail ? 'cursor-pointer' : 'cursor-default',
            isActive
              ? 'border-blue-500 bg-blue-900/20 text-blue-300 animate-pulse'
              : isDone
                ? 'border-green-700/50 bg-green-900/20 text-green-400'
                : isError
                  ? 'border-red-700/50 bg-red-900/20 text-red-400'
                  : isSkipped
                    ? 'border-gray-700/30 bg-gray-900/10 text-gray-600'
                    : 'border-gray-800/40 bg-transparent text-gray-700',
          )}
          title={`${stepId}${phase ? ` — ${phase.status} (${phase.elapsed_s}s)` : ''}${hasDetail ? ' — click to expand' : ''}`}
        >
          <div className="flex items-center justify-center gap-0.5">
            <span>{STEP_SHORT_LABELS[stepId] ?? stepId}</span>
            {hasDetail && (
              <ChevronDown
                className={clsx('w-2 h-2 transition-transform', expanded && 'rotate-180')}
              />
            )}
          </div>
          {phase?.elapsed_s != null && (
            <span className="block text-[8px] opacity-60">{phase.elapsed_s}s</span>
          )}
        </button>

        {/* Expanded detail panel */}
        {expanded && phase && (
          <div
            className="mt-1 rounded border border-gray-700/50 bg-gray-900/60 px-2 py-1.5 space-y-1 min-w-[120px] max-w-[200px] z-10"
            onClick={(e) => e.stopPropagation()}
          >
            {/* Counts */}
            {(phase.item_count != null || phase.ioc_count != null) && (
              <div className="flex flex-wrap gap-1">
                {phase.item_count != null && (
                  <span className="text-[8px] font-mono text-brand-400">
                    {phase.item_count} items
                  </span>
                )}
                {phase.ioc_count != null && (
                  <span className="text-[8px] font-mono text-blue-400">
                    {phase.ioc_count} IOCs
                    {phase.noisy_count ? ` (${phase.noisy_count} noisy)` : ''}
                  </span>
                )}
              </div>
            )}
            {/* Tools used */}
            {(phase.tools_used?.length ?? 0) > 0 && (
              <div className="flex flex-wrap gap-0.5">
                {phase.tools_used!.map((t) => (
                  <span
                    key={t}
                    className="text-[8px] font-mono bg-purple-900/30 text-purple-300 border border-purple-800/30 rounded px-1"
                  >
                    {t}
                  </span>
                ))}
              </div>
            )}
            {/* Decision text */}
            {phase.decision && (
              <p className="text-[8px] text-gray-500 italic leading-relaxed">
                {phase.decision.slice(0, 120)}
                {phase.decision.length > 120 ? '…' : ''}
              </p>
            )}
          </div>
        )}
      </div>
      {!isLast && (
        <ChevronRight className="w-2.5 h-2.5 text-gray-700 shrink-0 mt-2" />
      )}
    </div>
  )
}

interface ProcessArrowProps {
  pkg: THuntPackage
}

function ProcessArrow({ pkg }: ProcessArrowProps) {
  if (!pkg.phases?.length) return null

  const phaseByStep: Record<string, THPhaseEntry> = {}
  for (const p of pkg.phases) {
    phaseByStep[p.step] = p
  }

  // Derive current step from generation_status (running packages may still be active)
  const runningStep =
    pkg.generation_status === 'running'
      ? STEP_ORDER.find((s) => !phaseByStep[s])
      : null

  return (
    <div className="mt-2">
      <div className="flex items-start flex-wrap gap-0.5">
        {STEP_ORDER.map((stepId, i) => (
          <PhaseCard
            key={stepId}
            phase={phaseByStep[stepId]}
            stepId={stepId}
            currentStep={runningStep ?? null}
            isLast={i === STEP_ORDER.length - 1}
          />
        ))}
      </div>
      {pkg.total_elapsed_s != null && (
        <div className="flex items-center gap-1 mt-1">
          <Timer className="w-2.5 h-2.5 text-gray-600" />
          <span className="text-[9px] text-gray-600 font-mono">
            {pkg.total_elapsed_s}s total
          </span>
        </div>
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
