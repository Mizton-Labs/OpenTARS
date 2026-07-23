/**
 * PipelineStepper — issue-local-015
 *
 * Horizontal, arrow-connected progress blocks for the hunt package's
 * coarse, user-facing phases — Evidence → IOC → Analysis → Execution →
 * Report — matching HuntDetail's own tabs. This intentionally does NOT
 * show the ~16 granular LangGraph node names (see WorkflowVisualizer.tsx
 * for that view, inside the Analysis tab) — an earlier version of this
 * component did, but that read as noise rather than a status overview.
 */

import { ArrowRight, CheckCircle, Loader2, XCircle } from 'lucide-react'
import { clsx } from 'clsx'
import type { THGenerationRecord } from '../../api/client'

type PhaseState = 'done' | 'active' | 'error' | 'pending'

const ANALYSIS_STEPS = new Set([
  'threat_context_builder',
  'deep_retrohunt_planner',
  'hypothesis_generator',
  'hunting_lead_planner',
  'ttp_analyst',
  'query_drafting_agent',
])

function derivePhases(
  genRecord: THGenerationRecord | undefined,
  hasEvidence: boolean,
  hasResults: boolean,
  hasReport: boolean,
): { id: string; label: string; state: PhaseState }[] {
  const status = genRecord?.generation_status
  const currentStep = genRecord?.current_step ?? ''
  const completed = genRecord?.completed_steps ?? []
  const analysisDone = status === 'awaiting_approval' || status === 'approved' || status === 'completed'
  const failed = status === 'error'

  return [
    {
      id: 'evidence',
      label: 'Evidence',
      state: hasEvidence ? 'done' : 'active',
    },
    {
      id: 'ioc',
      label: 'IOC',
      state: completed.includes('intake_classifier')
        ? 'done'
        : currentStep === 'intake_classifier'
          ? 'active'
          : failed && !completed.length
            ? 'error'
            : 'pending',
    },
    {
      id: 'analysis',
      label: 'Analysis',
      state: analysisDone
        ? 'done'
        : failed
          ? 'error'
          : status === 'running' && ANALYSIS_STEPS.has(currentStep)
            ? 'active'
            : 'pending',
    },
    {
      id: 'execution',
      label: 'Execution',
      state: hasResults ? 'done' : status === 'executing' ? 'active' : 'pending',
    },
    {
      id: 'report',
      label: 'Report',
      state: hasReport ? 'done' : status === 'reporting' ? 'active' : 'pending',
    },
  ]
}

export default function PipelineStepper({
  genRecord,
  hasEvidence,
  hasResults,
  hasReport,
}: {
  genRecord: THGenerationRecord | undefined
  hasEvidence: boolean
  hasResults: boolean
  hasReport: boolean
}) {
  const phases = derivePhases(genRecord, hasEvidence, hasResults, hasReport)

  return (
    <div className="flex items-center gap-0.5 overflow-x-auto py-1">
      {phases.map((phase, idx) => {
        const isLast = idx === phases.length - 1
        return (
          <div key={phase.id} className="flex items-center shrink-0">
            <div
              className={clsx(
                'flex items-center gap-1.5 px-3 py-1.5 rounded-md border text-[11px] font-medium whitespace-nowrap transition-colors',
                phase.state === 'done' && 'bg-green-900/20 border-green-800/40 text-green-400',
                phase.state === 'error' && 'bg-red-900/20 border-red-800/40 text-red-400',
                phase.state === 'active' && 'bg-blue-900/20 border-blue-700/50 text-blue-300',
                phase.state === 'pending' && 'bg-gray-800/30 border-gray-700/40 text-gray-600',
              )}
            >
              {phase.state === 'done' && <CheckCircle className="w-3.5 h-3.5 shrink-0" />}
              {phase.state === 'error' && <XCircle className="w-3.5 h-3.5 shrink-0" />}
              {phase.state === 'active' && <Loader2 className="w-3.5 h-3.5 shrink-0 animate-spin" />}
              {phase.label}
            </div>
            {!isLast && (
              <ArrowRight
                className={clsx(
                  'w-3.5 h-3.5 mx-1 shrink-0',
                  phase.state === 'done' ? 'text-green-700' : 'text-gray-700',
                )}
              />
            )}
          </div>
        )
      })}
    </div>
  )
}
