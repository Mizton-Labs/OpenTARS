/**
 * ComparisonProgress — issue-local-035 follow-up.
 *
 * Horizontal, arrow-connected progress blocks for a background comparison
 * job's four stages, matching PipelineStepper.tsx's visual grammar (same
 * markup shape, same done/active/error/pending color language) so this
 * reads as the same kind of "background job progress" the rest of the
 * platform already uses for hunt generation runs, not a bespoke widget.
 */
import { ArrowRight, CheckCircle, Loader2, XCircle } from 'lucide-react'
import { clsx } from 'clsx'
import type { THComparisonJob, THComparisonJobStep } from '../../api/client'

type StepState = 'done' | 'active' | 'error' | 'pending'

const STEPS: { id: THComparisonJobStep; label: string }[] = [
  { id: 'loading_runs', label: 'Loading Runs' },
  { id: 'building_tables', label: 'Building Tables' },
  { id: 'generating_narrative', label: 'Generating Narrative' },
  { id: 'finalizing', label: 'Finalizing' },
]

function deriveSteps(job: THComparisonJob): { id: string; label: string; state: StepState }[] {
  const currentIdx = STEPS.findIndex((s) => s.id === job.current_step)
  return STEPS.map((step, idx) => {
    let state: StepState = 'pending'
    if (job.status === 'completed') {
      state = 'done'
    } else if (job.status === 'error') {
      state = idx < currentIdx ? 'done' : idx === currentIdx ? 'error' : 'pending'
    } else if (idx < currentIdx) {
      state = 'done'
    } else if (idx === currentIdx) {
      state = 'active'
    }
    return { id: step.id, label: step.label, state }
  })
}

export default function ComparisonProgress({ job }: { job: THComparisonJob }) {
  const steps = deriveSteps(job)
  return (
    <div className="card space-y-2">
      <div className="flex items-center justify-between">
        <span className="text-sm font-medium text-gray-200">
          {job.status === 'error' ? 'Comparison failed' : 'Comparison in progress…'}
        </span>
        <span className="text-[11px] text-gray-500">
          {job.phase === 'preliminary' ? 'Preliminary Analysis' : 'Full Assessment'}
        </span>
      </div>
      <div className="flex items-center gap-0.5 overflow-x-auto py-1">
        {steps.map((step, idx) => {
          const isLast = idx === steps.length - 1
          return (
            <div key={step.id} className="flex items-center shrink-0">
              <div
                className={clsx(
                  'flex items-center gap-1.5 px-3 py-1.5 rounded-md border text-[12px] font-medium whitespace-nowrap transition-colors',
                  step.state === 'done' && 'bg-green-900/20 border-green-800/40 text-green-400',
                  step.state === 'error' && 'bg-red-900/20 border-red-800/40 text-red-400',
                  step.state === 'active' && 'bg-blue-900/20 border-blue-700/50 text-blue-300',
                  step.state === 'pending' && 'bg-gray-800/30 border-gray-700/40 text-gray-600',
                )}
              >
                {step.state === 'done' && <CheckCircle className="w-3.5 h-3.5 shrink-0" />}
                {step.state === 'error' && <XCircle className="w-3.5 h-3.5 shrink-0" />}
                {step.state === 'active' && <Loader2 className="w-3.5 h-3.5 shrink-0 animate-spin" />}
                {step.label}
              </div>
              {!isLast && (
                <ArrowRight
                  className={clsx(
                    'w-3.5 h-3.5 mx-1 shrink-0',
                    step.state === 'done' ? 'text-green-700' : 'text-gray-700',
                  )}
                />
              )}
            </div>
          )
        })}
      </div>
      {job.status === 'error' && job.error_message && (
        <p className="text-[11px] text-red-300">{job.error_message}</p>
      )}
    </div>
  )
}
