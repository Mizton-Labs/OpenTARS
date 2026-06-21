/**
 * WorkflowVisualizer — issue-local-004
 *
 * Renders the live agent pipeline during a generation run.
 * Reads the global verbosity + visualization settings and renders accordingly.
 *
 * Verbosity levels:
 *   info    — compact checklist (current behavior)
 *   verbose — animated pipeline card: per-step status, tools, timing, item counts
 *   debug   — verbose view + a live scoped log textbox at the bottom
 *
 * Visualization styles (only for verbose/debug):
 *   timeline  — animated vertical step list (no extra deps)
 *   mermaid   — live Mermaid flowchart (lazy-loaded)
 *   reactflow — interactive ReactFlow graph (lazy-loaded)
 */

import { lazy, Suspense, useEffect, useRef } from 'react'
import {
  CheckCircle,
  Loader2,
  XCircle,
  Clock,
  SkipForward,
  AlertCircle,
} from 'lucide-react'
import { clsx } from 'clsx'
import { useQuery } from '@tanstack/react-query'
import { api, type THGenerationRecord, type THStepLog } from '../../api/client'

// ── Lazy-loaded visualizers ───────────────────────────────────────────────────

const MermaidVisualizer = lazy(() => import('./MermaidVisualizer'))
const ReactFlowVisualizer = lazy(() => import('./ReactFlowVisualizer'))

// ── Pipeline step metadata ────────────────────────────────────────────────────

const PIPELINE_STEPS = [
  { id: 'intake_classifier',       label: 'Intake Classifier',       description: 'Loads evidence, builds corpus, extracts IOC summary' },
  { id: 'threat_context_builder',  label: 'Threat Context Builder',  description: 'Produces structured threat actor/campaign context' },
  { id: 'deep_retrohunt_planner',  label: 'Deep Retrohunt Planner',  description: 'Sanitizes IOCs, noise-scores, drafts SPL macro' },
  { id: 'hypothesis_generator',    label: 'Hypothesis Generator',    description: 'Generates actionable hunting hypotheses' },
  { id: 'hunting_lead_planner',    label: 'Hunting Lead Planner',    description: 'Converts hypotheses into concrete hunting leads' },
  { id: 'ttp_analyst',             label: 'TTP Analyst',             description: 'Maps evidence to MITRE ATT&CK techniques' },
  { id: 'query_drafting_agent',    label: 'Query Drafting Agent',    description: 'Drafts SPL, KQL, and ES DSL SIEM queries' },
]

// ── Step log icon ─────────────────────────────────────────────────────────────

function StepIcon({ log, active }: { log?: THStepLog; active: boolean }) {
  if (!log && active) return <Loader2 className="w-4 h-4 text-blue-400 animate-spin shrink-0" />
  if (!log) return <div className="w-4 h-4 rounded-full border border-gray-700 shrink-0" />
  if (log.status === 'ok') return <CheckCircle className="w-4 h-4 text-green-400 shrink-0" />
  if (log.status === 'partial') return <AlertCircle className="w-4 h-4 text-amber-400 shrink-0" />
  if (log.status === 'skipped') return <SkipForward className="w-4 h-4 text-gray-500 shrink-0" />
  if (log.status === 'error') return <XCircle className="w-4 h-4 text-red-400 shrink-0" />
  return <Clock className="w-4 h-4 text-gray-500 shrink-0" />
}

// ── Timeline view ─────────────────────────────────────────────────────────────

function TimelineVisualizer({
  genRecord,
  debug,
}: {
  genRecord: THGenerationRecord
  debug: boolean
}) {
  const stepLogs: Record<string, THStepLog> = {}
  for (const log of genRecord.step_logs ?? []) {
    stepLogs[log.step] = log
  }
  const completed = genRecord.completed_steps ?? []
  const currentStep = genRecord.current_step ?? ''

  const allDebugLines: string[] = []
  for (const step of PIPELINE_STEPS) {
    const log = stepLogs[step.id]
    if (log?.debug_lines?.length) {
      allDebugLines.push(`=== ${step.label} ===`)
      allDebugLines.push(...log.debug_lines)
    }
  }

  const debugRef = useRef<HTMLPreElement>(null)
  useEffect(() => {
    if (debug && debugRef.current) {
      debugRef.current.scrollTop = debugRef.current.scrollHeight
    }
  }, [allDebugLines.length, debug])

  return (
    <div className="space-y-4">
      <div className="space-y-1">
        {PIPELINE_STEPS.map((step) => {
          const log = stepLogs[step.id]
          const isActive = currentStep === step.id
          const isDone = completed.includes(step.id)

          return (
            <div
              key={step.id}
              className={clsx(
                'rounded-lg border px-3 py-2 transition-colors',
                isActive
                  ? 'border-blue-700/50 bg-blue-900/10'
                  : isDone
                    ? log?.status === 'error'
                      ? 'border-red-800/30 bg-red-900/5'
                      : 'border-green-800/20 bg-green-900/5'
                    : 'border-gray-800/50 bg-transparent',
              )}
            >
              <div className="flex items-start gap-2">
                <StepIcon log={log} active={isActive} />
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span
                      className={clsx(
                        'text-xs font-medium',
                        isActive ? 'text-blue-300' : isDone ? 'text-gray-200' : 'text-gray-600',
                      )}
                    >
                      {step.label}
                    </span>
                    {log?.elapsed_s !== undefined && (
                      <span className="text-[10px] text-gray-600 font-mono">
                        {log.elapsed_s}s
                      </span>
                    )}
                    {log?.item_count !== undefined && (
                      <span className="text-[10px] text-brand-600 font-mono">
                        {log.item_count} items
                      </span>
                    )}
                    {log?.ioc_count !== undefined && (
                      <span className="text-[10px] text-brand-600 font-mono">
                        {log.ioc_count} IOCs
                        {log.noisy_count ? ` (${log.noisy_count} noisy)` : ''}
                      </span>
                    )}
                    {log?.effort && (
                      <span className="text-[10px] text-gray-700 font-mono">
                        effort={log.effort}
                      </span>
                    )}
                  </div>
                  {isActive && (
                    <p className="text-[10px] text-gray-500 mt-0.5">{step.description}</p>
                  )}
                  {log?.error && (
                    <p className="text-[10px] text-red-400 mt-0.5">Error: {log.error}</p>
                  )}
                </div>
              </div>
            </div>
          )
        })}
      </div>

      {/* Debug log panel */}
      {debug && (
        <div className="space-y-1">
          <p className="text-[10px] text-gray-500 font-semibold uppercase tracking-wider">
            Pipeline Log
          </p>
          <pre
            ref={debugRef}
            className="bg-gray-950 border border-gray-800 rounded p-2 text-[9px] text-green-400 font-mono h-48 overflow-y-auto whitespace-pre-wrap"
          >
            {allDebugLines.length > 0
              ? allDebugLines.join('\n')
              : '(No log lines yet. Lines will appear here as steps complete.)'}
          </pre>
        </div>
      )}
    </div>
  )
}

// ── Main component ────────────────────────────────────────────────────────────

interface WorkflowVisualizerProps {
  genRecord: THGenerationRecord
  /** Compact mode: show minimal info (used in Info verbosity). */
  compact?: boolean
}

export default function WorkflowVisualizer({ genRecord, compact = false }: WorkflowVisualizerProps) {
  // Load verbosity + visualization settings (cached — low frequency)
  const { data: verbosityData } = useQuery({
    queryKey: ['agent-verbosity'],
    queryFn: () => api.getAgentVerbosity(),
    staleTime: 30_000,
  })
  const { data: vizData } = useQuery({
    queryKey: ['agent-visualization'],
    queryFn: () => api.getAgentVisualization(),
    staleTime: 30_000,
  })

  const verbosity = (verbosityData?.agent_workflow_verbosity ?? 'info') as 'info' | 'verbose' | 'debug'
  const visualization = (vizData?.agent_workflow_visualization ?? 'timeline') as 'timeline' | 'mermaid' | 'reactflow'

  const completed = genRecord.completed_steps ?? []
  const currentStep = genRecord.current_step ?? ''

  // Info / compact — minimal checklist (existing behavior)
  if (compact || verbosity === 'info') {
    return (
      <div className="space-y-1.5">
        {PIPELINE_STEPS.map((step) => {
          const isDone = completed.includes(step.id)
          const isActive = currentStep === step.id
          return (
            <div
              key={step.id}
              className={clsx(
                'flex items-center gap-2 text-xs',
                isDone ? 'text-green-400' : isActive ? 'text-blue-400' : 'text-gray-600',
              )}
            >
              {isDone ? (
                <CheckCircle className="w-3.5 h-3.5" />
              ) : isActive ? (
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
              ) : (
                <div className="w-3.5 h-3.5 rounded-full border border-gray-700" />
              )}
              {step.label}
            </div>
          )
        })}
      </div>
    )
  }

  // Verbose / Debug
  const debug = verbosity === 'debug'

  if (visualization === 'mermaid') {
    return (
      <div className="space-y-3">
        <Suspense
          fallback={
            <div className="flex items-center gap-2 text-xs text-gray-500">
              <Loader2 className="w-3.5 h-3.5 animate-spin" />
              Loading Mermaid diagram…
            </div>
          }
        >
          <MermaidVisualizer genRecord={genRecord} />
        </Suspense>
        {debug && (
          <TimelineVisualizer genRecord={genRecord} debug />
        )}
      </div>
    )
  }

  if (visualization === 'reactflow') {
    return (
      <div className="space-y-3">
        <Suspense
          fallback={
            <div className="flex items-center gap-2 text-xs text-gray-500">
              <Loader2 className="w-3.5 h-3.5 animate-spin" />
              Loading React Flow graph…
            </div>
          }
        >
          <ReactFlowVisualizer genRecord={genRecord} />
        </Suspense>
        {debug && (
          <TimelineVisualizer genRecord={genRecord} debug />
        )}
      </div>
    )
  }

  // Default: timeline
  return <TimelineVisualizer genRecord={genRecord} debug={debug} />
}
