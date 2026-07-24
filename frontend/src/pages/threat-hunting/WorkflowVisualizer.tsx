/**
 * WorkflowVisualizer — issue-local-004 / issue-006-C
 *
 * Renders the live agent pipeline during a generation run.
 * Reads the global verbosity + visualization settings and renders accordingly.
 *
 * Verbosity levels:
 *   info    — compact checklist
 *   verbose — 2-col layout: task list LEFT, diagram card RIGHT (issue-006-C)
 *   debug   — verbose view + a live scoped log textbox at the bottom
 *
 * Visualization styles (only for verbose/debug):
 *   timeline  — animated vertical step list (no extra deps)
 *   mermaid   — live Mermaid flowchart (lazy-loaded)
 *   reactflow — interactive ReactFlow graph (lazy-loaded)
 *
 * issue-006-C additions:
 *   - tools_used pills per step in timeline view
 *   - decision sub-text per step in timeline view
 *   - 2-col layout: always-visible compact task list on left + diagram on right
 *
 * Current additions (Part 1b):
 *   - showSubtasks toggle toolbar row above diagram
 *   - passes showSubtasks prop to MermaidVisualizer / ReactFlowVisualizer
 */

import { lazy, Suspense, useEffect, useRef, useState } from 'react'
import {
  CheckCircle,
  Loader2,
  XCircle,
  Clock,
  SkipForward,
  AlertCircle,
  ArrowRight,
} from 'lucide-react'
import { clsx } from 'clsx'
import { useQuery } from '@tanstack/react-query'
import { api, type THGenerationRecord, type THStepLog, type THIntakeSource } from '../../api/client'

// ── Lazy-loaded visualizers ───────────────────────────────────────────────────

const MermaidVisualizer = lazy(() => import('./MermaidVisualizer'))
const ReactFlowVisualizer = lazy(() => import('./ReactFlowVisualizer'))

// ── Pipeline step metadata ────────────────────────────────────────────────────

const PIPELINE_STEPS = [
  // ── LangGraph pipeline ──────────────────────────────────────────────────────
  { id: 'intake_classifier',       label: 'Intake Classifier',       description: 'Loads evidence, builds corpus, extracts IOC summary' },
  { id: 'threat_context_builder',  label: 'Threat Context Builder',  description: 'Produces structured threat actor/campaign context' },
  { id: 'deep_retrohunt_planner',  label: 'Deep Retrohunt Planner',  description: 'Sanitizes IOCs, noise-scores, drafts SPL macro' },
  { id: 'hypothesis_generator',    label: 'Hypothesis Generator',    description: 'Generates actionable hunting hypotheses' },
  { id: 'hunting_lead_planner',    label: 'Hunting Lead Planner',    description: 'Converts hypotheses into concrete hunting leads' },
  { id: 'ttp_analyst',             label: 'TTP Analyst',             description: 'Maps evidence to MITRE ATT&CK techniques' },
  { id: 'query_drafting_agent',    label: 'Query Drafting Agent',    description: 'Drafts SPL, KQL, and ES DSL SIEM queries' },
  // ── SIEM execution (issue-local-009) ────────────────────────────────────────
  { id: 'siem_connect',            label: 'SIEM Connect',            description: 'Builds and verifies the SIEM connector' },
  { id: 'siem_submit',             label: 'SIEM Submit',             description: 'Submits SPL retrohunt search, obtains job SID' },
  { id: 'siem_poll',               label: 'SIEM Poll',               description: 'Polls search job until complete, tracks progress' },
  { id: 'siem_fetch',              label: 'SIEM Fetch',              description: 'Retrieves result rows from completed search job' },
  { id: 'siem_interpret',          label: 'SIEM Interpret',          description: 'LLM interprets SIEM results into plain findings' },
  // ── Report generation (issue-local-009) ─────────────────────────────────────
  { id: 'report_assemble',         label: 'Assemble Report',         description: 'Loads all hunt data and assembles report structure' },
  { id: 'report_exec_summary',     label: 'Exec Summary',            description: 'LLM generates executive summary for stakeholders' },
  { id: 'report_findings',         label: 'Findings',                description: 'LLM generates detailed Findings/Conclusion section' },
  { id: 'report_render',           label: 'Render Report',           description: 'Renders and persists PDF and Markdown formats' },
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

// ── Per-evidence sub-status dot ───────────────────────────────────────────────

function IntakeSourceSubStatus({ src }: { src: THIntakeSource }) {
  const s = src.sub_status
  const dotClass =
    s === 'ok'
      ? 'bg-green-500'
      : s === 'error'
        ? 'bg-red-500'
        : s === 'partial'
          ? 'bg-amber-400'
          : s === 'pending'
            ? 'bg-blue-500 animate-pulse'
            : 'bg-gray-600'
  return (
    <div className="flex items-center gap-2 py-0.5">
      <div className="w-1.5 flex justify-center shrink-0">
        <div className={clsx('w-1.5 h-1.5 rounded-full shrink-0', dotClass)} />
      </div>
      <span className="text-[11px] text-gray-400 truncate flex-1 min-w-0">
        {src.label || src.item_type || 'source'}
      </span>
      <span className="text-[10px] text-gray-600 font-mono shrink-0 ml-1">
        {src.item_type}
      </span>
      {src.text_length > 0 && (
        <span className="text-[10px] text-gray-700 font-mono shrink-0">
          {src.text_length.toLocaleString()} chars
        </span>
      )}
      {src.ioc_count != null && src.ioc_count > 0 && (
        <span className="text-[10px] text-blue-500 font-mono shrink-0">
          {src.ioc_count} IOC{src.ioc_count !== 1 ? 's' : ''}
        </span>
      )}
      {src.parser_used && (
        <span className="text-[10px] font-mono bg-gray-800 text-gray-500 border border-gray-700/50 rounded px-1 shrink-0">
          {src.parser_used}
        </span>
      )}
    </div>
  )
}

// ── Timeline view ─────────────────────────────────────────────────────────────

function TimelineVisualizer({
  genRecord,
  debug,
  onShowIocs,
}: {
  genRecord: THGenerationRecord
  debug: boolean
  onShowIocs?: () => void
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

          // Part 7a: intake sub-list
          const intakeSources = step.id === 'intake_classifier' ? (log?.intake_sources ?? []) : []

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
                        'text-sm font-medium',
                        isActive ? 'text-blue-300' : isDone ? 'text-gray-200' : 'text-gray-600',
                      )}
                    >
                      {step.label}
                    </span>
                    {log?.elapsed_s !== undefined && (
                      <span className="text-[11px] text-gray-600 font-mono">
                        {log.elapsed_s}s
                      </span>
                    )}
                    {log?.item_count !== undefined && (
                      <span className="text-[11px] text-brand-600 font-mono">
                        {log.item_count} items
                      </span>
                    )}
                    {log?.ioc_count !== undefined && (
                      <span className="text-[11px] text-brand-600 font-mono">
                        {log.ioc_count} IOCs
                        {log.noisy_count ? ` (${log.noisy_count} noisy)` : ''}
                      </span>
                    )}
                    {/* Part 7a: "View N IOCs" link when IOCs are present */}
                    {log?.ioc_count != null && log.ioc_count > 0 && onShowIocs && (
                      <button
                        className="flex items-center gap-0.5 text-[11px] text-blue-400 hover:text-blue-300 transition-colors"
                        onClick={onShowIocs}
                        title="Switch to IOCs tab"
                      >
                        View {log.ioc_count} IOC{log.ioc_count !== 1 ? 's' : ''}
                        <ArrowRight className="w-3 h-3" />
                      </button>
                    )}
                    {log?.effort && (
                      <span className="text-[11px] text-gray-700 font-mono">
                        effort={log.effort}
                      </span>
                    )}
                    {/* issue-006-C: tools_used pills */}
                    {log?.tools_used?.map((tool) => (
                      <span
                        key={tool}
                        className="text-[10px] font-mono bg-purple-900/40 text-purple-300 border border-purple-800/40 rounded px-1 py-0.5"
                      >
                        {tool}()
                      </span>
                    ))}
                  </div>
                  {/* issue-006-C: decision sub-text */}
                  {log?.decision && (
                    <p className="text-[11px] text-gray-500 mt-0.5 italic">{log.decision}</p>
                  )}
                  {isActive && !log?.decision && (
                    <p className="text-[11px] text-gray-500 mt-0.5">{step.description}</p>
                  )}
                  {log?.error && (
                    <p className="text-[11px] text-red-400 mt-0.5">Error: {log.error}</p>
                  )}
                  {/* Part 7a: per-evidence sub-list below intake_classifier */}
                  {intakeSources.length > 0 && (
                    <div className="mt-1.5 pl-3 border-l border-gray-700/60 space-y-0">
                      {intakeSources.map((src, i) => (
                        <IntakeSourceSubStatus key={i} src={src} />
                      ))}
                    </div>
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
          <p className="text-[11px] text-gray-500 font-semibold uppercase tracking-wider">
            Pipeline Log
          </p>
          <pre
            ref={debugRef}
            className="bg-gray-950 border border-gray-800 rounded p-2 text-[10px] text-green-400 font-mono h-48 overflow-y-auto whitespace-pre-wrap"
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
  /** Called when the user clicks the "View N IOCs" link in the intake step row. */
  onShowIocs?: () => void
}

export default function WorkflowVisualizer({ genRecord, compact = false, onShowIocs }: WorkflowVisualizerProps) {
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

  // Part 1b: show-subtasks setting
  const { data: subtasksData } = useQuery({
    queryKey: ['agent-show-subtasks'],
    queryFn: () => api.getAgentShowSubtasks(),
    staleTime: 30_000,
  })
  const showSubtasksDefault = subtasksData?.agent_workflow_show_subtasks ?? false
  const [showSubtasks, setShowSubtasks] = useState(false)

  useEffect(() => {
    setShowSubtasks(showSubtasksDefault)
  }, [showSubtasksDefault])

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
                'flex items-center gap-2 text-sm',
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

  // Verbose / Debug — issue-006-C: 2-col layout (task list LEFT, diagram RIGHT)
  const debug = verbosity === 'debug'

  // Part 1b: toolbar row component
  const SubtasksToolbar = (
    <div className="col-span-2 flex items-center gap-3 pb-1 border-b border-gray-800/50">
      <button
        className="text-sm text-gray-400 flex items-center gap-1.5 cursor-pointer select-none hover:text-gray-200 transition-colors"
        onClick={() => {
          const next = !showSubtasks
          setShowSubtasks(next)
          // fire-and-forget
          void api.setAgentShowSubtasks(next)
        }}
      >
        <span
          className={clsx(
            'inline-block w-3 h-3 border rounded-sm flex-shrink-0 transition-colors',
            showSubtasks
              ? 'bg-brand-500 border-brand-400'
              : 'bg-transparent border-gray-600',
          )}
        />
        Show subtasks
      </button>
    </div>
  )

  if (visualization === 'mermaid') {
    return (
      <div className="grid grid-cols-1 lg:grid-cols-[minmax(200px,1fr)_minmax(0,1.6fr)] gap-4">
        {/* Part 1b: toolbar row spans both columns */}
        {SubtasksToolbar}
        {/* Left: compact task list always visible */}
        <div className="min-w-0">
          <TimelineVisualizer genRecord={genRecord} debug={debug} onShowIocs={onShowIocs} />
        </div>
        {/* Right: Mermaid diagram */}
        <div className="min-w-0">
          <Suspense
            fallback={
              <div className="flex items-center gap-2 text-sm text-gray-500">
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
                Loading Mermaid diagram…
              </div>
            }
          >
            <MermaidVisualizer genRecord={genRecord} showSubtasks={showSubtasks} />
          </Suspense>
        </div>
      </div>
    )
  }

  if (visualization === 'reactflow') {
    return (
      <div className="grid grid-cols-1 lg:grid-cols-[minmax(200px,1fr)_minmax(0,1.6fr)] gap-4">
        {/* Part 1b: toolbar row spans both columns */}
        {SubtasksToolbar}
        {/* Left: compact task list always visible */}
        <div className="min-w-0">
          <TimelineVisualizer genRecord={genRecord} debug={debug} onShowIocs={onShowIocs} />
        </div>
        {/* Right: ReactFlow graph */}
        <div className="min-w-0">
          <Suspense
            fallback={
              <div className="flex items-center gap-2 text-sm text-gray-500">
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
                Loading React Flow graph…
              </div>
            }
          >
            <ReactFlowVisualizer genRecord={genRecord} showSubtasks={showSubtasks} />
          </Suspense>
        </div>
      </div>
    )
  }

  // Default: timeline (full width, includes debug panel)
  return <TimelineVisualizer genRecord={genRecord} debug={debug} onShowIocs={onShowIocs} />
}
