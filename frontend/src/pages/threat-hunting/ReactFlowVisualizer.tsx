/**
 * ReactFlowVisualizer — lazy-loaded interactive React Flow graph.
 * Loaded only when the user selects "React Flow" visualization style.
 *
 * issue-006-C: adds Threat Intel source nodes above intake_classifier,
 * distributed horizontally at y=-120.
 *
 * Current additions:
 *   - Part 1a: evidence source nodes use pill/capsule shape (borderRadius 20px) +
 *              dashed border + teal fallback color for pending/undefined sub_status
 *   - Part 1b: showSubtasks prop — renders subtask child nodes per step
 *   - Part 1c: active node gets .node-active class for CSS pulse animation
 */

import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  ReactFlow,
  Background,
  Controls,
  Handle,
  Position,
  useNodesInitialized,
  useReactFlow,
  type Node,
  type NodeProps,
  type Edge,
  type ReactFlowInstance,
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import { type THGenerationRecord, type THStepLog } from '../../api/client'
import { PIPELINE_STEPS as STEP_DESCRIPTIONS } from './WorkflowVisualizer'

// issue-local-041: brief per-node hover descriptions — reuses
// WorkflowVisualizer.tsx's PIPELINE_STEPS (the same list already shown as
// timeline sub-text there) instead of maintaining a second copy; a couple of
// ids only exist on THIS component's own graph (the approval gate, SIEM
// connector steps not covered there) and get a description of their own.
const STEP_DESCRIPTION_BY_ID = new Map(STEP_DESCRIPTIONS.map((s) => [s.id, s.description]))
const EXTRA_DESCRIPTIONS: Record<string, string> = {
  approval_gate: 'Pauses the pipeline for operator review of the analysis before execution proceeds',
}
function stepDescription(id: string): string | undefined {
  return STEP_DESCRIPTION_BY_ID.get(id) ?? EXTRA_DESCRIPTIONS[id]
}

// issue-local-041: combines the static "what this node does" description
// with this run's actual step_logs entry (if any) for a brief-but-informed
// tooltip — status/elapsed time/decision, when known, not just a static
// label repeated from the node itself.
function nodeTooltip(id: string, label: string, log: THStepLog | undefined): string {
  const lines = [label]
  const description = stepDescription(id)
  if (description) lines.push(description)
  if (log) {
    const bits: string[] = [log.status]
    if (log.elapsed_s != null) bits.push(`${log.elapsed_s.toFixed(1)}s`)
    lines.push(bits.join(' · '))
    if (log.decision) lines.push(log.decision)
  }
  return lines.join('\n')
}

// issue-local-041: minimal custom node — swaps in for the default @xyflow/
// react node renderer solely to add a native `title` attribute (the
// simplest, zero-dependency way to get a browser hover tooltip); keeps
// invisible top/bottom handles so edges still attach exactly as before.
//
// issue-local-042 follow-up: `w-full h-full` only resolves against an
// ancestor with an explicitly-set (not intrinsic/content) height — the
// outer `.react-flow__node` wrapper doesn't have one (only padding/
// min-width come from `node.style`), so the height rule silently fell back
// to `auto` and this div only ever covered the text's own line-height —
// live measurement on a real run found it covering ~45% of the visibly
// colored node, so hovering its padding/edges (most of what a user aims
// for) never reached the `title`-bearing element at all. `absolute inset-0`
// fills the nearest *positioned* ancestor's box directly (`.react-flow__node`
// is already `position: absolute` per React Flow's own base CSS), which
// works regardless of how that ancestor's height was resolved — so this
// always covers the node's full rendered/visible area.
function TooltipNode({ data }: NodeProps) {
  const { label, tooltip } = data as { label: string; tooltip?: string }
  return (
    <div title={tooltip} className="absolute inset-0 flex items-center justify-center whitespace-pre-line">
      <Handle type="target" position={Position.Top} style={{ opacity: 0 }} />
      {label as string}
      <Handle type="source" position={Position.Bottom} style={{ opacity: 0 }} />
    </div>
  )
}
const NODE_TYPES = { default: TooltipNode }

// issue-local-042 follow-up: the scoped initial `fitView` used to run
// synchronously inside `onInit`, which React Flow's own docs note does NOT
// guarantee node dimensions have been measured yet — usually harmless (there
// was enough incidental delay before onInit fired for it to work out), but
// once the diagram could mount on-demand from a freshly-toggled collapsible
// section (HuntingPackageDraft's "Show Pipeline Diagram"), onInit routinely
// fired before measurement, and fitView's bounding-box math over
// still-zero-size nodes produced a wildly wrong transform — live
// measurement found the focus node's own fitted position at y≈-320px,
// entirely above the visible viewport, so nothing was hoverable at all.
// `useNodesInitialized()` is React Flow's documented mechanism for exactly
// this: it flips true only once every node has actually been measured.
// Rendered as a child of `<ReactFlow>` (not in ReactFlowVisualizer's own
// body) because these hooks require the provider context `<ReactFlow>`
// establishes for its children — same reason `<Background>`/`<Controls>`
// are children here rather than called directly.
function FitViewOnReady({ focusIds }: { focusIds: string[] }) {
  const nodesInitialized = useNodesInitialized()
  const { fitView } = useReactFlow()
  const firedRef = useRef(false)

  useEffect(() => {
    if (!nodesInitialized || firedRef.current) return
    firedRef.current = true
    fitView({ nodes: focusIds.map((id) => ({ id })), padding: 0.4, duration: 0 })
  }, [nodesInitialized, focusIds, fitView])

  return null
}

const PIPELINE_STEPS = [
  // ── LangGraph pipeline ──────────────────────────────────────────────────────
  { id: 'intake_classifier',      label: 'Intake Classifier',      x: 250, y: 0   },
  { id: 'threat_context_builder', label: 'Threat Context Builder',  x: 50,  y: 120 },
  { id: 'deep_retrohunt_planner', label: 'Deep Retrohunt Planner',  x: 450, y: 120 },
  { id: 'hypothesis_generator',   label: 'Hypothesis Generator',    x: 250, y: 240 },
  { id: 'hunting_lead_planner',   label: 'Hunting Lead Planner',    x: 250, y: 360 },
  { id: 'ttp_analyst',            label: 'TTP Analyst',             x: 250, y: 480 },
  { id: 'query_drafting_agent',   label: 'Query Drafting Agent',    x: 250, y: 600 },
  // ── Threat Intel Analyst, preliminary phase (issue-local-020/021/022) ───────
  { id: 'threat_intel_preliminary', label: 'Threat Intel (Preliminary)', x: 250, y: 660 },
  // ── Approval gate ───────────────────────────────────────────────────────────
  { id: 'approval_gate',          label: '⚑ Approval Gate',         x: 250, y: 720 },
  // ── SIEM execution (issue-local-009) ────────────────────────────────────────
  { id: 'siem_connect',           label: 'SIEM Connect',            x: 250, y: 840  },
  { id: 'siem_submit',            label: 'SIEM Submit',             x: 250, y: 960  },
  { id: 'siem_poll',              label: 'SIEM Poll',               x: 250, y: 1080 },
  { id: 'siem_fetch',             label: 'SIEM Fetch',              x: 250, y: 1200 },
  { id: 'siem_interpret',         label: 'SIEM Interpret',          x: 250, y: 1320 },
  // ── Threat Intel Analyst, final phase (issue-local-020/021/022) ────────────
  { id: 'threat_intel_final',     label: 'Threat Intel (Final)',    x: 250, y: 1380 },
  // ── Report generation (issue-local-009) ─────────────────────────────────────
  { id: 'report_assemble',        label: 'Assemble Report',         x: 250, y: 1440 },
  { id: 'report_exec_summary',    label: 'Exec Summary',            x: 250, y: 1560 },
  { id: 'report_findings',        label: 'Findings',                x: 250, y: 1680 },
  { id: 'report_render',          label: 'Render Report',           x: 250, y: 1800 },
]

const PIPELINE_EDGES_DEF = [
  // Pipeline
  { source: 'intake_classifier',      target: 'threat_context_builder' },
  { source: 'intake_classifier',      target: 'deep_retrohunt_planner' },
  { source: 'threat_context_builder', target: 'hypothesis_generator' },
  { source: 'deep_retrohunt_planner', target: 'hypothesis_generator' },
  { source: 'hypothesis_generator',   target: 'hunting_lead_planner' },
  { source: 'hunting_lead_planner',   target: 'ttp_analyst' },
  { source: 'ttp_analyst',            target: 'query_drafting_agent' },
  { source: 'query_drafting_agent',   target: 'threat_intel_preliminary' },
  { source: 'threat_intel_preliminary', target: 'approval_gate' },
  // Execution
  { source: 'approval_gate',          target: 'siem_connect' },
  { source: 'siem_connect',           target: 'siem_submit' },
  { source: 'siem_submit',            target: 'siem_poll' },
  { source: 'siem_poll',              target: 'siem_fetch' },
  { source: 'siem_fetch',             target: 'siem_interpret' },
  { source: 'siem_interpret',         target: 'threat_intel_final' },
  // Report
  { source: 'threat_intel_final',     target: 'report_assemble' },
  { source: 'report_assemble',        target: 'report_exec_summary' },
  { source: 'report_exec_summary',    target: 'report_findings' },
  { source: 'report_findings',        target: 'report_render' },
]

function nodeColor(id: string, completed: Set<string>, active: string): string {
  if (id === 'approval_gate') return '#78350f'  // amber — always distinct
  if (completed.has(id)) return '#14532d'        // green
  if (active === id) return '#1e3a5f'            // blue
  return '#1f2937'                               // gray
}

function nodeBorderColor(id: string, completed: Set<string>, active: string): string {
  if (id === 'approval_gate') return '#f59e0b'
  if (completed.has(id)) return '#22c55e'
  if (active === id) return '#3b82f6'
  return '#374151'
}

export default function ReactFlowVisualizer({
  genRecord,
  showSubtasks = false,
  trackWorkflow = false,
}: {
  genRecord: THGenerationRecord
  showSubtasks?: boolean
  /** issue-local-018 follow-up: when true, the view re-centers on whichever
   *  node is currently active every time it changes, instead of staying at
   *  its initial fit. */
  trackWorkflow?: boolean
}) {
  const completed = useMemo(() => new Set(genRecord.completed_steps ?? []), [genRecord.completed_steps])
  const active = genRecord.current_step ?? ''

  // issue-006-C: extract intake sources from step_logs
  const intakeSources = useMemo(() => {
    const intakeLog = (genRecord.step_logs ?? []).find((l) => l.step === 'intake_classifier')
    return intakeLog?.intake_sources ?? []
  }, [genRecord.step_logs])

  // issue-local-041: this run's step_logs entry per step id, for tooltips.
  const stepLogById = useMemo(
    () => new Map((genRecord.step_logs ?? []).map((l) => [l.step, l])),
    [genRecord.step_logs],
  )

  const nodes: Node[] = useMemo(() => {
    // Pipeline nodes
    const pipelineNodes: Node[] = PIPELINE_STEPS.map((s) => ({
      id: s.id,
      position: { x: s.x, y: s.y },
      data: { label: s.label, tooltip: nodeTooltip(s.id, s.label, stepLogById.get(s.id)) },
      // Part 1c: apply .node-active class for the CSS glow animation
      className: active === s.id ? 'node-active' : undefined,
      style: {
        background: nodeColor(s.id, completed, active),
        border: `1px solid ${nodeBorderColor(s.id, completed, active)}`,
        color: completed.has(s.id) ? '#d1fae5' : active === s.id ? '#bfdbfe' : '#6b7280',
        borderRadius: '8px',
        padding: '6px 12px',
        fontSize: '11px',
        fontWeight: 500,
        minWidth: '160px',
        textAlign: 'center' as const,
      },
    }))

    // Source nodes — color by sub_status (issue-local-011 Part 7d)
    // Part 1a: pill shape (borderRadius 20px) + dashed border + teal for pending/undefined
    const sourceNodes: Node[] = (() => {
      if (intakeSources.length === 0) return []
      const totalWidth = 500
      const spacing = intakeSources.length > 1 ? totalWidth / (intakeSources.length - 1) : 0
      const startX = intakeSources.length === 1 ? 250 : 0
      return intakeSources.map((src, i) => {
        const subStatus = src.sub_status
        let bg: string, borderColor: string, color: string
        if (subStatus === 'ok') {
          // Part 4 (issue-local-018 follow-up): a distinct teal "success" —
          // not agent nodes' green — so a completed Evidence node never
          // reads as a completed Agent node at a glance.
          bg = '#134e4a'; borderColor = '#2dd4bf'; color = '#99f6e4'
        } else if (subStatus === 'error') {
          bg = '#7f1d1d'; borderColor = '#ef4444'; color = '#fee2e2'
        } else if (subStatus === 'partial') {
          bg = '#78350f'; borderColor = '#f59e0b'; color = '#fef3c7'
        } else {
          // pending or undefined → teal (Part 1a distinct color)
          bg = '#0e4f4f'; borderColor = '#14b8a6'; color = '#ccfbf1'
        }
        return {
          id: `src_${i}`,
          position: { x: startX + i * spacing, y: -120 },
          data: {
            label: `${(src.label || src.item_type || 'source').slice(0, 20)}\n(${src.item_type})`,
            tooltip: [
              src.label || src.item_type || 'Evidence source',
              `Type: ${src.item_type}`,
              src.sub_status ? `Status: ${src.sub_status}` : undefined,
              src.parser_used ? `Parser: ${src.parser_used}` : undefined,
              src.text_length ? `${src.text_length.toLocaleString()} chars extracted` : undefined,
              src.ioc_count != null && src.ioc_count > 0 ? `${src.ioc_count} IOC(s) found` : undefined,
            ]
              .filter(Boolean)
              .join('\n'),
          },
          style: {
            background: bg,
            // Part 1a: dashed border + pill/capsule shape
            border: `1px dashed ${borderColor}`,
            borderRadius: '20px',
            color,
            padding: '4px 10px',
            fontSize: '10px',
            fontWeight: 500,
            minWidth: '120px',
            textAlign: 'center' as const,
          },
        }
      })
    })()

    // Part 1b: subtask nodes
    const subtaskNodes: Node[] = (() => {
      if (!showSubtasks) return []
      const result: Node[] = []
      for (const stepLog of (genRecord.step_logs ?? [])) {
        const toolsUsed = stepLog.tools_used ?? []
        // Find the parent step's position
        const parentStep = PIPELINE_STEPS.find((s) => s.id === stepLog.step)
        if (!parentStep) continue
        const count = toolsUsed.length
        for (let i = 0; i < count; i++) {
          const offsetX = count === 1 ? 0 : (i - (count - 1) / 2) * 120
          result.push({
            id: `sub_${stepLog.step}_${i}`,
            position: { x: parentStep.x + offsetX, y: parentStep.y + 80 },
            data: { label: toolsUsed[i], tooltip: `Tool call: ${toolsUsed[i]}` },
            style: {
              background: '#2d1b69',
              border: '1px solid #7c3aed',
              borderRadius: '4px',
              color: '#c4b5fd',
              fontSize: '10px',
              padding: '4px 8px',
            },
          })
        }
      }
      return result
    })()

    return [...sourceNodes, ...pipelineNodes, ...subtaskNodes]
  }, [completed, active, intakeSources, showSubtasks, genRecord.step_logs, stepLogById])

  const edges: Edge[] = useMemo(() => {
    const pipelineEdges: Edge[] = PIPELINE_EDGES_DEF.map((e, i) => ({
      id: `e${i}`,
      source: e.source,
      target: e.target,
      style: { stroke: '#4b5563', strokeWidth: 1.5 },
      animated: active === e.source,
    }))

    // Source → intake_classifier edges
    const sourceEdges: Edge[] = intakeSources.map((_, i) => ({
      id: `src_e${i}`,
      source: `src_${i}`,
      target: 'intake_classifier',
      style: { stroke: '#14b8a6', strokeWidth: 1, strokeDasharray: '4 2' },
      animated: false,
    }))

    // Part 1b: subtask edges
    const subtaskEdges: Edge[] = (() => {
      if (!showSubtasks) return []
      const result: Edge[] = []
      for (const stepLog of (genRecord.step_logs ?? [])) {
        const toolsUsed = stepLog.tools_used ?? []
        for (let i = 0; i < toolsUsed.length; i++) {
          result.push({
            id: `sub_e_${stepLog.step}_${i}`,
            source: stepLog.step,
            target: `sub_${stepLog.step}_${i}`,
            style: { stroke: '#7c3aed', strokeWidth: 1, strokeDasharray: '3 2' },
            animated: false,
          })
        }
      }
      return result
    })()

    return [...sourceEdges, ...pipelineEdges, ...subtaskEdges]
  }, [active, intakeSources, showSubtasks, genRecord.step_logs])

  const graphHeight = intakeSources.length > 0 ? 1000 : 900

  // issue-local-018 follow-up: on first render (i.e. when an analysis run
  // starts and this chart mounts), focus the view tightly on Evidence +
  // the initial/root agent node (intake_classifier) instead of fitting the
  // whole ~1800px-tall pipeline, which zooms out so far the starting point
  // is barely visible. issue-local-042 follow-up: the actual scoped fitView
  // call moved into <FitViewOnReady> (rendered below, as a child of
  // <ReactFlow>) — see its comment for why onInit itself was the wrong place
  // to call it.
  const focusIds = useMemo(
    () => ['intake_classifier', ...intakeSources.map((_, i) => `src_${i}`)],
    [intakeSources],
  )
  const instanceRef = useRef<ReactFlowInstance | null>(null)
  // issue-local-041: the tracking effect below used to depend only on
  // [trackWorkflow, active] — on every remount (e.g. switching tabs and
  // back, which unmounts AnalysisTab and its WorkflowVisualizer/
  // ReactFlowVisualizer subtree) it ran once immediately with
  // instanceRef.current still null (onInit hasn't fired yet), silently
  // no-op'd, and then never ran again unless trackWorkflow or active
  // actually changed value — so a checkbox that was already checked before
  // the remount looked checked but did nothing until unchecked/rechecked.
  // isReady flips true exactly once, right when onInit populates the ref,
  // giving the effect a deps change to react to on every mount.
  const [isReady, setIsReady] = useState(false)

  const handleInit = useCallback((instance: ReactFlowInstance) => {
    instanceRef.current = instance
    setIsReady(true)
  }, [])

  // issue-local-018 follow-up: "Track workflow" — while enabled, re-center
  // on whichever node is currently active every time it changes, so the
  // chart follows the run instead of staying at its initial fit. `padding`
  // (rather than a fixed zoom level) keeps a consistent, readable margin
  // around the single focused node regardless of its size on screen.
  useEffect(() => {
    if (!trackWorkflow || !active || !isReady) return
    // issue-local-021: zoomed out slightly (0.6 -> 1.1) so neighboring
    // nodes stay visible for context while still centering on the active one.
    instanceRef.current?.fitView({ nodes: [{ id: active }], padding: 1.1, duration: 400 })
  }, [trackWorkflow, active, isReady])

  return (
    <div className="rounded-lg border border-gray-700 overflow-hidden" style={{ height: graphHeight }}>
      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={NODE_TYPES}
        onInit={handleInit}
        nodesDraggable={false}
        nodesConnectable={false}
        elementsSelectable={false}
        // issue-local-042 follow-up: THE actual reason hover never worked,
        // at any point — React Flow computes
        // `hasPointerEvents = isSelectable || isDraggable || onClick ||
        // onMouseEnter || onMouseMove || onMouseLeave` per node and sets
        // `pointer-events: none` INLINE (higher specificity than any CSS
        // rule, including its own base stylesheet's
        // `.react-flow__node { pointer-events: all }`) whenever that's
        // false. `elementsSelectable={false}` + `nodesDraggable={false}`
        // above (both correct — this is a read-only diagram) with no mouse
        // handler meant every node had pointer-events:none the whole time,
        // so a hover could never reach the `title`-bearing element to begin
        // with, independent of the fitView-positioning and inset-coverage
        // fixes elsewhere in this file. A no-op handler is enough to flip
        // `hasPointerEvents` true without adding any real interactivity.
        onNodeMouseEnter={() => {}}
        proOptions={{ hideAttribution: true }}
        colorMode="dark"
      >
        <Background color="#374151" gap={16} size={1} />
        <Controls showInteractive={false} />
        <FitViewOnReady focusIds={focusIds} />
      </ReactFlow>
    </div>
  )
}
