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

import { useMemo } from 'react'
import {
  ReactFlow,
  Background,
  Controls,
  type Node,
  type Edge,
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import { type THGenerationRecord } from '../../api/client'

const PIPELINE_STEPS = [
  // ── LangGraph pipeline ──────────────────────────────────────────────────────
  { id: 'intake_classifier',      label: 'Intake Classifier',      x: 250, y: 0   },
  { id: 'threat_context_builder', label: 'Threat Context Builder',  x: 50,  y: 120 },
  { id: 'deep_retrohunt_planner', label: 'Deep Retrohunt Planner',  x: 450, y: 120 },
  { id: 'hypothesis_generator',   label: 'Hypothesis Generator',    x: 250, y: 240 },
  { id: 'hunting_lead_planner',   label: 'Hunting Lead Planner',    x: 250, y: 360 },
  { id: 'ttp_analyst',            label: 'TTP Analyst',             x: 250, y: 480 },
  { id: 'query_drafting_agent',   label: 'Query Drafting Agent',    x: 250, y: 600 },
  // ── Approval gate ───────────────────────────────────────────────────────────
  { id: 'approval_gate',          label: '⚑ Approval Gate',         x: 250, y: 720 },
  // ── SIEM execution (issue-local-009) ────────────────────────────────────────
  { id: 'siem_connect',           label: 'SIEM Connect',            x: 250, y: 840  },
  { id: 'siem_submit',            label: 'SIEM Submit',             x: 250, y: 960  },
  { id: 'siem_poll',              label: 'SIEM Poll',               x: 250, y: 1080 },
  { id: 'siem_fetch',             label: 'SIEM Fetch',              x: 250, y: 1200 },
  { id: 'siem_interpret',         label: 'SIEM Interpret',          x: 250, y: 1320 },
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
  { source: 'query_drafting_agent',   target: 'approval_gate' },
  // Execution
  { source: 'approval_gate',          target: 'siem_connect' },
  { source: 'siem_connect',           target: 'siem_submit' },
  { source: 'siem_submit',            target: 'siem_poll' },
  { source: 'siem_poll',              target: 'siem_fetch' },
  { source: 'siem_fetch',             target: 'siem_interpret' },
  // Report
  { source: 'siem_interpret',         target: 'report_assemble' },
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
}: {
  genRecord: THGenerationRecord
  showSubtasks?: boolean
}) {
  const completed = useMemo(() => new Set(genRecord.completed_steps ?? []), [genRecord.completed_steps])
  const active = genRecord.current_step ?? ''

  // issue-006-C: extract intake sources from step_logs
  const intakeSources = useMemo(() => {
    const intakeLog = (genRecord.step_logs ?? []).find((l) => l.step === 'intake_classifier')
    return intakeLog?.intake_sources ?? []
  }, [genRecord.step_logs])

  const nodes: Node[] = useMemo(() => {
    // Pipeline nodes
    const pipelineNodes: Node[] = PIPELINE_STEPS.map((s) => ({
      id: s.id,
      position: { x: s.x, y: s.y },
      data: { label: s.label },
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
          bg = '#14532d'; borderColor = '#22c55e'; color = '#d1fae5'
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
            data: { label: toolsUsed[i] },
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
  }, [completed, active, intakeSources, showSubtasks, genRecord.step_logs])

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

  return (
    <div className="rounded-lg border border-gray-700 overflow-hidden" style={{ height: graphHeight }}>
      <ReactFlow
        nodes={nodes}
        edges={edges}
        fitView
        fitViewOptions={{ padding: 0.2 }}
        nodesDraggable={false}
        nodesConnectable={false}
        elementsSelectable={false}
        proOptions={{ hideAttribution: true }}
        colorMode="dark"
      >
        <Background color="#374151" gap={16} size={1} />
        <Controls showInteractive={false} />
      </ReactFlow>
    </div>
  )
}
