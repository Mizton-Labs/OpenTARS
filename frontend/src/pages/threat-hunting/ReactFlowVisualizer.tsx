/**
 * ReactFlowVisualizer — lazy-loaded interactive React Flow graph.
 * Loaded only when the user selects "React Flow" visualization style.
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

const STEPS = [
  { id: 'intake_classifier',      label: 'Intake Classifier',      x: 250, y: 0   },
  { id: 'threat_context_builder', label: 'Threat Context Builder',  x: 50,  y: 120 },
  { id: 'deep_retrohunt_planner', label: 'Deep Retrohunt Planner',  x: 450, y: 120 },
  { id: 'hypothesis_generator',   label: 'Hypothesis Generator',    x: 250, y: 240 },
  { id: 'hunting_lead_planner',   label: 'Hunting Lead Planner',    x: 250, y: 360 },
  { id: 'ttp_analyst',            label: 'TTP Analyst',             x: 250, y: 480 },
  { id: 'query_drafting_agent',   label: 'Query Drafting Agent',    x: 250, y: 600 },
]

const EDGES_DEF = [
  { source: 'intake_classifier',      target: 'threat_context_builder' },
  { source: 'intake_classifier',      target: 'deep_retrohunt_planner' },
  { source: 'threat_context_builder', target: 'hypothesis_generator' },
  { source: 'deep_retrohunt_planner', target: 'hypothesis_generator' },
  { source: 'hypothesis_generator',   target: 'hunting_lead_planner' },
  { source: 'hunting_lead_planner',   target: 'ttp_analyst' },
  { source: 'ttp_analyst',            target: 'query_drafting_agent' },
]

function nodeColor(id: string, completed: Set<string>, active: string): string {
  if (completed.has(id)) return '#14532d' // green
  if (active === id) return '#1e3a5f'     // blue
  return '#1f2937'                         // gray
}

function nodeBorderColor(id: string, completed: Set<string>, active: string): string {
  if (completed.has(id)) return '#22c55e'
  if (active === id) return '#3b82f6'
  return '#374151'
}

export default function ReactFlowVisualizer({ genRecord }: { genRecord: THGenerationRecord }) {
  const completed = useMemo(() => new Set(genRecord.completed_steps ?? []), [genRecord.completed_steps])
  const active = genRecord.current_step ?? ''

  const nodes: Node[] = useMemo(
    () =>
      STEPS.map((s) => ({
        id: s.id,
        position: { x: s.x, y: s.y },
        data: { label: s.label },
        style: {
          background: nodeColor(s.id, completed, active),
          border: `1px solid ${nodeBorderColor(s.id, completed, active)}`,
          color: completed.has(s.id) ? '#d1fae5' : active === s.id ? '#bfdbfe' : '#6b7280',
          borderRadius: '8px',
          padding: '6px 12px',
          fontSize: '11px',
          fontWeight: 500,
          minWidth: '160px',
          textAlign: 'center',
        },
      })),
    [completed, active],
  )

  const edges: Edge[] = useMemo(
    () =>
      EDGES_DEF.map((e, i) => ({
        id: `e${i}`,
        source: e.source,
        target: e.target,
        style: { stroke: '#4b5563', strokeWidth: 1.5 },
        animated: active === e.source,
      })),
    [active],
  )

  return (
    <div className="rounded-lg border border-gray-700 overflow-hidden" style={{ height: 680 }}>
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
