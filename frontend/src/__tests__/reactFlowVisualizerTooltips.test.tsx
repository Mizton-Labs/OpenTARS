/**
 * Tests for issue-local-041: ReactFlowVisualizer's flowchart nodes get a
 * brief hover tooltip (native `title` attribute) describing what that node
 * did/does — combining the static per-step description (shared with
 * WorkflowVisualizer.tsx's timeline) with this run's actual step_logs
 * status/elapsed/decision, when known.
 *
 * @xyflow/react is mocked to actually invoke the custom `nodeTypes.default`
 * renderer per node (unlike reactFlowVisualizerTracking.test.tsx's stub,
 * which only needs onInit/fitView) so the rendered `title` attributes can be
 * asserted on directly.
 */
import { render, screen } from '@testing-library/react'
import type { ComponentType } from 'react'
import { describe, it, expect, vi } from 'vitest'
import type { THGenerationRecord } from '../api/client'

let lastReactFlowProps: Record<string, unknown> | undefined

vi.mock('@xyflow/react', () => {
  return {
    ReactFlow: ({
      nodes,
      nodeTypes,
      ...rest
    }: {
      nodes: { id: string; data: Record<string, unknown> }[]
      nodeTypes: { default: ComponentType<{ data: Record<string, unknown> }> }
      [key: string]: unknown
    }) => {
      lastReactFlowProps = { nodes, nodeTypes, ...rest }
      const NodeComponent = nodeTypes.default
      return (
        <div data-testid="react-flow-stub">
          {nodes.map((n) => (
            <NodeComponent key={n.id} data={n.data} />
          ))}
        </div>
      )
    },
    Background: () => null,
    Controls: () => null,
    Handle: () => null,
    Position: { Top: 'top', Bottom: 'bottom' },
    useNodesInitialized: () => true,
    useReactFlow: () => ({ fitView: () => {} }),
  }
})

import ReactFlowVisualizer from '../pages/threat-hunting/ReactFlowVisualizer'

function makeGenRecord(overrides: Partial<THGenerationRecord> = {}): THGenerationRecord {
  return {
    id: 'run-1',
    hunt_package_id: 'pkg-1',
    generation_status: 'running',
    current_step: 'intake_classifier',
    completed_steps: [],
    step_logs: [],
    ...overrides,
  } as THGenerationRecord
}

describe('ReactFlowVisualizer — node hover tooltips (issue-local-041)', () => {
  it('gives a pipeline node a title combining its static description and no dynamic status when no step_log exists yet', () => {
    render(<ReactFlowVisualizer genRecord={makeGenRecord()} />)
    const node = screen.getByText('Intake Classifier')
    expect(node).toHaveAttribute(
      'title',
      expect.stringContaining('Loads evidence, builds corpus, extracts IOC summary'),
    )
  })

  it('adds this run\'s actual status/elapsed/decision once a step_log entry exists', () => {
    render(
      <ReactFlowVisualizer
        genRecord={makeGenRecord({
          step_logs: [
            {
              step: 'hypothesis_generator',
              status: 'ok',
              elapsed_s: 4.2,
              decision: 'Generated 5 hypotheses',
            },
          ],
        })}
      />,
    )
    const node = screen.getByText('Hypothesis Generator')
    const title = node.getAttribute('title') || ''
    expect(title).toContain('Generates actionable hunting hypotheses')
    expect(title).toContain('ok')
    expect(title).toContain('4.2s')
    expect(title).toContain('Generated 5 hypotheses')
  })

  it('gives the approval gate node a description even though it has no entry in WorkflowVisualizer\'s timeline list', () => {
    render(<ReactFlowVisualizer genRecord={makeGenRecord()} />)
    const node = screen.getByText('⚑ Approval Gate')
    expect(node).toHaveAttribute('title', expect.stringContaining('operator review'))
  })

  // issue-local-042 follow-up: the real bug behind "hover doesn't work" —
  // React Flow computes `hasPointerEvents = isSelectable || isDraggable ||
  // onClick || onMouseEnter || onMouseMove || onMouseLeave` per node and, if
  // that's false, sets `pointer-events: none` INLINE (beats any CSS rule,
  // including its own base stylesheet's unconditional
  // `.react-flow__node { pointer-events: all }` — which is why a static CSS
  // read alone looked fine and missed this). `elementsSelectable={false}` +
  // `nodesDraggable={false}` (both correct for a read-only diagram) with no
  // mouse handler meant every node had pointer-events:none, so a hover could
  // never reach the title-bearing element at all, independent of the
  // separately-fixed fitView-positioning and inset-coverage bugs. This is a
  // library-internal computation the mocked <ReactFlow> above can't
  // exercise directly, so this test instead pins the one thing our own code
  // controls: that a mouse-event handler prop is actually passed, which is
  // what flips `hasPointerEvents` true in the real component.
  it('passes a mouse-event handler to <ReactFlow> so nodes are not left pointer-events:none', () => {
    render(<ReactFlowVisualizer genRecord={makeGenRecord()} />)
    expect(typeof lastReactFlowProps?.onNodeMouseEnter).toBe('function')
  })
})
